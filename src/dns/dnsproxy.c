/*
 * dnsproxy.c
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */
#include <zroxy/dnsproxy.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <zroxy/log.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <zroxy/socks.h>
#include <pthread.h>
#include <zroxy/dns.h>
#include <unistd.h>
#include <zroxy/net.h>
#include <zroxy/filter.h>
#include <time.h>
#include <zroxy/net_io.h>
#include <poll.h>

static void close_fd(int *fd)
{
	if (fd && *fd >= 0)
	{
		close(*fd);
		*fd = -1;
	}
}

dnsserver_t *localdns_init_config(dnshost_t *conf)
{
	dnsserver_t *ptr = (dnsserver_t*)malloc(sizeof(dnsserver_t));
	if(!ptr)
		return NULL;
	memset(ptr,0,sizeof(dnsserver_t));
	ptr->local_sock = -1;
	ptr->wake[0] = -1;
	ptr->wake[1] = -1;

	/* fifo init*/
	ptr->fifo = (fifo_t*)malloc(sizeof(fifo_t));
	if(!ptr->fifo || !fifo_init(ptr->fifo,DNS_QUEUE_ITEM_SIZE,DNS_QUEUE_LEN))
	{
		log_error("[!] Error DNS fifo not Set");
		free(ptr->fifo);
		ptr->fifo = NULL;
		localdns_free(ptr);
		return NULL;
	}

	if (strlen(conf->Local.ip) >= sizeof(ptr->listen_addr))
	{
		log_error("[!] DNS listen address too long");
		localdns_free(ptr);
		return NULL;
	}
	memcpy(ptr->listen_addr, conf->Local.ip, strlen(conf->Local.ip) + 1);
	snprintf(ptr->listen_port, sizeof(ptr->listen_port), "%u", (unsigned)conf->Local.port);
	ptr->socks = conf->Socks;

	/*init upstream dns server*/
	ptr->upstream = conf->Remote;

	// copy stat handler
	ptr->Stat = conf->Stat;

	// copy whitelist status;
	ptr->whitelist = conf->whitelist;

	// copy sni ip
	memcpy(ptr->sni_ip,conf->sni_ip,4);

	// copy timeout
	ptr->timeout = conf->timeout;

	return ptr;
}

static void *localdns_worker(void *arg);

bool localdns_start_workers(dnsserver_t *dns)
{
	int i;
	if (!dns || dns->worker_count != 0)
		return false;
	for (i = 0; i < DNS_WORKER_COUNT; i++)
	{
		if (pthread_create(&dns->workers[i], NULL, localdns_worker, dns) != 0)
		{
			log_error("can not create dns worker %d", i);
			localdns_stop_workers(dns);
			return false;
		}
		dns->worker_count++;
	}
	log_info("DNS started %d workers", dns->worker_count);
	return true;
}

void localdns_stop_workers(dnsserver_t *dns)
{
	int i;
	if (!dns || dns->worker_count == 0)
		return;
	fifo_close(dns->fifo);
	for (i = 0; i < dns->worker_count; i++)
		pthread_join(dns->workers[i], NULL);
	dns->worker_count = 0;
}

void localdns_free(dnsserver_t *dns)
{
	if (!dns)
		return;
	/* socks aliases configuration memory and is not owned here. */
	close_fd(&dns->local_sock);
	close_fd(&dns->wake[0]);
	close_fd(&dns->wake[1]);
	if (dns->fifo)
	{
		fifo_deinit(dns->fifo);
		free(dns->fifo);
		dns->fifo = NULL;
	}
	free(dns);
}

bool localdns_init_sockets(dnsserver_t *dns)
{
  struct sockaddr_in addr;
  char *end = NULL;
  unsigned long port;

  dns->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dns->local_sock < 0)
  {
    log_error("dns socket creation failed");
    return false;
  }

  /*
   * The listen address is an IPv4 literal. inet_pton avoids getaddrinfo, which
   * on this glibc can leave a resolver allocation behind if the process exits
   * immediately after a failed bind.
   */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  port = strtoul(dns->listen_port, &end, 10);
  if (dns->listen_port[0] == '\0' || end == NULL || *end != '\0' || port > 65535UL ||
      inet_pton(AF_INET, dns->listen_addr, &addr.sin_addr) != 1)
  {
    log_error("dns listen address rejected %s:%s", dns->listen_addr, dns->listen_port);
    close_fd(&dns->local_sock);
    return false;
  }
  addr.sin_port = htons((uint16_t)port);

  if (bind(dns->local_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    log_error("Can't bind address %s:%s\n", dns->listen_addr, dns->listen_port);
    close_fd(&dns->local_sock);
    return false;
  }

  return true;
}

bool localdns_pull(dnsserver_t *dns)
{
	socklen_t client_size = sizeof(struct sockaddr_in);

	dnsMessage_t	msg;
	ssize_t nread;
	memset(&msg, 0, sizeof(msg));
	// receive a dns request from the client
	nread = recvfrom(dns->local_sock, &msg.message[2], DNS_MSG_SIZE - 2, 0, (struct sockaddr *)&msg.client, &client_size);

	// lets not fork if recvfrom was interrupted
	if (nread < 0 && errno == EINTR)
	{
		return true;
	}

	// other invalid values from recvfrom
	if (nread < 0)
	{
		log_error("recvfrom failed: %s\n", strerror(errno));
		return true;
	}

	if (nread == 0 || (size_t)nread > DNS_MSG_SIZE - 2)
	{
		return true;
	}
	msg.len = (uint16_t)nread;

	// the tcp query requires the length to precede the packet, so we put the length there
	msg.message[0] = (char)((msg.len>>8) & 0xFF);
	msg.message[1] = (char)(msg.len & 0xFF);

	/*send dns message to dns fifo*/
	if(fifo_push(dns->fifo,&msg))
	{
		if(dns->Stat)
			state_IncConnection(dns->Stat);
	}
	else
	{
		log_error("dns fifo is full:");
	}

	return true;
}

/* Return Len of packet*/
static int localdns_answer_local(dnsserver_t *dns,struct Message *msg,uint8_t *buf)
{
	struct ResourceRecord *rr;
	size_t written = 0;

	if (!msg || !msg->questions || !msg->questions->qName || !buf)
		return 0;

	rr = calloc(1, sizeof(struct ResourceRecord));
	if (!rr)
		return 0;

	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->ra = 0; // no recursion available
	msg->rcode = Ok_ResponseType;
	
	// should already be 0
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	rr->name = strdup(msg->questions->qName);
	if (!rr->name)
	{
		free(rr);
		return 0;
	}
	rr->type = msg->questions->qType;
	rr->class = msg->questions->qClass;
	rr->ttl = 60*60; // in seconds; 0 means no caching

	// We only can only answer two question types so far
    // and the answer (resource records) will be all put
    // into the answers list.
    switch (msg->questions->qType)
	{
		case A_Resource_RecordType:
			rr->rd_length = 4;
			rr->rd_data.a_record.addr[0] = dns->sni_ip[0];
			rr->rd_data.a_record.addr[1] = dns->sni_ip[1];
			rr->rd_data.a_record.addr[2] = dns->sni_ip[2];
			rr->rd_data.a_record.addr[3] = dns->sni_ip[3];
			msg->anCount++;
			// prepend resource record to answers list
    		msg->answers = rr;
		break;
		case AAAA_Resource_RecordType:
			rr->rd_length = 16;
			memset(rr->rd_data.aaaa_record.addr,0,16);
			msg->anCount++;
			// prepend resource record to answers list
    		msg->answers = rr;
		break;
		default:
			free(rr->name);
			free(rr);
			msg->rcode = NotImplemented_ResponseType;
		break;
	}

	if (!dns_encode_msg_n(msg, buf, DNS_MSG_SIZE, &written) || written > DNS_MSG_SIZE)
	{
		return 0;
	}

	return (int)written;
}

static const char *dns_type_name(uint16_t type)
{
  switch(type)
  {
  	case A_Resource_RecordType: return "A";
  	case NS_Resource_RecordType: return "NS";
  	case CNAME_Resource_RecordType: return "CNAME";
  	case SOA_Resource_RecordType: return "SOA";
  	case PTR_Resource_RecordType: return "PTR";
  	case MX_Resource_RecordType:  return "MX";
  	case TXT_Resource_RecordType: return "TXT";
  	case AAAA_Resource_RecordType: return "AAAA";
  	case SRV_Resource_RecordType: return "SRV";
	case HTTPS_Resource_RecordType: return "HTTPS";
	case SVCB_Resource_RecordType: return "SVCB";
	default:	return "unknown";
  }
  return "";
}



/*
 * Drop an idle upstream connection if the server already closed it (or sent
 * something unsolicited). Catches the common "server closes idle TCP" case
 * before a query is written into a dead socket.
 */
static void upstream_drop_if_stale(int *fd)
{
	struct pollfd p;
	if (*fd < 0)
		return;
	p.fd = *fd;
	p.events = POLLIN;
	p.revents = 0;
	if (poll(&p, 1, 0) != 0)
		close_fd(fd);
}

static bool upstream_connect(dnsserver_t *dns, int *fd)
{
	if (dns->socks)
		return socks5_connect(fd, dns->socks, dns->upstream.ip, dns->upstream.port, true, (int)dns->timeout);
	return net_connect(fd, dns->upstream.ip, dns->upstream.port, (int)dns->timeout);
}

/* One length-prefixed query/response. Returns the response length, or 0. */
static uint16_t upstream_exchange(dnsserver_t *dns, int fd, const dnsMessage_t *msg, uint8_t *resp)
{
	int timeout_ms = net_timeout_ms((int)dns->timeout);
	uint8_t prefix[2];
	uint16_t response_len;

	if (!net_write_all_ms(fd, msg->message, (size_t)msg->len + 2u, timeout_ms))
		return 0;
	if (!net_read_exact_ms(fd, prefix, sizeof(prefix), timeout_ms))
		return 0;

	response_len = (uint16_t)((prefix[0] << 8) | prefix[1]);
	if (response_len == 0 || response_len > DNS_MSG_SIZE - 2)
	{
		log_error("DNS: upstream response length rejected: %u", response_len);
		return 0;
	}
	if (!net_read_exact_ms(fd, resp, response_len, timeout_ms))
		return 0;
	return response_len;
}

/*
 * Forward over the worker's persistent connection, opening one if needed.
 * A failure on a reused connection is retried once on a fresh one; a failure
 * on a fresh connection is final.
 */
static uint16_t upstream_forward(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd, uint8_t *resp)
{
	int attempt;

	upstream_drop_if_stale(upstream_fd);
	for (attempt = 0; attempt < 2; attempt++)
	{
		bool reused = *upstream_fd >= 0;
		uint16_t n;

		if (!reused && !upstream_connect(dns, upstream_fd))
			return 0;
		n = upstream_exchange(dns, *upstream_fd, msg, resp);
		if (n > 0)
			return n;
		close_fd(upstream_fd);
		if (!reused)
			return 0;
	}
	return 0;
}

void localdns_handle_request(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd)
{
	char domain_resolve[1024] = {0};
	int64_t start_time = net_mono_ms();
	uint16_t rlen = 0;
	bool handled_local = false;
	struct Message dns_msg = {0};

	/*Check and Print DNS Question*/
	if(dns_decode_msg(&dns_msg,(const uint8_t *) &msg->message[2], msg->len))
	{
		struct Question *q = dns_msg.questions;
		if (q && q->qName)
		{
			snprintf(domain_resolve,sizeof(domain_resolve),"resolve { (%s) qName '%s'} ",dns_type_name(q->qType),q->qName);

			/*try make replay*/
			if(dns->whitelist && filter_IsWhite(dns->whitelist,q->qName))
			{
				uint8_t buffer[DNS_MSG_SIZE];
				int len = localdns_answer_local(dns,&dns_msg,buffer);
				handled_local = true;
				/*if packet fill send to network*/
				if(len > 0)
				{
					// send the reply back to the client
					sendto(dns->local_sock, buffer, (size_t)len, 0, (const struct sockaddr *)&msg->client, sizeof(struct sockaddr_in));

					int64_t End_Time = net_mono_ms() - start_time;
					double time_taken = ((double)End_Time)/(1000); // convert to sec
					log_trace("%s in %0.3fs Local reply",domain_resolve,time_taken);
				}
			}
		}
	}
	dns_free_msg(&dns_msg);

	if (!handled_local)
	{
		uint8_t resp[DNS_MSG_SIZE];
		int64_t End_Time;
		double time_taken;

		rlen = upstream_forward(dns, msg, upstream_fd, resp);
		End_Time = net_mono_ms() - start_time;
		time_taken = ((double)End_Time)/(1000); // convert to sec
		if(rlen>0)
		{
			// send the reply back to the client
			sendto(dns->local_sock, resp, rlen, 0, (const struct sockaddr *)&msg->client, sizeof(struct sockaddr_in));
			log_info("%s in %0.3fs txrx(%i/%i)",domain_resolve,time_taken,msg->len,rlen + 2);
		}
		else
		{
			log_error("NO DATA %s in %0.3fs",domain_resolve,time_taken);
		}
	}

	//Update statistics
	if(dns->Stat)
	{
		state_RxTxClose(dns->Stat, rlen > 0 ? (uint32_t)rlen + 2u : 0u, (uint32_t)msg->len + 2u);
	}
}

/* Fixed pool member: one query at a time over its own upstream connection. */
static void *localdns_worker(void *arg)
{
	dnsserver_t *dns = (dnsserver_t*) arg;
	dnsMessage_t msg;
	int upstream_fd = -1;

	while (fifo_pop_wait(dns->fifo, &msg))
		localdns_handle_request(dns, &msg, &upstream_fd);

	close_fd(&upstream_fd);
	return NULL;
}
