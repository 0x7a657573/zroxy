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

/*
 * Local answers are short-lived so a whitelist reload or a new SNIP reaches
 * clients quickly.
 */
#define DNS_LOCAL_TTL	300

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
	/* MSG_TRUNC reports the real datagram size, so an oversized query is seen. */
	nread = recvfrom(dns->local_sock, &msg.message[2], DNS_MSG_SIZE - 2, MSG_TRUNC, (struct sockaddr *)&msg.client, &client_size);

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

	/* Not a query: too short for a header, too large, or a response (QR set). */
	if (nread < DNS_HEADER_SIZE || (size_t)nread > DNS_MSG_SIZE - 2 ||
		((uint8_t)msg.message[4] & 0x80) != 0)
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
			stats_open_connection(dns->Stat);
	}
	else
	{
		uint8_t reply[DNS_MSG_SIZE];
		size_t n = dns_build_error((const uint8_t *)&msg.message[2], msg.len,
				ServerFailure_ResponseType, reply, sizeof(reply));
		if (n > 0)
			sendto(dns->local_sock, reply, n, 0, (const struct sockaddr *)&msg.client, sizeof(struct sockaddr_in));
		log_error("dns fifo is full:");
	}

	return true;
}

/*
 * Answer a whitelisted name. Only A gets a record, pointing at the SNI proxy.
 * Every other type, including AAAA, HTTPS and SVCB, gets NODATA: forwarding
 * those would hand the client real addresses that bypass the proxy, and IPv6
 * is not proxied at all. Returns the packet length, or 0.
 */
static int localdns_answer_local(dnsserver_t *dns,struct Message *msg,uint8_t *buf)
{
	struct ResourceRecord *rr;
	size_t written = 0;

	if (!msg || !msg->questions || !msg->questions->qName || !buf)
		return 0;

	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->tc = 0;
	msg->ra = 1; // stub resolvers expect recursion from their server
	msg->rcode = Ok_ResponseType;
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	if (msg->questions->qType == A_Resource_RecordType && msg->questions->qClass == DNS_CLASS_IN)
	{
		rr = calloc(1, sizeof(struct ResourceRecord));
		if (!rr)
			return 0;
		rr->name = strdup(msg->questions->qName);
		if (!rr->name)
		{
			free(rr);
			return 0;
		}
		rr->type = A_Resource_RecordType;
		rr->class = DNS_CLASS_IN;
		rr->ttl = DNS_LOCAL_TTL;
		rr->rd_length = 4;
		memcpy(rr->rd_data.a_record.addr, dns->sni_ip, 4);
		msg->answers = rr;
		msg->anCount = 1;
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

static int remaining_ms(int64_t deadline)
{
	int64_t left = deadline - net_mono_ms();
	if (left <= 0)
		return 0;
	return left > INT32_MAX ? INT32_MAX : (int)left;
}

/*
 * One length-prefixed query/response. The first cap bytes are stored in resp
 * and the rest is read and discarded, so the connection stays in step.
 * Returns the full response length, or 0.
 */
static uint16_t upstream_exchange(dnsserver_t *dns, int fd, const dnsMessage_t *msg,
		uint8_t *resp, size_t cap)
{
	int64_t deadline = net_mono_ms() + net_timeout_ms((int)dns->timeout);
	uint8_t prefix[2];
	uint8_t discard[512];
	uint16_t response_len;
	size_t stored;
	size_t left;

	if (!net_write_all_ms(fd, msg->message, (size_t)msg->len + 2u, remaining_ms(deadline)))
		return 0;
	if (!net_read_exact_ms(fd, prefix, sizeof(prefix), remaining_ms(deadline)))
		return 0;

	response_len = (uint16_t)((prefix[0] << 8) | prefix[1]);
	if (response_len < DNS_HEADER_SIZE)
	{
		log_error("DNS: upstream response length rejected: %u", response_len);
		return 0;
	}
	stored = response_len < cap ? response_len : cap;
	if (!net_read_exact_ms(fd, resp, stored, remaining_ms(deadline)))
		return 0;
	for (left = response_len - stored; left > 0; )
	{
		size_t n = left < sizeof(discard) ? left : sizeof(discard);
		if (!net_read_exact_ms(fd, discard, n, remaining_ms(deadline)))
			return 0;
		left -= n;
	}
	return response_len;
}

/*
 * Forward over the worker's persistent connection, opening one if needed.
 * A failure on a reused connection is retried once on a fresh one; a failure
 * on a fresh connection is final.
 */
static uint16_t upstream_forward(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd,
		uint8_t *resp, size_t cap)
{
	int attempt;

	upstream_drop_if_stale(upstream_fd);
	for (attempt = 0; attempt < 2; attempt++)
	{
		bool reused = *upstream_fd >= 0;
		uint16_t n;

		if (!reused && !upstream_connect(dns, upstream_fd))
			return 0;
		n = upstream_exchange(dns, *upstream_fd, msg, resp, cap);
		if (n > 0)
			return n;
		close_fd(upstream_fd);
		if (!reused)
			return 0;
	}
	return 0;
}

static void reply_client(dnsserver_t *dns, const dnsMessage_t *msg, const uint8_t *buf, size_t len)
{
	if (len > 0)
		sendto(dns->local_sock, buf, len, 0, (const struct sockaddr *)&msg->client, sizeof(struct sockaddr_in));
}

static void reply_error(dnsserver_t *dns, const dnsMessage_t *msg, uint8_t rcode)
{
	uint8_t buf[DNS_MSG_SIZE];
	size_t n = dns_build_error((const uint8_t *)&msg->message[2], msg->len, rcode, buf, sizeof(buf));
	reply_client(dns, msg, buf, n);
}

void localdns_handle_request(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd)
{
	const uint8_t *query = (const uint8_t *)&msg->message[2];
	char domain_resolve[1024] = {0};
	int64_t start_time = net_mono_ms();
	uint16_t rlen = 0;
	bool handled_local = false;
	struct Message dns_msg = {0};

	if (msg->len < DNS_HEADER_SIZE)
	{
		/* localdns_pull never queues these; keep the statistics balanced anyway. */
		handled_local = true;
	}
	else if (((query[2] >> 3) & 0x0F) != QUERY_OperationCode)
	{
		reply_error(dns, msg, NotImplemented_ResponseType);
		handled_local = true;
	}
	else if (((query[4] << 8) | query[5]) != 1)
	{
		/* RFC 9619: a query carries exactly one question. */
		reply_error(dns, msg, FormatError_ResponseType);
		handled_local = true;
	}
	/* A query the decoder rejects is still forwarded; upstream judges it. */
	else if(dns_decode_msg(&dns_msg, query, msg->len))
	{
		struct Question *q = dns_msg.questions;
		if (q && q->qName)
		{
			snprintf(domain_resolve,sizeof(domain_resolve),"resolve { (%s) qName '%s'} ",dns_type_name(q->qType),q->qName);

			if(dns->whitelist && filter_match(dns->whitelist,q->qName))
			{
				uint8_t buffer[DNS_MSG_SIZE];
				int len = localdns_answer_local(dns,&dns_msg,buffer);
				handled_local = true;
				if(len > 0)
					reply_client(dns, msg, buffer, (size_t)len);
				else
					reply_error(dns, msg, ServerFailure_ResponseType);
				log_trace("%s in %0.3fs Local reply",domain_resolve,
						(double)(net_mono_ms() - start_time) / 1000);
			}
		}
	}
	dns_free_msg(&dns_msg);

	if (!handled_local)
	{
		/* Big enough for any UDP reply; the rest of a larger answer is discarded. */
		uint8_t resp[DNS_UDP_MAX_PAYLOAD];
		rlen = upstream_forward(dns, msg, upstream_fd, resp, sizeof(resp));
		double time_taken = ((double)(net_mono_ms() - start_time))/(1000); // convert to sec

		if(rlen>0)
		{
			size_t limit = dns_udp_limit(query, msg->len, DNS_UDP_MAX_PAYLOAD);
			if (rlen <= limit)
			{
				reply_client(dns, msg, resp, rlen);
				log_info("%s in %0.3fs txrx(%i/%i)",domain_resolve,time_taken,msg->len,rlen + 2);
			}
			else
			{
				/* TC tells the client the answer needs TCP. */
				uint8_t tc[DNS_MSG_SIZE];
				size_t n = dns_build_truncated(resp, rlen < sizeof(resp) ? rlen : sizeof(resp), tc, sizeof(tc));
				if (n > 0)
					reply_client(dns, msg, tc, n);
				else
					reply_error(dns, msg, ServerFailure_ResponseType);
				log_info("%s in %0.3fs truncated %u > %u",domain_resolve,time_taken,
						(unsigned)rlen,(unsigned)limit);
			}
		}
		else
		{
			reply_error(dns, msg, ServerFailure_ResponseType);
			log_error("NO DATA %s in %0.3fs",domain_resolve,time_taken);
		}
	}

	//Update statistics
	if(dns->Stat)
	{
		stats_close_connection(dns->Stat, rlen > 0 ? (uint32_t)rlen + 2u : 0u, (uint32_t)msg->len + 2u);
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
