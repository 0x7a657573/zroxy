/*
 * dnsproxy.c
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */
#include "dnsproxy.h"
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <log.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <socks.h>
#include <pthread.h>
#include <dns.h>
#include <unistd.h>
#include <net.h>
#include <filter/filter.h>
#include <time.h>
#include <net_io.h>

void *dnsserver_workerTask(void *vargp);

typedef struct
{
	dnsserver_t	*dns;
	dnsMessage_t msg;
}dnsThread_t;

#define DNS_MAX_WORKERS 128

static pthread_mutex_t dns_worker_mu = PTHREAD_MUTEX_INITIALIZER;
static int dns_workers = 0;

static bool dns_thread_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&dns_worker_mu);
	if (dns_workers < DNS_MAX_WORKERS)
	{
		dns_workers++;
		ok = true;
	}
	pthread_mutex_unlock(&dns_worker_mu);
	return ok;
}

static void dns_thread_release(void)
{
	pthread_mutex_lock(&dns_worker_mu);
	if (dns_workers > 0)
		dns_workers--;
	pthread_mutex_unlock(&dns_worker_mu);
}

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

	/* fifo init*/
	ptr->fifo = (fifo_t*)malloc(sizeof(fifo_t));
	if(!ptr->fifo || !fifo_init(ptr->fifo,D_FIFO_Message_Size,D_FIFO_Item))
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

bool localdns_start_worker(dnsserver_t *dns)
{
	pthread_t thread_id;
	if (!dns || dns->worker_started)
		return false;
	if (pthread_create(&thread_id, NULL, dnsserver_workerTask, dns) != 0)
		return false;
	pthread_detach(thread_id);
	dns->worker_started = true;
	return true;
}

void localdns_free(dnsserver_t *dns)
{
	if (!dns)
		return;
	/* socks aliases configuration memory and is not owned here. */
	if (dns->local_sock >= 0)
	{
		close(dns->local_sock);
		dns->local_sock = -1;
	}
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
  struct addrinfo hints;
  struct addrinfo *addr_ip;
  int r;

  dns->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dns->local_sock < 0)
  {
    log_error("dns socket creation failed");
    return false;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (0 != (r = getaddrinfo(dns->listen_addr, dns->listen_port, &hints, &addr_ip)))
  {
    log_error("%s:%s:%s\n", gai_strerror(r), dns->listen_addr, dns->listen_port);
    close_fd(&dns->local_sock);
    return false;
  }

  if (0 != bind(dns->local_sock, addr_ip->ai_addr, addr_ip->ai_addrlen))
  {
    log_error("Can't bind address %s:%s\n", dns->listen_addr, dns->listen_port);
    freeaddrinfo(addr_ip);
    close_fd(&dns->local_sock);
    return false;
  }

  freeaddrinfo(addr_ip);
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
	msg.message[0] = (msg.len>>8) & 0xFF;
	msg.message[1] = msg.len & 0xFF;

	/*send dns message to dns fifo*/
	if(fifo_incert(dns->fifo,&msg))
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
int dns_resolve_query(dnsserver_t *dns,struct Message *msg,uint8_t *buf)
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

const char *DNS_GetType(uint16_t type)
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
	default:	return "unknow";
  }
  return "";
}

uint64_t timeInMilliseconds(void) 
{
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((uint64_t)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}


void *DNS_HandleIncomingRequset(void *ptr)
{

	dnsserver_t *dns = ((dnsThread_t*)ptr)->dns;
	dnsMessage_t *msg = &((dnsThread_t*)ptr)->msg;
	
	
	char domain_resolve[1024] = {0};
	

	uint64_t start_time = timeInMilliseconds(); 
	int rlen = 0;
	int sockssocket = -1;
	bool handled_local = false;
	do
	{
		/*Check and Print DNS Question*/
		struct Message dns_msg = {0};
		if(dns_decode_msg(&dns_msg,(const uint8_t *) &msg->message[2], msg->len))
		{
			struct Question *q;
			q = dns_msg.questions;
			if (q && q->qName)
			{
				snprintf(domain_resolve,sizeof(domain_resolve),"resolve { (%s) qName '%s'} ",DNS_GetType(q->qType),q->qName);

				/*try make replay*/
				if(dns->whitelist && /*q->qType == A_Resource_RecordType &&*/
					filter_IsWhite(dns->whitelist,q->qName))
				{
					uint8_t buffer[DNS_MSG_SIZE];
					int len = dns_resolve_query(dns,&dns_msg,buffer);
					handled_local = true;
					/*if packet fill send to network*/
					if(len > 0)
					{
						// send the reply back to the client
						sendto(dns->local_sock, buffer, len, 0, (struct sockaddr *)&msg->client, sizeof(struct sockaddr_in));

						uint64_t End_Time = timeInMilliseconds() - start_time;
						double time_taken = ((double)End_Time)/(1000); // convert to sec
						log_trace("%s in %0.3fs Local replay",domain_resolve,time_taken);
					}
				}
			}
		}
		free_msg(&dns_msg);
		if (handled_local)
			break;


		/*forward packet to server via socks*/
		int trysend = 2;
		while (trysend--)
		{
			if(dns->socks)
			{
				// make socks5 socket
				if(!socks5_connect(&sockssocket,dns->socks, dns->upstream.ip, dns->upstream.port,true))
					break;
			}
			else
			{
				/*direct connect to dns server*/
				if(!net_connect(&sockssocket, dns->upstream.ip, dns->upstream.port))
					break;
			}
			
			/*set socket timeout*/
			if(!net_socket_timeout(sockssocket,dns->timeout,dns->timeout))
			{
				log_error("DNS: can not set socket timeout");
			}

			// forward dns query
			if(!net_write_all(sockssocket, msg->message, msg->len + 2))
			{
				break;
			}

			if(!net_read_exact(sockssocket, msg->message, 2))
			{
				break;
			}

			uint16_t response_len = ((uint8_t)msg->message[0] << 8) | (uint8_t)msg->message[1];
			if(response_len > DNS_MSG_SIZE - 2)
			{
				log_error("DNS: upstream response too large: %u", response_len);
				break;
			}

			if(!net_read_exact(sockssocket, msg->message + 2, response_len))
			{
				break;
			}

			rlen = response_len + 2;
			break;
		}

		/*close sockst*/
		close_fd(&sockssocket);

		if(rlen>0)
		{
			// forward the packet to the tcp dns server
			// send the reply back to the client (minus the length at the beginning)
			sendto(dns->local_sock, msg->message + 2, rlen - 2 , 0, (struct sockaddr *)&msg->client, sizeof(struct sockaddr_in));

			uint64_t End_Time = timeInMilliseconds() - start_time;
					double time_taken = ((double)End_Time)/(1000); // convert to sec
			log_info("%s in %0.3fs txrx(%i/%i)",domain_resolve,time_taken,msg->len,rlen);
		}
		else
		{
			uint64_t End_Time = timeInMilliseconds() - start_time;
			double time_taken = ((double)End_Time)/(1000); // convert to sec
			log_error("NO DATA %s in %0.3fs",domain_resolve,time_taken);
		}

	}while(0);

	//Update statistics
	if(dns->Stat)
	{
		state_RxTxClose(dns->Stat, (uint32_t)(rlen < 0 ? 0 : rlen), (uint32_t)msg->len + 2u);
	}

	dns_thread_release();
	free(ptr);
	return NULL;
}

void *dnsserver_workerTask(void *vargp)
{
	dnsserver_t *dns = (dnsserver_t*) vargp;
	dnsMessage_t msg;
	
	log_info("DNS Worker Started");
	while(1)
	{
		if(!fifo_Read(dns->fifo,&msg))
		{
			usleep(10000);
			continue;
		}
		
		
		
		/*clone message*/
		dnsThread_t *newmsg;
		pthread_t thread_id;
		if (!dns_thread_acquire())
		{
			log_error("dns worker limit reached");
			continue;
		}
		newmsg = malloc(sizeof(dnsThread_t));
		if (!newmsg)
		{
			dns_thread_release();
			continue;
		}
		memcpy(&newmsg->msg,&msg,sizeof(dnsMessage_t));
		newmsg->dns = dns;
		/*Process incoming dns message*/
		if(pthread_create(&thread_id, NULL, DNS_HandleIncomingRequset, (void*)newmsg) != 0)
		{
			log_error("can not create thread for new dns request");
			free(newmsg);
			dns_thread_release();
			continue;
		}
		pthread_detach(thread_id);
	}

	return NULL;
}
