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
#include <log/log.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <socks.h>
#include <pthread.h>
#include <dns.h>

dnsserver_t *localdns_init_config(dnshost_t *conf)
{
	if(!conf->Socks)
	{
		log_error("[!] Error DNS Socks not Set");
		return NULL;
	}

	dnsserver_t *ptr = (dnsserver_t*)malloc(sizeof(dnsserver_t));
	if(!ptr)
		return NULL;

	bzero(ptr,sizeof(dnsserver_t));
	strcpy(ptr->listen_addr,conf->Local.ip);
	sprintf(ptr->listen_port,"%d",conf->Local.port);
	ptr->socks = *conf->Socks;

	/*init upstream dns server*/
	ptr->upstream = conf->Remote;

	// copy stat handler
	ptr->Stat = conf->Stat;
	return ptr;
}

void localdns_free(dnsserver_t *dns)
{
	free(dns);
}

bool localdns_init_sockets(dnsserver_t *dns)
{
  struct addrinfo hints;
  struct addrinfo *addr_ip;
  int r;

  dns->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (0 != (r = getaddrinfo(dns->listen_addr, dns->listen_port, &hints, &addr_ip)))
  {
    log_error("%s:%s:%s\n", gai_strerror(r), dns->listen_addr, dns->listen_port);
    return false;
  }

  if (0 != bind(dns->local_sock, addr_ip->ai_addr, addr_ip->ai_addrlen))
  {
    log_error("Can't bind address %s:%s\n", dns->listen_addr, dns->listen_port);
    return false;
  }

  freeaddrinfo(addr_ip);
  return true;
}

void *DNS_HandleIncomingRequset(void *dnsreq)
{
	dnsserver_t *dns = (dnsserver_t*) dnsreq;
	do
	{
		/*Check and Print DNS Question*/
		struct Message dns_msg = {0};
		if(dns_decode_msg(&dns_msg, &dns->buffer[2], dns->len))
		{
			struct Question *q;
			q = dns_msg.questions;
			while (q) 
			{
				log_info("DNS Question { qName '%s'}",q->qName);
				q = q->next;
			}
		}
		free_msg(&dns_msg);

		// make socks5 socket
		int sockssocket = 0;
		if(!socks5_connect(&sockssocket,&dns->socks, dns->upstream.ip, dns->upstream.port))
			break;

		// forward dns query
		write(sockssocket, dns->buffer, dns->len + 2);
		int rlen = read(sockssocket, dns->buffer, TMP_BUF_SIZE);

		// close socks socket
		close(sockssocket);

		log_info("DNS SEND %i and GET %i",dns->len,rlen);

		// forward the packet to the tcp dns server
		// send the reply back to the client (minus the length at the beginning)
		sendto(dns->local_sock, dns->buffer + 2, rlen - 2 , 0, (struct sockaddr *)&dns->client, sizeof(struct sockaddr_in));

		//Update statistics
		if(dns->Stat)
		{
			state_RxTxClose(dns->Stat,rlen,dns->len+2);
		}

	}while(0);


	free(dns);
	pthread_exit(0);
	return NULL;
}

bool localdns_pull(dnsserver_t *dns)
{
	dns->client_size = sizeof(struct sockaddr_in);

	// receive a dns request from the client
	dns->len = recvfrom(dns->local_sock, &dns->buffer[2], TMP_BUF_SIZE - 2, 0, (struct sockaddr *)&dns->client, &dns->client_size);

	// lets not fork if recvfrom was interrupted
	if (dns->len < 0 && errno == EINTR) { return true; }

	// other invalid values from recvfrom
	if (dns->len < 0)
	{
		log_error("recvfrom failed: %s\n", strerror(errno));
		return true;
	}

	// the tcp query requires the length to precede the packet, so we put the length there
	dns->buffer[0] = (dns->len>>8) & 0xFF;
	dns->buffer[1] = dns->len & 0xFF;

	/*clone dns server*/
	dnsserver_t *ptr = malloc(sizeof(dnsserver_t));
	memcpy(ptr,dns,sizeof(dnsserver_t));

	if(dns->Stat)
		state_IncConnection(dns->Stat);

	// fork so we can keep receiving requests
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, DNS_HandleIncomingRequset, (void*)ptr);
	pthread_detach(thread_id);

	return true;
}
