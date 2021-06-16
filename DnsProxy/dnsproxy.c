/*
 * dnsproxy.c
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */
#include "../DnsProxy/dnsproxy.h"

#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <log/log.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <socks.h>

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
	strcpy(ptr->listen_addr,conf->host);
	sprintf(ptr->listen_port,"%d",conf->port);
	ptr->socks = *conf->Socks;

	/*init upstream dns server*/
	ptr->upstream = conf->dnsserver;

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

bool localdns_pull(dnsserver_t *dns)
{
	char buffer[TMP_BUF_SIZE] = {0};
	struct sockaddr_in dns_client;
	socklen_t dns_client_size = sizeof(struct sockaddr_in);

	// receive a dns request from the client
	int len = recvfrom(dns->local_sock, &buffer[2], sizeof(buffer) - 2, 0, (struct sockaddr *)&dns_client, &dns_client_size);

	// lets not fork if recvfrom was interrupted
	if (len < 0 && errno == EINTR) { return true; }

	// other invalid values from recvfrom
	if (len < 0)
	{
		log_error("recvfrom failed: %s\n", strerror(errno));
		return true;
	}

	// fork so we can keep receiving requests
	if (fork() != 0) { return true; }

	// the tcp query requires the length to precede the packet, so we put the length there
	buffer[0] = (len>>8) & 0xFF;
	buffer[1] = len & 0xFF;

	// make socks5 socket
	int sockssocket = 0;
	if(!socks5_connect(&sockssocket,dns->socks.host , dns->socks.port, dns->upstream.ip, dns->upstream.port))
		return true;

	// forward dns query
	write(sockssocket, buffer, len + 2);
	int rlen = read(sockssocket, buffer, sizeof(buffer));

	// close socks socket
	close(sockssocket);


	log_info("DNS we GET %i and SEND %i",len,rlen);

	// forward the packet to the tcp dns server
	// send the reply back to the client (minus the length at the beginning)
	sendto(dns->local_sock, buffer + 2, rlen - 2 , 0, (struct sockaddr *)&dns_client, sizeof(dns_client));

	/*exit from this fork*/
	exit(0);
	return true;
}
