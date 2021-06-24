/*
 * dnsproxy.h
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */

#ifndef DNSPROXY_H_
#define DNSPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <config.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include "DnsServer.h"


#define TMP_BUF_SIZE	512

typedef struct
{
	/*bind ip/port*/
	char 	 	  listen_addr[_MaxIPAddress_];
	char	 	  listen_port[_MaxPORTAddress_];
	dnsUpstream_t upstream;
	sockshost_t	  socks;
	/*socket file handler*/
	int local_sock;
	statistics_t  *Stat;
	char buffer[TMP_BUF_SIZE];
	int  len;
	struct sockaddr_in client;
	socklen_t client_size;
}dnsserver_t;


dnsserver_t *localdns_init_config(dnshost_t *conf);
void localdns_free(dnsserver_t *dns);

bool localdns_init_sockets(dnsserver_t *dns);
bool localdns_pull(dnsserver_t *dns);

#endif /* DNSPROXY_H_ */
