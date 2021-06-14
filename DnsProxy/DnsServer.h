/*
 * DnsServer.h
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */

#ifndef DNSSERVER_H_
#define DNSSERVER_H_
#include <stdint.h>
#include <stdbool.h>
#include <config.h>
#include <socks.h>
#include <sys/socket.h>

typedef struct
{
	char 	 ip[_MaxIPAddress_];
	uint16_t port;
}dnsUpstream_t;

typedef struct
{
	char 	 	  host[_MaxIPAddress_];
	uint16_t 	  port;
	dnsUpstream_t dnsserver;
	sockshost_t	  *Socks;
}dnshost_t;

void dnsserver_init(dnshost_t *config);

#endif /* DNSSERVER_H_ */
