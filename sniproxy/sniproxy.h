/*
 * SniProxy.h
 *
 *  Created on: Jan 28, 2020
 *      Author: zeus
 */

#ifndef SNIPROXY_H_
#define SNIPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <config.h>
#include <statistics.h>
#include <filter/filter.h>
#include <socks.h>

typedef struct
{
	char	 bindip[_MaxIPAddress_];
	uint16_t local_port;
	uint16_t remote_port;
	void 	 *next;
}lport_t;

typedef struct
{
	lport_t 	Port;
	sockshost_t	 *Socks;
	statistics_t *sta;
	filter_t	 *wlist;
	bool UserInternalDNS;
	char DNSServer[20];
	int			 snitimeout;
}SniServer_t;

typedef struct
{
	SniServer_t SniConfig;
	int			sockfd;
}server_t;



bool SniProxy_Start(SniServer_t *Sni);
bool sni_worker_acquire(void);
void sni_worker_release(void);



#endif /* SNIPROXY_H_ */
