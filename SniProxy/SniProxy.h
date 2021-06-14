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
#include <statistics/statistics.h>
#include <filter/filter.h>
#include <socks.h>

typedef struct
{
	uint16_t 	Port;
	sockshost_t	 *Socks;
	statistics_t *sta;
	filter_t	 *wlist;
	bool UserInternalDNS;
	char DNSServer[20];
}SniServer_t;

typedef struct
{
	SniServer_t SniConfig;
	int			sockfd;
}server_t;



bool SniProxy_Start(SniServer_t *Sni);



#endif /* SNIPROXY_H_ */
