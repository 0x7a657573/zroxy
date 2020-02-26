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

#define _MaxHostName_	(255)


typedef struct
{
	char 	host[_MaxHostName_];
	uint16_t port;
}sockshost_t;

typedef struct
{
	uint16_t 	Port;
	sockshost_t	 *Socks;
	statistics_t *sta;
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
