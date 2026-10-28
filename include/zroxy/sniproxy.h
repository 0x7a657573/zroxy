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
#include <zroxy/config.h>
#include <zroxy/statistics.h>
#include <zroxy/filter.h>
#include <zroxy/socks.h>

typedef struct
{
	char	 bindip[ZROXY_MAX_IP_TEXT];
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



typedef struct sni_listener sni_listener;

/* Listen and start the event loop. NULL on failure. */
sni_listener *sniproxy_start(SniServer_t *Sni);
/* Stop accepting, close every connection, join the loop and free. */
void sniproxy_stop(sni_listener *ls);
bool sni_worker_acquire(void);
void sni_worker_release(void);



#endif /* SNIPROXY_H_ */
