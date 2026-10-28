/*
 * SniProxy.c
 *
 *  Created on: Jan 28, 2020
 *      Author: zeus
 */
#include <zroxy/sniproxy.h>
#include "sni_event_loop.h"
#include "sni_resolver.h"

sni_listener *sniproxy_start(SniServer_t *Sni)
{
	sni_listener *ls = NULL;

	if (Sni->Socks && Sni->Socks->host && Sni->Socks->host[0] != '\0') {
		if (!sni_resolver_prime_socks(Sni->Socks->host, Sni->Socks->port,
				SNI_INFRA_STARTUP_MS))
			return NULL;
	}

	/* One event-loop thread owns the listening socket. Clients are not threads. */
	if (!sni_listener_open(Sni, &ls))
		return NULL;
	return ls;
}

void sniproxy_stop(sni_listener *ls)
{
	sni_listener_close(ls);
}
