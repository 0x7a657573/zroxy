/*
 * SniProxy.c
 *
 *  Created on: Jan 28, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <zroxy/sniproxy.h>
#include <zroxy/log.h>
#include <string.h>
#include "sni_event_loop.h"
#include "sni_resolver.h"
#include <zroxy/net.h>
#include <arpa/inet.h>

bool SniProxy_Start(SniServer_t *Sni)
{
	int sockfd;
	in_addr_t host_ip = inet_addr(Sni->Port.bindip);

	if (Sni->Socks && Sni->Socks->host && Sni->Socks->host[0] != '\0') {
		if (!sni_resolver_prime_socks(Sni->Socks->host, Sni->Socks->port,
				SNI_INFRA_STARTUP_MS))
			return false;
	}

	if (net_ListenIp4(host_ip, Sni->Port.local_port, &sockfd) == false)
	{
		log_error("can not listen on Port %s:%i", Sni->Port.bindip, Sni->Port.local_port);
		return false;
	}

	log_info("socket listen on %s:%d", Sni->Port.bindip, Sni->Port.local_port);
	/* One event-loop thread owns sockfd. Clients are not threads. */
	if (!sni_spawn_detached(sockfd, Sni))
		return false;
	return true;
}
