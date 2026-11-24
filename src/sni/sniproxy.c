/*
 * Copyright (c) 2020-2026 zeus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*
 * SniProxy.c
 *
 *  Created on: Jan 28, 2020
 *      Author: zeus
 */
#include <zroxy/sniproxy.h>
#include "sni_event_loop.h"
#include "resolver.h"

sni_listener *sniproxy_start(sni_server_t *cfg)
{
	sni_listener *ls = NULL;

	if (cfg->socks && cfg->socks->host && cfg->socks->host[0] != '\0')
	{
		if (!resolver_prime_socks(cfg->socks->host, cfg->socks->port,
		            RESOLVER_INFRA_STARTUP_MS))
			return NULL;
	}

	/* One event-loop thread owns the listening socket. Clients are not threads. */
	if (!sni_listener_open(cfg, &ls))
		return NULL;
	return ls;
}

void sniproxy_stop(sni_listener *ls)
{
	sni_listener_close(ls);
}
