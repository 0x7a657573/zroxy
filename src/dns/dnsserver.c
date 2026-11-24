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
 * DnsServer.c
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */
#include <zroxy/dnsserver.h>

#include <zroxy/log.h>
#include <stdlib.h>
#include "dns_internal.h"
#include "dns_event_loop.h"

struct dnsserver *dnsserver_start(dnshost_t *conf)
{
	dnsserver_t *dns = localdns_init_config(conf);
	if (!dns)
	{
		log_error("dns server config error...");
		return NULL;
	}

	if (!localdns_init_sockets(dns))
	{
		log_error("dns server socket error.");
		localdns_free(dns);
		return NULL;
	}

	if (!localdns_init_tcp(dns))
		log_error("dns TCP listener unavailable; truncated replies cannot be retried over TCP");

	if (!dns_event_loop_start(dns))
	{
		log_error("dns event loop start failed");
		localdns_free(dns);
		return NULL;
	}
	stats_set_extra(dns->stats, dns_stats_json, dns);

	log_info("dns server start on %s:%d", conf->local.ip, conf->local.port);
	return dns;
}

void dnsserver_stop(struct dnsserver *dns)
{
	if (!dns)
		return;
	dns_event_loop_stop(dns);
	stats_set_extra(dns->stats, NULL, NULL);
	localdns_free(dns);
	log_info("dns server stopped");
}
