/*
 * DnsServer.c
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */
#include <zroxy/dnsserver.h>

#include <zroxy/log.h>
#include <stdlib.h>
#include <zroxy/dnsproxy.h>
#include "dns_event_loop.h"

struct dnsserver *dnsserver_start(dnshost_t *conf)
{
	dnsserver_t *dns = localdns_init_config(conf);
	if(!dns)
	{
		log_error("dns server config error...");
		return NULL;
	}

	if(!localdns_init_sockets(dns))
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
	if (dns->Stat)
		stats_set_extra(dns->Stat, dns_stats_json, dns);

	log_info("dns server start on %s:%d",conf->Local.ip,conf->Local.port);
	return dns;
}

void dnsserver_stop(struct dnsserver *dns)
{
	if (!dns)
		return;
	dns_event_loop_stop(dns);
	if (dns->Stat)
		stats_set_extra(dns->Stat, NULL, NULL);
	localdns_free(dns);
	log_info("dns server stopped");
}
