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
 * dns_internal.h
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */

#ifndef DNS_INTERNAL_H_
#define DNS_INTERNAL_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/config.h>
#include <zroxy/dnsserver.h>
#include <zroxy/filter.h>
#include <zroxy/dnscache.h>

#define DNS_MSG_SIZE 512

/* Largest message DNS over TCP can carry (two-byte length prefix). */
#define DNS_TCP_MSG_MAX 65535

#define DNS_TCP_IDLE_MS 3000
#define DNS_TCP_MAX_QUERIES 32

typedef struct
{
	uint32_t last_ms; /* low 32 bits of the last logged time; 0 = never logged */
	uint32_t suppressed;
} log_throttle_t;

typedef struct dnsserver
{
	/* answer cache and in-flight coalescing; NULL disables both */
	dnscache_t *cache;

	/* whitelist*/
	filter_t *whitelist;

	/*sni server ip*/
	uint8_t sni_ip[4];

	/*bind ip/port*/
	char listen_addr[ZROXY_MAX_DNS_HOST + 1];
	char listen_port[ZROXY_MAX_PORT_TEXT];

	bool rx_started;
	int wake[2];
	void *event_loop;

	dns_route_t routes[DNS_ROUTES_MAX];
	unsigned route_count;
	uint32_t timeout;
	uint32_t local_ttl;
	uint16_t upstream_connections;

	/*socket file handler*/
	int local_sock;
	/* TCP listener on the same address; -1 when it could not be opened */
	int tcp_sock;
	int tcp_active;
	/* Monitoring counters may wrap; 32-bit atomics work on supported targets. */
	uint32_t tcp_refused;
	uint32_t acl_dropped;
	uint32_t rate_dropped;
	uint32_t queue_dropped;
	uint32_t upstream_timeouts;
	uint32_t upstream_errors;
	uint32_t active_upstreams;
	uint32_t active_route;
	uint32_t route_switches;
	zroxy_cidr_t *acl;
	size_t acl_count;
	dns_rate_t rate;
	statistics_t *stats;
} dnsserver_t;

dnsserver_t *localdns_init_config(dnshost_t *conf);
void localdns_free(dnsserver_t *dns);

bool localdns_init_sockets(dnsserver_t *dns);
/* Open the TCP listener on the UDP address. False leaves the service UDP-only. */
bool localdns_init_tcp(dnsserver_t *dns);

/* Test hook for the time-injected throttle state machine. */
bool dnsproxy_test_throttle_take(log_throttle_t *t, int64_t now_ms,
        int64_t interval_ms, uint32_t *dropped);
bool dns_stats_json(void *ctx, char **ptr, char *end);

#endif /* DNS_INTERNAL_H_ */
