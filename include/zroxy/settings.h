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
 * Configuration types produced by args and consumed by the services
 */
#ifndef ZROXY_SETTINGS_H_
#define ZROXY_SETTINGS_H_
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zroxy/config.h>
#include <zroxy/socks.h>
#include <zroxy/acl.h>
#include <zroxy/filter.h>
#include <zroxy/statistics.h>

#define SNI_CONN_LIMIT_DEFAULT 1024
#define SNI_CONN_LIMIT_MAX 65535

typedef struct
{
	char bindip[ZROXY_MAX_IP_TEXT];
	uint16_t local_port;
	uint16_t remote_port;
	void *next;
} lport_t;

#define DNS_LOCAL_TTL_DEFAULT 300
#define DNS_UPSTREAM_CONNECTIONS_DEFAULT 96
/* Upstream DNS routes one server can be given (DNS= / -u, in order). */
#define DNS_ROUTES_MAX 4

typedef struct
{
	char ip[ZROXY_MAX_DNS_HOST + 1];
	uint16_t port;
} dns_stream_t;

/*
 * One way to reach an upstream DNS server. In dnshost_t, socks is the
 * route's own SOCKS5 proxy ("via") and belongs to the route; NULL with
 * direct false means "use the global DSOCKS, if any". In dnsserver_t it is
 * the resolved proxy (borrowed, NULL = connect directly).
 */
typedef struct
{
	dns_stream_t upstream;
	sockshost_t *socks;
	bool direct;
} dns_route_t;

typedef struct
{
	filter_t *whitelist;
	uint8_t sni_ip[4];
	dns_stream_t local;
	dns_route_t routes[DNS_ROUTES_MAX];
	unsigned route_count;
	sockshost_t *socks; /* global DSOCKS; routes without via/direct use it */
	statistics_t *stats;
	uint32_t timeout;
	bool listen_set;
	uint32_t cache_entries;
	uint32_t local_ttl;
	zroxy_cidr_t *acl;
	size_t acl_count;
	bool acl_set;
	uint32_t rate_qps;
	uint16_t upstream_connections;
} dnshost_t;

#endif /* ZROXY_SETTINGS_H_ */
