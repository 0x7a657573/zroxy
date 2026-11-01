/*
 * DnsServer.h
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */

#ifndef DNSSERVER_H_
#define DNSSERVER_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/config.h>
#include <zroxy/socks.h>
#include <zroxy/monitor.h>
#include <sys/socket.h>
#include <zroxy/filter.h>
#include <zroxy/dnsacl.h>
#include <zroxy/dnsrate.h>

#define DNS_LOCAL_TTL_DEFAULT	300
#define DNS_UPSTREAM_CONNECTIONS_DEFAULT 96
/* Upstream DNS routes one server can be given (DNS= / -u, in order). */
#define DNS_ROUTES_MAX 4

typedef struct
{
	char 	 ip[ZROXY_MAX_DNS_HOST + 1];
	uint16_t port;
}dnsStream_t;

/*
 * One way to reach an upstream DNS server. In dnshost_t, socks is the
 * route's own SOCKS5 proxy ("via") and belongs to the route; NULL with
 * direct false means "use the global DSOCKS, if any". In dnsserver_t it is
 * the resolved proxy (borrowed, NULL = connect directly).
 */
typedef struct
{
	dnsStream_t	  upstream;
	sockshost_t	  *socks;
	bool		  direct;
}dns_route_t;

typedef struct
{
	filter_t 	  *whitelist;
	uint8_t		  sni_ip[4];
	dnsStream_t	  Local;
	dns_route_t	  routes[DNS_ROUTES_MAX];
	unsigned	  route_count;
	sockshost_t	  *Socks;	/* global DSOCKS; routes without via/direct use it */
	statistics_t  *Stat;
	uint32_t	  timeout;
	bool		  listen_set;
	uint32_t	  cache_entries;
	uint32_t	  local_ttl;
	dns_cidr_t	  *acl;
	size_t	  acl_count;
	bool		  acl_set;
	uint32_t	  rate_qps;
	uint16_t	  upstream_connections;
}dnshost_t;

struct dnsserver;

/* Bind, start workers and the receive loop. NULL on failure. */
struct dnsserver *dnsserver_start(dnshost_t *config);
/* Stop receiving, drain queued queries, join all threads and free. */
void dnsserver_stop(struct dnsserver *dns);

#endif /* DNSSERVER_H_ */
