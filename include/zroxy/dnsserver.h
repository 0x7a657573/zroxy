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


typedef struct
{
	char 	 ip[ZROXY_MAX_DNS_HOST + 1];
	uint16_t port;
}dnsStream_t;

typedef struct
{
	filter_t 	  *whitelist;
	uint8_t		  sni_ip[4];
	dnsStream_t	  Local;
	dnsStream_t   Remote;
	sockshost_t	  *Socks;
	statistics_t  *Stat;
	uint32_t	  timeout;
	bool		  listen_set;
	uint32_t	  cache_entries;
	uint32_t	  local_ttl;
	dns_cidr_t	  *acl;
	size_t	  acl_count;
	bool		  acl_set;
}dnshost_t;

struct dnsserver;

/* Bind, start workers and the receive loop. NULL on failure. */
struct dnsserver *dnsserver_start(dnshost_t *config);
/* Stop receiving, drain queued queries, join all threads and free. */
void dnsserver_stop(struct dnsserver *dns);

#endif /* DNSSERVER_H_ */
