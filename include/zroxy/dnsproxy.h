/*
 * dnsproxy.h
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */

#ifndef DNSPROXY_H_
#define DNSPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/config.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <zroxy/dnsserver.h>
#include <zroxy/filter.h>
#include <zroxy/dnscache.h>
#include <pthread.h>

struct Message;

#define DNS_MSG_SIZE	512

/* Largest message DNS over TCP can carry (two-byte length prefix). */
#define DNS_TCP_MSG_MAX	65535

#define DNS_TCP_IDLE_MS		3000
#define DNS_TCP_MAX_QUERIES	32

typedef struct
{
	uint32_t last_ms;	/* low 32 bits of the last logged time; 0 = never logged */
	uint32_t suppressed;
} log_throttle_t;

typedef struct dnsserver
{
	/* answer cache and in-flight coalescing; NULL disables both */
	dnscache_t	  *cache;
	
	/* whitelist*/
	filter_t *whitelist;
	
	/*sni server ip*/
	uint8_t sni_ip[4];

	/*bind ip/port*/
	char 	 	  listen_addr[ZROXY_MAX_DNS_HOST + 1];
	char	 	  listen_port[ZROXY_MAX_PORT_TEXT];

	bool		  rx_started;
	int			  wake[2];
	void		  *event_loop;

	dnsStream_t   upstream;
	sockshost_t	  *socks;
	uint32_t	  timeout;
	uint32_t	  local_ttl;
	uint16_t	  upstream_connections;
	
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
	dns_cidr_t *acl;
	size_t acl_count;
	dns_rate_t rate;
	statistics_t  *Stat;
}dnsserver_t;


dnsserver_t *localdns_init_config(dnshost_t *conf);
void localdns_free(dnsserver_t *dns);

bool localdns_init_sockets(dnsserver_t *dns);
/* Open the TCP listener on the UDP address. False leaves the service UDP-only. */
bool localdns_init_tcp(dnsserver_t *dns);

/* Build the synthetic whitelist answer used by both DNS execution engines. */
int localdns_answer_local(dnsserver_t *dns, struct Message *msg, uint8_t *buf);

/* Test hook for the time-injected throttle state machine. */
bool dnsproxy_test_throttle_take(log_throttle_t *t, int64_t now_ms,
		int64_t interval_ms, uint32_t *dropped);
bool dns_stats_json(void *ctx, char **ptr, char *end);

#endif /* DNSPROXY_H_ */
