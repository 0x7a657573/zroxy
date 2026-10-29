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
#include <zroxy/fifo.h>
#include <zroxy/filter.h>
#include <zroxy/dnscache.h>
#include <pthread.h>

#define DNS_MSG_SIZE	512

/* Largest message DNS over TCP can carry (two-byte length prefix). */
#define DNS_TCP_MSG_MAX	65535

typedef enum
{
	DNS_MSG_UDP = 0,	/* query from client; reply with sendto */
	DNS_MSG_TCP_CONN,	/* accepted TCP connection in tcp_fd; no query yet */
	DNS_MSG_TCP		/* query read from tcp_fd; reply framed on it */
} dnsMessageKind;

typedef struct
{
	uint16_t len;
	char message[DNS_MSG_SIZE];
	struct sockaddr_in client;
	int64_t received_ms;	/* monotonic receive time; 0 = unknown */
	dnsMessageKind kind;
	int tcp_fd;
}dnsMessage_t;


#define DNS_QUEUE_ITEM_SIZE	sizeof(dnsMessage_t)
#define DNS_QUEUE_LEN			128

/*
 * Fixed number of forwarding threads. Each handles one query at a time and
 * keeps its own upstream TCP connection open between queries.
 */
#define DNS_WORKER_COUNT	32

/*
 * A query that waited in the queue longer than this is dropped before it is
 * forwarded: the client has given up or already retried.
 */
#define DNS_QUEUE_MAX_AGE_MS	3000

/*
 * Local DNS over TCP, used by clients after a truncated (TC) UDP reply.
 * A worker serves one connection at a time until it idles or reaches the
 * query limit, so at most DNS_TCP_MAX_CONNS workers are taken from UDP.
 */
#define DNS_TCP_MAX_CONNS	8
#define DNS_TCP_IDLE_MS		3000
#define DNS_TCP_MAX_QUERIES	32

typedef struct
{
	int64_t next_ms;
	uint32_t suppressed;
} log_throttle_t;

typedef struct dnsserver
{
	/* Fifo */
	fifo_t		  *fifo;

	/* answer cache and in-flight coalescing; NULL disables both */
	dnscache_t	  *cache;
	
	/* whitelist*/
	filter_t *whitelist;
	
	/*sni server ip*/
	uint8_t sni_ip[4];

	/*bind ip/port*/
	char 	 	  listen_addr[ZROXY_MAX_DNS_HOST + 1];
	char	 	  listen_port[ZROXY_MAX_PORT_TEXT];

	pthread_t	  workers[DNS_WORKER_COUNT];
	int			  worker_count;

	/* receive loop */
	pthread_t	  rx_thread;
	bool		  rx_started;
	int			  wake[2];

	dnsStream_t   upstream;
	sockshost_t	  *socks;
	uint32_t	  timeout;
	uint32_t	  local_ttl;
	
	/*socket file handler*/
	int local_sock;
	/* TCP listener on the same address; -1 when it could not be opened */
	int tcp_sock;
	int tcp_active;
	log_throttle_t fifo_log;
	log_throttle_t tcp_limit_log;
	log_throttle_t tcp_fifo_log;
	log_throttle_t no_data_log;
	uint64_t stale_dropped;
	uint64_t fifo_full;
	uint64_t tcp_refused;
	uint64_t acl_dropped;
	dns_cidr_t *acl;
	size_t acl_count;
	statistics_t  *Stat;
}dnsserver_t;


dnsserver_t *localdns_init_config(dnshost_t *conf);
void localdns_free(dnsserver_t *dns);

bool localdns_init_sockets(dnsserver_t *dns);
/* Open the TCP listener on the UDP address. False leaves the service UDP-only. */
bool localdns_init_tcp(dnsserver_t *dns);
/* Accept one TCP client and queue it for a worker. */
void localdns_accept(dnsserver_t *dns);
bool localdns_start_workers(dnsserver_t *dns);
/* Close the queue, let workers drain it, and join them. */
void localdns_stop_workers(dnsserver_t *dns);
bool localdns_pull(dnsserver_t *dns);

/*
 * Answer one query: locally for whitelisted names, otherwise over
 * *upstream_fd (-1 = not connected), which stays open for the next call.
 */
void localdns_handle_request(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd);

/* Answer queries on an accepted TCP connection until it idles, then close it. */
void localdns_serve_tcp(dnsserver_t *dns, int fd, int *upstream_fd);

/* Test hook for the time-injected throttle state machine. */
bool dnsproxy_test_throttle_take(log_throttle_t *t, int64_t now_ms,
		int64_t interval_ms, uint32_t *dropped);
bool dns_stats_json(void *ctx, char **ptr, char *end);

#endif /* DNSPROXY_H_ */
