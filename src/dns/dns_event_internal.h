#ifndef DNS_EVENT_INTERNAL_H
#define DNS_EVENT_INTERNAL_H

#include "dns_internal.h"
#include "resolver.h"
#include "reactor.h"

#include <pthread.h>
#include <sys/socket.h>

#include <zroxy/socks5_codec.h>

/* These bounds keep the loop's memory and fd use independent of input load. */
#define DNS_EVENT_UPSTREAMS 96u
#define DNS_EVENT_CLIENTS 128u
#define DNS_EVENT_REQUESTS 2048u
#define DNS_EVENT_RESPONSE_BYTES (16u * 1024u * 1024u)
#define DNS_EVENT_UDP_BURST 64u
/* Fixed sockets, upstreams and clients; bounds the poll backend only. */
#define DNS_REACTOR_CAP (4 + DNS_EVENT_UPSTREAMS + DNS_EVENT_CLIENTS)
#define DNS_EVENT_BATCH 64
#define DNS_EVENT_IDLE_MS 30000
#define DNS_RESOLVE_RETRY_MS 1000
#define DNS_RESOLVE_REFRESH_MS 60000

enum request_kind { REQ_UDP, REQ_TCP };
enum client_state { CLIENT_READ_LEN, CLIENT_READ_QUERY, CLIENT_WAIT, CLIENT_WRITE };
enum upstream_state {
	UP_CLOSED, UP_CONNECT, UP_IDLE, UP_QUERY_WRITE, UP_REPLY_LEN, UP_REPLY_BODY,
	UP_SOCKS_WRITE, UP_SOCKS_READ
};
enum attempt_result { ATTEMPT_ERROR, ATTEMPT_BAD, ATTEMPT_LOCAL, ATTEMPT_TIMEOUT };
enum watch_kind { WATCH_UDP, WATCH_TCP_LISTEN, WATCH_WAKE, WATCH_RESOLVER,
	WATCH_UPSTREAM, WATCH_CLIENT };

typedef struct dns_event dns_event_t;
typedef struct dns_request dns_request_t;
typedef struct dns_client dns_client_t;
typedef struct dns_upstream dns_upstream_t;

typedef struct {
	int kind;
	void *ptr;
} dns_watch_t;

struct dns_request {
	dns_request_t *next;
	dns_request_t *followers;
	dns_request_t *follow_next;
	dns_event_t *event;
	dns_client_t *client;
	dnscache_flight *flight;
	struct sockaddr_in peer;
	uint8_t query[DNS_MSG_SIZE];
	uint16_t query_len;
	uint8_t *response;
	size_t response_len;
	size_t response_off;
	size_t response_cap;
	int64_t received_ms;
	int64_t deadline_ms;
	unsigned attempts;
	unsigned route;
	uint32_t tried;
	int64_t attempt_deadline_ms;
	int kind;
	int stats_open;
	uint32_t stats_rx;
};

struct dns_client {
	dns_client_t *next;
	dns_client_t *dead_next;
	dns_watch_t watch;
	uint32_t interest;
	int registered;
	int dead;
	dns_event_t *event;
	dns_request_t *request;
	int fd;
	int state;
	int close_after_write;
	unsigned served;
	uint8_t input[DNS_MSG_SIZE];
	size_t input_off;
	size_t input_need;
	uint8_t *output;
	size_t output_len;
	size_t output_off;
	int64_t deadline_ms;
};

struct dns_upstream {
	dns_event_t *event;
	dns_watch_t watch;
	uint32_t interest;
	int registered;
	uint64_t closed_batch;
	dns_request_t *request;
	int fd;
	int state;
	socks5_client socks;
	uint8_t out[600];
	size_t out_len;
	size_t out_off;
	uint8_t in[600];
	size_t in_len;
	size_t in_need;
	int64_t idle_since_ms;
	uint64_t address_generation;
	unsigned route;
	int reused;
};

/* An address being resolved, or already known, for an upstream or a SOCKS proxy. */
typedef struct {
	int slot;
	uint64_t req;
	struct sockaddr_storage addr;
	socklen_t len;
	int ready;
	int literal;
	int64_t resolve_at_ms;
} dns_target_t;

typedef struct {
	dns_target_t upstream;
	dns_target_t socks;
	uint64_t address_generation;
} dns_route_state_t;

struct dns_event {
	dnsserver_t *dns;
	pthread_t thread;
	int started;
	int stop;
	resolver_sink *resolver;
	uint64_t generation;
	dns_route_state_t routes[DNS_ROUTES_MAX];
	unsigned active;	/* route that new queries go to */
	dns_upstream_t upstreams[DNS_EVENT_UPSTREAMS];
	reactor re;
	dns_watch_t fixed[4];
	uint64_t batch;
	dns_client_t *clients;
	dns_client_t *graveyard;
	unsigned client_count;
	dns_request_t *pending_head;
	dns_request_t *pending_tail;
	unsigned request_count;
	size_t response_bytes;
};

#endif /* DNS_EVENT_INTERNAL_H */
