#define _GNU_SOURCE

#include "dns_event_loop.h"
#include "sni_resolver.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zroxy/dns.h>
#include <zroxy/log.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>

/* These bounds keep the loop's memory and fd use independent of input load. */
#define DNS_EVENT_UPSTREAMS 96u
#define DNS_EVENT_CLIENTS 128u
#define DNS_EVENT_REQUESTS 2048u
#define DNS_EVENT_RESPONSE_BYTES (16u * 1024u * 1024u)
#define DNS_EVENT_UDP_BURST 64u
#define DNS_EVENT_POLL_MAX (4u + DNS_EVENT_UPSTREAMS + DNS_EVENT_CLIENTS)
#define DNS_EVENT_IDLE_MS 30000
#define DNS_RESOLVE_RETRY_MS 1000
#define DNS_RESOLVE_REFRESH_MS 60000

enum request_kind { REQ_UDP, REQ_TCP };
enum client_state { CLIENT_READ_LEN, CLIENT_READ_QUERY, CLIENT_WAIT, CLIENT_WRITE };
enum upstream_state {
	UP_CLOSED, UP_CONNECT, UP_IDLE, UP_QUERY_WRITE, UP_REPLY_LEN, UP_REPLY_BODY,
	UP_SOCKS_WRITE, UP_SOCKS_READ
};
enum socks_phase { SOCKS_GREETING, SOCKS_AUTH, SOCKS_REQUEST, SOCKS_REPLY_HEAD,
	SOCKS_REPLY_LEN, SOCKS_REPLY_REST };
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
	int kind;
	int stats_open;
	uint32_t stats_rx;
};

struct dns_client {
	dns_client_t *next;
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
	dns_request_t *request;
	int fd;
	int state;
	int socks_phase;
	uint8_t out[600];
	size_t out_len;
	size_t out_off;
	uint8_t in[600];
	size_t in_len;
	size_t in_need;
	int64_t idle_since_ms;
	uint64_t address_generation;
};

struct dns_event {
	dnsserver_t *dns;
	pthread_t thread;
	int started;
	int stop;
	sni_completion_sink *resolver;
	uint64_t generation;
	int upstream_slot;
	uint64_t upstream_req;
	int socks_slot;
	uint64_t socks_req;
	struct sockaddr_storage upstream_addr;
	socklen_t upstream_len;
	struct sockaddr_storage socks_addr;
	socklen_t socks_len;
	int upstream_ready;
	int socks_ready;
	int upstream_literal;
	int socks_literal;
	int64_t upstream_resolve_at_ms;
	int64_t socks_resolve_at_ms;
	uint64_t upstream_address_generation;
	dns_upstream_t upstreams[DNS_EVENT_UPSTREAMS];
	dns_client_t *clients;
	unsigned client_count;
	dns_request_t *pending_head;
	dns_request_t *pending_tail;
	unsigned request_count;
	size_t response_bytes;
};

static void request_fail(dns_event_t *event, dns_request_t *request);
static void request_complete(dns_event_t *event, dns_request_t *request,
		const uint8_t *response, size_t len);
static void schedule(dns_event_t *event);

static void close_fd(int *fd)
{
	if (fd && *fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

static int64_t mono_now(void)
{
	return net_mono_ms();
}

static int timeout_ms(int64_t deadline, int64_t now)
{
	int64_t left;
	if (deadline <= now)
		return 0;
	left = deadline - now;
	return left > INT_MAX ? INT_MAX : (int)left;
}

static bool addr_literal(const char *host, uint16_t port,
		struct sockaddr_storage *addr, socklen_t *len)
{
	struct sockaddr_in in;
	if (!host || !addr || !len || inet_pton(AF_INET, host, &in.sin_addr) != 1)
		return false;
	memset(&in, 0, sizeof(in));
	in.sin_family = AF_INET;
	in.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &in.sin_addr) != 1)
		return false;
	memset(addr, 0, sizeof(*addr));
	memcpy(addr, &in, sizeof(in));
	*len = sizeof(in);
	return true;
}

static void request_unlink_pending(dns_event_t *event, dns_request_t *request)
{
	dns_request_t **p = &event->pending_head;
	while (*p) {
		if (*p == request) {
			*p = request->next;
			if (event->pending_tail == request)
				event->pending_tail = NULL;
			if (!event->pending_head)
				event->pending_tail = NULL;
			return;
		}
		p = &(*p)->next;
	}
}

static void pending_push(dns_event_t *event, dns_request_t *request)
{
	request->next = NULL;
	if (event->pending_tail)
		event->pending_tail->next = request;
	else
		event->pending_head = request;
	event->pending_tail = request;
}

static void pending_push_front(dns_event_t *event, dns_request_t *request)
{
	request->next = event->pending_head;
	event->pending_head = request;
	if (!event->pending_tail)
		event->pending_tail = request;
}

static dns_request_t *pending_pop(dns_event_t *event)
{
	dns_request_t *request = event->pending_head;
	if (!request)
		return NULL;
	event->pending_head = request->next;
	if (!event->pending_head)
		event->pending_tail = NULL;
	request->next = NULL;
	return request;
}

static void request_free(dns_event_t *event, dns_request_t *request)
{
	if (!request)
		return;
	if (request->flight)
		dnscache_finish(event->dns->cache, request->flight, NULL, 0, 0, mono_now());
	if (request->response) {
		if (event->response_bytes >= request->response_cap)
			event->response_bytes -= request->response_cap;
		else
			event->response_bytes = 0;
		free(request->response);
	}
	if (request->stats_open && event->dns->Stat)
		stats_close_connection(event->dns->Stat, 0, (uint32_t)request->query_len + 2u);
	if (event->request_count > 0)
		event->request_count--;
	free(request);
}

static void request_close_stats(dns_event_t *event, dns_request_t *request, size_t response_len)
{
	(void)response_len;
	if (request->stats_open && event->dns->Stat)
		stats_close_connection(event->dns->Stat, request->stats_rx,
				(uint32_t)request->query_len + 2u);
	request->stats_open = 0;
}

static void request_complete_followers(dns_event_t *event, dns_request_t *leader,
		const uint8_t *response, size_t len)
{
	dns_request_t *follower = leader->followers;
	leader->followers = NULL;
	while (follower) {
		dns_request_t *next = follower->follow_next;
		uint8_t *copy = malloc(len);
		follower->follow_next = NULL;
		if (copy) {
			memcpy(copy, response, len);
			if (dns_reply_adopt(copy, len, follower->query, follower->query_len)) {
				request_complete(event, follower, copy, len);
				free(copy);
			} else {
				free(copy);
				request_fail(event, follower);
			}
		} else {
			request_fail(event, follower);
		}
		follower = next;
	}
}

static void send_udp(dns_event_t *event, const struct sockaddr_in *peer,
		const uint8_t *buf, size_t len)
{
	if (len > 0)
		(void)sendto(event->dns->local_sock, buf, len, 0,
				(const struct sockaddr *)peer, sizeof(*peer));
}

static void client_close(dns_event_t *event, dns_client_t *client)
{
	dns_client_t **p;
	if (!client)
		return;
	if (client->request) {
		client->request->client = NULL;
		client->request = NULL;
	}
	close_fd(&client->fd);
	if (__atomic_load_n(&event->dns->tcp_active, __ATOMIC_RELAXED) > 0)
		__atomic_sub_fetch(&event->dns->tcp_active, 1, __ATOMIC_RELAXED);
	free(client->output);
	p = &event->clients;
	while (*p && *p != client)
		p = &(*p)->next;
	if (*p)
		*p = client->next;
	if (event->client_count > 0)
		event->client_count--;
	free(client);
}

static bool client_queue_reply(dns_client_t *client, const uint8_t *buf, size_t len)
{
	uint8_t *out;
	if (!client || client->fd < 0 || len > DNS_TCP_MSG_MAX || client->output)
		return false;
	out = malloc(len + 2u);
	if (!out)
		return false;
	out[0] = (uint8_t)(len >> 8);
	out[1] = (uint8_t)len;
	memcpy(out + 2, buf, len);
	client->output = out;
	client->output_len = len + 2u;
	client->output_off = 0;
	client->state = CLIENT_WRITE;
	client->deadline_ms = mono_now() + net_timeout_ms((int)client->event->dns->timeout);
	return true;
}

static void request_send_error(dns_event_t *event, dns_request_t *request, uint8_t rcode)
{
	uint8_t error[DNS_MSG_SIZE];
	size_t len = dns_build_error(request->query, request->query_len, rcode,
			error, sizeof(error));
	request_complete(event, request, error, len);
}

static void request_complete(dns_event_t *event, dns_request_t *request,
		const uint8_t *response, size_t len)
{
	uint8_t trunc[DNS_MSG_SIZE];
	const uint8_t *out = response;
	size_t out_len = len;

	if (!request)
		return;
	if (request->kind == REQ_UDP) {
		size_t limit = dns_udp_limit(request->query, request->query_len, DNS_UDP_MAX_PAYLOAD);
		if (len > limit) {
			out_len = dns_build_truncated(response, len, trunc, sizeof(trunc));
			out = trunc;
		}
		if (out_len > 0)
			send_udp(event, &request->peer, out, out_len);
	} else if (request->client) {
		dns_client_t *client = request->client;
		if (client_queue_reply(client, response, len)) {
			client->request = NULL;
		} else {
			client->request = NULL;
			request->client = NULL;
			client_close(event, client);
			out_len = 0;
		}
	} else {
		out_len = 0;
	}
	request_close_stats(event, request, out_len);
	request_free(event, request);
}

static void request_finish_upstream(dns_event_t *event, dns_request_t *request)
{
	if (!request || !request->response || request->response_len == 0 ||
		!dns_reply_matches(request->query, request->query_len,
				request->response, request->response_len)) {
		if (request && request->flight) {
			dnscache_finish(event->dns->cache, request->flight, NULL, 0, 0, mono_now());
			request->flight = NULL;
		}
		request_send_error(event, request, ServerFailure_ResponseType);
		return;
	}
	if (request->flight) {
		dnscache_finish(event->dns->cache, request->flight, request->response,
				request->response_len, request->response_len, mono_now());
		request->flight = NULL;
	}
	request_complete_followers(event, request, request->response, request->response_len);
	request->stats_rx = (uint32_t)request->response_len + 2u;
	request_complete(event, request, request->response, request->response_len);
}

static void request_fail(dns_event_t *event, dns_request_t *request)
{
	dns_request_t *follower;
	if (!request)
		return;
	if (request->flight) {
		dnscache_finish(event->dns->cache, request->flight, NULL, 0, 0, mono_now());
		request->flight = NULL;
	}
	follower = request->followers;
	request->followers = NULL;
	while (follower) {
		dns_request_t *next = follower->follow_next;
		follower->follow_next = NULL;
		request_fail(event, follower);
		follower = next;
	}
	log_error("NO DATA DNS upstream request failed");
	request_send_error(event, request, ServerFailure_ResponseType);
}

static dns_request_t *find_flight_leader(dns_event_t *event, dnscache_flight *flight)
{
	dns_request_t *request;
	unsigned i;
	for (request = event->pending_head; request; request = request->next)
		if (request->flight == flight)
			return request;
	for (i = 0; i < event->dns->upstream_connections; i++)
		if (event->upstreams[i].request && event->upstreams[i].request->flight == flight)
			return event->upstreams[i].request;
	return NULL;
}

static bool request_ensure_response(dns_event_t *event, dns_request_t *request, size_t cap)
{
	uint8_t *buf;
	if (cap > DNS_EVENT_RESPONSE_BYTES || event->response_bytes > DNS_EVENT_RESPONSE_BYTES - cap)
		return false;
	if (request->response && request->response_cap >= cap)
		return true;
	buf = realloc(request->response, cap);
	if (!buf)
		return false;
	if (request->response)
		event->response_bytes -= request->response_cap;
	request->response = buf;
	request->response_cap = cap;
	event->response_bytes += cap;
	return true;
}

static bool handle_local(dns_event_t *event, dns_request_t *request)
{
	struct Message msg = {0};
	uint8_t answer[DNS_MSG_SIZE];
	int len;
	if (((request->query[2] >> 3) & 0x0f) != QUERY_OperationCode) {
		request_send_error(event, request, NotImplemented_ResponseType);
		return true;
	}
	if (((request->query[4] << 8) | request->query[5]) != 1) {
		request_send_error(event, request, FormatError_ResponseType);
		return true;
	}
	if (!dns_decode_msg(&msg, request->query, request->query_len))
		return false;
	if (!msg.questions || !msg.questions->qName || !event->dns->whitelist ||
		!filter_match(event->dns->whitelist, msg.questions->qName)) {
		dns_free_msg(&msg);
		return false;
	}
	len = localdns_answer_local(event->dns, &msg, answer);
	dns_free_msg(&msg);
	if (len > 0)
		request_complete(event, request, answer, (size_t)len);
	else
		request_send_error(event, request, ServerFailure_ResponseType);
	return true;
}

static void request_start(dns_event_t *event, dns_request_t *request)
{
	dnscache_flight *flight = NULL;
	dnscache_result cached;
	size_t full = 0;
	int64_t now = mono_now();

	if (handle_local(event, request))
		return;
	if (!request_ensure_response(event, request, DNS_UDP_MAX_PAYLOAD)) {
		request_fail(event, request);
		return;
	}
	cached = dnscache_begin(event->dns->cache, request->query, request->query_len,
			now, request->response, request->response_cap, &full, &flight);
	if (cached == DNSCACHE_HIT) {
		request->response_len = full;
		request_complete(event, request, request->response, full);
		return;
	}
	if (cached == DNSCACHE_LEAD)
		request->flight = flight;
	else if (cached == DNSCACHE_FOLLOW) {
		dns_request_t *leader = find_flight_leader(event, flight);
		dnscache_abandon_follower(event->dns->cache, flight);
		if (leader) {
			request->follow_next = leader->followers;
			leader->followers = request;
			return;
		}
	}
	pending_push(event, request);
}

static dns_request_t *request_new(dns_event_t *event, int kind,
		const uint8_t *query, size_t len, const struct sockaddr_in *peer, dns_client_t *client)
{
	dns_request_t *request;
	int64_t now;
	if (!query || len < DNS_HEADER_SIZE || len > DNS_MSG_SIZE ||
		event->request_count >= DNS_EVENT_REQUESTS)
		return NULL;
	request = calloc(1, sizeof(*request));
	if (!request)
		return NULL;
	now = mono_now();
	request->event = event;
	request->kind = kind;
	request->client = client;
	request->query_len = (uint16_t)len;
	memcpy(request->query, query, len);
	if (peer)
		request->peer = *peer;
	request->received_ms = now;
	request->deadline_ms = now + 2 * (int64_t)net_timeout_ms((int)event->dns->timeout);
	request->stats_open = 1;
	event->request_count++;
	if (event->dns->Stat)
		stats_open_connection(event->dns->Stat);
	return request;
}

static void upstream_close(dns_event_t *event, dns_upstream_t *upstream)
{
	if (upstream->fd >= 0 && event->dns->active_upstreams > 0)
		__atomic_sub_fetch(&event->dns->active_upstreams, 1u, __ATOMIC_RELAXED);
	close_fd(&upstream->fd);
	upstream->state = UP_CLOSED;
	upstream->out_len = upstream->out_off = 0;
	upstream->in_len = upstream->in_need = 0;
}

static void upstream_fail(dns_event_t *event, dns_upstream_t *upstream)
{
	dns_request_t *request = upstream->request;
	upstream->request = NULL;
	upstream_close(event, upstream);
	if (request && mono_now() < request->deadline_ms)
		(void)__atomic_fetch_add(&event->dns->upstream_errors, 1u, __ATOMIC_RELAXED);
	if (!request)
		return;
	if (request->attempts++ == 0 && mono_now() < request->deadline_ms)
		pending_push_front(event, request);
	else
		request_fail(event, request);
}

static bool queue_socks_request(dns_event_t *event, dns_upstream_t *upstream)
{
	const char *host = event->dns->upstream.ip;
	size_t hlen = strlen(host);
	uint16_t port = htons(event->dns->upstream.port);
	if (hlen == 0 || hlen > 255 || hlen + 7 > sizeof(upstream->out))
		return false;
	upstream->out[0] = 5;
	upstream->out[1] = 1;
	upstream->out[2] = 0;
	upstream->out[3] = 3;
	upstream->out[4] = (uint8_t)hlen;
	memcpy(upstream->out + 5, host, hlen);
	memcpy(upstream->out + 5 + hlen, &port, sizeof(port));
	upstream->out_len = 7 + hlen;
	upstream->out_off = 0;
	upstream->socks_phase = SOCKS_REQUEST;
	upstream->state = UP_SOCKS_WRITE;
	return true;
}

static bool queue_socks_auth(dns_event_t *event, dns_upstream_t *upstream)
{
	sockshost_t *socks = event->dns->socks;
	size_t ulen;
	size_t plen;
	if (!socks || !socks->user || !socks->pass)
		return false;
	ulen = strlen(socks->user);
	plen = strlen(socks->pass);
	if (ulen == 0 || ulen > 255 || plen > 255 || ulen + plen + 3 > sizeof(upstream->out))
		return false;
	upstream->out[0] = 1;
	upstream->out[1] = (uint8_t)ulen;
	memcpy(upstream->out + 2, socks->user, ulen);
	upstream->out[2 + ulen] = (uint8_t)plen;
	memcpy(upstream->out + 3 + ulen, socks->pass, plen);
	upstream->out_len = 3 + ulen + plen;
	upstream->out_off = 0;
	upstream->socks_phase = SOCKS_AUTH;
	upstream->state = UP_SOCKS_WRITE;
	return true;
}

static bool upstream_queue_query(dns_upstream_t *upstream)
{
	dns_request_t *request = upstream->request;
	if (!request || request->query_len + 2u > sizeof(upstream->out))
		return false;
	upstream->out[0] = (uint8_t)(request->query_len >> 8);
	upstream->out[1] = (uint8_t)request->query_len;
	memcpy(upstream->out + 2, request->query, request->query_len);
	upstream->out_len = request->query_len + 2u;
	upstream->out_off = 0;
	upstream->state = UP_QUERY_WRITE;
	return true;
}

static void upstream_connected(dns_event_t *event, dns_upstream_t *upstream)
{
	if (event->dns->socks) {
		static const uint8_t hello[] = { 5, 2, 0, 2 };
		memcpy(upstream->out, hello, sizeof(hello));
		upstream->out_len = sizeof(hello);
		upstream->out_off = 0;
		upstream->socks_phase = SOCKS_GREETING;
		upstream->state = UP_SOCKS_WRITE;
	} else if (!upstream_queue_query(upstream)) {
		upstream_fail(event, upstream);
	}
}

static bool upstream_open(dns_event_t *event, dns_upstream_t *upstream, dns_request_t *request)
{
	const struct sockaddr *addr;
	socklen_t len;
	int fd;
	int rc;
	int one = 1;
	if (!event->upstream_ready || (event->dns->socks && !event->socks_ready))
		return false;
	if (event->dns->socks) {
		addr = (const struct sockaddr *)&event->socks_addr;
		len = event->socks_len;
	} else {
		addr = (const struct sockaddr *)&event->upstream_addr;
		len = event->upstream_len;
	}
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (fd < 0 || !net_set_nonblock_cloexec(fd)) {
		if (fd >= 0)
			close(fd);
		return false;
	}
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	upstream->request = request;
	upstream->address_generation = event->upstream_address_generation;
	upstream->fd = fd;
	rc = connect(fd, addr, len);
	if (rc == 0) {
		(void)__atomic_fetch_add(&event->dns->active_upstreams, 1u, __ATOMIC_RELAXED);
		upstream_connected(event, upstream);
		return true;
	}
	if (errno != EINPROGRESS && errno != EALREADY) {
		upstream->request = NULL;
		close_fd(&upstream->fd);
		return false;
	}
	upstream->state = UP_CONNECT;
	(void)__atomic_fetch_add(&event->dns->active_upstreams, 1u, __ATOMIC_RELAXED);
	return true;
}

static void upstream_write(dns_event_t *event, dns_upstream_t *upstream)
{
	for (;;) {
		ssize_t n = write(upstream->fd, upstream->out + upstream->out_off,
				upstream->out_len - upstream->out_off);
		if (n > 0) {
			upstream->out_off += (size_t)n;
			if (upstream->out_off < upstream->out_len)
				return;
			break;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		upstream_fail(event, upstream);
		return;
	}
	if (upstream->state == UP_QUERY_WRITE) {
		upstream->in_len = 0;
		upstream->in_need = 2;
		upstream->state = UP_REPLY_LEN;
		return;
	}
	upstream->in_len = 0;
	upstream->in_need = upstream->socks_phase == SOCKS_REQUEST ? 4u : 2u;
	upstream->state = UP_SOCKS_READ;
}

static bool socks_read_done(dns_event_t *event, dns_upstream_t *upstream)
{
	if (upstream->socks_phase == SOCKS_GREETING) {
		if (upstream->in[0] != 5)
			return false;
		if (upstream->in[1] == 0)
			return queue_socks_request(event, upstream);
		if (upstream->in[1] == 2)
			return queue_socks_auth(event, upstream);
		return false;
	}
	if (upstream->socks_phase == SOCKS_AUTH) {
		if (upstream->in[0] != 1 || upstream->in[1] != 0)
			return false;
		return queue_socks_request(event, upstream);
	}
	if (upstream->socks_phase == SOCKS_REQUEST) {
		if (upstream->in[0] != 5 || upstream->in[1] != 0)
			return false;
		if (upstream->in[3] == 1) {
			upstream->socks_phase = SOCKS_REPLY_REST;
			upstream->in_len = 0;
			upstream->in_need = 6;
			return true;
		}
		if (upstream->in[3] == 4) {
			upstream->socks_phase = SOCKS_REPLY_REST;
			upstream->in_len = 0;
			upstream->in_need = 18;
			return true;
		}
		if (upstream->in[3] == 3) {
			upstream->socks_phase = SOCKS_REPLY_LEN;
			upstream->in_len = 0;
			upstream->in_need = 1;
			return true;
		}
		return false;
	}
	if (upstream->socks_phase == SOCKS_REPLY_LEN) {
		upstream->socks_phase = SOCKS_REPLY_REST;
		upstream->in_len = 0;
		upstream->in_need = (size_t)upstream->in[0] + 2u;
		return true;
	}
	if (upstream->socks_phase == SOCKS_REPLY_REST) {
		upstream->state = UP_IDLE;
		upstream->idle_since_ms = mono_now();
		return upstream_queue_query(upstream);
	}
	return false;
}

static void upstream_read(dns_event_t *event, dns_upstream_t *upstream)
{
	dns_request_t *request = upstream->request;
	uint8_t *dst;
	size_t left;
	for (;;) {
		if (upstream->state == UP_SOCKS_READ || upstream->state == UP_REPLY_LEN) {
			dst = upstream->in;
			left = upstream->in_need - upstream->in_len;
		} else if (upstream->state == UP_REPLY_BODY && request && request->response) {
			dst = request->response;
			left = request->response_len - request->response_off;
		} else {
			upstream_fail(event, upstream);
			return;
		}
		ssize_t n = read(upstream->fd, dst +
			(upstream->state == UP_REPLY_BODY ? request->response_off : upstream->in_len), left);
		if (n > 0) {
			if (upstream->state == UP_REPLY_BODY)
				request->response_off += (size_t)n;
			else
				upstream->in_len += (size_t)n;
			if ((upstream->state == UP_REPLY_BODY && request->response_off < request->response_len) ||
				(upstream->state != UP_REPLY_BODY && upstream->in_len < upstream->in_need))
				return;
			if (upstream->state == UP_SOCKS_READ) {
				if (!socks_read_done(event, upstream)) {
					upstream_fail(event, upstream);
					return;
				}
				if (upstream->state == UP_SOCKS_READ)
					continue;
				return;
			}
			if (upstream->state == UP_REPLY_LEN) {
				size_t length = ((size_t)upstream->in[0] << 8) | upstream->in[1];
				if (length < DNS_HEADER_SIZE || !request_ensure_response(event, request, length)) {
					request->attempts = 1;
					upstream_fail(event, upstream);
					return;
				}
				request->response_len = length;
				request->response_off = 0;
				upstream->state = UP_REPLY_BODY;
				continue;
			}
			upstream->request = NULL;
			upstream->state = UP_IDLE;
			upstream->idle_since_ms = mono_now();
			request_finish_upstream(event, request);
			schedule(event);
			return;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		upstream_fail(event, upstream);
		return;
	}
}

static void upstream_pump(dns_event_t *event, dns_upstream_t *upstream, short revents)
{
	if (!upstream || upstream->fd < 0)
		return;
	if (upstream->state == UP_CONNECT && (revents & (POLLOUT | POLLERR | POLLHUP))) {
		int error = 0;
		socklen_t len = sizeof(error);
		if (getsockopt(upstream->fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
			upstream_fail(event, upstream);
			return;
		}
		upstream_connected(event, upstream);
	}
	if (upstream->state == UP_QUERY_WRITE || upstream->state == UP_SOCKS_WRITE) {
		if (revents & POLLOUT)
			upstream_write(event, upstream);
		else if (revents & (POLLERR | POLLHUP))
			upstream_fail(event, upstream);
		return;
	}
	if (upstream->state == UP_REPLY_LEN || upstream->state == UP_REPLY_BODY ||
		upstream->state == UP_SOCKS_READ) {
		if (revents & POLLIN)
			upstream_read(event, upstream);
		else if (revents & (POLLERR | POLLHUP))
			upstream_fail(event, upstream);
		return;
	}
	if (upstream->state == UP_IDLE && revents & (POLLIN | POLLERR | POLLHUP))
		upstream_close(event, upstream);
}

static void schedule(dns_event_t *event)
{
	unsigned i;
	for (i = 0; i < event->dns->upstream_connections; i++) {
		dns_upstream_t *upstream = &event->upstreams[i];
		if (upstream->state == UP_IDLE &&
				upstream->address_generation != event->upstream_address_generation)
			upstream_close(event, upstream);
	}
	while (event->pending_head) {
		dns_upstream_t *upstream = NULL;
		dns_request_t *request;
		for (i = 0; i < event->dns->upstream_connections; i++) {
			if (event->upstreams[i].state == UP_IDLE && !event->upstreams[i].request) {
				upstream = &event->upstreams[i];
				break;
			}
		}
		if (!upstream) {
			for (i = 0; i < event->dns->upstream_connections; i++) {
				if (event->upstreams[i].state == UP_CLOSED) {
					upstream = &event->upstreams[i];
					break;
				}
			}
		}
		if (!upstream)
			return;
		request = pending_pop(event);
		if (mono_now() >= request->deadline_ms) {
			(void)__atomic_fetch_add(&event->dns->upstream_timeouts, 1u, __ATOMIC_RELAXED);
			request_fail(event, request);
			continue;
		}
		if (upstream->state == UP_IDLE) {
			upstream->request = request;
			if (!upstream_queue_query(upstream))
				upstream_fail(event, upstream);
		} else if (!upstream_open(event, upstream, request)) {
			pending_push_front(event, request);
			return;
		}
	}
}

static void client_pump(dns_event_t *event, dns_client_t *client, short revents)
{
	if (!client || client->fd < 0) return;
	if (revents & (POLLERR | POLLHUP)) {
		client_close(event, client);
		return;
	}
	if (client->state == CLIENT_WRITE && revents & POLLOUT) {
		for (;;) {
			ssize_t n = write(client->fd, client->output + client->output_off,
					client->output_len - client->output_off);
			if (n > 0) {
				client->output_off += (size_t)n;
				if (client->output_off < client->output_len) return;
				free(client->output); client->output = NULL;
				if (client->close_after_write || ++client->served >= DNS_TCP_MAX_QUERIES) {
					client_close(event, client); return;
				}
				client->state = CLIENT_READ_LEN; client->input_off = 0; client->input_need = 2;
				client->deadline_ms = mono_now() + DNS_TCP_IDLE_MS;
				return;
			}
			if (n < 0 && errno == EINTR) continue;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
			client_close(event, client); return;
		}
	}
	if ((client->state == CLIENT_READ_LEN || client->state == CLIENT_READ_QUERY) && revents & POLLIN) {
		for (;;) {
			ssize_t n = read(client->fd, client->input + client->input_off, client->input_need - client->input_off);
			if (n > 0) {
				client->input_off += (size_t)n;
				if (client->input_off < client->input_need) return;
				if (client->state == CLIENT_READ_LEN) {
					client->input_need = ((size_t)client->input[0] << 8) | client->input[1];
				if (client->input_need < DNS_HEADER_SIZE || client->input_need > DNS_MSG_SIZE) {
						client_close(event, client); return;
					}
					client->input_off = 0; client->state = CLIENT_READ_QUERY;
					client->deadline_ms = mono_now() + net_timeout_ms((int)event->dns->timeout);
					continue;
				}
				if ((client->input[2] & 0x80) != 0) { client_close(event, client); return; }
				client->request = request_new(event, REQ_TCP, client->input, client->input_need, NULL, client);
				if (!client->request) { client_close(event, client); return; }
				client->state = CLIENT_WAIT;
				request_start(event, client->request);
				schedule(event);
				return;
			}
			if (n < 0 && errno == EINTR) continue;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
			client_close(event, client); return;
		}
	}
}

static void accept_clients(dns_event_t *event)
{
	for (;;) {
		dns_client_t *client;
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		int fd = accept(event->dns->tcp_sock, (struct sockaddr *)&peer, &peer_len);
		if (fd < 0) {
			if (errno == EINTR) continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) log_error("dns accept failed: %s", strerror(errno));
			return;
		}
		if ((event->dns->acl_count > 0 &&
				!dns_acl_allows(event->dns->acl, event->dns->acl_count,
					ntohl(peer.sin_addr.s_addr))) ||
			event->client_count >= DNS_EVENT_CLIENTS || !net_set_nonblock_cloexec(fd)) {
			(void)__atomic_fetch_add(&event->dns->tcp_refused, 1u, __ATOMIC_RELAXED);
			close(fd); continue;
		}
		client = calloc(1, sizeof(*client));
		if (!client) { close(fd); continue; }
		client->event = event; client->fd = fd; client->state = CLIENT_READ_LEN;
		client->input_need = 2; client->deadline_ms = mono_now() + DNS_TCP_IDLE_MS;
		client->next = event->clients; event->clients = client; event->client_count++;
		(void)__atomic_add_fetch(&event->dns->tcp_active, 1, __ATOMIC_RELAXED);
	}
}

static void pull_udp(dns_event_t *event)
{
	unsigned i;
	for (i = 0; i < DNS_EVENT_UDP_BURST; i++) {
		uint8_t query[DNS_MSG_SIZE];
		struct sockaddr_in peer;
		socklen_t plen = sizeof(peer);
		ssize_t n = recvfrom(event->dns->local_sock, query, sizeof(query), MSG_TRUNC,
				(struct sockaddr *)&peer, &plen);
		dns_request_t *request;
		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) log_error("dns recvfrom failed: %s", strerror(errno));
			return;
		}
		if (event->dns->acl_count > 0 && !dns_acl_allows(event->dns->acl, event->dns->acl_count,
				ntohl(peer.sin_addr.s_addr))) { __atomic_fetch_add(&event->dns->acl_dropped, 1u, __ATOMIC_RELAXED); continue; }
		if (!dns_rate_take(&event->dns->rate, ntohl(peer.sin_addr.s_addr), mono_now())) { __atomic_fetch_add(&event->dns->rate_dropped, 1u, __ATOMIC_RELAXED); continue; }
		if (n < DNS_HEADER_SIZE || (size_t)n > sizeof(query) || (query[2] & 0x80) != 0) continue;
		request = request_new(event, REQ_UDP, query, (size_t)n, &peer, NULL);
		if (!request) {
			uint8_t error[DNS_MSG_SIZE]; size_t len = dns_build_error(query, (size_t)n, ServerFailure_ResponseType, error, sizeof(error));
			__atomic_fetch_add(&event->dns->queue_dropped, 1u, __ATOMIC_RELAXED);
			send_udp(event, &peer, error, len); continue;
		}
		request_start(event, request);
	}
	schedule(event);
}

static bool resolution_submit(dns_event_t *event, unsigned role)
{
	const char *host = role == 1 ? event->dns->upstream.ip : event->dns->socks->host;
	uint16_t port = role == 1 ? event->dns->upstream.port : event->dns->socks->port;
	int *slot = role == 1 ? &event->upstream_slot : &event->socks_slot;
	uint64_t *req = role == 1 ? &event->upstream_req : &event->socks_req;
	int64_t *next = role == 1 ? &event->upstream_resolve_at_ms : &event->socks_resolve_at_ms;
	int *literal = role == 1 ? &event->upstream_literal : &event->socks_literal;
	struct sockaddr_storage *addr = role == 1 ? &event->upstream_addr : &event->socks_addr;
	socklen_t *len = role == 1 ? &event->upstream_len : &event->socks_len;
	int *ready = role == 1 ? &event->upstream_ready : &event->socks_ready;

	if (*literal || *slot >= 0)
		return true;
	if (addr_literal(host, port, addr, len)) {
		*literal = 1;
		*ready = 1;
		event->upstream_address_generation++;
		return true;
	}
	if (sni_resolver_submit(event->resolver, role, event->generation, host, port, AF_INET,
			mono_now() + net_timeout_ms((int)event->dns->timeout), slot, req) == SNI_SUBMIT_OK)
		return true;
	*next = mono_now() + DNS_RESOLVE_RETRY_MS;
	return false;
}

static void resolution_tick(dns_event_t *event, int64_t now)
{
	if (!event->upstream_literal && event->upstream_slot < 0 &&
			now >= event->upstream_resolve_at_ms)
		(void)resolution_submit(event, 1);
	if (event->dns->socks && !event->socks_literal && event->socks_slot < 0 &&
			now >= event->socks_resolve_at_ms)
		(void)resolution_submit(event, 2);
}

static void resolver_drain(dns_event_t *event)
{
	resolve_slot *done[SNI_RESOLVER_SLOTS];
	size_t n = sni_resolver_drain(event->resolver, done, SNI_RESOLVER_SLOTS);
	size_t i;
	int64_t now = mono_now();

	for (i = 0; i < n; i++) {
		resolve_slot *slot = done[i];
		struct sockaddr_storage *addr;
		socklen_t *len;
		int *ready;
		int *pending_slot;
		uint64_t *pending_req;
		int64_t *next;
		bool changed;

		if (!slot)
			continue;
		if (slot->connection_generation != event->generation) {
			sni_resolver_release(slot->index, slot->req_id);
			continue;
		}
		if (slot->connection_index == 1) {
			addr = &event->upstream_addr; len = &event->upstream_len;
			ready = &event->upstream_ready; pending_slot = &event->upstream_slot;
			pending_req = &event->upstream_req; next = &event->upstream_resolve_at_ms;
		} else if (slot->connection_index == 2) {
			addr = &event->socks_addr; len = &event->socks_len;
			ready = &event->socks_ready; pending_slot = &event->socks_slot;
			pending_req = &event->socks_req; next = &event->socks_resolve_at_ms;
		} else {
			sni_resolver_release(slot->index, slot->req_id);
			continue;
		}
		if (*pending_slot == slot->index && *pending_req == slot->req_id) {
			*pending_slot = -1;
			*pending_req = 0;
		}
		if (slot->gai_error == 0 && slot->address_count > 0) {
			changed = !*ready || *len != slot->addresses[0].length ||
				memcmp(addr, &slot->addresses[0].address, *len) != 0;
			*addr = slot->addresses[0].address;
			*len = slot->addresses[0].length;
			*ready = 1;
			if (changed)
				event->upstream_address_generation++;
			*next = now + DNS_RESOLVE_REFRESH_MS;
		} else {
			log_error("dns resolver failed for %s; retrying",
				slot->connection_index == 1 ? event->dns->upstream.ip : event->dns->socks->host);
			*next = now + DNS_RESOLVE_RETRY_MS;
		}
		sni_resolver_release(slot->index, slot->req_id);
	}
	resolution_tick(event, now);
	schedule(event);
}

static int loop_timeout(dns_event_t *event, int64_t now)
{
	int64_t best = now + 1000;
	dns_request_t *request;
	dns_client_t *client;
	unsigned i;
	for (request = event->pending_head; request; request = request->next)
		if (request->deadline_ms < best) best = request->deadline_ms;
	for (client = event->clients; client; client = client->next)
		if (client->deadline_ms < best) best = client->deadline_ms;
	for (i = 0; i < event->dns->upstream_connections; i++)
		if (event->upstreams[i].request && event->upstreams[i].request->deadline_ms < best)
			best = event->upstreams[i].request->deadline_ms;
	return timeout_ms(best, now);
}

static void sweep(dns_event_t *event, int64_t now)
{
	dns_request_t *request = event->pending_head;
	dns_client_t *client = event->clients;
	unsigned i;
	resolution_tick(event, now);
	while (request) {
		dns_request_t *next = request->next;
		if (now >= request->deadline_ms) {
			request_unlink_pending(event, request);
			__atomic_fetch_add(&event->dns->upstream_timeouts, 1u, __ATOMIC_RELAXED);
			request_fail(event, request);
		}
		request = next;
	}
	for (i = 0; i < event->dns->upstream_connections; i++) {
		dns_upstream_t *upstream = &event->upstreams[i];
		if (upstream->request && now >= upstream->request->deadline_ms) {
			__atomic_fetch_add(&event->dns->upstream_timeouts, 1u, __ATOMIC_RELAXED);
			upstream->request->attempts = 1;
			upstream_fail(event, upstream);
		} else if (upstream->state == UP_IDLE && now - upstream->idle_since_ms >= DNS_EVENT_IDLE_MS) {
			upstream_close(event, upstream);
		}
	}
	while (client) {
		dns_client_t *next = client->next;
		if (now >= client->deadline_ms && client->state != CLIENT_WAIT)
			client_close(event, client);
		client = next;
	}
	schedule(event);
}

static void drain_wake(dns_event_t *event)
{
	char buf[64];
	for (;;) {
		ssize_t n = read(event->dns->wake[0], buf, sizeof(buf));
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return;
	}
}

static void *event_main(void *arg)
{
	dns_event_t *event = arg;
	while (!event->stop) {
		struct pollfd fds[DNS_EVENT_POLL_MAX];
		dns_watch_t watch[DNS_EVENT_POLL_MAX];
		nfds_t count = 0;
		int rc;
		int64_t now = mono_now();
		unsigned i;
		dns_client_t *client;
		fds[count] = (struct pollfd){ event->dns->local_sock, POLLIN, 0 }; watch[count++] = (dns_watch_t){ WATCH_UDP, NULL };
		if (event->dns->tcp_sock >= 0) { fds[count] = (struct pollfd){ event->dns->tcp_sock, POLLIN, 0 }; watch[count++] = (dns_watch_t){ WATCH_TCP_LISTEN, NULL }; }
		fds[count] = (struct pollfd){ event->dns->wake[0], POLLIN, 0 }; watch[count++] = (dns_watch_t){ WATCH_WAKE, NULL };
		fds[count] = (struct pollfd){ event->resolver->pipe_read, POLLIN, 0 }; watch[count++] = (dns_watch_t){ WATCH_RESOLVER, NULL };
		for (i = 0; i < event->dns->upstream_connections; i++) {
			dns_upstream_t *upstream = &event->upstreams[i]; short events = 0;
			if (upstream->fd < 0) continue;
			if (upstream->state == UP_CONNECT || upstream->state == UP_QUERY_WRITE || upstream->state == UP_SOCKS_WRITE) events |= POLLOUT;
			if (upstream->state == UP_IDLE || upstream->state == UP_REPLY_LEN || upstream->state == UP_REPLY_BODY || upstream->state == UP_SOCKS_READ) events |= POLLIN;
			fds[count] = (struct pollfd){ upstream->fd, events, 0 }; watch[count++] = (dns_watch_t){ WATCH_UPSTREAM, upstream };
		}
		for (client = event->clients; client && count < DNS_EVENT_POLL_MAX; client = client->next) {
			short events = client->state == CLIENT_WRITE ? POLLOUT : (client->state == CLIENT_WAIT ? 0 : POLLIN);
			fds[count] = (struct pollfd){ client->fd, events, 0 }; watch[count++] = (dns_watch_t){ WATCH_CLIENT, client };
		}
		rc = poll(fds, count, loop_timeout(event, now));
		if (rc < 0) { if (errno == EINTR) continue; log_error("dns event poll failed: %s", strerror(errno)); break; }
		for (i = 0; i < count; i++) {
			if (!fds[i].revents) continue;
			switch (watch[i].kind) {
			case WATCH_UDP: pull_udp(event); break;
			case WATCH_TCP_LISTEN: accept_clients(event); break;
			case WATCH_WAKE: drain_wake(event); event->stop = 1; break;
			case WATCH_RESOLVER: resolver_drain(event); break;
			case WATCH_UPSTREAM: upstream_pump(event, watch[i].ptr, fds[i].revents); break;
			case WATCH_CLIENT: client_pump(event, watch[i].ptr, fds[i].revents); break;
			default: break;
			}
		}
		sweep(event, mono_now());
	}
	return NULL;
}

static void event_destroy(dns_event_t *event)
{
	unsigned i;
	if (!event) return;
	while (event->pending_head) { dns_request_t *request = pending_pop(event); request_fail(event, request); }
	for (i = 0; i < DNS_EVENT_UPSTREAMS; i++) {
		if (event->upstreams[i].request) { dns_request_t *request = event->upstreams[i].request; event->upstreams[i].request = NULL; request_fail(event, request); }
		upstream_close(event, &event->upstreams[i]);
	}
	while (event->clients) client_close(event, event->clients);
	if (event->upstream_req) sni_resolver_cancel(event->upstream_slot, event->upstream_req);
	if (event->socks_req) sni_resolver_cancel(event->socks_slot, event->socks_req);
	if (event->resolver) { sni_resolver_sink_mark_closed(event->resolver); sni_resolver_sink_release(event->resolver); }
	free(event);
}

bool dns_event_loop_start(dnsserver_t *dns)
{
	dns_event_t *event;
	unsigned i;
	if (!dns || dns->event_loop) return false;
	event = calloc(1, sizeof(*event));
	if (!event) return false;
	if (dns->upstream_connections == 0 || dns->upstream_connections > DNS_EVENT_UPSTREAMS)
		dns->upstream_connections = DNS_EVENT_UPSTREAMS;
	event->dns = dns; event->generation = 1; event->upstream_slot = event->socks_slot = -1;
	for (i = 0; i < DNS_EVENT_UPSTREAMS; i++) { event->upstreams[i].event = event; event->upstreams[i].fd = -1; event->upstreams[i].state = UP_CLOSED; }
	if (pipe(dns->wake) != 0 || !net_set_nonblock_cloexec(dns->wake[0]) || !net_set_nonblock_cloexec(dns->wake[1]) ||
		!net_set_nonblock_cloexec(dns->local_sock) || (dns->tcp_sock >= 0 && !net_set_nonblock_cloexec(dns->tcp_sock)) ||
		!sni_resolver_sink_open(SNI_SINK_DIRECT, &event->resolver)) {
		event_destroy(event); return false;
	}
	event->upstream_resolve_at_ms = mono_now();
	event->socks_resolve_at_ms = event->upstream_resolve_at_ms;
	(void)resolution_submit(event, 1);
	if (dns->socks)
		(void)resolution_submit(event, 2);
	dns->event_loop = event;
	if (pthread_create(&event->thread, NULL, event_main, event) != 0) {
		dns->event_loop = NULL; event_destroy(event); return false;
	}
	event->started = 1; dns->rx_started = true;
	return true;
}

void dns_event_loop_stop(dnsserver_t *dns)
{
	dns_event_t *event;
	char byte = 1;
	if (!dns || !(event = dns->event_loop)) return;
	(void)write(dns->wake[1], &byte, 1);
	if (event->started) pthread_join(event->thread, NULL);
	dns->rx_started = false; dns->event_loop = NULL;
	event_destroy(event);
}
