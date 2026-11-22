#define _GNU_SOURCE

#include "dns_event_loop.h"
#include "dns_event_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include <zroxy/socks5_codec.h>

static void request_complete(dns_event_t *event, dns_request_t *request,
		const uint8_t *response, size_t len);


void dnsev_close_fd(int *fd)
{
	if (fd && *fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

int64_t dnsev_mono_now(void)
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

void dnsev_pending_push_front(dns_event_t *event, dns_request_t *request)
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
		dnscache_finish(event->dns->cache, request->flight, NULL, 0, 0, dnsev_mono_now());
	if (request->response) {
		if (event->response_bytes >= request->response_cap)
			event->response_bytes -= request->response_cap;
		else
			event->response_bytes = 0;
		free(request->response);
	}
	if (request->stats_open)
		stats_close_connection(event->dns->Stat, 0, (uint32_t)request->query_len + 2u);
	if (event->request_count > 0)
		event->request_count--;
	free(request);
}

static void request_close_stats(dns_event_t *event, dns_request_t *request, size_t response_len)
{
	(void)response_len;
	if (request->stats_open)
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
				dnsev_request_fail(event, follower);
			}
		} else {
			dnsev_request_fail(event, follower);
		}
		follower = next;
	}
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
			dnsev_send_udp(event, &request->peer, out, out_len);
	} else if (request->client) {
		dns_client_t *client = request->client;
		if (dnsev_client_queue_reply(client, response, len)) {
			client->request = NULL;
		} else {
			client->request = NULL;
			request->client = NULL;
			dnsev_client_close(event, client);
			out_len = 0;
		}
	} else {
		out_len = 0;
	}
	request_close_stats(event, request, out_len);
	request_free(event, request);
}

void dnsev_request_finish_upstream(dns_event_t *event, dns_request_t *request)
{
	if (!request || !request->response || request->response_len == 0 ||
		!dns_reply_matches(request->query, request->query_len,
				request->response, request->response_len)) {
		if (request && request->flight) {
			dnscache_finish(event->dns->cache, request->flight, NULL, 0, 0, dnsev_mono_now());
			request->flight = NULL;
		}
		request_send_error(event, request, ServerFailure_ResponseType);
		return;
	}
	if (request->flight) {
		dnscache_finish(event->dns->cache, request->flight, request->response,
				request->response_len, request->response_len, dnsev_mono_now());
		request->flight = NULL;
	}
	request_complete_followers(event, request, request->response, request->response_len);
	request->stats_rx = (uint32_t)request->response_len + 2u;
	request_complete(event, request, request->response, request->response_len);
}

void dnsev_request_fail(dns_event_t *event, dns_request_t *request)
{
	dns_request_t *follower;
	if (!request)
		return;
	if (request->flight) {
		dnscache_finish(event->dns->cache, request->flight, NULL, 0, 0, dnsev_mono_now());
		request->flight = NULL;
	}
	follower = request->followers;
	request->followers = NULL;
	while (follower) {
		dns_request_t *next = follower->follow_next;
		follower->follow_next = NULL;
		dnsev_request_fail(event, follower);
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

bool dnsev_request_ensure_response(dns_event_t *event, dns_request_t *request, size_t cap)
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

void dnsev_request_start(dns_event_t *event, dns_request_t *request)
{
	dnscache_flight *flight = NULL;
	dnscache_result cached;
	size_t full = 0;
	int64_t now = dnsev_mono_now();

	if (handle_local(event, request))
		return;
	if (!dnsev_request_ensure_response(event, request, DNS_UDP_MAX_PAYLOAD)) {
		dnsev_request_fail(event, request);
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

dns_request_t *dnsev_request_new(dns_event_t *event, int kind,
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
	now = dnsev_mono_now();
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
	stats_open_connection(event->dns->Stat);
	return request;
}

void dnsev_schedule(dns_event_t *event)
{
	unsigned i;
	for (i = 0; i < event->dns->upstream_connections; i++) {
		dns_upstream_t *upstream = &event->upstreams[i];
		if (upstream->state == UP_IDLE &&
				(upstream->route != event->active ||
				upstream->address_generation != event->routes[upstream->route].address_generation))
			dnsev_upstream_close(event, upstream);
	}
	while (event->pending_head) {
		dns_upstream_t *upstream = NULL;
		dns_request_t *request = event->pending_head;
		int route;
		if (dnsev_mono_now() >= request->deadline_ms) {
			(void)pending_pop(event);
			(void)__atomic_fetch_add(&event->dns->upstream_timeouts, 1u, __ATOMIC_RELAXED);
			dnsev_request_fail(event, request);
			continue;
		}
		route = dnsev_request_pick_route(event, request);
		if (route < 0)
			return;
		for (i = 0; i < event->dns->upstream_connections; i++) {
			if (event->upstreams[i].state == UP_IDLE && !event->upstreams[i].request &&
					event->upstreams[i].route == (unsigned)route) {
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
		if (!upstream) {
			/* every slot is idle on another route: give one up */
			for (i = 0; i < event->dns->upstream_connections; i++) {
				if (event->upstreams[i].state == UP_IDLE && !event->upstreams[i].request) {
					upstream = &event->upstreams[i];
					dnsev_upstream_close(event, upstream);
					break;
				}
			}
		}
		if (!upstream)
			return;
		(void)pending_pop(event);
		request->route = (unsigned)route;
		request->attempt_deadline_ms = request->deadline_ms;
		if (event->dns->route_count > 1) {
			int64_t limit = dnsev_mono_now() + net_timeout_ms((int)event->dns->timeout);
			if (limit < request->attempt_deadline_ms)
				request->attempt_deadline_ms = limit;
		}
		if (upstream->state == UP_IDLE) {
			upstream->request = request;
			upstream->reused = 1;
			if (!dnsev_upstream_queue_query(upstream))
				dnsev_upstream_fail(event, upstream);
		} else {
			int rc = dnsev_upstream_open(event, upstream, request, (unsigned)route);
			if (rc == OPEN_WAIT) {
				dnsev_pending_push_front(event, request);
				return;
			}
			if (rc == OPEN_FAILED)
				dnsev_request_attempt_failed(event, request, ATTEMPT_ERROR, false);
		}
	}
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
		if (event->upstreams[i].request && event->upstreams[i].request->attempt_deadline_ms < best)
			best = event->upstreams[i].request->attempt_deadline_ms;
	return timeout_ms(best, now);
}

static void sweep(dns_event_t *event, int64_t now)
{
	dns_request_t *request = event->pending_head;
	dns_client_t *client = event->clients;
	unsigned i;
	dnsev_resolution_tick(event, now);
	while (request) {
		dns_request_t *next = request->next;
		if (now >= request->deadline_ms) {
			request_unlink_pending(event, request);
			__atomic_fetch_add(&event->dns->upstream_timeouts, 1u, __ATOMIC_RELAXED);
			dnsev_request_fail(event, request);
		}
		request = next;
	}
	for (i = 0; i < event->dns->upstream_connections; i++) {
		dns_upstream_t *upstream = &event->upstreams[i];
		if (upstream->request && now >= upstream->request->attempt_deadline_ms) {
			__atomic_fetch_add(&event->dns->upstream_timeouts, 1u, __ATOMIC_RELAXED);
			dnsev_upstream_fail_mode(event, upstream, ATTEMPT_TIMEOUT);
		} else if (upstream->state == UP_IDLE && now - upstream->idle_since_ms >= DNS_EVENT_IDLE_MS) {
			dnsev_upstream_close(event, upstream);
		}
	}
	while (client) {
		dns_client_t *next = client->next;
		if (now >= client->deadline_ms && client->state != CLIENT_WAIT)
			dnsev_client_close(event, client);
		client = next;
	}
	dnsev_schedule(event);
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


/*
 * Bring the reactor in line with the state transitions of the last batch.
 * Only fds whose interest changed (or that were just opened) cost a syscall.
 * An fd the reactor refuses is dropped like any other failed connection;
 * that can dnsev_schedule more work, so go again until nothing was dropped.
 */
static void sync_interest(dns_event_t *event)
{
	bool again;
	do {
		dns_client_t *client;
		unsigned i;
		again = false;
		for (i = 0; i < event->dns->upstream_connections; i++) {
			dns_upstream_t *upstream = &event->upstreams[i];
			uint32_t want;
			bool ok = true;
			if (upstream->fd < 0)
				continue;
			want = dnsev_upstream_interest(upstream);
			if (!upstream->registered)
				ok = reactor_add(&event->re, upstream->fd, want, &upstream->watch);
			else if (upstream->interest != want)
				ok = reactor_mod(&event->re, upstream->fd, want, &upstream->watch);
			if (!ok) {
				dnsev_upstream_fail(event, upstream);
				again = true;
				continue;
			}
			upstream->registered = 1;
			upstream->interest = want;
		}
		for (client = event->clients; client; ) {
			dns_client_t *next = client->next;
			uint32_t want = dnsev_client_interest(client);
			if (client->interest != want) {
				if (!reactor_mod(&event->re, client->fd, want, &client->watch)) {
					dnsev_client_close(event, client);
					again = true;
				} else {
					client->interest = want;
				}
			}
			client = next;
		}
		dnsev_client_reap(event);
	} while (again);
}


static void *event_main(void *arg)
{
	dns_event_t *event = arg;
	while (!event->stop) {
		reactor_event ready[DNS_EVENT_BATCH];
		int n;
		int i;
		n = reactor_wait(&event->re, ready, DNS_EVENT_BATCH, loop_timeout(event, dnsev_mono_now()));
		if (n < 0) { if (errno == EINTR) continue; log_error("dns event wait failed: %s", strerror(errno)); break; }
		event->batch++;
		for (i = 0; i < n; i++) {
			dns_watch_t *watch = ready[i].tag;
			if (!watch) continue;
			switch (watch->kind) {
			case WATCH_UDP: dnsev_pull_udp(event); break;
			case WATCH_TCP_LISTEN: dnsev_accept_clients(event); break;
			case WATCH_WAKE: drain_wake(event); event->stop = 1; break;
			case WATCH_RESOLVER: dnsev_dns_drain_resolver(event); break;
			case WATCH_UPSTREAM: dnsev_upstream_dispatch(event, watch->ptr, ready[i].ev); break;
			case WATCH_CLIENT:
				/* Closed by an earlier event of this batch; freed after it. */
				if (!((dns_client_t *)watch->ptr)->dead)
					dnsev_client_pump(event, watch->ptr, ready[i].ev);
				break;
			default: break;
			}
		}
		dnsev_client_reap(event);
		sweep(event, dnsev_mono_now());
		sync_interest(event);
	}
	return NULL;
}

static void event_destroy(dns_event_t *event)
{
	unsigned i;
	if (!event) return;
	while (event->pending_head) { dns_request_t *request = pending_pop(event); dnsev_request_fail(event, request); }
	for (i = 0; i < DNS_EVENT_UPSTREAMS; i++) {
		if (event->upstreams[i].request) { dns_request_t *request = event->upstreams[i].request; event->upstreams[i].request = NULL; dnsev_request_fail(event, request); }
		dnsev_upstream_close(event, &event->upstreams[i]);
	}
	while (event->clients) dnsev_client_close(event, event->clients);
	dnsev_client_reap(event);
	reactor_close(&event->re);
	for (i = 0; i < DNS_ROUTES_MAX; i++) {
		if (event->routes[i].upstream.req)
			resolver_cancel(event->routes[i].upstream.slot, event->routes[i].upstream.req);
		if (event->routes[i].socks.req)
			resolver_cancel(event->routes[i].socks.slot, event->routes[i].socks.req);
	}
	if (event->resolver) { resolver_sink_mark_closed(event->resolver); resolver_sink_release(event->resolver); }
	free(event);
}

static bool register_fixed(dns_event_t *event)
{
	event->fixed[0] = (dns_watch_t){ WATCH_UDP, NULL };
	event->fixed[1] = (dns_watch_t){ WATCH_TCP_LISTEN, NULL };
	event->fixed[2] = (dns_watch_t){ WATCH_WAKE, NULL };
	event->fixed[3] = (dns_watch_t){ WATCH_RESOLVER, NULL };
	return reactor_add(&event->re, event->dns->local_sock, RE_IN, &event->fixed[0]) &&
		(event->dns->tcp_sock < 0 ||
			reactor_add(&event->re, event->dns->tcp_sock, RE_IN, &event->fixed[1])) &&
		reactor_add(&event->re, event->dns->wake[0], RE_IN, &event->fixed[2]) &&
		reactor_add(&event->re, event->resolver->pipe_read, RE_IN, &event->fixed[3]);
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
	event->dns = dns; event->generation = 1; event->re.epfd = -1;
	for (i = 0; i < DNS_ROUTES_MAX; i++) event->routes[i].upstream.slot = event->routes[i].socks.slot = -1;
	for (i = 0; i < DNS_EVENT_UPSTREAMS; i++) { event->upstreams[i].event = event; event->upstreams[i].fd = -1; event->upstreams[i].watch = (dns_watch_t){ WATCH_UPSTREAM, &event->upstreams[i] }; event->upstreams[i].state = UP_CLOSED; }
	if (pipe(dns->wake) != 0 || !net_set_nonblock_cloexec(dns->wake[0]) || !net_set_nonblock_cloexec(dns->wake[1]) ||
		!net_set_nonblock_cloexec(dns->local_sock) || (dns->tcp_sock >= 0 && !net_set_nonblock_cloexec(dns->tcp_sock)) ||
		!resolver_sink_open(RESOLVER_SINK_DIRECT, &event->resolver) ||
		!reactor_open(&event->re, DNS_REACTOR_CAP, false) || !register_fixed(event)) {
		event_destroy(event); return false;
	}
	for (i = 0; i < dns->route_count; i++) {
		event->routes[i].upstream.resolve_at_ms = event->routes[i].socks.resolve_at_ms = dnsev_mono_now();
		(void)dnsev_resolution_submit(event, 1u + 2u * i);
		if (dns->routes[i].socks)
			(void)dnsev_resolution_submit(event, 2u + 2u * i);
	}
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
	ssize_t n;
	if (!dns || !(event = dns->event_loop)) return;
	do {
		n = write(dns->wake[1], &byte, 1);
	} while (n < 0 && errno == EINTR);
	if (event->started) pthread_join(event->thread, NULL);
	dns->rx_started = false; dns->event_loop = NULL;
	event_destroy(event);
}
