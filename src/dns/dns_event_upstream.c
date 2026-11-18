/* Owns DNS upstream TCP and SOCKS5 connection handling. */
#include "dns_event_internal.h"

#include <errno.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zroxy/log.h>
#include <zroxy/dns.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>
#include <zroxy/socks5_codec.h>

void dnsev_upstream_close(dns_event_t *event, dns_upstream_t *upstream)
{
	if (upstream->fd >= 0 && event->dns->active_upstreams > 0)
		__atomic_sub_fetch(&event->dns->active_upstreams, 1u, __ATOMIC_RELAXED);
	if (upstream->registered)
		reactor_del(&event->re, upstream->fd);
	upstream->registered = 0;
	/*
	 * The slot may be reopened in this same batch while a ready event for
	 * the old connection is still queued: dnsev_upstream_dispatch drops it.
	 */
	upstream->closed_batch = event->batch;
	dnsev_close_fd(&upstream->fd);
	upstream->state = UP_CLOSED;
	upstream->out_len = upstream->out_off = 0;
	upstream->in_len = upstream->in_need = 0;
}

static bool route_ready(dns_event_t *event, unsigned route)
{
	return event->routes[route].upstream.ready &&
		(!event->dns->routes[route].socks || event->routes[route].socks.ready);
}

/* Route for the next attempt: the first ready one from active that is not yet tried. */
int dnsev_request_pick_route(dns_event_t *event, const dns_request_t *request)
{
	unsigned count = event->dns->route_count;
	unsigned k;
	for (k = 0; k < count; k++) {
		unsigned route = (event->active + k) % count;
		if (count > 1 && (request->tried & (1u << route)))
			continue;
		if (route_ready(event, route))
			return (int)route;
	}
	return -1;
}

/* Only the route that is still active moves it, so a burst of failures does not skip a route. */
static void route_failed(dns_event_t *event, unsigned route)
{
	unsigned count = event->dns->route_count;
	if (count > 1 && route == event->active) {
		event->active = (route + 1) % count;
		__atomic_store_n(&event->dns->active_route, event->active, __ATOMIC_RELAXED);
		(void)__atomic_fetch_add(&event->dns->route_switches, 1u, __ATOMIC_RELAXED);
		log_debug("dns route %u failed; using route %u", route, event->active);
	}
}

/*
 * An attempt on request->route failed. With several routes the request moves
 * to one it has not tried while time is left; with one route a fast error is
 * retried once and a timeout is not.
 */
void dnsev_request_attempt_failed(dns_event_t *event, dns_request_t *request,
		int mode, bool reused)
{
	unsigned count = event->dns->route_count;
	int64_t now = dnsev_mono_now();

	if (mode != ATTEMPT_TIMEOUT && now < request->deadline_ms)
		(void)__atomic_fetch_add(&event->dns->upstream_errors, 1u, __ATOMIC_RELAXED);
	if (mode == ATTEMPT_LOCAL) {
		dnsev_request_fail(event, request);
		return;
	}
	if (reused && mode == ATTEMPT_ERROR && request->attempts == 0 && now < request->deadline_ms) {
		/* a pooled connection the server had already closed says nothing about the route */
		request->attempts = 1;
		dnsev_pending_push_front(event, request);
		return;
	}
	if (count > 1) {
		request->tried |= 1u << request->route;
		route_failed(event, request->route);
		if (now < request->deadline_ms && request->tried != (1u << count) - 1u) {
			dnsev_pending_push_front(event, request);
			return;
		}
	} else if (mode == ATTEMPT_ERROR && now < request->deadline_ms &&
			request->attempts++ == 0) {
		dnsev_pending_push_front(event, request);
		return;
	}
	dnsev_request_fail(event, request);
}

void dnsev_upstream_fail_mode(dns_event_t *event, dns_upstream_t *upstream, int mode)
{
	dns_request_t *request = upstream->request;
	bool reused = upstream->reused != 0;
	upstream->request = NULL;
	dnsev_upstream_close(event, upstream);
	if (request)
		dnsev_request_attempt_failed(event, request, mode, reused);
}

void dnsev_upstream_fail(dns_event_t *event, dns_upstream_t *upstream)
{
	dnsev_upstream_fail_mode(event, upstream, ATTEMPT_ERROR);
}

bool dnsev_upstream_queue_query(dns_upstream_t *upstream)
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

static bool upstream_socks_apply(dns_event_t *event, dns_upstream_t *upstream, s5_step step)
{
	sockshost_t *socks = event->dns->routes[upstream->route].socks;
	if (step == S5_SEND) {
		memcpy(upstream->out, upstream->socks.out, upstream->socks.out_len);
		upstream->out_len = upstream->socks.out_len;
		upstream->out_off = 0;
		upstream->state = UP_SOCKS_WRITE;
		return true;
	}
	if (step == S5_READ) {
		upstream->in_len = 0;
		upstream->in_need = upstream->socks.need;
		upstream->state = UP_SOCKS_READ;
		return true;
	}
	if (step == S5_DONE) {
		upstream->state = UP_IDLE;
		upstream->idle_since_ms = dnsev_mono_now();
		return dnsev_upstream_queue_query(upstream);
	}
	log_error("[!] SOCKS server %s:%u: %s", socks && socks->host ? socks->host : "?",
			socks ? (unsigned)socks->port : 0u, socks5_client_strerror(&upstream->socks));
	return false;
}

static void upstream_connected(dns_event_t *event, dns_upstream_t *upstream)
{
	if (event->dns->routes[upstream->route].socks) {
		sockshost_t *socks = event->dns->routes[upstream->route].socks;
		/* The codec offers user/pass only when both are configured. */
		if (!socks5_client_init(&upstream->socks, socks->user, socks->pass,
				event->dns->routes[upstream->route].upstream.ip,
				(uint16_t)event->dns->routes[upstream->route].upstream.port) ||
			!upstream_socks_apply(event, upstream, socks5_client_start(&upstream->socks)))
			dnsev_upstream_fail(event, upstream);
	} else if (!dnsev_upstream_queue_query(upstream)) {
		dnsev_upstream_fail(event, upstream);
	}
}

int dnsev_upstream_open(dns_event_t *event, dns_upstream_t *upstream, dns_request_t *request,
		unsigned route)
{
	const struct sockaddr *addr;
	socklen_t len;
	int fd;
	int rc;
	int one = 1;
	dns_route_state_t *state = &event->routes[route];
	if (!route_ready(event, route))
		return OPEN_WAIT;
	if (event->dns->routes[route].socks) {
		addr = (const struct sockaddr *)&state->socks.addr;
		len = state->socks.len;
	} else {
		addr = (const struct sockaddr *)&state->upstream.addr;
		len = state->upstream.len;
	}
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (fd < 0 || !net_set_nonblock_cloexec(fd)) {
		if (fd >= 0)
			close(fd);
		return OPEN_WAIT;
	}
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	upstream->request = request;
	upstream->route = route;
	upstream->reused = 0;
	upstream->address_generation = state->address_generation;
	upstream->fd = fd;
	rc = connect(fd, addr, len);
	if (rc == 0) {
		(void)__atomic_fetch_add(&event->dns->active_upstreams, 1u, __ATOMIC_RELAXED);
		upstream_connected(event, upstream);
		return OPEN_OK;
	}
	if (errno != EINPROGRESS && errno != EALREADY) {
		upstream->request = NULL;
		dnsev_close_fd(&upstream->fd);
		return OPEN_FAILED;
	}
	upstream->state = UP_CONNECT;
	(void)__atomic_fetch_add(&event->dns->active_upstreams, 1u, __ATOMIC_RELAXED);
	return OPEN_OK;
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
		dnsev_upstream_fail(event, upstream);
		return;
	}
	if (upstream->state == UP_QUERY_WRITE) {
		upstream->in_len = 0;
		upstream->in_need = 2;
		upstream->state = UP_REPLY_LEN;
		return;
	}
	if (!upstream_socks_apply(event, upstream, socks5_client_sent(&upstream->socks)))
		dnsev_upstream_fail(event, upstream);
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
			dnsev_upstream_fail(event, upstream);
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
				if (!upstream_socks_apply(event, upstream,
						socks5_client_feed(&upstream->socks, upstream->in, upstream->in_len))) {
					dnsev_upstream_fail(event, upstream);
					return;
				}
				if (upstream->state == UP_SOCKS_READ)
					continue;
				return;
			}
			if (upstream->state == UP_REPLY_LEN) {
				size_t length = ((size_t)upstream->in[0] << 8) | upstream->in[1];
				if (length < DNS_HEADER_SIZE) {
					dnsev_upstream_fail_mode(event, upstream, ATTEMPT_BAD);
					return;
				}
				if (!dnsev_request_ensure_response(event, request, length)) {
					dnsev_upstream_fail_mode(event, upstream, ATTEMPT_LOCAL);
					return;
				}
				request->response_len = length;
				request->response_off = 0;
				upstream->state = UP_REPLY_BODY;
				continue;
			}
			upstream->request = NULL;
			upstream->state = UP_IDLE;
			upstream->idle_since_ms = dnsev_mono_now();
			dnsev_request_finish_upstream(event, request);
			dnsev_schedule(event);
			return;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		dnsev_upstream_fail(event, upstream);
		return;
	}
}

static void upstream_pump(dns_event_t *event, dns_upstream_t *upstream, uint32_t revents)
{
	if (!upstream || upstream->fd < 0)
		return;
	if (upstream->state == UP_CONNECT && (revents & (RE_OUT | RE_ERR | RE_HUP))) {
		int error = 0;
		socklen_t len = sizeof(error);
		if (getsockopt(upstream->fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
			dnsev_upstream_fail(event, upstream);
			return;
		}
		upstream_connected(event, upstream);
	}
	if (upstream->state == UP_QUERY_WRITE || upstream->state == UP_SOCKS_WRITE) {
		if (revents & RE_OUT)
			upstream_write(event, upstream);
		else if (revents & (RE_ERR | RE_HUP))
			dnsev_upstream_fail(event, upstream);
		return;
	}
	if (upstream->state == UP_REPLY_LEN || upstream->state == UP_REPLY_BODY ||
		upstream->state == UP_SOCKS_READ) {
		if (revents & RE_IN)
			upstream_read(event, upstream);
		else if (revents & (RE_ERR | RE_HUP))
			dnsev_upstream_fail(event, upstream);
		return;
	}
	if (upstream->state == UP_IDLE && revents & (RE_IN | RE_ERR | RE_HUP))
		dnsev_upstream_close(event, upstream);
}

uint32_t dnsev_upstream_interest(const dns_upstream_t *upstream)
{
	switch (upstream->state) {
	case UP_CONNECT: case UP_QUERY_WRITE: case UP_SOCKS_WRITE:
		return RE_OUT;
	case UP_IDLE: case UP_REPLY_LEN: case UP_REPLY_BODY: case UP_SOCKS_READ:
		return RE_IN;
	default:
		return 0;
	}
}

void dnsev_upstream_dispatch(dns_event_t *event, dns_upstream_t *upstream, uint32_t revents)
{
	/* Closed earlier in this batch (maybe reopened): the event is stale. */
	if (upstream->closed_batch == event->batch)
		return;
	upstream_pump(event, upstream, revents);
}
