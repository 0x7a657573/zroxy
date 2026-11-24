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
#define _GNU_SOURCE

#include "sni_event_loop.h"
#include "sni_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <zroxy/log.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>
#include <zroxy/socks5_codec.h>
#include "resolver.h"
#include "reactor.h"

/*
 * Plan:
 * - sni_listener_open listens, then one joinable thread runs sni_engine_run
 *   until sni_listener_close wakes it.
 * - accept() running out of descriptors (EMFILE/ENFILE) takes the listen fd out
 *   of the reactor for SNI_ACCEPT_PAUSE_MS; the loop keeps serving its
 *   connections and re-arms the listener from its timeout handling.
 * - A full connection cap evicts the loop's own oldest connection that is still
 *   in HELLO (an intrusive FIFO list, O(1)), or refuses when it has none. A
 *   connection past HELLO is never evicted.
 * - accept() only allocates a connection and arms it. The 1024 slot cap stays
 *   a connection limit (sni_conn_acquire), not a thread count.
 * - Mutable connection fields are touched only on that event-loop thread.
 * - HELLO reads until net_get_host, overflow, EOF, or the old hello deadline
 *   (absolute net_timeout_ms plus a 5s gap with no bytes).
 * - A non-numeric upstream name is submitted to the process-wide resolver.
 *   The loop never calls getaddrinfo(). RESOLVE and CONNECT do not arm
 *   client EPOLLIN, so a buffered client byte cannot spin the loop.
 * - CONNECT is non-blocking, with the same address order as net_connect.
 * - SOCKS5 is an explicit send/recv sequence with partial I/O.
 * - RELAY copies through two fixed buffers, stops reading a direction while
 *   its buffer is full, and shutdown(SHUT_WR) after a peer EOF is flushed.
 *   One pump moves at most SNI_RELAY_BUDGET bytes, then level-triggered
 *   readiness brings the connection back on a later wait.
 * - stats_close_connection and sni_conn_release run once, from conn_kill.
 */

/*
 * Counters for every listener, reported through the SNI_Server monitor
 * object. Word-sized and updated with relaxed atomics: 64-bit atomics are not
 * lock-free on every target.
 */
static uint32_t g_sni_close[SNI_CLOSE_COUNT];
static uint32_t g_sni_relayed;

static const char *const g_sni_close_keys[SNI_CLOSE_COUNT] = {
        [SNI_CLOSE_REFUSED] = "Refused",
        [SNI_CLOSE_NO_HOSTNAME] = "NoHostname",
        [SNI_CLOSE_BLOCKED] = "Blocked",
        [SNI_CLOSE_UNSAFE] = "UnsafeDestination",
        [SNI_CLOSE_RESOLVE] = "ResolveFailures",
        [SNI_CLOSE_SOCKS] = "SocksFailures",
        [SNI_CLOSE_CONNECT] = "ConnectFailures",
        [SNI_CLOSE_HANDSHAKE_TIMEOUT] = "HandshakeTimeouts",
        [SNI_CLOSE_IDLE_TIMEOUT] = "IdleTimeouts",
        [SNI_CLOSE_STALL_TIMEOUT] = "StallTimeouts",
        [SNI_CLOSE_EVICTED] = "Evicted",
        [SNI_CLOSE_ACL_DENIED] = "AclDenied"};

void sni_count_relayed(void)
{
	(void)__atomic_fetch_add(&g_sni_relayed, 1u, __ATOMIC_RELAXED);
}

static void count_close(int reason)
{
	if (reason <= SNI_CLOSE_NONE || reason >= SNI_CLOSE_COUNT)
		return;
	(void)__atomic_fetch_add(&g_sni_close[reason], 1u, __ATOMIC_RELAXED);
}

bool sni_stats_json(void *ctx, char **ptr, char *end)
{
	int n;
	int reason;
	size_t left;

	(void)ctx;
	if (!ptr || !*ptr || *ptr >= end)
		return false;
	left = (size_t)(end - *ptr);
	n = snprintf(*ptr, left, ",\n\"ConnectionLimit\" : %d,\n"
	                         "\"Relayed\" : %" PRIu32,
	        sni_conn_limit(), __atomic_load_n(&g_sni_relayed, __ATOMIC_RELAXED));
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
	for (reason = SNI_CLOSE_REFUSED; reason < SNI_CLOSE_COUNT; reason++)
	{
		left = (size_t)(end - *ptr);
		n = snprintf(*ptr, left, ",\n\"%s\" : %" PRIu32,
		        g_sni_close_keys[reason],
		        __atomic_load_n(&g_sni_close[reason], __ATOMIC_RELAXED));
		if (n < 0 || (size_t)n >= left)
			return false;
		*ptr += n;
	}
	return true;
}

static void hello_link(sni_engine *e, sni_conn *c)
{
	if (c->in_hello_list)
		return;
	c->hello_prev = e->hello_tail;
	c->hello_next = NULL;
	if (e->hello_tail)
		e->hello_tail->hello_next = c;
	else
		e->hello_head = c;
	e->hello_tail = c;
	c->in_hello_list = 1;
}

static void hello_unlink(sni_engine *e, sni_conn *c)
{
	if (!c->in_hello_list)
		return;
	if (c->hello_prev)
		c->hello_prev->hello_next = c->hello_next;
	else
		e->hello_head = c->hello_next;
	if (c->hello_next)
		c->hello_next->hello_prev = c->hello_prev;
	else
		e->hello_tail = c->hello_prev;
	c->hello_prev = NULL;
	c->hello_next = NULL;
	c->in_hello_list = 0;
}

/* Every move out of HELLO goes through here, so the list holds HELLO only. */
void sni_conn_set_state(sni_engine *e, sni_conn *c, int state)
{
	if (state != SNI_ST_HELLO)
		hello_unlink(e, c);
	c->state = state;
}

void sni_conn_kill(sni_engine *e, sni_conn *c, int reason)
{
	if (!c || c->dead)
		return;
	c->dead = 1;
	hello_unlink(e, c);
	if (c->pending_req_id != 0)
	{
		resolver_cancel(c->resolve_slot, c->pending_req_id);
		c->pending_req_id = 0;
	}
	sni_drop_watched(e, &c->client_fd, &c->client_interest, &c->client_tag);
	sni_drop_watched(e, &c->up_fd, &c->up_interest, &c->up_tag);
	if (c->settled)
		return;
	c->settled = 1;
	count_close(reason);
	if (c->close_stats)
		stats_close_connection(c->cfg.stats, c->rx, c->tx);
	if (c->slot_held)
	{
		sni_conn_release();
		c->slot_held = 0;
	}
}

static void conn_timeout(sni_engine *e, sni_conn *c, int reason)
{
	if (c->host[0] != '\0')
		log_trace("SNI timeout Host { %s }", c->host);
	else
		log_trace("TimeOut tid:%i", c->client_fd);
	sni_conn_kill(e, c, reason);
}

bool sni_conn_arm(sni_engine *e, sni_conn *c)
{
	uint32_t cin = 0;
	uint32_t uin = 0;
	if (c->dead)
		return true;
	if (c->state == SNI_ST_HELLO)
	{
		if (!c->client_eof && c->hello_len < SNI_HELLO_CAP)
			cin |= SNI_EV_IN;
	}
	else if (c->state == SNI_ST_RESOLVE)
	{
		cin |= SNI_EV_ARMED;
	}
	else if (c->state == SNI_ST_CONNECT)
	{
		cin |= SNI_EV_ARMED;
		uin |= SNI_EV_OUT;
	}
	else if (c->state == SNI_ST_SOCKS)
	{
		if (c->socks_step == S5_SEND)
			uin |= SNI_EV_OUT;
		else if (c->socks_step == S5_READ)
			uin |= SNI_EV_IN;
	}
	else if (c->state == SNI_ST_RELAY)
	{
		if (!c->client_eof && c->c2u_off == c->c2u_len)
			cin |= SNI_EV_IN;
		if (!c->client_shut && c->u2c_off < c->u2c_len)
			cin |= SNI_EV_OUT;
		if (c->up_fd >= 0 && !c->up_eof && c->u2c_off == c->u2c_len)
			uin |= SNI_EV_IN;
		if (c->up_fd >= 0 && !c->up_shut && c->c2u_off < c->c2u_len)
			uin |= SNI_EV_OUT;
	}
	if (!sni_watch(e, c->client_fd, cin, &c->client_interest, &c->client_tag))
		return false;
	if (!sni_watch(e, c->up_fd, uin, &c->up_interest, &c->up_tag))
		return false;
	return true;
}

static void reap(sni_engine *e)
{
	sni_conn **pp = &e->head;
	while (*pp)
	{
		sni_conn *c = *pp;
		if (!c->dead)
		{
			pp = &c->next;
			continue;
		}
		*pp = c->next;
		free(c);
	}
}

static sni_conn *conn_new(sni_engine *e, int client_fd)
{
	sni_conn *c;
	int64_t now;
#ifdef SNI_TEST_HOOKS
	if (sni_take_fault(SNI_FAULT_FAIL_ALLOCS))
		return NULL;
#endif
	now = net_mono_ms();
	if (now < 0)
		return NULL;
	c = (sni_conn *)calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	c->eng = e;
	c->cfg = e->cfg;
	c->client_fd = client_fd;
	c->up_fd = -1;
	c->client_tag.kind = SNI_TAG_CONN;
	c->client_tag.fd = client_fd;
	c->client_tag.eng = e;
	c->client_tag.conn = c;
	c->up_tag.kind = SNI_TAG_CONN;
	c->up_tag.fd = -1;
	c->up_tag.eng = e;
	c->up_tag.conn = c;
	c->io_ms = net_timeout_ms(e->cfg.snitimeout);
	c->idle_ms = e->cfg.sniidletimeout > 0 ? net_timeout_ms(e->cfg.sniidletimeout) : c->io_ms;
	c->resolve_slot = -1;
	c->generation = ++e->next_generation;
	c->hello_abs = now + (int64_t)c->io_ms;
	c->last_hello = now;
	c->state = SNI_ST_HELLO;
	return c;
}

static bool copy_host(char *dst, const char *src)
{
	size_t n = strlen(src);
	if (n == 0 || n >= ZROXY_MAX_HOSTNAME)
		return false;
	memcpy(dst, src, n + 1);
	return true;
}

static bool host_ready(sni_engine *e, sni_conn *c)
{
	char raw[ZROXY_MAX_HOSTNAME];
	char norm[RESOLVER_HOST_MAX + 1];
	if (!net_get_host(c->hello, c->hello_len, raw, (uint16_t)ZROXY_MAX_HOSTNAME))
		return false;
	if (!resolver_normalize(raw, norm, sizeof(norm)) || !copy_host(c->host, norm))
	{
		sni_conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
		return true;
	}
	if (c->cfg.whitelist && filter_match(c->cfg.whitelist, c->host) == false)
	{
		log_trace("SNI filter Host { %s }", c->host);
		sni_conn_kill(e, c, SNI_CLOSE_BLOCKED);
		return true;
	}
	if (net_is_ip_literal(c->host))
	{
		log_trace("SNI we can't support IP address");
		sni_conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
		return true;
	}
	log_trace("SNI start Host { %s } ", c->host);
	sni_begin_upstream(e, c);
	return true;
}

static void hello_pump(sni_engine *e, sni_conn *c)
{
	int guard = 0;
	while (!c->dead && guard++ < 100000)
	{
		uint32_t before;
		int rr;
		if (c->hello_len >= SNI_HELLO_CAP)
		{
			log_error("Host Buffer OverFlow");
			sni_conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
			return;
		}
		before = c->hello_len;
		rr = sni_read_some(c->client_fd, c->hello, SNI_HELLO_CAP, &c->hello_len);
		if (rr == 0)
			break;
		if (rr < 0)
		{
			sni_conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
			return;
		}
		sni_note_client_read(c->hello_len - before);
		c->last_hello = net_mono_ms();
		if (host_ready(e, c))
			return;
	}
	if (!c->dead && !sni_conn_arm(e, c))
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
}

static void pump(sni_engine *e, sni_conn *c, int fd, uint32_t ev)
{
	if (c->state == SNI_ST_HELLO)
	{
		if (fd == c->client_fd)
			hello_pump(e, c);
		return;
	}
	if (c->state == SNI_ST_RESOLVE || c->state == SNI_ST_CONNECT)
	{
		if (fd == c->client_fd && (ev & (SNI_EV_ERR | SNI_EV_HUP)) != 0)
		{
			sni_conn_kill(e, c, SNI_CLOSE_NONE);
			return;
		}
		if (c->state == SNI_ST_CONNECT && fd == c->up_fd &&
		        (ev & (SNI_EV_OUT | SNI_EV_ERR | SNI_EV_HUP)) != 0)
			sni_connect_pump(e, c, ev);
		return;
	}
	if (c->state == SNI_ST_SOCKS)
	{
		if (fd == c->up_fd)
			sni_socks_pump(e, c);
		return;
	}
	if (c->state == SNI_ST_RELAY)
		sni_relay_pump(e, c);
}

static bool conn_start(sni_engine *e, sni_conn *c)
{
	c->next = e->head;
	e->head = c;
	hello_link(e, c);
	if (!sni_conn_arm(e, c))
	{
		sni_conn_kill(e, c, SNI_CLOSE_REFUSED);
		return false;
	}
	return true;
}

/*
 * Out of descriptors: a level-triggered listener would fire again at once, so
 * take it out of the reactor and let engine_timeout bring it back.
 */
static void accept_pause(sni_engine *e)
{
	int64_t now = net_mono_ms();

	if (now < 0)
		return;
	if (now >= e->accept_log_at)
	{
		log_error("server accept() out of file descriptors, pausing accept for %d ms",
		        SNI_ACCEPT_PAUSE_MS);
		e->accept_log_at = now + SNI_ACCEPT_LOG_MS;
	}
	(void)sni_watch(e, e->listen_fd, 0, &e->listen_interest, &e->listen_tag);
	e->accept_paused = 1;
	e->accept_resume_at = now + SNI_ACCEPT_PAUSE_MS;
	sni_note_accept_pause();
}

static void accept_resume(sni_engine *e)
{
	int64_t now;

	if (!e->accept_paused)
		return;
	now = net_mono_ms();
	if (now >= 0 && now < e->accept_resume_at)
		return;
	e->accept_paused = 0;
	if (e->listen_fd < 0)
		return;
	if (!sni_watch(e, e->listen_fd, SNI_EV_IN, &e->listen_interest, &e->listen_tag))
	{
		log_error("sni listener re-arm failed: %s", strerror(errno));
		if (now >= 0)
		{
			e->accept_paused = 1;
			e->accept_resume_at = now + SNI_ACCEPT_PAUSE_MS;
		}
	}
}

/*
 * The cap is process-wide but a loop can close only its own connections.
 * Close this loop's oldest connection still in HELLO, which has no hostname,
 * resolver request or upstream, and report whether one was closed. conn_kill
 * releases its slot, so the caller can take it right after.
 */
static bool evict_oldest_hello(sni_engine *e)
{
	sni_conn *victim = e->hello_head;

	if (!victim || victim->dead || victim->state != SNI_ST_HELLO)
		return false;
	sni_conn_kill(e, victim, SNI_CLOSE_EVICTED);
	return true;
}

static bool take_slot(sni_engine *e)
{
	if (sni_conn_acquire())
		return true;
	if (!evict_oldest_hello(e))
		return false;
	return sni_conn_acquire();
}

/* No ACL allows every client. A list matches IPv4 peers only; the listeners are IPv4. */
static bool peer_allowed(const sni_engine *e, const struct sockaddr_storage *peer)
{
	if (e->cfg.acl_count == 0)
		return true;
	if (peer->ss_family != AF_INET)
		return false;
	return acl_allows(e->cfg.acl, e->cfg.acl_count,
	        ntohl(((const struct sockaddr_in *)peer)->sin_addr.s_addr));
}

static void accept_clients(sni_engine *e)
{
	for (;;)
	{
		struct sockaddr_storage peer;
		int fd;
		sni_conn *c;
		memset(&peer, 0, sizeof(peer));
		fd = sni_io_accept(e->listen_fd, &peer);
		if (fd < 0)
		{
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == EMFILE || errno == ENFILE)
			{
				accept_pause(e);
				break;
			}
			log_error("server accept() %i: %s", errno, strerror(errno));
			break;
		}
		if (!peer_allowed(e, &peer))
		{
			count_close(SNI_CLOSE_ACL_DENIED);
			close(fd);
			continue;
		}
		if (!sni_set_nb_cloexec(fd))
		{
			count_close(SNI_CLOSE_REFUSED);
			close(fd);
			continue;
		}
		if (!take_slot(e))
		{
			log_error("refusing SNI connection");
			count_close(SNI_CLOSE_REFUSED);
			close(fd);
			continue;
		}
		(void)net_set_nodelay(fd);
		c = conn_new(e, fd);
		if (!c)
		{
			log_error("malloc failed for sni connection");
			count_close(SNI_CLOSE_REFUSED);
			sni_conn_release();
			close(fd);
			continue;
		}
		c->slot_held = 1;
		if (!conn_start(e, c))
			continue;
		if (e->cfg.stats)
		{
			stats_open_connection(e->cfg.stats);
			c->close_stats = 1;
		}
	}
}

static void drain_wake(sni_engine *e)
{
	char buf[32];
	for (;;)
	{
		ssize_t n = read(e->wake_r, buf, sizeof(buf));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
	}
}

static void dispatch_one(sni_engine *e, const sni_ready *ev)
{
	sni_tag *tag = ev->tag;
	sni_conn *c;
	if (!tag)
		return;
	if (tag->kind == SNI_TAG_WAKE)
	{
		drain_wake(e);
		e->stop = 1;
		return;
	}
	if (tag->kind == SNI_TAG_SINK)
	{
		sni_drain_resolve(e);
		return;
	}
	if (tag->kind == SNI_TAG_LISTEN)
	{
		accept_clients(e);
		return;
	}
	c = tag->conn;
	if (!c || c->dead)
		return;
	if (ev->fd < 0 || (ev->fd != c->client_fd && ev->fd != c->up_fd))
		return;
	pump(e, c, ev->fd, ev->ev);
}

static int hello_idle_ms(void)
{
#ifdef SNI_TEST_HOOKS
	int ms = sni_hello_idle_ms_override();
	if (ms > 0)
		return ms;
#endif
	return SNI_HELLO_IDLE_MS;
}

static void consider(int64_t value, int64_t *best, int *have)
{
	if (!*have || value < *best)
		*best = value;
	*have = 1;
}

static int64_t handshake_due(const sni_conn *c)
{
	if (c->state == SNI_ST_HELLO)
	{
		int64_t idle = c->last_hello + (int64_t)hello_idle_ms();
		return c->hello_abs < idle ? c->hello_abs : idle;
	}
	if (c->state == SNI_ST_RESOLVE)
		return c->resolve_deadline;
	if (c->state == SNI_ST_CONNECT)
		return c->connect_deadline;
	return c->deadline;
}

static int engine_timeout(sni_engine *e)
{
	sni_conn *c;
	int64_t now = net_mono_ms();
	int64_t best = 0;
	int have = 0;
	if (now < 0)
		return 1000;
	for (c = e->head; c != NULL; c = c->next)
	{
		if (c->dead)
			continue;
		if (c->state == SNI_ST_RELAY)
		{
			if (c->c2u_off < c->c2u_len)
				consider(c->c2u_by > 0 ? c->c2u_by : now, &best, &have);
			if (c->u2c_off < c->u2c_len)
				consider(c->u2c_by > 0 ? c->u2c_by : now, &best, &have);
			if (c->c2u_off == c->c2u_len && c->u2c_off == c->u2c_len)
				consider(c->idle_at, &best, &have);
		}
		else
		{
			consider(handshake_due(c), &best, &have);
		}
	}
	if (e->accept_paused)
		consider(e->accept_resume_at, &best, &have);
	if (!have)
		return -1;
	if (best <= now)
		return 0;
	if (best - now > (int64_t)INT_MAX)
		return INT_MAX;
	return (int)(best - now);
}

static void expire_conns(sni_engine *e)
{
	sni_conn *c;
	int64_t now = net_mono_ms();
	if (now < 0)
		return;
	for (c = e->head; c != NULL; c = c->next)
	{
		int64_t due;
		if (c->dead)
			continue;
		if (c->state == SNI_ST_RELAY)
		{
			if (c->c2u_off < c->c2u_len)
			{
				if (c->c2u_by == 0)
					c->c2u_by = now + (int64_t)c->io_ms;
				if (now >= c->c2u_by)
					conn_timeout(e, c, SNI_CLOSE_STALL_TIMEOUT);
			}
			if (!c->dead && c->u2c_off < c->u2c_len)
			{
				if (c->u2c_by == 0)
					c->u2c_by = now + (int64_t)c->io_ms;
				if (now >= c->u2c_by)
					conn_timeout(e, c, SNI_CLOSE_STALL_TIMEOUT);
			}
			if (!c->dead && c->c2u_off == c->c2u_len && c->u2c_off == c->u2c_len &&
			        !c->touched && now >= c->idle_at)
				conn_timeout(e, c, SNI_CLOSE_IDLE_TIMEOUT);
			continue;
		}
		due = handshake_due(c);
		if (now >= due)
			conn_timeout(e, c, SNI_CLOSE_HANDSHAKE_TIMEOUT);
	}
}

static void sni_engine_run(sni_engine *e)
{
	sni_ready ready[64];
	while (!e->stop)
	{
		sni_conn *c;
		int n;
		int i;
		for (c = e->head; c != NULL; c = c->next)
			c->touched = 0;
		reap(e);
		if (e->listen_fd < 0 && e->head == NULL)
			break;
		n = sni_react_wait(e, ready, 64, engine_timeout(e));
		if (n < 0)
		{
			if (errno == EINTR)
				n = 0;
			else
			{
				log_error("sni event wait failed: %s", strerror(errno));
				break;
			}
		}
		for (i = 0; i < n; i++)
			dispatch_one(e, &ready[i]);
		accept_resume(e);
		expire_conns(e);
		reap(e);
	}
	if (e->sink)
		resolver_sink_mark_closed(e->sink);
	{
		sni_conn *c;
		for (c = e->head; c != NULL; c = c->next)
			sni_conn_kill(e, c, SNI_CLOSE_NONE);
	}
	reap(e);
	if (e->sink && e->sink_interest != 0)
	{
		sni_react_del(e, e->sink->pipe_read);
		e->sink_interest = 0;
	}
	sni_drain_resolve(e);
}

static void sni_engine_deinit(sni_engine *e)
{
	sni_conn *c = e->head;
	if (e->sink)
	{
		if (e->sink_interest != 0)
		{
			sni_react_del(e, e->sink->pipe_read);
			e->sink_interest = 0;
		}
		resolver_sink_mark_closed(e->sink);
		sni_drain_resolve(e);
		resolver_sink_release(e->sink);
		e->sink = NULL;
	}
	while (c)
	{
		sni_conn *next = c->next;
		if (!c->dead)
			sni_conn_kill(e, c, SNI_CLOSE_NONE);
		free(c);
		c = next;
	}
	e->head = NULL;
	if (e->wake_r >= 0)
	{
		close(e->wake_r);
		e->wake_r = -1;
	}
	if (e->wake_w >= 0)
	{
		close(e->wake_w);
		e->wake_w = -1;
	}
	if (e->listen_fd >= 0)
	{
		close(e->listen_fd);
		e->listen_fd = -1;
	}
	reactor_close(&e->re);
}

static bool sni_engine_init(sni_engine *e, int listen_fd, const sni_server_t *cfg)
{
	int pipes[2];
	memset(e, 0, sizeof(*e));
	e->re.epfd = -1;
	e->listen_fd = -1;
	e->wake_r = -1;
	e->wake_w = -1;
	if (!cfg)
		goto fail;
	e->cfg = *cfg;
	e->listen_tag.kind = SNI_TAG_LISTEN;
	e->listen_tag.eng = e;
	e->listen_tag.fd = -1;
	e->wake_tag.kind = SNI_TAG_WAKE;
	e->wake_tag.eng = e;
	e->wake_tag.fd = -1;
	e->sink_tag.kind = SNI_TAG_SINK;
	e->sink_tag.eng = e;
	e->sink_tag.fd = -1;
	if (!resolver_sink_open(listen_fd >= 0 ? RESOLVER_SINK_LISTENER : RESOLVER_SINK_DIRECT,
	            &e->sink))
		goto fail;
	resolver_watch_bind(e->sink->listener_id, e->cfg.port.bindip, e->cfg.port.local_port);
	if (!reactor_open(&e->re, SNI_POLL_MAX, SNI_USE_POLL))
		goto fail;
	if (pipe(pipes) != 0)
		goto fail;
	e->wake_r = pipes[0];
	e->wake_w = pipes[1];
	if (!sni_set_nb_cloexec(e->wake_r) || !sni_set_nb_cloexec(e->wake_w))
		goto fail;
	e->wake_tag.fd = e->wake_r;
	if (!sni_watch(e, e->wake_r, SNI_EV_IN, &e->wake_interest, &e->wake_tag))
		goto fail;
	e->sink_tag.fd = e->sink->pipe_read;
	if (!sni_watch(e, e->sink->pipe_read, SNI_EV_IN, &e->sink_interest, &e->sink_tag))
		goto fail;
	if (listen_fd >= 0)
	{
		e->listen_fd = listen_fd;
		listen_fd = -1;
		if (!sni_set_nb_cloexec(e->listen_fd))
			goto fail;
		e->listen_tag.fd = e->listen_fd;
		if (!sni_watch(e, e->listen_fd, SNI_EV_IN, &e->listen_interest, &e->listen_tag))
			goto fail;
	}
	return true;
fail:
	if (listen_fd >= 0)
		close(listen_fd);
	sni_engine_deinit(e);
	return false;
}

static void publish_listener(sni_listener *ls, sni_engine *eng, int ok)
{
	if (!ls)
		return;
	pthread_mutex_lock(&ls->mu);
	ls->eng = eng;
	ls->ok = ok;
	ls->ready = 1;
	pthread_cond_signal(&ls->cv);
	pthread_mutex_unlock(&ls->mu);
}

static void *engine_thread(void *arg)
{
	sni_boot *boot = (sni_boot *)arg;
	sni_listener *ls = boot->joinable;
	int fd = boot->listen_fd;
	sni_server_t cfg = boot->cfg;
	sni_engine eng;
	free(boot);
	if (!sni_engine_init(&eng, fd, &cfg))
	{
		publish_listener(ls, NULL, 0);
		return NULL;
	}
	publish_listener(ls, &eng, 1);
	sni_engine_run(&eng);
	if (ls)
	{
		pthread_mutex_lock(&ls->mu);
		ls->sink = eng.sink;
		eng.sink = NULL;
		ls->eng = NULL;
		pthread_mutex_unlock(&ls->mu);
	}
	sni_engine_deinit(&eng);
	return NULL;
}

static void request_stop(sni_engine *e)
{
	char byte = 1;
	ssize_t n;
	if (!e || e->wake_w < 0)
		return;
	do
	{
		n = write(e->wake_w, &byte, 1);
	} while (n < 0 && errno == EINTR);
}

bool sni_listener_open(const sni_server_t *cfg, sni_listener **out)
{
	int fd = -1;
	in_addr_t ip;
	sni_listener *ls;
	sni_boot *boot;
	if (!cfg || !out)
		return false;
	*out = NULL;
	ip = inet_addr(cfg->port.bindip);
	if (!net_listen_ipv4(ip, cfg->port.local_port, &fd))
	{
		log_error("can not listen on Port %s:%i", cfg->port.bindip, cfg->port.local_port);
		return false;
	}
	log_info("socket listen on %s:%d", cfg->port.bindip, cfg->port.local_port);
	ls = (sni_listener *)calloc(1, sizeof(*ls));
	if (!ls)
	{
		close(fd);
		return false;
	}
	if (pthread_mutex_init(&ls->mu, NULL) != 0)
		goto fail_ls;
	if (pthread_cond_init(&ls->cv, NULL) != 0)
		goto fail_mu;
	boot = (sni_boot *)calloc(1, sizeof(*boot));
	if (!boot)
		goto fail_cv;
	boot->listen_fd = fd;
	boot->cfg = *cfg;
	boot->joinable = ls;
	if (pthread_create(&ls->thread, NULL, engine_thread, boot) != 0)
	{
		log_error("sni listener thread create failed");
		goto fail_boot;
	}
	fd = -1;
	pthread_mutex_lock(&ls->mu);
	while (!ls->ready)
		pthread_cond_wait(&ls->cv, &ls->mu);
	pthread_mutex_unlock(&ls->mu);
	if (!ls->ok)
	{
		pthread_join(ls->thread, NULL);
		goto fail_cv;
	}
	*out = ls;
	return true;

fail_boot:
	free(boot);
fail_cv:
	pthread_cond_destroy(&ls->cv);
fail_mu:
	pthread_mutex_destroy(&ls->mu);
fail_ls:
	if (fd >= 0)
		close(fd);
	free(ls);
	return false;
}

void sni_listener_close(sni_listener *ls)
{
	if (!ls)
		return;
	/*
	 * Wake under mu: engine_thread clears ls->eng under mu before deinit
	 * closes wake_w, so the write never reaches a closed or reused fd.
	 */
	pthread_mutex_lock(&ls->mu);
	if (ls->eng)
		request_stop(ls->eng);
	pthread_mutex_unlock(&ls->mu);
	pthread_join(ls->thread, NULL);
	if (ls->sink)
	{
		resolver_sink_release(ls->sink);
		ls->sink = NULL;
	}
	pthread_cond_destroy(&ls->cv);
	pthread_mutex_destroy(&ls->mu);
	free(ls);
}

#ifdef SNI_TEST_HOOKS
void sni_connection_run(sniclient_t *client)
{
	sni_engine eng;
	sni_conn *c;
	int fd;
	if (!client)
		return;
	fd = client->connid;
	client->connid = -1;
	if (fd < 0 || !sni_set_nb_cloexec(fd))
	{
		if (fd >= 0)
			close(fd);
		stats_close_connection(client->config.stats, 0, 0);
		return;
	}
	if (!sni_engine_init(&eng, -1, &client->config))
	{
		close(fd);
		stats_close_connection(client->config.stats, 0, 0);
		return;
	}
	c = conn_new(&eng, fd);
	if (!c)
	{
		close(fd);
		stats_close_connection(client->config.stats, 0, 0);
		sni_engine_deinit(&eng);
		return;
	}
	if (!conn_start(&eng, c))
	{
		stats_close_connection(client->config.stats, 0, 0);
		sni_engine_run(&eng);
		sni_engine_deinit(&eng);
		return;
	}
	if (client->config.stats)
		c->close_stats = 1;
	sni_engine_run(&eng);
	sni_engine_deinit(&eng);
}

void *sni_client_handler(void *arg)
{
	sniclient_t *client = (sniclient_t *)arg;
	if (!client)
		return NULL;
	sni_connection_run(client);
	sni_conn_release();
	free(client);
	return NULL;
}
#endif /* SNI_TEST_HOOKS */
