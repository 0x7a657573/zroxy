#define _GNU_SOURCE

#include "sni_event_loop.h"

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
 *   a connection limit (sni_worker_acquire), not a thread count.
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
 * - stats_close_connection and sni_worker_release run once, from conn_kill.
 */

#define SNI_SOCKS_CAP 600u
/* Bytes one relay_pump call may move before yielding to other connections. */
#define SNI_RELAY_BUDGET (256u * 1024u)
#define SNI_ADDR_MAX 16
#define SNI_POLL_MAX 4096
/* How long the listener stays unarmed after accept() runs out of descriptors. */
#define SNI_ACCEPT_PAUSE_MS 100
/* The out-of-descriptors error is logged at most this often per listener. */
#define SNI_ACCEPT_LOG_MS 1000

#ifdef SNI_FORCE_POLL
#define SNI_USE_POLL true
#else
#define SNI_USE_POLL false
#endif

enum {
	SNI_EV_IN = RE_IN,
	SNI_EV_OUT = RE_OUT,
	SNI_EV_ERR = RE_ERR,
	SNI_EV_HUP = RE_HUP,
	/* Keep the fd registered so ERR/HUP are reported. No read or write. */
	SNI_EV_ARMED = 16
};

enum {
	SNI_TAG_CONN = 1,
	SNI_TAG_LISTEN = 2,
	SNI_TAG_WAKE = 3,
	SNI_TAG_SINK = 4
};

enum {
	SNI_ST_HELLO = 0,
	SNI_ST_RESOLVE,
	SNI_ST_CONNECT,
	SNI_ST_SOCKS,
	SNI_ST_RELAY
};

/*
 * Why a connection ended, set at the failure site and counted once by
 * conn_kill. NONE is a normal end (EOF or reset from either side of a relay,
 * listener shutdown) or an internal failure with no counter of its own.
 */
enum {
	SNI_CLOSE_NONE = 0,
	SNI_CLOSE_REFUSED,
	SNI_CLOSE_NO_HOSTNAME,
	SNI_CLOSE_BLOCKED,
	SNI_CLOSE_UNSAFE,
	SNI_CLOSE_RESOLVE,
	SNI_CLOSE_SOCKS,
	SNI_CLOSE_CONNECT,
	SNI_CLOSE_HANDSHAKE_TIMEOUT,
	SNI_CLOSE_IDLE_TIMEOUT,
	SNI_CLOSE_STALL_TIMEOUT,
	SNI_CLOSE_EVICTED,
	SNI_CLOSE_ACL_DENIED
};

typedef struct sni_engine sni_engine;
typedef struct sni_conn sni_conn;

typedef struct sni_tag {
	int kind;
	int fd;
	sni_engine *eng;
	sni_conn *conn;
} sni_tag;

typedef struct sni_addr {
	struct sockaddr_storage sa;
	socklen_t len;
} sni_addr;

struct sni_conn {
	sni_conn *next;
	/* FIFO of connections still in HELLO, oldest first (see hello_link). */
	sni_conn *hello_prev;
	sni_conn *hello_next;
	int in_hello_list;
	sni_engine *eng;
	sni_tag client_tag;
	sni_tag up_tag;
	int client_fd;
	int up_fd;
	uint32_t client_interest;
	uint32_t up_interest;
	int state;
	int dead;
	int touched;
	int slot_held;
	int close_stats;
	int settled;
	int client_eof;
	int up_eof;
	int client_shut;
	int up_shut;
	int io_ms;
	int idle_ms;
	int socks_step;
	int naddr;
	int addr_i;
	int resolve_slot;
	uint32_t index;
	uint64_t generation;
	uint64_t pending_req_id;
	int64_t hello_abs;
	int64_t last_hello;
	int64_t resolve_deadline;
	int64_t connect_deadline;
	int64_t deadline;
	int64_t idle_at;
	int64_t c2u_by;
	int64_t u2c_by;
	uint32_t rx;
	uint32_t tx;
	uint32_t hello_len;
	uint32_t c2u_len;
	uint32_t c2u_off;
	uint32_t u2c_len;
	uint32_t u2c_off;
	uint32_t socks_out_off;
	uint32_t socks_in_len;
	char host[ZROXY_MAX_HOSTNAME];
	uint8_t hello[SNI_HELLO_CAP];
	uint8_t c2u[SNI_RELAY_CAP];
	uint8_t u2c[SNI_RELAY_CAP];
	uint8_t socks_in[SNI_SOCKS_CAP];
	socks5_client socks;
	sni_addr addrs[SNI_ADDR_MAX];
	SniServer_t cfg;
};

struct sni_engine {
	reactor re;
	int listen_fd;
	int wake_r;
	int wake_w;
	uint32_t listen_interest;
	int accept_paused;
	int64_t accept_resume_at;
	int64_t accept_log_at;
	uint32_t wake_interest;
	int stop;
	SniServer_t cfg;
	sni_conn *head;
	sni_conn *hello_head;
	sni_conn *hello_tail;
	sni_tag listen_tag;
	sni_tag wake_tag;
	sni_tag sink_tag;
	sni_completion_sink *sink;
	uint32_t sink_interest;
	uint32_t next_index;
	uint64_t next_generation;
};

struct sni_listener {
	pthread_t thread;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	sni_engine *eng;
	sni_completion_sink *sink;
	int ready;
	int ok;
};

typedef struct sni_boot {
	int listen_fd;
	SniServer_t cfg;
	sni_listener *joinable;
} sni_boot;

typedef struct sni_ready {
	sni_tag *tag;
	int fd;
	uint32_t ev;
} sni_ready;

#ifdef SNI_TEST_HOOKS
static int g_read_limit;
static int g_write_limit;
static int g_eagain_write;
static int g_eintr_read;
static int g_eintr_write;
static int g_eintr_connect;
static int g_eintr_wait;
static int g_fail_wait;
static int g_fail_allocs;
static int g_fail_accept;
static uint32_t g_accept_pauses;
static uint32_t g_client_bytes;
static uint32_t g_max_pending;
static uint32_t g_eagain;
static uint32_t g_wait_calls;
static uint32_t g_relay_yields;
static int g_hello_idle_ms = SNI_HELLO_IDLE_MS;
static uint32_t g_relay_budget = SNI_RELAY_BUDGET;

static int take_one(int *counter)
{
	int cur = __atomic_load_n(counter, __ATOMIC_RELAXED);
	while (cur > 0) {
		if (__atomic_compare_exchange_n(counter, &cur, cur - 1, 1,
				__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			return 1;
	}
	return 0;
}

static void note_client_read(uint32_t n)
{
	__atomic_fetch_add(&g_client_bytes, n, __ATOMIC_RELAXED);
}

static void note_pending(uint32_t n)
{
	uint32_t cur = __atomic_load_n(&g_max_pending, __ATOMIC_RELAXED);
	while (n > cur) {
		if (__atomic_compare_exchange_n(&g_max_pending, &cur, n, 1,
				__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
}

static void note_eagain(void)
{
	__atomic_fetch_add(&g_eagain, 1, __ATOMIC_RELAXED);
}

static void note_wait(void)
{
	__atomic_fetch_add(&g_wait_calls, 1u, __ATOMIC_RELAXED);
}

static void note_relay_yield(void)
{
	__atomic_fetch_add(&g_relay_yields, 1u, __ATOMIC_RELAXED);
}

static void note_accept_pause(void)
{
	__atomic_fetch_add(&g_accept_pauses, 1u, __ATOMIC_RELAXED);
}
#else
static void note_client_read(uint32_t n) { (void)n; }
static void note_pending(uint32_t n) { (void)n; }
static void note_eagain(void) { }
static void note_wait(void) { }
static void note_relay_yield(void) { }
static void note_accept_pause(void) { }
#endif

static bool set_nb_cloexec(int fd)
{
	return net_set_nonblock_cloexec(fd);
}

static ssize_t io_read(int fd, void *buf, size_t len)
{
#ifdef SNI_TEST_HOOKS
	int limit;
	if (take_one(&g_eintr_read)) {
		errno = EINTR;
		return -1;
	}
	limit = __atomic_load_n(&g_read_limit, __ATOMIC_RELAXED);
	if (limit > 0 && len > (size_t)limit)
		len = (size_t)limit;
#endif
	return read(fd, buf, len);
}

static ssize_t io_write(int fd, const void *buf, size_t len)
{
#ifdef SNI_TEST_HOOKS
	int limit;
	if (take_one(&g_eagain_write)) {
		errno = EAGAIN;
		return -1;
	}
	if (take_one(&g_eintr_write)) {
		errno = EINTR;
		return -1;
	}
	limit = __atomic_load_n(&g_write_limit, __ATOMIC_RELAXED);
	if (limit > 0 && len > (size_t)limit)
		len = (size_t)limit;
#endif
#if defined(MSG_NOSIGNAL)
	return send(fd, buf, len, MSG_NOSIGNAL);
#else
	return write(fd, buf, len);
#endif
}

static int io_accept(int fd, struct sockaddr_storage *peer)
{
	socklen_t len = (socklen_t)sizeof(*peer);

#ifdef SNI_TEST_HOOKS
	if (take_one(&g_fail_accept)) {
		errno = EMFILE;
		return -1;
	}
#endif
	return accept(fd, (struct sockaddr *)peer, &len);
}

static int io_connect(int fd, const struct sockaddr *sa, socklen_t len)
{
#ifdef SNI_TEST_HOOKS
	if (take_one(&g_eintr_connect)) {
		errno = EINTR;
		return -1;
	}
#endif
	return connect(fd, sa, len);
}

static bool react_add(sni_engine *e, int fd, uint32_t ev, sni_tag *tag)
{
	return reactor_add(&e->re, fd, ev, tag);
}

static bool react_mod(sni_engine *e, int fd, uint32_t ev, sni_tag *tag)
{
	return reactor_mod(&e->re, fd, ev, tag);
}

static void react_del(sni_engine *e, int fd)
{
	reactor_del(&e->re, fd);
}

static int react_wait(sni_engine *e, sni_ready *out, int max, int timeout_ms)
{
	reactor_event evs[64];
	int n;
	int i;
	if (max > 64)
		max = 64;
	note_wait();
#ifdef SNI_TEST_HOOKS
	if (take_one(&g_eintr_wait)) {
		errno = EINTR;
		return -1;
	}
	if (take_one(&g_fail_wait)) {
		errno = EBADF;
		return -1;
	}
#endif
	n = reactor_wait(&e->re, evs, max, timeout_ms);
	if (n < 0)
		return -1;
	for (i = 0; i < n; i++) {
		sni_tag *tag = (sni_tag *)evs[i].tag;
		out[i].tag = tag;
		/* epoll reports no fd; the tag holds the fd it is armed with. */
		out[i].fd = evs[i].fd >= 0 ? evs[i].fd : (tag ? tag->fd : -1);
		out[i].ev = evs[i].ev;
	}
	return n;
}

static bool watch(sni_engine *e, int fd, uint32_t ev, uint32_t *slot, sni_tag *tag)
{
	if (fd < 0) {
		*slot = 0;
		return true;
	}
	if (ev == *slot)
		return true;
	if (tag)
		tag->fd = fd;
	if (ev == 0) {
		react_del(e, fd);
		*slot = 0;
		return true;
	}
	if (*slot == 0) {
		if (!react_add(e, fd, ev, tag))
			return false;
	} else if (!react_mod(e, fd, ev, tag)) {
		return false;
	}
	*slot = ev;
	return true;
}

static void drop_watched(sni_engine *e, int *fd, uint32_t *slot, sni_tag *tag)
{
	if (*fd < 0) {
		if (tag)
			tag->fd = -1;
		return;
	}
	if (*slot != 0) {
		react_del(e, *fd);
		*slot = 0;
	}
	close(*fd);
	*fd = -1;
	if (tag)
		tag->fd = -1;
}

static int read_some(int fd, uint8_t *buf, uint32_t cap, uint32_t *len)
{
	size_t space;
	ssize_t n;
	if (*len >= cap)
		return 0;
	space = (size_t)(cap - *len);
	do {
		n = io_read(fd, buf + *len, space);
	} while (n < 0 && errno == EINTR);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}
	if (n == 0)
		return -2;
	if ((size_t)n > space)
		return -1;
	*len += (uint32_t)n;
	return 1;
}

static int write_some(int fd, const uint8_t *buf, uint32_t len, uint32_t *off, uint32_t *counter)
{
	while (*off < len) {
		size_t space = (size_t)(len - *off);
		ssize_t n;
		do {
			n = io_write(fd, buf + *off, space);
		} while (n < 0 && errno == EINTR);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				note_eagain();
				return 0;
			}
			return -1;
		}
		if (n == 0 || (size_t)n > space)
			return -1;
		*off += (uint32_t)n;
		if (counter)
			*counter += (uint32_t)n;
	}
	return 1;
}

static int shut_write(int fd)
{
	int rc;
	do {
		rc = shutdown(fd, SHUT_WR);
	} while (rc < 0 && errno == EINTR);
	return rc;
}

/*
 * Counters for every listener, reported through the SNI_Server monitor
 * object. Word-sized and updated with relaxed atomics: 64-bit atomics are not
 * lock-free on every target.
 */
static struct {
	uint32_t relayed;
	uint32_t refused;
	uint32_t no_hostname;
	uint32_t blocked;
	uint32_t unsafe;
	uint32_t resolve;
	uint32_t socks;
	uint32_t connect;
	uint32_t handshake_timeout;
	uint32_t idle_timeout;
	uint32_t stall_timeout;
	uint32_t evicted;
	uint32_t acl_denied;
} g_sni_close;

static void count_close(int reason)
{
	uint32_t *counter = NULL;

	switch (reason) {
	case SNI_CLOSE_REFUSED: counter = &g_sni_close.refused; break;
	case SNI_CLOSE_NO_HOSTNAME: counter = &g_sni_close.no_hostname; break;
	case SNI_CLOSE_BLOCKED: counter = &g_sni_close.blocked; break;
	case SNI_CLOSE_UNSAFE: counter = &g_sni_close.unsafe; break;
	case SNI_CLOSE_RESOLVE: counter = &g_sni_close.resolve; break;
	case SNI_CLOSE_SOCKS: counter = &g_sni_close.socks; break;
	case SNI_CLOSE_CONNECT: counter = &g_sni_close.connect; break;
	case SNI_CLOSE_HANDSHAKE_TIMEOUT: counter = &g_sni_close.handshake_timeout; break;
	case SNI_CLOSE_IDLE_TIMEOUT: counter = &g_sni_close.idle_timeout; break;
	case SNI_CLOSE_STALL_TIMEOUT: counter = &g_sni_close.stall_timeout; break;
	case SNI_CLOSE_EVICTED: counter = &g_sni_close.evicted; break;
	case SNI_CLOSE_ACL_DENIED: counter = &g_sni_close.acl_denied; break;
	default: return;
	}
	(void)__atomic_fetch_add(counter, 1u, __ATOMIC_RELAXED);
}

bool sni_stats_json(void *ctx, char **ptr, char *end)
{
	int n;
	size_t left;

	(void)ctx;
	if (!ptr || !*ptr || *ptr >= end)
		return false;
	left = (size_t)(end - *ptr);
	n = snprintf(*ptr, left, ",\n\"ConnectionLimit\" : %d,\n"
		"\"Relayed\" : %" PRIu32 ",\n"
		"\"Refused\" : %" PRIu32 ",\n"
		"\"NoHostname\" : %" PRIu32 ",\n"
		"\"Blocked\" : %" PRIu32 ",\n"
		"\"UnsafeDestination\" : %" PRIu32 ",\n"
		"\"ResolveFailures\" : %" PRIu32 ",\n"
		"\"SocksFailures\" : %" PRIu32 ",\n"
		"\"ConnectFailures\" : %" PRIu32 ",\n"
		"\"HandshakeTimeouts\" : %" PRIu32 ",\n"
		"\"IdleTimeouts\" : %" PRIu32 ",\n"
		"\"StallTimeouts\" : %" PRIu32 ",\n"
		"\"Evicted\" : %" PRIu32 ",\n"
		"\"AclDenied\" : %" PRIu32,
		sni_worker_limit(),
		__atomic_load_n(&g_sni_close.relayed, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.refused, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.no_hostname, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.blocked, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.unsafe, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.resolve, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.socks, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.connect, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.handshake_timeout, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.idle_timeout, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.stall_timeout, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.evicted, __ATOMIC_RELAXED),
		__atomic_load_n(&g_sni_close.acl_denied, __ATOMIC_RELAXED));
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
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
static void conn_set_state(sni_engine *e, sni_conn *c, int state)
{
	if (state != SNI_ST_HELLO)
		hello_unlink(e, c);
	c->state = state;
}

static void conn_kill(sni_engine *e, sni_conn *c, int reason)
{
	if (!c || c->dead)
		return;
	c->dead = 1;
	hello_unlink(e, c);
	if (c->pending_req_id != 0) {
		sni_resolver_cancel(c->resolve_slot, c->pending_req_id);
		c->pending_req_id = 0;
	}
	drop_watched(e, &c->client_fd, &c->client_interest, &c->client_tag);
	drop_watched(e, &c->up_fd, &c->up_interest, &c->up_tag);
	if (c->settled)
		return;
	c->settled = 1;
	count_close(reason);
	if (c->close_stats && c->cfg.sta)
		stats_close_connection(c->cfg.sta, c->rx, c->tx);
	if (c->slot_held) {
		sni_worker_release();
		c->slot_held = 0;
	}
}

static void conn_timeout(sni_engine *e, sni_conn *c, int reason)
{
	if (c->host[0] != '\0')
		log_trace("SNI timeout Host { %s }", c->host);
	else
		log_trace("TimeOut tid:%i", c->client_fd);
	conn_kill(e, c, reason);
}

static bool conn_arm(sni_engine *e, sni_conn *c)
{
	uint32_t cin = 0;
	uint32_t uin = 0;
	if (c->dead)
		return true;
	if (c->state == SNI_ST_HELLO) {
		if (!c->client_eof && c->hello_len < SNI_HELLO_CAP)
			cin |= SNI_EV_IN;
	} else if (c->state == SNI_ST_RESOLVE) {
		cin |= SNI_EV_ARMED;
	} else if (c->state == SNI_ST_CONNECT) {
		cin |= SNI_EV_ARMED;
		uin |= SNI_EV_OUT;
	} else if (c->state == SNI_ST_SOCKS) {
		if (c->socks_step == S5_SEND)
			uin |= SNI_EV_OUT;
		else if (c->socks_step == S5_READ)
			uin |= SNI_EV_IN;
	} else if (c->state == SNI_ST_RELAY) {
		if (!c->client_eof && c->c2u_off == c->c2u_len)
			cin |= SNI_EV_IN;
		if (!c->client_shut && c->u2c_off < c->u2c_len)
			cin |= SNI_EV_OUT;
		if (c->up_fd >= 0 && !c->up_eof && c->u2c_off == c->u2c_len)
			uin |= SNI_EV_IN;
		if (c->up_fd >= 0 && !c->up_shut && c->c2u_off < c->c2u_len)
			uin |= SNI_EV_OUT;
	}
	if (!watch(e, c->client_fd, cin, &c->client_interest, &c->client_tag))
		return false;
	if (!watch(e, c->up_fd, uin, &c->up_interest, &c->up_tag))
		return false;
	return true;
}

static void reap(sni_engine *e)
{
	sni_conn **pp = &e->head;
	while (*pp) {
		sni_conn *c = *pp;
		if (!c->dead) {
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
	if (take_one(&g_fail_allocs))
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
	e->next_generation++;
	if (e->next_generation == 0)
		e->next_generation = 1;
	e->next_index++;
	if (e->next_index == 0)
		e->next_index = 1;
	c->generation = e->next_generation;
	c->index = e->next_index;
	c->hello_abs = now + (int64_t)c->io_ms;
	c->last_hello = now;
	c->state = SNI_ST_HELLO;
	return c;
}

static void note_idle(sni_conn *c)
{
	int64_t now = net_mono_ms();
	c->touched = 1;
	if (now < 0)
		return;
	if (c->c2u_off < c->c2u_len || c->u2c_off < c->u2c_len)
		return;
	/* idle_ms is clamped, so a zero timeout cannot make the idle timer fire at once. */
	c->idle_at = now + (int64_t)c->idle_ms;
}

static void relay_pump(sni_engine *e, sni_conn *c);

static void enter_relay(sni_engine *e, sni_conn *c)
{
	int64_t now = net_mono_ms();
	if (now < 0) {
		conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	conn_set_state(e, c, SNI_ST_RELAY);
	(void)__atomic_fetch_add(&g_sni_close.relayed, 1u, __ATOMIC_RELAXED);
	if (c->hello_len > SNI_RELAY_CAP) {
		conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	if (c->hello_len > 0) {
		memcpy(c->c2u, c->hello, (size_t)c->hello_len);
		c->c2u_len = c->hello_len;
		c->c2u_off = 0;
		c->c2u_by = now + (int64_t)c->io_ms;
		note_pending(c->c2u_len);
	}
	c->idle_at = now + (int64_t)c->idle_ms;
	c->touched = 1;
	relay_pump(e, c);
}

static void socks_deadline(sni_conn *c)
{
	int64_t now = net_mono_ms();
	c->deadline = (now < 0) ? 0 : now + (int64_t)c->io_ms;
}

/* The codec moved to its next step: restart the I/O counters and the deadline. */
static void socks_next(sni_conn *c, s5_step step)
{
	c->socks_step = step;
	c->socks_out_off = 0;
	c->socks_in_len = 0;
	socks_deadline(c);
}

static void socks_pump(sni_engine *e, sni_conn *c)
{
	int guard = 0;
	while (!c->dead && c->state == SNI_ST_SOCKS && guard++ < 100000) {
		if (c->socks_step == S5_SEND) {
			int wr = write_some(c->up_fd, c->socks.out, (uint32_t)c->socks.out_len,
					&c->socks_out_off, NULL);
			if (wr < 0) {
				conn_kill(e, c, SNI_CLOSE_SOCKS);
				return;
			}
			if (c->socks_out_off < c->socks.out_len)
				break;
			socks_next(c, socks5_client_sent(&c->socks));
		} else if (c->socks_step == S5_READ) {
			s5_step step;
			int rr;
			if (c->socks.need > SNI_SOCKS_CAP) {
				conn_kill(e, c, SNI_CLOSE_SOCKS);
				return;
			}
			rr = read_some(c->up_fd, c->socks_in, (uint32_t)c->socks.need, &c->socks_in_len);
			if (rr == 0)
				break;
			if (rr < 0) {
				conn_kill(e, c, SNI_CLOSE_SOCKS);
				return;
			}
			if (c->socks_in_len < c->socks.need)
				break;
			step = socks5_client_feed(&c->socks, c->socks_in, c->socks_in_len);
			socks_next(c, step);
		} else if (c->socks_step == S5_DONE) {
			enter_relay(e, c);
			return;
		} else {
			break;
		}
		if (c->socks_step == S5_FAIL) {
			log_error("[!] SOCKS server %s:%u: %s",
				c->cfg.Socks->host ? c->cfg.Socks->host : "?",
				(unsigned)c->cfg.Socks->port, socks5_client_strerror(&c->socks));
			conn_kill(e, c, SNI_CLOSE_SOCKS);
			return;
		}
	}
	if (!c->dead && c->state == SNI_ST_SOCKS && !conn_arm(e, c))
		conn_kill(e, c, SNI_CLOSE_NONE);
}

static void socks_begin(sni_engine *e, sni_conn *c)
{
	conn_set_state(e, c, SNI_ST_SOCKS);
	if (!socks5_client_init(&c->socks, c->cfg.Socks->user, c->cfg.Socks->pass, c->host,
			c->cfg.Port.remote_port)) {
		conn_kill(e, c, SNI_CLOSE_SOCKS);
		return;
	}
	socks_next(c, socks5_client_start(&c->socks));
	socks_pump(e, c);
}

static void set_addr_port(sni_resolved_addr *addr, uint16_t port)
{
	struct sockaddr *sa = (struct sockaddr *)&addr->address;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		in->sin_port = htons(port);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
		in6->sin6_port = htons(port);
	}
}

static bool install_addrs(sni_conn *c, const sni_resolved_addr *in, size_t n)
{
	size_t i;
	c->naddr = 0;
	c->addr_i = 0;
	for (i = 0; i < n && c->naddr < SNI_ADDR_MAX; i++) {
		sni_addr *dst;
		if (in[i].length == 0 || (size_t)in[i].length > sizeof(c->addrs[0].sa))
			continue;
		dst = &c->addrs[c->naddr];
		memset(dst, 0, sizeof(*dst));
		memcpy(&dst->sa, &in[i].address, (size_t)in[i].length);
		dst->len = in[i].length;
		c->naddr++;
	}
	return c->naddr > 0;
}

static bool install_checked(sni_conn *c, sni_resolved_addr *in, size_t n, uint16_t port)
{
	size_t i;
	size_t kept;
	for (i = 0; i < n; i++)
		set_addr_port(&in[i], port);
	kept = sni_resolver_policy_keep(in, n,
		(c->cfg.allow_loopback ? SNI_POLICY_ALLOW_LOOPBACK : 0u) |
		(c->cfg.deny_private ? SNI_POLICY_DENY_PRIVATE : 0u));
	return install_addrs(c, in, kept);
}

static void try_connect(sni_engine *e, sni_conn *c);

static void on_connected(sni_engine *e, sni_conn *c)
{
	if (c->cfg.Socks)
		socks_begin(e, c);
	else
		enter_relay(e, c);
}

static void try_connect(sni_engine *e, sni_conn *c)
{
	while (c->addr_i < c->naddr && !c->dead) {
		sni_addr *addr = &c->addrs[c->addr_i];
		int fam = ((struct sockaddr *)&addr->sa)->sa_family;
		int fd;
		int rc;
		int64_t now = net_mono_ms();
		if (now < 0 || now >= c->connect_deadline) {
			conn_kill(e, c, now < 0 ? SNI_CLOSE_NONE : SNI_CLOSE_HANDSHAKE_TIMEOUT);
			return;
		}
		fd = socket(fam, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) {
			c->addr_i++;
			continue;
		}
		if (!set_nb_cloexec(fd)) {
			close(fd);
			c->addr_i++;
			continue;
		}
		do {
			rc = io_connect(fd, (struct sockaddr *)&addr->sa, addr->len);
		} while (rc < 0 && errno == EINTR);
		if (rc == 0 || (rc < 0 && errno == EISCONN)) {
			c->up_fd = fd;
			c->up_tag.fd = fd;
			on_connected(e, c);
			return;
		}
		if (rc < 0 && (errno == EINPROGRESS || errno == EALREADY)) {
			c->up_fd = fd;
			c->up_tag.fd = fd;
			conn_set_state(e, c, SNI_ST_CONNECT);
			if (!conn_arm(e, c))
				conn_kill(e, c, SNI_CLOSE_NONE);
			return;
		}
		close(fd);
		c->addr_i++;
	}
	if (!c->dead) {
		log_error("net_connect Error : Connect Failed");
		conn_kill(e, c, SNI_CLOSE_CONNECT);
	}
}

static void connect_pump(sni_engine *e, sni_conn *c, uint32_t ev)
{
	int err = 0;
	socklen_t sl = (socklen_t)sizeof(err);
	if (getsockopt(c->up_fd, SOL_SOCKET, SO_ERROR, &err, &sl) != 0) {
		conn_kill(e, c, SNI_CLOSE_CONNECT);
		return;
	}
	if ((err == 0 || err == EISCONN) && (ev & SNI_EV_OUT) != 0) {
		on_connected(e, c);
		return;
	}
	if (err == EINPROGRESS || err == EALREADY ||
			(err == 0 && (ev & SNI_EV_OUT) == 0)) {
		if (!conn_arm(e, c))
			conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	drop_watched(e, &c->up_fd, &c->up_interest, &c->up_tag);
	c->addr_i++;
	try_connect(e, c);
}

static void start_connect(sni_engine *e, sni_conn *c)
{
	int64_t now = net_mono_ms();
	if (now < 0) {
		conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	c->connect_deadline = now + (int64_t)c->io_ms;
	try_connect(e, c);
}

static void submit_resolve(sni_engine *e, sni_conn *c, const char *host, uint16_t port)
{
	int slot = -1;
	uint64_t req = 0;
	int64_t now = net_mono_ms();
	int rc;
	if (now < 0 || !e->sink) {
		conn_kill(e, c, SNI_CLOSE_RESOLVE);
		return;
	}
	c->resolve_deadline = now + (int64_t)c->io_ms;
	conn_set_state(e, c, SNI_ST_RESOLVE);
	rc = sni_resolver_submit(e->sink, c->index, c->generation, host, port,
			AF_INET, c->resolve_deadline, &slot, &req);
	if (rc != SNI_SUBMIT_OK) {
		log_trace("resolve_overflow");
		conn_kill(e, c, SNI_CLOSE_RESOLVE);
		return;
	}
	c->resolve_slot = slot;
	c->pending_req_id = req;
	if (!conn_arm(e, c))
		conn_kill(e, c, SNI_CLOSE_NONE);
}

static void begin_upstream(sni_engine *e, sni_conn *c)
{
	sni_resolved_addr got[SNI_RESOLVER_ADDR_MAX];
	size_t n = 0;
	int st;
	if (c->cfg.Socks) {
		if (!c->cfg.Socks->host || c->cfg.Socks->host[0] == '\0') {
			conn_kill(e, c, SNI_CLOSE_SOCKS);
			return;
		}
		st = sni_resolver_copy_upstream(c->cfg.Socks->host, c->cfg.Socks->port, got, &n);
		if (st != SNI_UP_READY || !install_addrs(c, got, n)) {
			log_trace("socks_unresolved");
			conn_kill(e, c, SNI_CLOSE_RESOLVE);
			return;
		}
		start_connect(e, c);
		return;
	}
	submit_resolve(e, c, c->host, c->cfg.Port.remote_port);
}

static sni_conn *find_pending(sni_engine *e, const resolve_slot *slot)
{
	sni_conn *c;
	for (c = e->head; c != NULL; c = c->next) {
		if (c->dead || c->pending_req_id == 0)
			continue;
		if (c->pending_req_id != slot->req_id)
			continue;
		if (c->index != slot->connection_index)
			continue;
		if (c->generation != slot->connection_generation)
			continue;
		return c;
	}
	return NULL;
}

static void apply_resolve(sni_engine *e, resolve_slot *slot)
{
	sni_resolved_addr addrs[SNI_RESOLVER_ADDR_MAX];
	sni_conn *c;
	size_t count;
	int err;
	int index;
	uint64_t req;
	uint16_t port;
	if (!slot)
		return;
	index = slot->index;
	req = slot->req_id;
	port = slot->port;
	err = slot->gai_error;
	count = slot->address_count;
	if (count > SNI_RESOLVER_ADDR_MAX)
		count = SNI_RESOLVER_ADDR_MAX;
	if (count > 0)
		memcpy(addrs, slot->addresses, count * sizeof(addrs[0]));
	c = find_pending(e, slot);
	if (c)
		c->pending_req_id = 0;
	sni_resolver_release(index, req);
	if (!c)
		return;
	if (err != 0 || count == 0) {
		log_error("%s -> %s\n", c->host, gai_strerror(err));
		conn_kill(e, c, SNI_CLOSE_RESOLVE);
		return;
	}
	if (!install_checked(c, addrs, count, port)) {
		log_trace("SNI address rejected");
		conn_kill(e, c, SNI_CLOSE_UNSAFE);
		return;
	}
	start_connect(e, c);
}

static void drain_resolve(sni_engine *e)
{
	resolve_slot *batch[SNI_RESOLVER_SLOTS];
	size_t n;
	size_t i;
	if (!e->sink)
		return;
	do {
		n = sni_resolver_drain(e->sink, batch, SNI_RESOLVER_SLOTS);
		for (i = 0; i < n; i++)
			apply_resolve(e, batch[i]);
	} while (n == SNI_RESOLVER_SLOTS);
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
	char norm[SNI_RESOLVER_HOST_MAX + 1];
	if (!net_get_host(c->hello, c->hello_len, raw, (uint16_t)ZROXY_MAX_HOSTNAME))
		return false;
	if (!sni_resolver_normalize(raw, norm, sizeof(norm)) || !copy_host(c->host, norm)) {
		conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
		return true;
	}
	if (c->cfg.wlist && filter_match(c->cfg.wlist, c->host) == false) {
		log_trace("SNI filter Host { %s }", c->host);
		conn_kill(e, c, SNI_CLOSE_BLOCKED);
		return true;
	}
	if (net_is_ip_literal(c->host)) {
		log_trace("SNI we can't support IP address");
		conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
		return true;
	}
	log_trace("SNI start Host { %s } ", c->host);
	begin_upstream(e, c);
	return true;
}

static void hello_pump(sni_engine *e, sni_conn *c)
{
	int guard = 0;
	while (!c->dead && guard++ < 100000) {
		uint32_t before;
		int rr;
		if (c->hello_len >= SNI_HELLO_CAP) {
			log_error("Host Buffer OverFlow");
			conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
			return;
		}
		before = c->hello_len;
		rr = read_some(c->client_fd, c->hello, SNI_HELLO_CAP, &c->hello_len);
		if (rr == 0)
			break;
		if (rr < 0) {
			conn_kill(e, c, SNI_CLOSE_NO_HOSTNAME);
			return;
		}
		note_client_read(c->hello_len - before);
		c->last_hello = net_mono_ms();
		if (host_ready(e, c))
			return;
	}
	if (!c->dead && !conn_arm(e, c))
		conn_kill(e, c, SNI_CLOSE_NONE);
}

static uint32_t relay_budget(void)
{
#ifdef SNI_TEST_HOOKS
	uint32_t b = __atomic_load_n(&g_relay_budget, __ATOMIC_RELAXED);
	if (b > 0)
		return b;
#endif
	return SNI_RELAY_BUDGET;
}

static void relay_pump(sni_engine *e, sni_conn *c)
{
	uint32_t budget = relay_budget();
	uint32_t moved = 0;
	while (!c->dead) {
		int progress = 0;
		int wr;
		int rr;
		if (c->up_fd >= 0 && !c->up_shut && c->c2u_off < c->c2u_len) {
			uint32_t before = c->c2u_off;
			wr = write_some(c->up_fd, c->c2u, c->c2u_len, &c->c2u_off, &c->tx);
			if (wr < 0) {
				conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			}
			if (c->c2u_off > before) {
				progress = 1;
				moved += c->c2u_off - before;
			}
			if (c->c2u_off == c->c2u_len)
				c->c2u_by = 0;
			if (c->c2u_len >= c->c2u_off)
				note_pending(c->c2u_len - c->c2u_off);
		}
		if (!c->dead && !c->client_shut && c->u2c_off < c->u2c_len) {
			uint32_t before = c->u2c_off;
			wr = write_some(c->client_fd, c->u2c, c->u2c_len, &c->u2c_off, &c->rx);
			if (wr < 0) {
				conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			}
			if (c->u2c_off > before) {
				progress = 1;
				moved += c->u2c_off - before;
			}
			if (c->u2c_off == c->u2c_len)
				c->u2c_by = 0;
			if (c->u2c_len >= c->u2c_off)
				note_pending(c->u2c_len - c->u2c_off);
		}
		if (!c->dead && !c->client_eof && c->c2u_off == c->c2u_len) {
			c->c2u_off = 0;
			c->c2u_len = 0;
			rr = read_some(c->client_fd, c->c2u, SNI_RELAY_CAP, &c->c2u_len);
			if (rr == -2) {
				c->client_eof = 1;
			} else if (rr < 0) {
				conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			} else if (rr == 1) {
				progress = 1;
				c->c2u_by = net_mono_ms() + (int64_t)c->io_ms;
				note_pending(c->c2u_len);
			}
		}
		if (!c->dead && c->up_fd >= 0 && !c->up_eof && c->u2c_off == c->u2c_len) {
			c->u2c_off = 0;
			c->u2c_len = 0;
			rr = read_some(c->up_fd, c->u2c, SNI_RELAY_CAP, &c->u2c_len);
			if (rr == -2) {
				c->up_eof = 1;
			} else if (rr < 0) {
				conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			} else if (rr == 1) {
				progress = 1;
				c->u2c_by = net_mono_ms() + (int64_t)c->io_ms;
				note_pending(c->u2c_len);
			}
		}
		if (!c->dead && c->client_eof && c->c2u_off == c->c2u_len &&
				c->up_fd >= 0 && !c->up_shut) {
			(void)shut_write(c->up_fd);
			c->up_shut = 1;
			progress = 1;
		}
		if (!c->dead && c->up_eof && c->u2c_off == c->u2c_len && !c->client_shut) {
			(void)shut_write(c->client_fd);
			c->client_shut = 1;
			progress = 1;
		}
		if (!c->dead && c->client_eof && c->up_eof &&
				c->c2u_off == c->c2u_len && c->u2c_off == c->u2c_len) {
			conn_kill(e, c, SNI_CLOSE_NONE);
			return;
		}
		if (progress)
			note_idle(c);
		if (!progress)
			break;
		/*
		 * Stop only after a whole pass, so EOF and shutdown steps above are
		 * never skipped. Whatever is left is a buffered write or a readable
		 * socket, and conn_arm keeps both armed.
		 */
		if (moved >= budget) {
			note_relay_yield();
			break;
		}
	}
	if (!c->dead && !conn_arm(e, c))
		conn_kill(e, c, SNI_CLOSE_NONE);
}

static void pump(sni_engine *e, sni_conn *c, int fd, uint32_t ev)
{
	if (c->state == SNI_ST_HELLO) {
		if (fd == c->client_fd)
			hello_pump(e, c);
		return;
	}
	if (c->state == SNI_ST_RESOLVE || c->state == SNI_ST_CONNECT) {
		if (fd == c->client_fd && (ev & (SNI_EV_ERR | SNI_EV_HUP)) != 0) {
			conn_kill(e, c, SNI_CLOSE_NONE);
			return;
		}
		if (c->state == SNI_ST_CONNECT && fd == c->up_fd &&
				(ev & (SNI_EV_OUT | SNI_EV_ERR | SNI_EV_HUP)) != 0)
			connect_pump(e, c, ev);
		return;
	}
	if (c->state == SNI_ST_SOCKS) {
		if (fd == c->up_fd)
			socks_pump(e, c);
		return;
	}
	if (c->state == SNI_ST_RELAY)
		relay_pump(e, c);
}

static bool conn_start(sni_engine *e, sni_conn *c)
{
	c->next = e->head;
	e->head = c;
	hello_link(e, c);
	if (!conn_arm(e, c)) {
		conn_kill(e, c, SNI_CLOSE_REFUSED);
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
	if (now >= e->accept_log_at) {
		log_error("server accept() out of file descriptors, pausing accept for %d ms",
			SNI_ACCEPT_PAUSE_MS);
		e->accept_log_at = now + SNI_ACCEPT_LOG_MS;
	}
	(void)watch(e, e->listen_fd, 0, &e->listen_interest, &e->listen_tag);
	e->accept_paused = 1;
	e->accept_resume_at = now + SNI_ACCEPT_PAUSE_MS;
	note_accept_pause();
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
	if (!watch(e, e->listen_fd, SNI_EV_IN, &e->listen_interest, &e->listen_tag)) {
		log_error("sni listener re-arm failed: %s", strerror(errno));
		if (now >= 0) {
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
	conn_kill(e, victim, SNI_CLOSE_EVICTED);
	return true;
}

static bool take_slot(sni_engine *e)
{
	if (sni_worker_acquire())
		return true;
	if (!evict_oldest_hello(e))
		return false;
	return sni_worker_acquire();
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
	for (;;) {
		struct sockaddr_storage peer;
		int fd;
		sni_conn *c;
		memset(&peer, 0, sizeof(peer));
		fd = io_accept(e->listen_fd, &peer);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == EMFILE || errno == ENFILE) {
				accept_pause(e);
				break;
			}
			log_error("server accept() %i: %s", errno, strerror(errno));
			break;
		}
		if (!peer_allowed(e, &peer)) {
			count_close(SNI_CLOSE_ACL_DENIED);
			close(fd);
			continue;
		}
		if (!set_nb_cloexec(fd)) {
			count_close(SNI_CLOSE_REFUSED);
			close(fd);
			continue;
		}
		if (!take_slot(e)) {
			log_error("refusing SNI connection");
			count_close(SNI_CLOSE_REFUSED);
			close(fd);
			continue;
		}
		c = conn_new(e, fd);
		if (!c) {
			log_error("malloc failed for sni connection");
			count_close(SNI_CLOSE_REFUSED);
			sni_worker_release();
			close(fd);
			continue;
		}
		c->slot_held = 1;
		if (!conn_start(e, c))
			continue;
		if (e->cfg.sta) {
			stats_open_connection(e->cfg.sta);
			c->close_stats = 1;
		}
	}
}

static void drain_wake(sni_engine *e)
{
	char buf[32];
	for (;;) {
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
	if (tag->kind == SNI_TAG_WAKE) {
		drain_wake(e);
		e->stop = 1;
		return;
	}
	if (tag->kind == SNI_TAG_SINK) {
		drain_resolve(e);
		return;
	}
	if (tag->kind == SNI_TAG_LISTEN) {
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
	int ms = __atomic_load_n(&g_hello_idle_ms, __ATOMIC_RELAXED);
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

static int engine_timeout(sni_engine *e)
{
	sni_conn *c;
	int64_t now = net_mono_ms();
	int64_t best = 0;
	int have = 0;
	if (now < 0)
		return 1000;
	for (c = e->head; c != NULL; c = c->next) {
		if (c->dead)
			continue;
		if (c->state == SNI_ST_RELAY) {
			if (c->c2u_off < c->c2u_len)
				consider(c->c2u_by > 0 ? c->c2u_by : now, &best, &have);
			if (c->u2c_off < c->u2c_len)
				consider(c->u2c_by > 0 ? c->u2c_by : now, &best, &have);
			if (c->c2u_off == c->c2u_len && c->u2c_off == c->u2c_len)
				consider(c->idle_at, &best, &have);
		} else if (c->state == SNI_ST_HELLO) {
			int64_t idle = c->last_hello + (int64_t)hello_idle_ms();
			consider(c->hello_abs < idle ? c->hello_abs : idle, &best, &have);
		} else if (c->state == SNI_ST_RESOLVE) {
			consider(c->resolve_deadline, &best, &have);
		} else if (c->state == SNI_ST_CONNECT) {
			consider(c->connect_deadline, &best, &have);
		} else {
			consider(c->deadline, &best, &have);
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
	for (c = e->head; c != NULL; c = c->next) {
		int64_t due;
		if (c->dead)
			continue;
		if (c->state == SNI_ST_RELAY) {
			if (c->c2u_off < c->c2u_len) {
				if (c->c2u_by == 0)
					c->c2u_by = now + (int64_t)c->io_ms;
				if (now >= c->c2u_by)
					conn_timeout(e, c, SNI_CLOSE_STALL_TIMEOUT);
			}
			if (!c->dead && c->u2c_off < c->u2c_len) {
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
		if (c->state == SNI_ST_HELLO) {
			int64_t idle = c->last_hello + (int64_t)hello_idle_ms();
			due = c->hello_abs < idle ? c->hello_abs : idle;
		} else if (c->state == SNI_ST_RESOLVE) {
			due = c->resolve_deadline;
		} else if (c->state == SNI_ST_CONNECT) {
			due = c->connect_deadline;
		} else {
			due = c->deadline;
		}
		if (now >= due)
			conn_timeout(e, c, SNI_CLOSE_HANDSHAKE_TIMEOUT);
	}
}

static void sni_engine_run(sni_engine *e)
{
	sni_ready ready[64];
	while (!e->stop) {
		sni_conn *c;
		int n;
		int i;
		for (c = e->head; c != NULL; c = c->next)
			c->touched = 0;
		reap(e);
		if (e->listen_fd < 0 && e->head == NULL)
			break;
		n = react_wait(e, ready, 64, engine_timeout(e));
		if (n < 0) {
			if (errno == EINTR) {
				accept_resume(e);
				expire_conns(e);
				reap(e);
				continue;
			}
			log_error("sni event wait failed: %s", strerror(errno));
			break;
		}
		for (i = 0; i < n; i++)
			dispatch_one(e, &ready[i]);
		accept_resume(e);
		expire_conns(e);
		reap(e);
		if (e->listen_fd < 0 && e->head == NULL)
			break;
	}
	if (e->sink)
		sni_resolver_sink_mark_closed(e->sink);
	{
		sni_conn *c;
		for (c = e->head; c != NULL; c = c->next)
			conn_kill(e, c, SNI_CLOSE_NONE);
	}
	reap(e);
	if (e->sink && e->sink_interest != 0) {
		react_del(e, e->sink->pipe_read);
		e->sink_interest = 0;
	}
	drain_resolve(e);
}

static void sni_engine_deinit(sni_engine *e)
{
	sni_conn *c = e->head;
	if (e->sink) {
		if (e->sink_interest != 0) {
			react_del(e, e->sink->pipe_read);
			e->sink_interest = 0;
		}
		sni_resolver_sink_mark_closed(e->sink);
		drain_resolve(e);
		sni_resolver_sink_release(e->sink);
		e->sink = NULL;
	}
	while (c) {
		sni_conn *next = c->next;
		if (!c->dead)
			conn_kill(e, c, SNI_CLOSE_NONE);
		free(c);
		c = next;
	}
	e->head = NULL;
	if (e->wake_r >= 0) {
		close(e->wake_r);
		e->wake_r = -1;
	}
	if (e->wake_w >= 0) {
		close(e->wake_w);
		e->wake_w = -1;
	}
	if (e->listen_fd >= 0) {
		close(e->listen_fd);
		e->listen_fd = -1;
	}
	reactor_close(&e->re);
}

static bool sni_engine_init(sni_engine *e, int listen_fd, const SniServer_t *cfg)
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
	if (!sni_resolver_sink_open(listen_fd >= 0 ? SNI_SINK_LISTENER : SNI_SINK_DIRECT,
			&e->sink))
		goto fail;
	sni_resolver_watch_bind(e->sink->listener_id, e->cfg.Port.bindip, e->cfg.Port.local_port);
	if (!reactor_open(&e->re, SNI_POLL_MAX, SNI_USE_POLL))
		goto fail;
	if (pipe(pipes) != 0)
		goto fail;
	e->wake_r = pipes[0];
	e->wake_w = pipes[1];
	if (!set_nb_cloexec(e->wake_r) || !set_nb_cloexec(e->wake_w))
		goto fail;
	e->wake_tag.fd = e->wake_r;
	if (!watch(e, e->wake_r, SNI_EV_IN, &e->wake_interest, &e->wake_tag))
		goto fail;
	e->sink_tag.fd = e->sink->pipe_read;
	if (!watch(e, e->sink->pipe_read, SNI_EV_IN, &e->sink_interest, &e->sink_tag))
		goto fail;
	if (listen_fd >= 0) {
		e->listen_fd = listen_fd;
		listen_fd = -1;
		if (!set_nb_cloexec(e->listen_fd))
			goto fail;
		e->listen_tag.fd = e->listen_fd;
		if (!watch(e, e->listen_fd, SNI_EV_IN, &e->listen_interest, &e->listen_tag))
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
	SniServer_t cfg = boot->cfg;
	sni_engine eng;
	free(boot);
	if (!sni_engine_init(&eng, fd, &cfg)) {
		publish_listener(ls, NULL, 0);
		return NULL;
	}
	publish_listener(ls, &eng, 1);
	sni_engine_run(&eng);
	if (ls) {
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
	do {
		n = write(e->wake_w, &byte, 1);
	} while (n < 0 && errno == EINTR);
}

bool sni_listener_open(const SniServer_t *cfg, sni_listener **out)
{
	int fd = -1;
	in_addr_t ip;
	sni_listener *ls;
	sni_boot *boot;
	if (!cfg || !out)
		return false;
	*out = NULL;
	ip = inet_addr(cfg->Port.bindip);
	if (!net_listen_ipv4(ip, cfg->Port.local_port, &fd)) {
		log_error("can not listen on Port %s:%i", cfg->Port.bindip, cfg->Port.local_port);
		return false;
	}
	log_info("socket listen on %s:%d", cfg->Port.bindip, cfg->Port.local_port);
	ls = (sni_listener *)calloc(1, sizeof(*ls));
	if (!ls) {
		close(fd);
		return false;
	}
	if (pthread_mutex_init(&ls->mu, NULL) != 0) {
		close(fd);
		free(ls);
		return false;
	}
	if (pthread_cond_init(&ls->cv, NULL) != 0) {
		pthread_mutex_destroy(&ls->mu);
		close(fd);
		free(ls);
		return false;
	}
	boot = (sni_boot *)calloc(1, sizeof(*boot));
	if (!boot) {
		pthread_cond_destroy(&ls->cv);
		pthread_mutex_destroy(&ls->mu);
		close(fd);
		free(ls);
		return false;
	}
	boot->listen_fd = fd;
	boot->cfg = *cfg;
	boot->joinable = ls;
	if (pthread_create(&ls->thread, NULL, engine_thread, boot) != 0) {
		log_error("sni listener thread create failed");
		free(boot);
		pthread_cond_destroy(&ls->cv);
		pthread_mutex_destroy(&ls->mu);
		close(fd);
		free(ls);
		return false;
	}
	pthread_mutex_lock(&ls->mu);
	while (!ls->ready)
		pthread_cond_wait(&ls->cv, &ls->mu);
	pthread_mutex_unlock(&ls->mu);
	if (!ls->ok) {
		pthread_join(ls->thread, NULL);
		pthread_cond_destroy(&ls->cv);
		pthread_mutex_destroy(&ls->mu);
		free(ls);
		return false;
	}
	*out = ls;
	return true;
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
	if (ls->sink) {
		sni_resolver_sink_release(ls->sink);
		ls->sink = NULL;
	}
	pthread_cond_destroy(&ls->cv);
	pthread_mutex_destroy(&ls->mu);
	free(ls);
}

void sni_connection_run(sniclient_t *client)
{
	sni_engine eng;
	sni_conn *c;
	int fd;
	if (!client)
		return;
	fd = client->connid;
	client->connid = -1;
	if (fd < 0 || !set_nb_cloexec(fd)) {
		if (fd >= 0)
			close(fd);
		if (client->SniConfig.sta)
			stats_close_connection(client->SniConfig.sta, 0, 0);
		return;
	}
	if (!sni_engine_init(&eng, -1, &client->SniConfig)) {
		close(fd);
		if (client->SniConfig.sta)
			stats_close_connection(client->SniConfig.sta, 0, 0);
		return;
	}
	c = conn_new(&eng, fd);
	if (!c) {
		close(fd);
		if (client->SniConfig.sta)
			stats_close_connection(client->SniConfig.sta, 0, 0);
		sni_engine_deinit(&eng);
		return;
	}
	if (!conn_start(&eng, c)) {
		if (client->SniConfig.sta)
			stats_close_connection(client->SniConfig.sta, 0, 0);
		sni_engine_run(&eng);
		sni_engine_deinit(&eng);
		return;
	}
	if (client->SniConfig.sta)
		c->close_stats = 1;
	sni_engine_run(&eng);
	sni_engine_deinit(&eng);
}

#ifdef SNI_TEST_HOOKS
void sni_test_set_faults(const sni_test_faults *faults)
{
	sni_test_faults none;
	if (!faults) {
		memset(&none, 0, sizeof(none));
		faults = &none;
	}
	__atomic_store_n(&g_read_limit, faults->read_limit, __ATOMIC_RELAXED);
	__atomic_store_n(&g_write_limit, faults->write_limit, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eagain_write, faults->eagain_write, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_read, faults->eintr_read, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_write, faults->eintr_write, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_connect, faults->eintr_connect, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_wait, faults->eintr_wait, __ATOMIC_RELAXED);
	__atomic_store_n(&g_fail_wait, faults->fail_wait, __ATOMIC_RELAXED);
	__atomic_store_n(&g_fail_allocs, faults->fail_allocs, __ATOMIC_RELAXED);
	__atomic_store_n(&g_fail_accept, faults->fail_accept, __ATOMIC_RELAXED);
}

void sni_test_clear_faults(void)
{
	sni_test_set_faults(NULL);
}

void sni_test_reset_counters(void)
{
	__atomic_store_n(&g_client_bytes, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_max_pending, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eagain, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_wait_calls, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_relay_yields, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_accept_pauses, 0u, __ATOMIC_RELAXED);
}

uint32_t sni_test_client_bytes(void)
{
	return __atomic_load_n(&g_client_bytes, __ATOMIC_RELAXED);
}

uint32_t sni_test_max_pending(void)
{
	return __atomic_load_n(&g_max_pending, __ATOMIC_RELAXED);
}

uint32_t sni_test_eagain_count(void)
{
	return __atomic_load_n(&g_eagain, __ATOMIC_RELAXED);
}

uint32_t sni_test_wait_calls(void)
{
	return __atomic_load_n(&g_wait_calls, __ATOMIC_RELAXED);
}

void sni_test_set_hello_idle_ms(int ms)
{
	if (ms <= 0)
		ms = SNI_HELLO_IDLE_MS;
	__atomic_store_n(&g_hello_idle_ms, ms, __ATOMIC_RELAXED);
}

uint32_t sni_test_accept_pauses(void)
{
	return __atomic_load_n(&g_accept_pauses, __ATOMIC_RELAXED);
}

uint32_t sni_test_relay_yields(void)
{
	return __atomic_load_n(&g_relay_yields, __ATOMIC_RELAXED);
}

void sni_test_set_relay_budget(uint32_t bytes)
{
	if (bytes == 0)
		bytes = SNI_RELAY_BUDGET;
	__atomic_store_n(&g_relay_budget, bytes, __ATOMIC_RELAXED);
}
#endif
