#define _GNU_SOURCE

/* Resolver, non-blocking connect, and SOCKS5 upstream path. */

#include "sni_internal.h"

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <zroxy/log.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>
#include <zroxy/socks5_codec.h>

static void socks_deadline(sni_conn *c)
{
	int64_t now = net_mono_ms();
	c->deadline = (now < 0) ? 0 : now + (int64_t)c->io_ms;
}

/* The codec moved to its next step: restart the I/O counters and the deadline. */
static void socks_next(sni_conn *c, s5_step step)
{
	c->socks_step = (int)step;
	c->socks_out_off = 0;
	c->socks_in_len = 0;
	socks_deadline(c);
}

void sni_socks_pump(sni_engine *e, sni_conn *c)
{
	int guard = 0;
	while (!c->dead && c->state == SNI_ST_SOCKS && guard++ < 100000) {
		if (c->socks_step == S5_SEND) {
			int wr = sni_write_some(c->up_fd, c->socks.out, (uint32_t)c->socks.out_len,
					&c->socks_out_off, NULL);
			if (wr < 0) {
				sni_conn_kill(e, c, SNI_CLOSE_SOCKS);
				return;
			}
			if (c->socks_out_off < c->socks.out_len)
				break;
			socks_next(c, socks5_client_sent(&c->socks));
		} else if (c->socks_step == S5_READ) {
			s5_step step;
			int rr;
			if (c->socks.need > SNI_SOCKS_CAP) {
				sni_conn_kill(e, c, SNI_CLOSE_SOCKS);
				return;
			}
			rr = sni_read_some(c->up_fd, c->socks_in, (uint32_t)c->socks.need, &c->socks_in_len);
			if (rr == 0)
				break;
			if (rr < 0) {
				sni_conn_kill(e, c, SNI_CLOSE_SOCKS);
				return;
			}
			if (c->socks_in_len < c->socks.need)
				break;
			step = socks5_client_feed(&c->socks, c->socks_in, c->socks_in_len);
			socks_next(c, step);
		} else if (c->socks_step == S5_DONE) {
			sni_enter_relay(e, c);
			return;
		} else {
			break;
		}
		if (c->socks_step == S5_FAIL) {
			log_error("[!] SOCKS server %s:%u: %s",
				c->cfg.Socks->host ? c->cfg.Socks->host : "?",
				(unsigned)c->cfg.Socks->port, socks5_client_strerror(&c->socks));
			sni_conn_kill(e, c, SNI_CLOSE_SOCKS);
			return;
		}
	}
	if (!c->dead && c->state == SNI_ST_SOCKS && !sni_conn_arm(e, c))
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
}

static void socks_begin(sni_engine *e, sni_conn *c)
{
	sni_conn_set_state(e, c, SNI_ST_SOCKS);
	if (!socks5_client_init(&c->socks, c->cfg.Socks->user, c->cfg.Socks->pass, c->host,
			c->cfg.Port.remote_port)) {
		sni_conn_kill(e, c, SNI_CLOSE_SOCKS);
		return;
	}
	socks_next(c, socks5_client_start(&c->socks));
	sni_socks_pump(e, c);
}

static void set_addr_port(resolver_addr *addr, uint16_t port)
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

static bool install_addrs(sni_conn *c, const resolver_addr *in, size_t n)
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

static bool install_checked(sni_conn *c, resolver_addr *in, size_t n, uint16_t port)
{
	size_t i;
	size_t kept;
	for (i = 0; i < n; i++)
		set_addr_port(&in[i], port);
	kept = resolver_policy_keep(in, n,
		(c->cfg.allow_loopback ? RESOLVER_POLICY_ALLOW_LOOPBACK : 0u) |
		(c->cfg.deny_private ? RESOLVER_POLICY_DENY_PRIVATE : 0u));
	return install_addrs(c, in, kept);
}

static void try_connect(sni_engine *e, sni_conn *c);

static void on_connected(sni_engine *e, sni_conn *c)
{
	if (c->cfg.Socks)
		socks_begin(e, c);
	else
		sni_enter_relay(e, c);
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
			sni_conn_kill(e, c, now < 0 ? SNI_CLOSE_NONE : SNI_CLOSE_HANDSHAKE_TIMEOUT);
			return;
		}
		fd = socket(fam, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) {
			c->addr_i++;
			continue;
		}
		(void)net_set_nodelay(fd);
		if (!sni_set_nb_cloexec(fd)) {
			close(fd);
			c->addr_i++;
			continue;
		}
		do {
			rc = sni_io_connect(fd, (struct sockaddr *)&addr->sa, addr->len);
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
			sni_conn_set_state(e, c, SNI_ST_CONNECT);
			if (!sni_conn_arm(e, c))
				sni_conn_kill(e, c, SNI_CLOSE_NONE);
			return;
		}
		close(fd);
		c->addr_i++;
	}
	if (!c->dead) {
		log_error("net_connect Error : Connect Failed");
		sni_conn_kill(e, c, SNI_CLOSE_CONNECT);
	}
}

void sni_connect_pump(sni_engine *e, sni_conn *c, uint32_t ev)
{
	int err = 0;
	socklen_t sl = (socklen_t)sizeof(err);
	if (getsockopt(c->up_fd, SOL_SOCKET, SO_ERROR, &err, &sl) != 0) {
		sni_conn_kill(e, c, SNI_CLOSE_CONNECT);
		return;
	}
	if ((err == 0 || err == EISCONN) && (ev & SNI_EV_OUT) != 0) {
		on_connected(e, c);
		return;
	}
	if (err == EINPROGRESS || err == EALREADY ||
			(err == 0 && (ev & SNI_EV_OUT) == 0)) {
		if (!sni_conn_arm(e, c))
			sni_conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	sni_drop_watched(e, &c->up_fd, &c->up_interest, &c->up_tag);
	c->addr_i++;
	try_connect(e, c);
}

static void start_connect(sni_engine *e, sni_conn *c)
{
	int64_t now = net_mono_ms();
	if (now < 0) {
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
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
		sni_conn_kill(e, c, SNI_CLOSE_RESOLVE);
		return;
	}
	c->resolve_deadline = now + (int64_t)c->io_ms;
	sni_conn_set_state(e, c, SNI_ST_RESOLVE);
	rc = resolver_submit(e->sink, c->index, c->generation, host, port,
			AF_INET, c->resolve_deadline, &slot, &req);
	if (rc != RESOLVER_SUBMIT_OK) {
		log_trace("resolve_overflow");
		sni_conn_kill(e, c, SNI_CLOSE_RESOLVE);
		return;
	}
	c->resolve_slot = slot;
	c->pending_req_id = req;
	if (!sni_conn_arm(e, c))
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
}

void sni_begin_upstream(sni_engine *e, sni_conn *c)
{
	resolver_addr got[RESOLVER_ADDR_MAX];
	size_t n = 0;
	int st;
	if (c->cfg.Socks) {
		if (!c->cfg.Socks->host || c->cfg.Socks->host[0] == '\0') {
			sni_conn_kill(e, c, SNI_CLOSE_SOCKS);
			return;
		}
		st = resolver_copy_upstream(c->cfg.Socks->host, c->cfg.Socks->port, got, &n);
		if (st != RESOLVER_UP_READY || !install_addrs(c, got, n)) {
			log_trace("socks_unresolved");
			sni_conn_kill(e, c, SNI_CLOSE_RESOLVE);
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
	resolver_addr addrs[RESOLVER_ADDR_MAX];
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
	if (count > RESOLVER_ADDR_MAX)
		count = RESOLVER_ADDR_MAX;
	if (count > 0)
		memcpy(addrs, slot->addresses, count * sizeof(addrs[0]));
	c = find_pending(e, slot);
	if (c)
		c->pending_req_id = 0;
	resolver_release(index, req);
	if (!c)
		return;
	if (err != 0 || count == 0) {
		log_error("%s -> %s\n", c->host, gai_strerror(err));
		sni_conn_kill(e, c, SNI_CLOSE_RESOLVE);
		return;
	}
	if (!install_checked(c, addrs, count, port)) {
		log_trace("SNI address rejected");
		sni_conn_kill(e, c, SNI_CLOSE_UNSAFE);
		return;
	}
	start_connect(e, c);
}

void sni_drain_resolve(sni_engine *e)
{
	resolve_slot *batch[RESOLVER_SLOTS];
	size_t n;
	size_t i;
	if (!e->sink)
		return;
	do {
		n = resolver_drain(e->sink, batch, RESOLVER_SLOTS);
		for (i = 0; i < n; i++)
			apply_resolve(e, batch[i]);
	} while (n == RESOLVER_SLOTS);
}
