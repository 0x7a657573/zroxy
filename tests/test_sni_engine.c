/*
 * Event-driven SNI data-plane tests. Loopback only.
 * Built with SNI_TEST_HOOKS (and optionally SNI_FORCE_POLL).
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdatomic.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <zroxy/log.h>
#include <zroxy/net.h>
#include "sni_event_loop.h"
#include "sni_resolver.h"
#include "sniclient.h"
#include <zroxy/sniproxy.h>
#include <zroxy/statistics.h>

static int failures = 0;

static const char REQ[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
static const char HOLD_REQ[] = "GET /HOLD HTTP/1.1\r\nHost: localhost\r\n\r\n";
static const char IP_REQ[] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
static const char EVIL_REQ[] = "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n";

static void expect_true(bool value, const char *name)
{
	if (!value) {
		fprintf(stderr, "FAIL: %s\n", name);
		failures++;
	}
}

static void expect_int(int actual, int expected, const char *name)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL: %s expected %d got %d\n", name, expected, actual);
		failures++;
	}
}

static int64_t mono_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void on_alarm(int sig)
{
	(void)sig;
	fprintf(stderr, "FAIL: watchdog expired\n");
	_exit(2);
}

static int set_nb(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int nodelay(int fd)
{
	int one = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static int wait_fd(int fd, short ev, int timeout_ms)
{
	struct pollfd pfd;
	int rc;
	pfd.fd = fd;
	pfd.events = ev;
	pfd.revents = 0;
	do {
		rc = poll(&pfd, 1, timeout_ms);
	} while (rc < 0 && errno == EINTR);
	if (rc <= 0)
		return -1;
	return (pfd.revents & ev) ? 0 : -1;
}

static int read_full_ms(int fd, void *buf, size_t len, int timeout_ms)
{
	uint8_t *p = (uint8_t *)buf;
	size_t off = 0;
	int64_t deadline = mono_ms() + timeout_ms;
	while (off < len) {
		ssize_t n;
		int left = (int)(deadline - mono_ms());
		if (left < 0)
			return -1;
		if (wait_fd(fd, POLLIN, left) != 0)
			return -1;
		n = read(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static int read_eof_ms(int fd, uint8_t *buf, size_t cap, size_t *out, int timeout_ms)
{
	size_t got = 0;
	int64_t deadline = mono_ms() + timeout_ms;
	while (got < cap) {
		ssize_t n;
		int left = (int)(deadline - mono_ms());
		if (left < 0)
			return -1;
		if (wait_fd(fd, POLLIN, left) != 0)
			return -1;
		n = read(fd, buf + got, cap - got);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			*out = got;
			return 0;
		}
		got += (size_t)n;
	}
	return -1;
}

static int listen_loopback(uint16_t *port)
{
	int fd;
	int one = 1;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
			listen(fd, 1024) != 0 ||
			getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
		close(fd);
		return -1;
	}
	*port = ntohs(addr.sin_port);
	return fd;
}

static int connect_local(uint16_t port, int timeout_ms)
{
	int fd;
	struct sockaddr_in addr;
	int rc;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	nodelay(fd);
	if (set_nb(fd) != 0) {
		close(fd);
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	if (rc < 0) {
		int err = 0;
		socklen_t el = sizeof(err);
		if (wait_fd(fd, POLLOUT, timeout_ms) != 0 ||
				getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
			close(fd);
			return -1;
		}
	}
	return fd;
}

static int count_dir(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *de;
	int n = 0;
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		n++;
	}
	closedir(d);
	return n;
}

static int count_threads(void)
{
	int prev = count_dir("/proc/self/task");
	int i;
	/* Ignore a resolver thread that exits between samples. */
	for (i = 0; i < 20; i++) {
		int now;
		usleep(10000);
		now = count_dir("/proc/self/task");
		if (now == prev)
			return now;
		prev = now;
	}
	return prev;
}

static int count_fds(void)
{
	return count_dir("/proc/self/fd");
}

static void raise_nofile(void)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
		return;
	if (rl.rlim_cur < 16384) {
		rl.rlim_cur = rl.rlim_max < 16384 ? rl.rlim_max : 16384;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
}

static int build_client_hello(uint8_t *out, size_t cap, size_t *out_len, const char *name)
{
	size_t hlen = strlen(name);
	size_t list_len = 3u + hlen;
	size_t ext_data = 2u + list_len;
	size_t ext_total = 4u + ext_data;
	size_t p;
	size_t record_len;
	size_t hs_len;
	if (hlen == 0 || hlen > 64 || cap < 160)
		return -1;
	memset(out, 0, cap);
	out[0] = 0x16;
	out[1] = 0x03;
	out[2] = 0x03;
	out[5] = 0x01;
	out[9] = 0x03;
	out[10] = 0x03;
	out[43] = 0;
	out[44] = 0x00;
	out[45] = 0x02;
	out[46] = 0x00;
	out[47] = 0x2f;
	out[48] = 0x01;
	out[49] = 0x00;
	out[50] = (uint8_t)(ext_total >> 8);
	out[51] = (uint8_t)ext_total;
	p = 52;
	out[p] = 0;
	out[p + 1] = 0;
	out[p + 2] = (uint8_t)(ext_data >> 8);
	out[p + 3] = (uint8_t)ext_data;
	p += 4;
	out[p] = (uint8_t)(list_len >> 8);
	out[p + 1] = (uint8_t)list_len;
	out[p + 2] = 0;
	out[p + 3] = (uint8_t)(hlen >> 8);
	out[p + 4] = (uint8_t)hlen;
	memcpy(out + p + 5, name, hlen);
	p += 5 + hlen;
	record_len = p - 5;
	out[3] = (uint8_t)(record_len >> 8);
	out[4] = (uint8_t)record_len;
	hs_len = record_len - 4;
	out[6] = (uint8_t)((hs_len >> 16) & 0xff);
	out[7] = (uint8_t)((hs_len >> 8) & 0xff);
	out[8] = (uint8_t)(hs_len & 0xff);
	*out_len = p;
	return 0;
}

static size_t first_host_len(const uint8_t *msg, size_t len)
{
	size_t i;
	char host[ZROXY_MAX_HOSTNAME];
	for (i = 1; i <= len; i++) {
		host[0] = '\0';
		if (net_get_host((uint8_t *)msg, (uint32_t)i, host, ZROXY_MAX_HOSTNAME))
			return i;
	}
	return 0;
}

static sniclient_t *make_client(int fd, uint16_t remote, int timeout,
		statistics_t *st, filter_t *wl, sockshost_t *socks)
{
	sniclient_t *c = (sniclient_t *)calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	c->connid = fd;
	memcpy(c->SniConfig.Port.bindip, "127.0.0.1", 10);
	c->SniConfig.Port.remote_port = remote;
	c->SniConfig.snitimeout = timeout;
	c->SniConfig.sta = st;
	c->SniConfig.wlist = wl;
	c->SniConfig.Socks = socks;
	return c;
}

static int wait_client_bytes(uint32_t target, int timeout_ms)
{
	int64_t deadline = mono_ms() + timeout_ms;
	while (sni_test_client_bytes() < target) {
		if (mono_ms() > deadline)
			return -1;
		usleep(1000);
	}
	return 0;
}

/* ---- single-thread echo used by the load tests ---- */

#define ECHO_MAX 160

typedef struct echo_conn {
	int fd;
	int hold;
	uint8_t pending[4096];
	size_t pend_len;
	size_t pend_off;
} echo_conn;

typedef struct echo_srv {
	int lfd;
	int wake_r;
	int wake_w;
	uint16_t port;
	pthread_t thread;
	int accepts;
	echo_conn conns[ECHO_MAX];
} echo_srv;

static int has_bytes(const uint8_t *buf, size_t n, const char *lit)
{
	size_t sl = strlen(lit);
	size_t i;
	if (n < sl)
		return 0;
	for (i = 0; i + sl <= n; i++) {
		if (memcmp(buf + i, lit, sl) == 0)
			return 1;
	}
	return 0;
}

static void echo_close_conn(echo_conn *c)
{
	if (c->fd >= 0)
		close(c->fd);
	c->fd = -1;
	c->pend_len = 0;
	c->pend_off = 0;
}

static void echo_queue(echo_conn *c, const uint8_t *buf, size_t n)
{
	if (c->hold)
		return;
	if (c->pend_len + n > sizeof(c->pending)) {
		echo_close_conn(c);
		return;
	}
	memcpy(c->pending + c->pend_len, buf, n);
	c->pend_len += n;
}

static void echo_flush(echo_conn *c)
{
	while (c->fd >= 0 && c->pend_off < c->pend_len) {
		ssize_t n = write(c->fd, c->pending + c->pend_off, c->pend_len - c->pend_off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			echo_close_conn(c);
			return;
		}
		if (n == 0) {
			echo_close_conn(c);
			return;
		}
		c->pend_off += (size_t)n;
	}
	if (c->pend_off == c->pend_len) {
		c->pend_off = 0;
		c->pend_len = 0;
	}
}

static void *echo_main(void *arg)
{
	echo_srv *srv = (echo_srv *)arg;
	int i;
	for (i = 0; i < ECHO_MAX; i++)
		srv->conns[i].fd = -1;
	for (;;) {
		struct pollfd pfds[ECHO_MAX + 2];
		int map[ECHO_MAX + 2];
		int np = 0;
		int rc;
		pfds[np].fd = srv->lfd;
		pfds[np].events = POLLIN;
		pfds[np].revents = 0;
		map[np] = -1;
		np++;
		pfds[np].fd = srv->wake_r;
		pfds[np].events = POLLIN;
		pfds[np].revents = 0;
		map[np] = -2;
		np++;
		for (i = 0; i < ECHO_MAX; i++) {
			short ev;
			if (srv->conns[i].fd < 0)
				continue;
			ev = POLLIN;
			if (srv->conns[i].pend_off < srv->conns[i].pend_len)
				ev = (short)(ev | POLLOUT);
			pfds[np].fd = srv->conns[i].fd;
			pfds[np].events = ev;
			pfds[np].revents = 0;
			map[np] = i;
			np++;
		}
		rc = poll(pfds, (nfds_t)np, 200);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (i = 0; i < np; i++) {
			echo_conn *c;
			uint8_t tmp[4096];
			ssize_t n;
			if (pfds[i].revents == 0)
				continue;
			if (map[i] == -2)
				return NULL;
			if (map[i] == -1) {
				int fd = accept(srv->lfd, NULL, NULL);
				int slot;
				if (fd < 0)
					continue;
				set_nb(fd);
				nodelay(fd);
				slot = -1;
				{
					int s;
					for (s = 0; s < ECHO_MAX; s++) {
						if (srv->conns[s].fd < 0) {
							slot = s;
							break;
						}
					}
				}
				if (slot < 0) {
					close(fd);
					continue;
				}
				memset(&srv->conns[slot], 0, sizeof(srv->conns[slot]));
				srv->conns[slot].fd = fd;
				__atomic_fetch_add(&srv->accepts, 1, __ATOMIC_RELAXED);
				continue;
			}
			c = &srv->conns[map[i]];
			if (c->fd < 0)
				continue;
			if (pfds[i].revents & (POLLERR | POLLNVAL)) {
				echo_close_conn(c);
				continue;
			}
			if (pfds[i].revents & POLLIN) {
				n = read(c->fd, tmp, sizeof(tmp));
				if (n < 0) {
					if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
						echo_close_conn(c);
				} else if (n == 0) {
					echo_flush(c);
					echo_close_conn(c);
				} else if (!c->hold && has_bytes(tmp, (size_t)n, "HOLD")) {
					c->hold = 1;
				} else if (!c->hold) {
					echo_queue(c, tmp, (size_t)n);
					echo_flush(c);
				}
			}
			if (c->fd >= 0 && (pfds[i].revents & POLLOUT))
				echo_flush(c);
		}
	}
	return NULL;
}

static int echo_start(echo_srv *srv)
{
	int pipes[2];
	memset(srv, 0, sizeof(*srv));
	srv->lfd = listen_loopback(&srv->port);
	if (srv->lfd < 0)
		return -1;
	if (set_nb(srv->lfd) != 0 || pipe(pipes) != 0) {
		close(srv->lfd);
		return -1;
	}
	srv->wake_r = pipes[0];
	srv->wake_w = pipes[1];
	set_nb(srv->wake_r);
	if (pthread_create(&srv->thread, NULL, echo_main, srv) != 0) {
		close(srv->lfd);
		close(srv->wake_r);
		close(srv->wake_w);
		return -1;
	}
	return 0;
}

static void echo_stop(echo_srv *srv)
{
	char b = 1;
	int i;
	if (srv->wake_w >= 0) {
		if (write(srv->wake_w, &b, 1) < 0)
			perror("echo wake");
	}
	pthread_join(srv->thread, NULL);
	for (i = 0; i < ECHO_MAX; i++)
		echo_close_conn(&srv->conns[i]);
	if (srv->lfd >= 0)
		close(srv->lfd);
	if (srv->wake_r >= 0)
		close(srv->wake_r);
	if (srv->wake_w >= 0)
		close(srv->wake_w);
	srv->lfd = srv->wake_r = srv->wake_w = -1;
}

static int echo_roundtrip(uint16_t port, const void *msg, size_t len, int timeout_ms)
{
	int fd = connect_local(port, timeout_ms);
	uint8_t buf[8192];
	size_t got = 0;
	if (fd < 0)
		return -1;
	if (write_full(fd, msg, len) != 0) {
		close(fd);
		return -1;
	}
	shutdown(fd, SHUT_WR);
	if (read_eof_ms(fd, buf, sizeof(buf), &got, timeout_ms) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	if (got != len || memcmp(buf, msg, len) != 0)
		return -1;
	return 0;
}

static void fill_listener(SniServer_t *cfg, uint16_t local, uint16_t remote, int timeout,
		statistics_t *st, filter_t *wl, sockshost_t *socks)
{
	memset(cfg, 0, sizeof(*cfg));
	memcpy(cfg->Port.bindip, "127.0.0.1", 10);
	cfg->Port.local_port = local;
	cfg->Port.remote_port = remote;
	cfg->snitimeout = timeout;
	cfg->sta = st;
	cfg->wlist = wl;
	cfg->Socks = socks;
}

static void state_drop(statistics_t *st)
{
	if (!st)
		return;
	pthread_mutex_destroy(&st->Lock);
	free(st);
}

static int slots_are_clear(void)
{
	int n = 0;
	int i;
	while (sni_worker_acquire())
		n++;
	for (i = 0; i < n; i++)
		sni_worker_release();
	return n == 1024;
}

/* Byte-at-a-time prefixes must not connect before net_get_host succeeds. */
static void test_split_prefixes(const uint8_t *msg, size_t len, const char *name)
{
	uint16_t port = 0;
	int lfd;
	int pair[2] = {-1, -1};
	sniclient_t *client;
	pthread_t tid = 0;
	size_t ready;
	size_t i;
	uint8_t got[4096];
	char label[128];
	lfd = listen_loopback(&port);
	expect_true(lfd >= 0, name);
	if (lfd < 0)
		return;
	set_nb(lfd);
	ready = first_host_len(msg, len);
	snprintf(label, sizeof(label), "%s host becomes visible", name);
	expect_true(ready > 1 && ready <= len, label);
	if (ready == 0) {
		close(lfd);
		return;
	}
	expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "prefix socketpair");
	if (pair[0] < 0) {
		close(lfd);
		return;
	}
	nodelay(pair[0]);
	sni_test_clear_faults();
	sni_test_reset_counters();
	client = make_client(pair[1], port, 5, NULL, NULL, NULL);
	expect_true(client != NULL, "prefix client");
	if (!client || pthread_create(&tid, NULL, sni_client_handler, client) != 0) {
		close(pair[0]);
		close(pair[1]);
		close(lfd);
		free(client);
		return;
	}
	for (i = 1; i < ready; i++) {
		snprintf(label, sizeof(label), "%s consume prefix %zu", name, i);
		expect_true(write_full(pair[0], msg + (i - 1), 1) == 0, label);
		expect_true(wait_client_bytes((uint32_t)i, 2000) == 0, label);
		snprintf(label, sizeof(label), "%s no upstream before host (%zu)", name, i);
		expect_true(wait_fd(lfd, POLLIN, 0) != 0, label);
	}
	expect_true(write_full(pair[0], msg + (ready - 1), len - (ready - 1)) == 0, "write tail");
	{
		int up = -1;
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0)
			up = accept(lfd, NULL, NULL);
		snprintf(label, sizeof(label), "%s upstream accepted", name);
		expect_true(up >= 0, label);
		if (up >= 0) {
			snprintf(label, sizeof(label), "%s full payload", name);
			expect_true(read_full_ms(up, got, len, 2000) == 0, label);
			if (failures == 0 || true) {
				if (memcmp(got, msg, len) != 0) {
					snprintf(label, sizeof(label), "%s payload bytes", name);
					expect_true(false, label);
				}
			}
			shutdown(up, SHUT_WR);
			close(up);
		}
	}
	close(pair[0]);
	pthread_join(tid, NULL);
	close(lfd);
	sni_test_clear_faults();
}

static void test_partial_write_and_eagain(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2] = {-1, -1};
	sniclient_t *client;
	pthread_t tid = 0;
	int up = -1;
	sni_test_faults faults;
	uint8_t bulk[64 * 1024];
	size_t sent = 0;
	int client_blocked = 0;
	int64_t deadline;
	int one = 1024;
	expect_true(lfd >= 0, "eagain listen");
	if (lfd < 0)
		return;
	memset(&faults, 0, sizeof(faults));
	faults.write_limit = 1;
	sni_test_set_faults(&faults);
	sni_test_reset_counters();
	expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "eagain pair");
	client = make_client(pair[1], port, 5, NULL, NULL, NULL);
	if (!client || pthread_create(&tid, NULL, sni_client_handler, client) != 0) {
		expect_true(false, "eagain handler");
		close(lfd);
		return;
	}
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "eagain request");
	{
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		expect_true(poll(&pfd, 1, 2000) > 0, "eagain upstream wait");
		up = accept(lfd, NULL, NULL);
	}
	expect_true(up >= 0, "eagain accept");
	if (up >= 0) {
		uint8_t got[128];
		setsockopt(up, SOL_SOCKET, SO_RCVBUF, &one, sizeof(one));
		expect_true(read_full_ms(up, got, sizeof(REQ) - 1, 2000) == 0, "eagain got request");
		sni_test_reset_counters();
		memset(&faults, 0, sizeof(faults));
		sni_test_set_faults(&faults);
		set_nb(pair[0]);
		faults.eagain_write = 1;
		sni_test_set_faults(&faults);
		memset(bulk, 0x61, sizeof(bulk));
		deadline = mono_ms() + 2000;
		while (mono_ms() < deadline && !client_blocked) {
			ssize_t n = write(pair[0], bulk, sizeof(bulk));
			if (n > 0) {
				sent += (size_t)n;
				continue;
			}
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				client_blocked = 1;
				break;
			}
			if (n < 0 && errno == EINTR)
				continue;
			break;
		}
		expect_true(client_blocked, "client write blocks once the relay buffer is full");
		expect_true(sent > 0, "some bytes were queued before backpressure");
		deadline = mono_ms() + 1000;
		while (mono_ms() < deadline && sni_test_max_pending() == 0)
			usleep(1000);
		expect_true(sni_test_eagain_count() > 0, "proxy write hit EAGAIN");
		expect_true(sni_test_max_pending() > 0, "pending output was observed");
		expect_true(sni_test_max_pending() <= SNI_RELAY_CAP, "pending output stays inside the cap");
		close(up);
	}
	close(pair[0]);
	pthread_join(tid, NULL);
	close(lfd);
	sni_test_clear_faults();
}

static void test_eintr_still_forwards(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	sni_test_faults faults;
	uint8_t got[128];
	int up;
	memset(&faults, 0, sizeof(faults));
	faults.eintr_read = 5;
	faults.eintr_write = 5;
	faults.eintr_connect = 3;
	faults.eintr_wait = 4;
	sni_test_set_faults(&faults);
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "eintr setup");
	if (lfd < 0)
		return;
	client = make_client(pair[1], port, 3, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "eintr handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "eintr write");
	up = -1;
	{
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0)
			up = accept(lfd, NULL, NULL);
	}
	expect_true(up >= 0, "eintr upstream");
	if (up >= 0) {
		expect_true(read_full_ms(up, got, sizeof(REQ) - 1, 2000) == 0, "eintr payload");
		expect_true(memcmp(got, REQ, sizeof(REQ) - 1) == 0, "eintr bytes");
		close(up);
	}
	close(pair[0]);
	pthread_join(tid, NULL);
	close(lfd);
	sni_test_clear_faults();
}

enum {
	SOCKS_NOAUTH = 1,
	SOCKS_AUTH,
	SOCKS_BAD_VER,
	SOCKS_BAD_METHOD,
	SOCKS_BAD_AUTH,
	SOCKS_BAD_REP
};

typedef struct socks_job {
	int lfd;
	int mode;
	const char *user;
	const char *pass;
	uint16_t upstream_port;
	int split;
	int ok;
	char host[256];
	int port;
} socks_job;

static int socks_read(int fd, void *buf, size_t len)
{
	return read_full_ms(fd, buf, len, 2000);
}

static int socks_write(int fd, const void *buf, size_t len, int split)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t off = 0;
	while (off < len) {
		size_t chunk = split ? 1 : (len - off);
		ssize_t n = write(fd, p + off, chunk);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static void socks_relay(int a, int b)
{
	int a_eof = 0;
	int b_eof = 0;
	set_nb(a);
	set_nb(b);
	while (!a_eof || !b_eof) {
		struct pollfd pfd[2];
		int nfd = 0;
		int rc;
		uint8_t buf[2048];
		if (!a_eof) {
			pfd[nfd].fd = a;
			pfd[nfd].events = POLLIN;
			pfd[nfd].revents = 0;
			nfd++;
		}
		if (!b_eof) {
			pfd[nfd].fd = b;
			pfd[nfd].events = POLLIN;
			pfd[nfd].revents = 0;
			nfd++;
		}
		if (nfd == 0)
			break;
		rc = poll(pfd, (nfds_t)nfd, 2000);
		if (rc <= 0)
			break;
		for (rc = 0; rc < nfd; rc++) {
			ssize_t n;
			int src;
			int dst;
			if ((pfd[rc].revents & POLLIN) == 0)
				continue;
			src = pfd[rc].fd;
			dst = src == a ? b : a;
			n = read(src, buf, sizeof(buf));
			if (n <= 0) {
				if (src == a)
					a_eof = 1;
				else
					b_eof = 1;
				shutdown(dst, SHUT_WR);
				continue;
			}
			if (write_full(dst, buf, (size_t)n) != 0)
				return;
		}
	}
}

static void *socks_thread(void *arg)
{
	socks_job *job = (socks_job *)arg;
	int fd = accept(job->lfd, NULL, NULL);
	uint8_t hdr[2];
	uint8_t methods[8];
	uint8_t req[512];
	uint8_t reply[16];
	int up = -1;
	job->ok = 0;
	if (fd < 0)
		return NULL;
	nodelay(fd);
	if (socks_read(fd, hdr, 2) != 0 || hdr[1] > sizeof(methods)) {
		close(fd);
		return NULL;
	}
	if (socks_read(fd, methods, hdr[1]) != 0) {
		close(fd);
		return NULL;
	}
	if (job->mode == SOCKS_BAD_VER) {
		socks_write(fd, "\x04\x00", 2, job->split);
		close(fd);
		job->ok = 1;
		return NULL;
	}
	if (job->mode == SOCKS_BAD_METHOD) {
		socks_write(fd, "\x05\xff", 2, job->split);
		close(fd);
		job->ok = 1;
		return NULL;
	}
	if (job->mode == SOCKS_AUTH || job->mode == SOCKS_BAD_AUTH) {
		uint8_t alen[2];
		uint8_t auth[512];
		size_t need;
		if (socks_write(fd, "\x05\x02", 2, job->split) != 0) {
			close(fd);
			return NULL;
		}
		if (socks_read(fd, alen, 2) != 0) {
			close(fd);
			return NULL;
		}
		need = (size_t)alen[1];
		if (need > sizeof(auth) || socks_read(fd, auth, need) != 0) {
			close(fd);
			return NULL;
		}
		if (socks_read(fd, alen, 1) != 0) {
			close(fd);
			return NULL;
		}
		if (socks_read(fd, auth + need, alen[0]) != 0) {
			close(fd);
			return NULL;
		}
		if (job->mode == SOCKS_BAD_AUTH) {
			socks_write(fd, "\x01\x01", 2, job->split);
			close(fd);
			job->ok = 1;
			return NULL;
		}
		if (job->user && (strlen(job->user) != need || memcmp(auth, job->user, need) != 0)) {
			close(fd);
			return NULL;
		}
		if (socks_write(fd, "\x01\x00", 2, job->split) != 0) {
			close(fd);
			return NULL;
		}
	} else if (socks_write(fd, "\x05\x00", 2, job->split) != 0) {
		close(fd);
		return NULL;
	}
	if (socks_read(fd, req, 4) != 0 || req[3] != 0x03) {
		close(fd);
		return NULL;
	}
	if (socks_read(fd, req + 4, 1) != 0) {
		close(fd);
		return NULL;
	}
	if (socks_read(fd, req + 5, req[4]) != 0 ||
			socks_read(fd, req + 5 + req[4], 2) != 0) {
		close(fd);
		return NULL;
	}
	memcpy(job->host, req + 5, req[4]);
	job->host[req[4]] = '\0';
	job->port = ((int)req[5 + req[4]] << 8) | req[6 + req[4]];
	if (job->mode == SOCKS_BAD_REP) {
		memset(reply, 0, sizeof(reply));
		reply[0] = 0x05;
		reply[1] = 0x05;
		reply[3] = 0x01;
		socks_write(fd, reply, 10, job->split);
		close(fd);
		job->ok = 1;
		return NULL;
	}
	memset(reply, 0, sizeof(reply));
	reply[0] = 0x05;
	reply[3] = 0x01;
	reply[4] = 127;
	socks_write(fd, reply, 10, job->split);
	up = connect_local((uint16_t)job->port, 2000);
	if (up < 0) {
		close(fd);
		return NULL;
	}
	socks_relay(fd, up);
	close(fd);
	close(up);
	job->ok = 1;
	return NULL;
}

static void test_socks_mode(int mode, int with_auth, int split, const char *name)
{
	uint16_t sport = 0;
	uint16_t eport = 0;
	int sfd = listen_loopback(&sport);
	int efd = listen_loopback(&eport);
	int pair[2];
	socks_job job;
	pthread_t stid;
	pthread_t htid = 0;
	sniclient_t *client;
	sockshost_t socks;
	uint8_t got[256];
	int up = -1;
	sni_test_faults faults;
	memset(&job, 0, sizeof(job));
	memset(&socks, 0, sizeof(socks));
	memset(&faults, 0, sizeof(faults));
	job.lfd = sfd;
	job.mode = mode;
	job.split = split;
	job.user = "alice";
	job.pass = "secret";
	socks.host = (char *)"127.0.0.1";
	socks.port = sport;
	if (with_auth) {
		socks.user = (char *)"alice";
		socks.pass = (char *)"secret";
	}
	if (split) {
		faults.read_limit = 1;
		faults.write_limit = 1;
		sni_test_set_faults(&faults);
	}
	expect_true(sfd >= 0 && efd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, name);
	if (sfd < 0 || efd < 0)
		return;
	expect_true(pthread_create(&stid, NULL, socks_thread, &job) == 0, "socks thread");
	client = make_client(pair[1], eport, 4, NULL, NULL, &socks);
	expect_true(client && pthread_create(&htid, NULL, sni_client_handler, client) == 0, "socks handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "socks client write");
	if (mode == SOCKS_NOAUTH || mode == SOCKS_AUTH) {
		struct pollfd pfd;
		pfd.fd = efd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 3000) > 0)
			up = accept(efd, NULL, NULL);
		expect_true(up >= 0, name);
		if (up >= 0) {
			expect_true(read_full_ms(up, got, sizeof(REQ) - 1, 3000) == 0, "socks upstream bytes");
			expect_true(memcmp(got, REQ, sizeof(REQ) - 1) == 0, "socks upstream match");
			expect_true(write_full(up, "OK", 2) == 0, "socks reply");
			close(up);
		}
		{
			uint8_t resp[8];
			expect_true(read_full_ms(pair[0], resp, 2, 3000) == 0, "socks client reply");
			expect_true(memcmp(resp, "OK", 2) == 0, "socks client reply bytes");
		}
		expect_true(strcmp(job.host, "localhost") == 0, "socks connect host");
		expect_int(job.port, (int)eport, "socks connect port");
	} else {
		uint8_t sink[8];
		size_t gotn = 0;
		/* Protocol failure closes the client without reaching upstream. */
		expect_true(read_eof_ms(pair[0], sink, sizeof(sink), &gotn, 3000) == 0, name);
		expect_true(gotn == 0, "rejected socks sends no payload");
		{
			struct pollfd pfd;
			pfd.fd = efd;
			pfd.events = POLLIN;
			expect_true(poll(&pfd, 1, 200) == 0, "rejected socks does not open upstream");
		}
	}
	close(pair[0]);
	pthread_join(htid, NULL);
	pthread_join(stid, NULL);
	expect_true(job.ok == 1, name);
	close(sfd);
	close(efd);
	sni_test_clear_faults();
}

static void test_connect_failure(void)
{
	int bound = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int64_t start;
	uint8_t sink[8];
	size_t got = 0;
	expect_true(bound >= 0, "bound socket");
	if (bound < 0)
		return;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	expect_true(bind(bound, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind closed port");
	expect_true(getsockname(bound, (struct sockaddr *)&addr, &len) == 0, "closed port number");
	expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "connect-fail pair");
	client = make_client(pair[1], ntohs(addr.sin_port), 2, NULL, NULL, NULL);
	start = mono_ms();
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "connect-fail handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "connect-fail request");
	expect_true(read_eof_ms(pair[0], sink, sizeof(sink), &got, 3000) == 0, "connect-fail closes");
	close(pair[0]);
	pthread_join(tid, NULL);
	expect_true(mono_ms() - start < 3000, "connect-fail returns");
	close(bound);
}

static void test_handshake_timeout(void)
{
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int64_t start;
	expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "handshake pair");
	client = make_client(pair[1], 1, 1, NULL, NULL, NULL);
	start = mono_ms();
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "handshake handler");
	pthread_join(tid, NULL);
	expect_true(mono_ms() - start >= 500, "handshake waits for the deadline");
	expect_true(mono_ms() - start < 2500, "handshake timeout does not hang");
	close(pair[0]);
}

static void test_idle_timeout(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int up = -1;
	int64_t start;
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "idle setup");
	if (lfd < 0)
		return;
	client = make_client(pair[1], port, 1, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "idle handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "idle request");
	{
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0)
			up = accept(lfd, NULL, NULL);
	}
	expect_true(up >= 0, "idle upstream accepted");
	start = mono_ms();
	pthread_join(tid, NULL);
	expect_true(mono_ms() - start < 2500, "idle forwarding timeout fires");
	close(pair[0]);
	if (up >= 0)
		close(up);
	close(lfd);
}

static int accept_ms(int lfd, int timeout_ms)
{
	if (wait_fd(lfd, POLLIN, timeout_ms) != 0)
		return -1;
	return accept(lfd, NULL, NULL);
}

/* snitimeout 0 used to arm a zero idle timer and drop the relay at once. */
static void test_zero_timeout_relays(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int up = -1;
	uint8_t req[64];
	uint8_t reply[4];
	int64_t start;
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "zero-timeout setup");
	if (lfd < 0)
		return;
	client = make_client(pair[1], port, 0, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "zero-timeout handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "zero-timeout request");
	up = accept_ms(lfd, 2000);
	expect_true(up >= 0, "zero-timeout upstream accepted");
	if (up >= 0) {
		expect_true(read_full_ms(up, req, sizeof(REQ) - 1, 2000) == 0, "zero-timeout upstream read");
		usleep(300000);
		expect_true(write_full(up, "PONG", 4) == 0, "zero-timeout reply");
	}
	expect_true(read_full_ms(pair[0], reply, sizeof(reply), 2000) == 0 &&
			memcmp(reply, "PONG", 4) == 0, "snitimeout 0 keeps an idle relay open");
	start = mono_ms();
	pthread_join(tid, NULL);
	expect_true(mono_ms() - start < 2500, "snitimeout 0 still idles out");
	close(pair[0]);
	if (up >= 0)
		close(up);
	close(lfd);
}

/* The loop may exit on its own; closing the listener afterwards must not write to its fds. */
static void test_listener_self_exit(void)
{
	SniServer_t cfg;
	sni_listener *ls = NULL;
	sni_test_faults faults;
	uint16_t local = 0;
	int binder;
	int threads;
	int probe[2] = {-1, -1};
	int64_t deadline;
	char byte;
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	fill_listener(&cfg, local, 1, 3, NULL, NULL, NULL);
	memset(&faults, 0, sizeof(faults));
	faults.fail_wait = 1;
	threads = count_threads();
	sni_test_set_faults(&faults);
	expect_true(sni_listener_open(&cfg, &ls), "self-exit listener");
	deadline = mono_ms() + 2000;
	while (count_threads() > threads && mono_ms() < deadline)
		usleep(1000);
	sni_test_clear_faults();
	expect_int(count_threads(), threads, "event loop exits on wait failure");
	/* Likely reuses the closed wake pipe numbers. */
	expect_true(pipe(probe) == 0 && set_nb(probe[0]) == 0, "self-exit probe pipe");
	sni_listener_close(ls);
	expect_true(read(probe[0], &byte, 1) < 0 && errno == EAGAIN, "close after exit writes nothing");
	if (probe[0] >= 0)
		close(probe[0]);
	if (probe[1] >= 0)
		close(probe[1]);
	expect_true(slots_are_clear(), "self-exit released slots");
}

#define BULK_LEN (1024u * 1024u)

typedef struct bulk_up {
	int lfd;
	int ok;
} bulk_up;

static void *bulk_upstream(void *arg)
{
	bulk_up *b = (bulk_up *)arg;
	uint8_t req[64];
	uint8_t chunk[4096];
	uint32_t sent = 0;
	int up = accept_ms(b->lfd, 2000);
	if (up < 0)
		return NULL;
	if (read_full_ms(up, req, sizeof(REQ) - 1, 2000) != 0) {
		close(up);
		return NULL;
	}
	while (sent < BULK_LEN) {
		uint32_t i;
		for (i = 0; i < sizeof(chunk); i++)
			chunk[i] = (uint8_t)((sent + i) * 131u);
		if (write_full(up, chunk, sizeof(chunk)) != 0)
			break;
		sent += (uint32_t)sizeof(chunk);
	}
	b->ok = sent == BULK_LEN;
	close(up);
	return NULL;
}

/* A fast transfer yields after the budget instead of holding the loop. */
static void test_relay_budget(void)
{
	uint16_t port = 0;
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	pthread_t utid = 0;
	bulk_up b;
	uint8_t *buf = (uint8_t *)malloc(BULK_LEN + 1);
	size_t got = 0;
	int intact = 1;
	size_t i;
	memset(&b, 0, sizeof(b));
	b.lfd = listen_loopback(&port);
	expect_true(buf && b.lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "budget setup");
	if (!buf || b.lfd < 0) {
		free(buf);
		return;
	}
	sni_test_reset_counters();
	/* Keep the test budget below one typical socket read on every backend. */
	sni_test_set_relay_budget(1024u);
	expect_true(pthread_create(&utid, NULL, bulk_upstream, &b) == 0, "budget upstream");
	client = make_client(pair[1], port, 5, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "budget handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "budget request");
	expect_true(read_eof_ms(pair[0], buf, BULK_LEN + 1, &got, 10000) == 0, "budget transfer ends");
	pthread_join(utid, NULL);
	expect_true(b.ok, "budget upstream sent everything");
	expect_int((int)got, (int)BULK_LEN, "budget transfer length");
	for (i = 0; i < got; i++) {
		if (buf[i] != (uint8_t)(i * 131u)) {
			intact = 0;
			break;
		}
	}
	expect_true(intact, "budget transfer is intact");
	expect_true(sni_test_relay_yields() > 0, "relay pump yields after the budget");
	close(pair[0]);
	pthread_join(tid, NULL);
	sni_test_set_relay_budget(0);
	close(b.lfd);
	free(buf);
}

static void test_client_eof_during_hello(void)
{
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int64_t start;
	expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "eof pair");
	client = make_client(pair[1], 1, 5, NULL, NULL, NULL);
	start = mono_ms();
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "eof handler");
	expect_true(write_full(pair[0], "GET /", 5) == 0, "partial hello");
	shutdown(pair[0], SHUT_WR);
	pthread_join(tid, NULL);
	expect_true(mono_ms() - start < 1000, "client EOF ends the handshake");
	close(pair[0]);
}

static void test_upstream_eof(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int up;
	uint8_t sink[64];
	size_t got = 0;
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "up-eof setup");
	if (lfd < 0)
		return;
	client = make_client(pair[1], port, 3, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "up-eof handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "up-eof request");
	up = -1;
	{
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0)
			up = accept(lfd, NULL, NULL);
	}
	expect_true(up >= 0, "up-eof accept");
	if (up >= 0) {
		uint8_t req[64];
		expect_true(read_full_ms(up, req, sizeof(REQ) - 1, 2000) == 0, "up-eof read");
		close(up);
	}
	expect_true(read_eof_ms(pair[0], sink, sizeof(sink), &got, 2000) == 0, "client sees upstream EOF");
	expect_true(got == 0, "upstream EOF with no response");
	close(pair[0]);
	pthread_join(tid, NULL);
	close(lfd);
}

static void test_half_close(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int up;
	uint8_t req[64];
	uint8_t extra[8];
	uint8_t resp[8];
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "half setup");
	if (lfd < 0)
		return;
	client = make_client(pair[1], port, 3, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "half handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "half request");
	shutdown(pair[0], SHUT_WR);
	up = -1;
	{
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0)
			up = accept(lfd, NULL, NULL);
	}
	expect_true(up >= 0, "half accept");
	if (up >= 0) {
		size_t got = 0;
		uint8_t all[128];
		expect_true(read_eof_ms(up, all, sizeof(all), &got, 2000) == 0, "upstream sees client half-close");
		expect_true(got == sizeof(REQ) - 1 && memcmp(all, REQ, got) == 0, "half-close flushed the request");
		expect_true(write_full(up, "OK", 2) == 0, "half reply");
		close(up);
	}
	expect_true(read_full_ms(pair[0], resp, 2, 2000) == 0, "client got reply after its half-close");
	expect_true(memcmp(resp, "OK", 2) == 0, "half reply bytes");
	close(pair[0]);
	pthread_join(tid, NULL);
	close(lfd);
	(void)req;
	(void)extra;
}

static void test_upstream_half_close(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	int up;
	uint8_t req[64];
	uint8_t more[4];
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "up-half setup");
	if (lfd < 0)
		return;
	client = make_client(pair[1], port, 3, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "up-half handler");
	expect_true(write_full(pair[0], REQ, sizeof(REQ) - 1) == 0, "up-half request");
	up = -1;
	{
		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0)
			up = accept(lfd, NULL, NULL);
	}
	expect_true(up >= 0, "up-half accept");
	if (up >= 0) {
		expect_true(read_full_ms(up, req, sizeof(REQ) - 1, 2000) == 0, "up-half read request");
		expect_true(write_full(up, "OK", 2) == 0, "up-half reply");
		shutdown(up, SHUT_WR);
		expect_true(read_full_ms(pair[0], more, 2, 2000) == 0, "client reads upstream half-close data");
		expect_true(memcmp(more, "OK", 2) == 0, "upstream half-close bytes");
		expect_true(write_full(pair[0], "MORE", 4) == 0, "client writes after upstream half-close");
		expect_true(read_full_ms(up, more, 4, 2000) == 0, "upstream still reads after SHUT_WR");
		expect_true(memcmp(more, "MORE", 4) == 0, "post half-close payload");
		close(up);
	}
	close(pair[0]);
	pthread_join(tid, NULL);
	close(lfd);
}

static void test_oversize_hello(void)
{
	uint16_t port = 0;
	int lfd = listen_loopback(&port);
	int pair[2];
	sniclient_t *client;
	pthread_t tid = 0;
	uint8_t big[SNI_HELLO_CAP];
	struct pollfd pfd;
	expect_true(lfd >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "oversize setup");
	if (lfd < 0)
		return;
	memset(big, 'A', sizeof(big));
	client = make_client(pair[1], port, 3, NULL, NULL, NULL);
	expect_true(client && pthread_create(&tid, NULL, sni_client_handler, client) == 0, "oversize handler");
	expect_true(write_full(pair[0], big, sizeof(big)) == 0, "write oversized hello");
	pthread_join(tid, NULL);
	pfd.fd = lfd;
	pfd.events = POLLIN;
	expect_true(poll(&pfd, 1, 200) == 0, "oversize hello never connects upstream");
	close(pair[0]);
	close(lfd);
}

static void test_alloc_failure(void)
{
	echo_srv echo;
	sni_listener *ls = NULL;
	SniServer_t cfg;
	statistics_t *st = NULL;
	uint16_t local = 0;
	int binder;
	sni_test_faults faults;
	int fd;
	uint8_t sink[8];
	size_t got = 0;
	stat_t snap;
	expect_true(echo_start(&echo) == 0, "alloc echo");
	binder = listen_loopback(&local);
	expect_true(binder >= 0, "alloc port");
	if (binder >= 0)
		close(binder);
	stats_init(&st, "sni-alloc");
	fill_listener(&cfg, local, echo.port, 2, st, NULL, NULL);
	expect_true(sni_listener_open(&cfg, &ls), "alloc listener");
	memset(&faults, 0, sizeof(faults));
	faults.fail_allocs = 1;
	sni_test_set_faults(&faults);
	fd = connect_local(local, 1000);
	expect_true(fd >= 0, "alloc connect");
	if (fd >= 0) {
		expect_true(read_eof_ms(fd, sink, sizeof(sink), &got, 1000) == 0, "alloc failure closes");
		close(fd);
	}
	usleep(50000);
	stats_get(st, &snap);
	expect_int((int)snap.ActiveConnection, 0, "alloc failure does not stick active");
	expect_int((int)snap.TotalConnection, 0, "alloc failure is not a completed connection");
	expect_true(slots_are_clear(), "alloc failure released its slot");
	sni_test_clear_faults();
	/* A later connection still works. */
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "forward after alloc failure");
	sni_listener_close(ls);
	echo_stop(&echo);
	stats_get(st, &snap);
	expect_int((int)snap.ActiveConnection, 0, "active after alloc test");
	expect_int((int)snap.TotalConnection, 1, "only the successful connection was counted");
	state_drop(st);
}

static void test_stats_once(void)
{
	echo_srv echo;
	sni_listener *ls = NULL;
	SniServer_t cfg;
	statistics_t *st = NULL;
	uint16_t local = 0;
	int binder;
	stat_t snap;
	int i;
	int pair[2];
	expect_true(echo_start(&echo) == 0, "stats echo");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	stats_init(&st, "sni-stats");
	fill_listener(&cfg, local, echo.port, 1, st, NULL, NULL);
	expect_true(sni_listener_open(&cfg, &ls), "stats listener");
	for (i = 0; i < 2; i++)
		expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "stats success");
	{
		int fd = connect_local(local, 1000);
		expect_true(fd >= 0, "stats ip connect");
		if (fd >= 0) {
			uint8_t sink[8];
			size_t got = 0;
			write_full(fd, IP_REQ, sizeof(IP_REQ) - 1);
			read_eof_ms(fd, sink, sizeof(sink), &got, 2000);
			close(fd);
		}
	}
	expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "unused");
	close(pair[0]);
	close(pair[1]);
	{
		int fd = connect_local(local, 1000);
		expect_true(fd >= 0, "stats timeout connect");
		if (fd >= 0) {
			uint8_t sink[8];
			size_t got = 0;
			read_eof_ms(fd, sink, sizeof(sink), &got, 2500);
			close(fd);
		}
	}
	usleep(100000);
	stats_get(st, &snap);
	expect_int((int)snap.ActiveConnection, 0, "stats active back to zero");
	expect_int((int)snap.TotalConnection, 4, "stats counted each accepted connection once");
	expect_true(snap.TotalTx == (uint64_t)(sizeof(REQ) - 1) * 2, "tx counted on the successes only");
	expect_true(snap.TotalRx == (uint64_t)(sizeof(REQ) - 1) * 2, "rx counted on the successes only");
	expect_true(snap.MaxConnection >= 1, "max connection observed");
	sni_listener_close(ls);
	echo_stop(&echo);
	stats_get(st, &snap);
	expect_int((int)snap.ActiveConnection, 0, "stats stay zero after listener stop");
	expect_int((int)snap.TotalConnection, 4, "listener stop does not count twice");
	state_drop(st);
}

static void test_whitelist_and_ip(void)
{
	echo_srv echo;
	sni_listener *ls = NULL;
	SniServer_t cfg;
	static const char *const allow[] = { "localhost" };
	filter_t *wl;
	uint16_t local = 0;
	int binder;
	int before;
	uint8_t sink[8];
	size_t got;
	int fd;
	wl = filter_from_list(allow, 1);
	expect_true(wl != NULL, "build whitelist");
	expect_true(echo_start(&echo) == 0, "filter echo");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	fill_listener(&cfg, local, echo.port, 2, NULL, wl, NULL);
	expect_true(sni_listener_open(&cfg, &ls), "filter listener");
	before = __atomic_load_n(&echo.accepts, __ATOMIC_RELAXED);
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, EVIL_REQ, sizeof(EVIL_REQ) - 1) == 0, "deny write");
	got = 0;
	if (fd >= 0) {
		read_eof_ms(fd, sink, sizeof(sink), &got, 2000);
		close(fd);
	}
	usleep(50000);
	expect_int(__atomic_load_n(&echo.accepts, __ATOMIC_RELAXED), before, "whitelist deny does not connect");
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, IP_REQ, sizeof(IP_REQ) - 1) == 0, "ip write");
	got = 0;
	if (fd >= 0) {
		read_eof_ms(fd, sink, sizeof(sink), &got, 2000);
		close(fd);
	}
	usleep(50000);
	expect_int(__atomic_load_n(&echo.accepts, __ATOMIC_RELAXED), before, "IP literal does not connect");
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "whitelist allow forwards");
	expect_true(__atomic_load_n(&echo.accepts, __ATOMIC_RELAXED) > before, "allow reached upstream");
	sni_listener_close(ls);
	echo_stop(&echo);
	filter_free(wl);
}

static void test_two_listeners(void)
{
	echo_srv a;
	echo_srv b;
	sni_listener *la = NULL;
	sni_listener *lb = NULL;
	SniServer_t ca;
	SniServer_t cb;
	uint16_t pa = 0;
	uint16_t pb = 0;
	int ba;
	int bb;
	int threads;
	expect_true(echo_start(&a) == 0 && echo_start(&b) == 0, "two echoes");
	ba = listen_loopback(&pa);
	bb = listen_loopback(&pb);
	if (ba >= 0)
		close(ba);
	if (bb >= 0)
		close(bb);
	fill_listener(&ca, pa, a.port, 3, NULL, NULL, NULL);
	fill_listener(&cb, pb, b.port, 3, NULL, NULL, NULL);
	threads = count_threads();
	expect_true(sni_listener_open(&ca, &la) && sni_listener_open(&cb, &lb), "two listeners");
	expect_int(count_threads(), threads + 2, "one event loop per listener");
	expect_true(echo_roundtrip(pa, REQ, sizeof(REQ) - 1, 2000) == 0, "listener A");
	expect_true(echo_roundtrip(pb, REQ, sizeof(REQ) - 1, 2000) == 0, "listener B");
	expect_int(count_threads(), threads + 2, "second exchange adds no threads");
	sni_listener_close(la);
	sni_listener_close(lb);
	expect_int(count_threads(), threads, "listener threads joined");
	echo_stop(&a);
	echo_stop(&b);
}

static void test_load_and_threads(void)
{
	echo_srv echo;
	sni_listener *ls = NULL;
	sni_listener *extra = NULL;
	SniServer_t cfg;
	uint16_t local = 0;
	int binder;
	int base_threads;
	int base_fds;
	int i;
	int n;
	const int steps[] = {1, 10, 100, 1000};
	expect_true(echo_start(&echo) == 0, "load echo");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	fill_listener(&cfg, local, echo.port, 3, NULL, NULL, NULL);
	base_threads = count_threads();
	expect_true(sni_listener_open(&cfg, &ls), "load listener");
	expect_int(count_threads(), base_threads + 1, "listener adds one thread");
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "warmup");
	base_threads = count_threads();
	base_fds = count_fds();
	for (n = 0; n < 4; n++) {
		char label[64];
		for (i = 0; i < steps[n]; i++) {
			if (echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) != 0) {
				snprintf(label, sizeof(label), "sequential exchange %d/%d", i, steps[n]);
				expect_true(false, label);
				break;
			}
		}
		snprintf(label, sizeof(label), "threads after %d connections", steps[n]);
		expect_int(count_threads(), base_threads, label);
	}
	expect_true(count_fds() <= base_fds + 2, "no fd leak after 1111 short connections");
	/* Concurrent burst while sampling threads. */
	{
		int fds[100];
		int up_ok = 0;
		for (i = 0; i < 100; i++)
			fds[i] = -1;
		for (i = 0; i < 100; i++) {
			fds[i] = connect_local(local, 2000);
			if (fds[i] < 0)
				break;
			if (write_full(fds[i], REQ, sizeof(REQ) - 1) != 0)
				break;
			shutdown(fds[i], SHUT_WR);
		}
		expect_int(count_threads(), base_threads, "threads during 100 in flight");
		for (i = 0; i < 100; i++) {
			uint8_t buf[128];
			size_t got = 0;
			if (fds[i] < 0)
				continue;
			if (read_eof_ms(fds[i], buf, sizeof(buf), &got, 2000) == 0 &&
					got == sizeof(REQ) - 1 && memcmp(buf, REQ, got) == 0)
				up_ok++;
			close(fds[i]);
		}
		expect_int(up_ok, 100, "100 concurrent exchanges");
		expect_int(count_threads(), base_threads, "threads after the burst");
	}
	/* Long-lived connection stays up across short ones. */
	{
		int live = connect_local(local, 2000);
		uint8_t buf[128];
		expect_true(live >= 0, "long-lived connect");
		if (live >= 0) {
			expect_true(write_full(live, REQ, sizeof(REQ) - 1) == 0, "long-lived write");
			expect_true(read_full_ms(live, buf, sizeof(REQ) - 1, 2000) == 0, "long-lived echo");
			for (i = 0; i < 30; i++)
				expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "short beside long");
			expect_true(write_full(live, "PING", 4) == 0, "long-lived second write");
			expect_true(read_full_ms(live, buf, 4, 2000) == 0 && memcmp(buf, "PING", 4) == 0,
					"long-lived still relays");
			expect_int(count_threads(), base_threads, "long-lived did not add threads");
			close(live);
		}
	}
	/* Second listener. */
	{
		uint16_t extra_port = 0;
		int eb = listen_loopback(&extra_port);
		SniServer_t cfg2;
		if (eb >= 0)
			close(eb);
		fill_listener(&cfg2, extra_port, echo.port, 3, NULL, NULL, NULL);
		expect_true(sni_listener_open(&cfg2, &extra), "extra listener");
		expect_int(count_threads(), base_threads + 1, "two listeners, two loops");
		expect_true(echo_roundtrip(extra_port, REQ, sizeof(REQ) - 1, 2000) == 0, "extra listener forwards");
		sni_listener_close(extra);
		expect_int(count_threads(), base_threads, "extra listener joined");
	}
	expect_true(count_fds() <= base_fds + 4, "fds settled after the load test");
	sni_listener_close(ls);
	echo_stop(&echo);
	expect_true(slots_are_clear(), "load test released every slot");
}

static void test_stall_stays_responsive(void)
{
	echo_srv echo;
	sni_listener *ls = NULL;
	SniServer_t cfg;
	uint16_t local = 0;
	int binder;
	int hold;
	int i;
	int64_t start;
	int base;
	expect_true(echo_start(&echo) == 0, "stall echo");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	fill_listener(&cfg, local, echo.port, 30, NULL, NULL, NULL);
	expect_true(sni_listener_open(&cfg, &ls), "stall listener");
	hold = connect_local(local, 2000);
	expect_true(hold >= 0 && write_full(hold, HOLD_REQ, sizeof(HOLD_REQ) - 1) == 0, "open hold");
	usleep(100000);
	base = count_threads();
	start = mono_ms();
	for (i = 0; i < 20; i++)
		expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "progress while upstream is stalled");
	expect_true(mono_ms() - start < 5000, "stalled upstream does not freeze the listener");
	expect_int(count_threads(), base, "stall did not create workers");
	close(hold);
	usleep(100000);
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "works after the hold closes");
	sni_listener_close(ls);
	echo_stop(&echo);
	expect_true(slots_are_clear(), "stall test released slots");
}

static void test_connection_cap(void)
{
	sni_listener *ls = NULL;
	SniServer_t cfg;
	uint16_t local = 0;
	int binder;
	int *fds;
	int i;
	int opened = 0;
	int refused;
	int base;
	struct rlimit rl;
	stat_t snap;
	statistics_t *st = NULL;
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur < 4096) {
		fprintf(stderr, "SKIP: connection cap needs a higher RLIMIT_NOFILE (have %lu)\n",
				(unsigned long)rl.rlim_cur);
		return;
	}
	fds = (int *)calloc(1024, sizeof(int));
	expect_true(fds != NULL, "cap storage");
	if (!fds)
		return;
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	stats_init(&st, "sni-cap");
	fill_listener(&cfg, local, 1, 180, st, NULL, NULL);
	base = count_threads();
	sni_test_set_hello_idle_ms(180000);
	expect_true(sni_listener_open(&cfg, &ls), "cap listener");
	expect_int(count_threads(), base + 1, "cap listener thread");
	for (i = 0; i < 1024; i++) {
		int j;
		fds[i] = connect_local(local, 2000);
		if (fds[i] < 0)
			break;
		if (write(fds[i], "G", 1) != 1) {
			close(fds[i]);
			fds[i] = -1;
			break;
		}
		opened++;
		/* A byte resets the 5s handshake idle once the loop reads it. */
		if ((opened % 64) == 0) {
			for (j = 0; j < opened; j++) {
				ssize_t n = write(fds[j], "G", 1);
				(void)n;
			}
		}
	}
	expect_int(opened, 1024, "opened the connection cap");
	{
		int64_t deadline = mono_ms() + 20000;
		do {
			int j;
			stats_get(st, &snap);
			if (snap.ActiveConnection >= 1024)
				break;
			for (j = 0; j < opened; j++) {
				ssize_t n = write(fds[j], "G", 1);
				(void)n;
			}
			usleep(50000);
		} while (mono_ms() < deadline);
	}
	expect_int(count_threads(), base + 1, "1024 connections did not add threads");
	refused = connect_local(local, 1000);
	expect_true(refused >= 0, "refused connect still completes the handshake");
	if (refused >= 0) {
		uint8_t sink[8];
		size_t got = 99;
		expect_true(read_eof_ms(refused, sink, sizeof(sink), &got, 5000) == 0, "cap refusal closes");
		expect_true(got == 0, "cap refusal has no payload");
		close(refused);
	}
	stats_get(st, &snap);
	expect_int((int)snap.ActiveConnection, 1024, "active matches the cap");
	for (i = 0; i < opened; i++)
		close(fds[i]);
	{
		int64_t deadline = mono_ms() + 15000;
		do {
			stats_get(st, &snap);
			if (snap.ActiveConnection == 0)
				break;
			usleep(20000);
		} while (mono_ms() < deadline);
	}
	stats_get(st, &snap);
	expect_int((int)snap.ActiveConnection, 0, "cap connections drained");
	expect_int((int)snap.TotalConnection, 1024, "refused connection was not counted");
	expect_int(count_threads(), base + 1, "threads after draining the cap");
	sni_listener_close(ls);
	sni_test_set_hello_idle_ms(SNI_HELLO_IDLE_MS);
	expect_true(slots_are_clear(), "cap slots released");
	state_drop(st);
	free(fds);
}

static void test_stress_cycles(void)
{
	echo_srv echo;
	sni_listener *ls = NULL;
	SniServer_t cfg;
	uint16_t local = 0;
	int binder;
	int holds[8];
	int i;
	int base_threads;
	int base_fds;
	int hi = 0;
	expect_true(echo_start(&echo) == 0, "stress echo");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	fill_listener(&cfg, local, echo.port, 15, NULL, NULL, NULL);
	expect_true(sni_listener_open(&cfg, &ls), "stress listener");
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "stress warmup");
	base_threads = count_threads();
	base_fds = count_fds();
	for (i = 0; i < 8; i++)
		holds[i] = -1;
	for (i = 0; i < 200; i++) {
		if (i % 25 == 0 && hi < 8) {
			holds[hi] = connect_local(local, 2000);
			if (holds[hi] >= 0)
				write_full(holds[hi], HOLD_REQ, sizeof(HOLD_REQ) - 1);
			hi++;
			continue;
		}
		if (echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) != 0) {
			expect_true(false, "stress cycle");
			break;
		}
	}
	expect_int(count_threads(), base_threads, "stress threads stayed at the event-loop count");
	for (i = 0; i < hi; i++) {
		if (holds[i] >= 0)
			close(holds[i]);
	}
	usleep(100000);
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "after stress");
	expect_int(count_threads(), base_threads, "threads after stress");
	expect_true(count_fds() <= base_fds + 4, "no fd leak after stress");
	sni_listener_close(ls);
	echo_stop(&echo);
	expect_true(slots_are_clear(), "stress released slots");
}

static void test_production_spawn(void)
{
	pid_t pid = fork();
	int status = 0;
	expect_true(pid >= 0, "fork production spawn");
	if (pid < 0)
		return;
	if (pid == 0) {
		echo_srv echo;
		SniServer_t cfg;
		uint16_t local = 0;
		int binder;
		int rc;
		if (echo_start(&echo) != 0)
			_exit(3);
		binder = listen_loopback(&local);
		if (binder >= 0)
			close(binder);
		fill_listener(&cfg, local, echo.port, 3, NULL, NULL, NULL);
		if (!sniproxy_start(&cfg))
			_exit(4);
		rc = echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000);
		echo_stop(&echo);
		_exit(rc == 0 ? 0 : 5);
	}
	expect_true(waitpid(pid, &status, 0) == pid, "wait production child");
	expect_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, "sniproxy_start forwarded");
}

static void test_tls_hello_builds(void)
{
	uint8_t hello[256];
	size_t len = 0;
	char host[ZROXY_MAX_HOSTNAME];
	expect_true(build_client_hello(hello, sizeof(hello), &len, "localhost") == 0, "build hello");
	expect_true(net_get_host(hello, (uint32_t)len, host, ZROXY_MAX_HOSTNAME), "parser accepts built hello");
	expect_true(strcmp(host, "localhost") == 0, "built hello name");
}

static void expect_pool(const char *name)
{
	sni_resolver_accounting a;
	int sum;
	if (!sni_resolver_test_accounting(&a)) {
		expect_true(false, name);
		return;
	}
	sum = a.free_n + a.queued + a.running + a.done + a.cancelled + a.in_ring;
	expect_int(sum, SNI_RESOLVER_SLOTS, name);
	expect_int(a.double_free, 0, name);
}

static void resolver_quiet(void)
{
	/*
	 * Reap cancels queued slots and unpauses under one lock. Unpausing first
	 * would let workers resolve them into a ring nobody drains.
	 */
	sni_resolver_test_hold_running(0);
	sni_resolver_test_reap();
}

static void resolver_settle(const char *name)
{
	resolver_quiet();
	expect_true(sni_resolver_test_wait_idle(3000) != 0, name);
	expect_pool(name);
}

static void release_slot(resolve_slot *slot)
{
	if (slot)
		sni_resolver_release(slot->index, slot->req_id);
}

static resolve_slot *wait_one(sni_completion_sink *sink, int ms)
{
	int64_t deadline = mono_ms() + ms;
	while (mono_ms() < deadline) {
		resolve_slot *batch[8];
		size_t n = sni_resolver_drain(sink, batch, 8);
		size_t i;
		if (n > 0) {
			for (i = 1; i < n; i++)
				release_slot(batch[i]);
			return batch[0];
		}
		usleep(1000);
	}
	return NULL;
}

static void set_port_test(sni_resolved_addr *addr, uint16_t port);

typedef struct drain_pack {
	sni_completion_sink *sink;
	resolve_slot **got;
	int *gotn;
	int want;
} drain_pack;

static void *race_drain(void *arg);

static void fill_v4(sni_resolved_addr *out, size_t *count, const char *ip)
{
	struct sockaddr_in in;
	memset(&in, 0, sizeof(in));
	memset(out, 0, sizeof(*out));
	in.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &in.sin_addr);
	memcpy(&out->address, &in, sizeof(in));
	out->length = (socklen_t)sizeof(in);
	*count = 1;
}

static void fill_v6(sni_resolved_addr *out, size_t *count, const char *ip)
{
	struct sockaddr_in6 in6;
	memset(&in6, 0, sizeof(in6));
	memset(out, 0, sizeof(*out));
	in6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ip, &in6.sin6_addr);
	memcpy(&out->address, &in6, sizeof(in6));
	out->length = (socklen_t)sizeof(in6);
	*count = 1;
}

enum {
	HOOK_V4 = 1,
	HOOK_V6,
	HOOK_ERR,
	HOOK_EINTR,
	HOOK_DELAY,
	HOOK_ORDER,
	HOOK_MAPPED
};

typedef struct hook_cfg {
	_Atomic int mode;
	_Atomic int err;
	_Atomic int eintr_left;
	_Atomic int calls;
	_Atomic int delay_ms;
	_Atomic int release_first;
} hook_cfg;

static pthread_mutex_t g_hook_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hook_cv = PTHREAD_COND_INITIALIZER;

static int test_hook(const char *hostname, int family, sni_resolved_addr *out,
		size_t max_out, size_t *count, void *cookie)
{
	hook_cfg *cfg = (hook_cfg *)cookie;
	(void)family;
	atomic_fetch_add_explicit(&cfg->calls, 1, memory_order_relaxed);
	*count = 0;
	if (max_out == 0)
		return EAI_FAIL;
	if (cfg->mode == HOOK_EINTR && atomic_load_explicit(&cfg->eintr_left, memory_order_relaxed) > 0) {
		atomic_fetch_sub_explicit(&cfg->eintr_left, 1, memory_order_relaxed);
		errno = EINTR;
		return EAI_SYSTEM;
	}
	if (cfg->mode == HOOK_DELAY && cfg->delay_ms > 0)
		usleep((useconds_t)cfg->delay_ms * 1000u);
	if (cfg->mode == HOOK_ORDER && strcmp(hostname, "first.test") == 0) {
		/* Held until the test has drained second.test's completion. */
		struct timespec ts;
		pthread_mutex_lock(&g_hook_mu);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 5;
		while (!cfg->release_first) {
			if (pthread_cond_timedwait(&g_hook_cv, &g_hook_mu, &ts) == ETIMEDOUT)
				break;
		}
		pthread_mutex_unlock(&g_hook_mu);
	}
	if (cfg->mode == HOOK_ERR)
		return cfg->err;
	if (cfg->mode == HOOK_V6) {
		fill_v6(out, count, "::1");
		return 0;
	}
	if (cfg->mode == HOOK_MAPPED) {
		fill_v6(out, count, "::ffff:127.0.0.1");
		return 0;
	}
	fill_v4(out, count, "127.0.0.1");
	return 0;
}

static int submit_name(sni_completion_sink *sink, const char *host, int64_t deadline,
		int *slot, uint64_t *req)
{
	return sni_resolver_submit(sink, 1, 1, host, 9, AF_UNSPEC, deadline, slot, req);
}

static void test_normalize(void)
{
	char out[SNI_RESOLVER_HOST_MAX + 1];
	char big[300];
	memset(big, 'a', sizeof(big));
	big[sizeof(big) - 1] = '\0';
	expect_true(sni_resolver_normalize("Example.COM", out, sizeof(out)), "normalize case");
	expect_true(strcmp(out, "example.com") == 0, "normalized lowercase");
	expect_true(sni_resolver_normalize("Example.COM.", out, sizeof(out)), "normalize dot");
	expect_true(strcmp(out, "example.com") == 0, "trailing dot stripped");
	expect_true(!sni_resolver_normalize("", out, sizeof(out)), "empty rejected");
	expect_true(!sni_resolver_normalize(".", out, sizeof(out)), "lone dot rejected");
	expect_true(!sni_resolver_normalize("-bad.com", out, sizeof(out)), "leading hyphen rejected");
	expect_true(!sni_resolver_normalize("bad-.com", out, sizeof(out)), "trailing hyphen rejected");
	expect_true(!sni_resolver_normalize("bad..com", out, sizeof(out)), "empty label rejected");
	expect_true(!sni_resolver_normalize(big, out, sizeof(out)), "overlong rejected");
	{
		int pos = 0;
		int label;
		for (label = 0; label < 3; label++) {
			int k;
			for (k = 0; k < 63; k++)
				big[pos++] = 'a';
			big[pos++] = '.';
		}
		while (pos < 253)
			big[pos++] = 'b';
		big[253] = '\0';
	}
	expect_true(sni_resolver_normalize(big, out, sizeof(out)), "253 bytes accepted");
}

static void test_policy_addresses(void)
{
	sni_completion_sink *sink = NULL;
	sni_resolved_addr addr;
	size_t n;
	expect_true(sni_resolver_sink_open(SNI_SINK_LISTENER, &sink), "policy sink");
	sni_resolver_watch_bind(sink->listener_id, "127.0.0.1", 9);
	fill_v4(&addr, &n, "127.0.0.1");
	set_port_test(&addr, 9);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 0, "self connect dropped");
	fill_v6(&addr, &n, "::ffff:127.0.0.1");
	set_port_test(&addr, 9);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 0, "mapped loopback dropped");
	fill_v4(&addr, &n, "127.0.0.1");
	set_port_test(&addr, 10);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 1, "other loopback port kept");
	fill_v4(&addr, &n, "10.1.2.3");
	set_port_test(&addr, 9);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 1, "private kept");
	fill_v4(&addr, &n, "169.254.1.1");
	set_port_test(&addr, 9);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 0, "link local dropped");
	fill_v4(&addr, &n, "0.0.0.0");
	set_port_test(&addr, 9);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 0, "unspecified dropped");
	sni_resolver_sink_release(sink);
	expect_true(sni_resolver_sink_open(SNI_SINK_DIRECT, &sink), "wildcard sink");
	sni_resolver_watch_bind(sink->listener_id, "0.0.0.0", 1);
	fill_v4(&addr, &n, "127.0.0.1");
	set_port_test(&addr, 80);
	expect_int((int)sni_resolver_policy_keep(&addr, 1), 0, "wildcard rejects loopback");
	sni_resolver_sink_release(sink);
	sink = NULL;
}

static void set_port_test(sni_resolved_addr *addr, uint16_t port)
{
	struct sockaddr *sa = (struct sockaddr *)&addr->address;
	if (sa->sa_family == AF_INET)
		((struct sockaddr_in *)sa)->sin_port = htons(port);
	else if (sa->sa_family == AF_INET6)
		((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
}

static void test_resolver_results(void)
{
	sni_completion_sink *sink = NULL;
	hook_cfg cfg;
	resolve_slot *slot;
	sni_resolver_counters st;
	int idx = -1;
	uint64_t req = 0;
	int64_t start;
	memset(&cfg, 0, sizeof(cfg));
	expect_true(sni_resolver_sink_open(SNI_SINK_DIRECT, &sink), "result sink");
	cfg.mode = HOOK_V4;
	sni_resolver_test_set_hook(test_hook, &cfg);
	sni_resolver_test_reset_stats();
	expect_int(submit_name(sink, "v4.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "v4 submit");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && slot->gai_error == 0 && slot->address_count == 1, "v4 result");
	if (slot) {
		struct sockaddr_in in;
		memcpy(&in, &slot->addresses[0].address, sizeof(in));
		expect_int(in.sin_family, AF_INET, "v4 family");
		release_slot(slot);
	}
	cfg.mode = HOOK_V6;
	cfg.calls = 0;
	expect_int(submit_name(sink, "v6.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "v6 submit");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && slot->gai_error == 0, "v6 result");
	if (slot) {
		struct sockaddr_in6 in6;
		memcpy(&in6, &slot->addresses[0].address, sizeof(in6));
		expect_int(in6.sin6_family, AF_INET6, "v6 family");
		release_slot(slot);
	}
	cfg.mode = HOOK_ERR;
	cfg.err = EAI_NONAME;
	expect_int(submit_name(sink, "none.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "noname submit");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && slot->gai_error == EAI_NONAME, "EAI_NONAME");
	release_slot(slot);
	cfg.err = EAI_AGAIN;
	expect_int(submit_name(sink, "again.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "again submit");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && slot->gai_error == EAI_AGAIN, "EAI_AGAIN");
	release_slot(slot);
	cfg.err = EAI_FAIL;
	expect_int(submit_name(sink, "fail.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "fail submit");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && slot->gai_error == EAI_FAIL, "EAI_FAIL");
	release_slot(slot);
	cfg.mode = HOOK_EINTR;
	cfg.eintr_left = 2;
	cfg.calls = 0;
	sni_resolver_test_reset_stats();
	expect_int(submit_name(sink, "eintr.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "eintr submit");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && slot->gai_error == 0, "EINTR then success");
	sni_resolver_test_stats(&st);
	expect_true(st.calls >= 3, "EINTR retried");
	release_slot(slot);
	cfg.mode = HOOK_DELAY;
	cfg.delay_ms = 200;
	start = mono_ms();
	expect_int(submit_name(sink, "slow.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "delay submit");
	expect_true(mono_ms() - start < 100, "submit does not wait for lookup");
	slot = wait_one(sink, 2000);
	expect_true(slot != NULL && mono_ms() - start >= 150, "delayed lookup");
	release_slot(slot);
	sni_resolver_test_pause_dequeue(1);
	sni_resolver_test_reset_stats();
	cfg.mode = HOOK_V4;
	cfg.calls = 0;
	expect_int(submit_name(sink, "expired.test", 1, &idx, &req), SNI_SUBMIT_OK, "expired submit");
	sni_resolver_test_pause_dequeue(0);
	slot = wait_one(sink, 2000);
	sni_resolver_test_stats(&st);
	expect_true(slot != NULL && slot->gai_error != 0, "expired result");
	expect_int((int)st.skipped_expired, 1, "expired skipped");
	expect_int(cfg.calls, 0, "expired did not call resolver");
	release_slot(slot);
	resolver_settle("after resolver results");
	sni_resolver_sink_release(sink);
}

static void test_resolver_quota_and_cancel(void)
{
	sni_completion_sink *a = NULL;
	sni_completion_sink *b = NULL;
	hook_cfg cfg;
	resolve_slot *slot;
	sni_resolver_counters st;
	int idx = -1;
	uint64_t req = 0;
	uint64_t old_req = 0;
	int old_idx = -1;
	int n;
	int i;
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HOOK_V4;
	sni_resolver_test_set_hook(test_hook, &cfg);
	expect_true(sni_resolver_sink_open(SNI_SINK_LISTENER, &a), "quota sink A");
	expect_true(sni_resolver_sink_open(SNI_SINK_LISTENER, &b), "quota sink B");
	sni_resolver_test_pause_dequeue(1);
	n = 0;
	while (submit_name(a, "full.test", mono_ms() + 5000, &idx, &req) == SNI_SUBMIT_OK)
		n++;
	expect_int(n, sni_resolver_sink_quota(a), "listener A filled its quota");
	expect_int(submit_name(a, "overflow.test", mono_ms() + 5000, &idx, &req),
			SNI_SUBMIT_OVERFLOW, "queue overflow");
	expect_int(submit_name(b, "other.test", mono_ms() + 5000, &idx, &req),
			SNI_SUBMIT_OK, "listener B still has quota");
	sni_resolver_cancel(idx, req);
	expect_int(sni_resolver_test_fill_infra(), SNI_RESOLVER_INFRA_RESERVE, "infra reserve filled");
	expect_int(sni_resolver_test_fill_infra(), 0, "infra reserve stops at the cap");
	resolver_settle("after quota");
	sni_resolver_test_pause_dequeue(1);
	sni_resolver_test_reset_stats();
	cfg.calls = 0;
	expect_int(submit_name(a, "cancel.test", mono_ms() + 5000, &idx, &req), SNI_SUBMIT_OK, "cancel submit");
	sni_resolver_cancel(idx, req);
	sni_resolver_test_pause_dequeue(0);
	resolver_settle("after queued cancel");
	sni_resolver_test_stats(&st);
	expect_true(st.skipped_cancelled >= 1, "cancel while queued");
	expect_int(cfg.calls, 0, "cancelled queue did not resolve");
	sni_resolver_test_hold_running(1);
	expect_int(submit_name(a, "running.test", mono_ms() + 5000, &idx, &req), SNI_SUBMIT_OK, "running submit");
	expect_true(sni_resolver_test_wait_running(1, 2000) != 0, "reached running");
	sni_resolver_cancel(idx, req);
	sni_resolver_test_hold_running(0);
	slot = wait_one(a, 2000);
	expect_true(slot != NULL && slot->req_id == req, "cancel while running still completes");
	release_slot(slot);
	release_slot(slot);
	expect_pool("duplicate release");
	sni_resolver_test_hold_running(1);
	sni_resolver_test_reset_stats();
	expect_int(submit_name(a, "closed.test", mono_ms() + 5000, &idx, &req), SNI_SUBMIT_OK, "closed submit");
	expect_true(sni_resolver_test_wait_running(1, 2000) != 0, "closed reached running");
	sni_resolver_sink_mark_closed(a);
	sni_resolver_test_hold_running(0);
	usleep(50000);
	slot = wait_one(a, 200);
	expect_true(slot == NULL, "closed sink dropped the result");
	sni_resolver_test_stats(&st);
	expect_true(st.closed_drops >= 1, "closed drop counted");
	resolver_settle("after closed sink");
	sni_resolver_sink_release(a);
	a = NULL;
	expect_true(sni_resolver_sink_open(SNI_SINK_LISTENER, &a), "recycle sink");
	cfg.mode = HOOK_V4;
	expect_int(submit_name(a, "recycle.test", mono_ms() + 2000, &old_idx, &old_req), SNI_SUBMIT_OK, "first id");
	slot = wait_one(a, 2000);
	expect_true(slot != NULL, "first completion");
	old_idx = slot ? slot->index : old_idx;
	old_req = slot ? slot->req_id : old_req;
	release_slot(slot);
	expect_int(submit_name(a, "recycle2.test", mono_ms() + 2000, &idx, &req), SNI_SUBMIT_OK, "recycled submit");
	sni_resolver_cancel(old_idx, old_req);
	slot = wait_one(a, 2000);
	expect_true(slot != NULL && slot->req_id == req, "stale req_id did not cancel the new slot");
	release_slot(slot);
	cfg.mode = HOOK_ORDER;
	cfg.release_first = 0;
	{
		int i1 = -1;
		int i2 = -1;
		uint64_t r1 = 0;
		uint64_t r2 = 0;
		resolve_slot *first = NULL;
		resolve_slot *second = NULL;
		sni_resolver_test_set_hook(test_hook, &cfg);
		expect_int(sni_resolver_submit(a, 1, 1, "first.test", 9, AF_UNSPEC,
				mono_ms() + 3000, &i1, &r1), SNI_SUBMIT_OK, "order first");
		expect_int(sni_resolver_submit(a, 2, 2, "second.test", 9, AF_UNSPEC,
				mono_ms() + 3000, &i2, &r2), SNI_SUBMIT_OK, "order second");
		/*
		 * first.test is held in its hook, so the only completion that can
		 * arrive now is second.test, unless the pool serialized it behind first.
		 */
		first = wait_one(a, 3000);
		pthread_mutex_lock(&g_hook_mu);
		cfg.release_first = 1;
		pthread_cond_broadcast(&g_hook_cv);
		pthread_mutex_unlock(&g_hook_mu);
		second = wait_one(a, 3000);
		expect_true(first && second, "both completions");
		if (first && second) {
			expect_true(strcmp(first->hostname, "second.test") == 0, "out of order completion");
			release_slot(first);
			release_slot(second);
		}
	}
	sni_resolver_test_pause_dequeue(1);
	n = 0;
	for (i = 0; i < 4; i++) {
		if (submit_name(a, "ring.test", mono_ms() + 2000, &idx, &req) == SNI_SUBMIT_OK)
			n++;
	}
	sni_resolver_test_pause_dequeue(0);
	{
		int64_t deadline = mono_ms() + 2000;
		sni_resolver_accounting acc;
		memset(&acc, 0, sizeof(acc));
		while (mono_ms() < deadline) {
			if (sni_resolver_test_accounting(&acc) && acc.in_ring >= n && n > 0)
				break;
			usleep(1000);
		}
		expect_true(n > 0 && acc.in_ring >= n, "completions queued in the ring");
	}
	sni_resolver_sink_release(a);
	a = NULL;
	resolver_settle("ring teardown freed the slots");
	{
		resolve_slot *got[32];
		int gotn = 0;
		pthread_t drainer;
		drain_pack arg;
		expect_true(sni_resolver_sink_open(SNI_SINK_LISTENER, &a), "race sink");
		arg.sink = a;
		arg.got = got;
		arg.gotn = &gotn;
		arg.want = 16;
		cfg.mode = HOOK_V4;
		sni_resolver_test_pause_dequeue(1);
		for (i = 0; i < 16; i++)
			expect_int(submit_name(a, "race.test", mono_ms() + 3000, &idx, &req),
					SNI_SUBMIT_OK, "race submit");
		expect_true(pthread_create(&drainer, NULL, race_drain, &arg) == 0, "drain thread");
		sni_resolver_test_pause_dequeue(0);
		pthread_join(drainer, NULL);
		expect_int(gotn, 16, "wakeup race delivered every result");
		for (i = 0; i < gotn; i++)
			release_slot(got[i]);
		{
			char buf[1024];
			sni_resolver_counters before;
			int64_t wake_by;
			memset(buf, 1, sizeof(buf));
			memset(&before, 0, sizeof(before));
			sni_resolver_test_reset_stats();
			sni_resolver_test_hold_running(1);
			expect_int(submit_name(a, "eagain.test", mono_ms() + 2000, &idx, &req),
					SNI_SUBMIT_OK, "eagain submit");
			expect_true(sni_resolver_test_wait_running(1, 2000) != 0, "eagain worker is held");
			for (;;) {
				ssize_t wr = write(a->pipe_write, buf, sizeof(buf));
				if (wr < 0 && errno == EINTR)
					continue;
				if (wr <= 0)
					break;
			}
			sni_resolver_test_hold_running(0);
			wake_by = mono_ms() + 2000;
			do {
				sni_resolver_test_stats(&before);
				if (before.eagain_wakeups >= 1)
					break;
				usleep(1000);
			} while (mono_ms() < wake_by);
			slot = wait_one(a, 2000);
			expect_true(slot != NULL, "eagain still delivered the slot");
			expect_true(before.eagain_wakeups >= 1, "pipe EAGAIN counted as a wakeup");
			release_slot(slot);
		}
		sni_resolver_sink_release(a);
	}
	sni_resolver_sink_release(b);
	resolver_settle("quota sinks released");
}

static void *race_drain(void *arg)
{
	drain_pack *job = (drain_pack *)arg;
	int64_t deadline = mono_ms() + 3000;
	while (*job->gotn < job->want && mono_ms() < deadline) {
		resolve_slot *batch[8];
		size_t n = sni_resolver_drain(job->sink, batch, 8);
		size_t i;
		for (i = 0; i < n && *job->gotn < job->want; i++)
			job->got[(*job->gotn)++] = batch[i];
		if (n == 0)
			usleep(1000);
	}
	return NULL;
}

static void test_stuck_worker_shutdown(void)
{
	pid_t pid = fork();
	int status = 0;
	expect_true(pid >= 0, "fork stuck worker");
	if (pid < 0)
		return;
	if (pid == 0) {
		sni_completion_sink *sink = NULL;
		hook_cfg cfg;
		int slot = -1;
		uint64_t req = 0;
		sni_resolver_accounting a;
		memset(&cfg, 0, sizeof(cfg));
		cfg.mode = HOOK_V4;
		failures = 0;
		sni_resolver_test_set_hook(test_hook, &cfg);
		sni_resolver_test_hold_running(1);
		if (!sni_resolver_sink_open(SNI_SINK_DIRECT, &sink) ||
				submit_name(sink, "stuck.test", mono_ms() + 10000, &slot, &req) != SNI_SUBMIT_OK ||
				!sni_resolver_test_wait_running(1, 2000) ||
				sni_resolver_shutdown(200) != 1 ||
				!sni_resolver_test_mutex_ok() ||
				!sni_resolver_test_accounting(&a) ||
				a.abandoned != 1)
			_exit(1);
		_exit(0);
	}
	expect_true(waitpid(pid, &status, 0) == pid, "wait stuck worker");
	expect_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, "stuck worker timeout path");
}

static const char CASE_REQ[] = "GET / HTTP/1.1\r\nHost: LocalHost.\r\n\r\n";

static void test_sni_resolver_behavior(void)
{
	hook_cfg cfg;
	echo_srv echo;
	sni_listener *ls = NULL;
	SniServer_t scfg;
	uint16_t local = 0;
	int binder;
	int calls_before;
	static const char *const allow[] = { "localhost" };
	filter_t *wl;
	uint32_t waits;
	int fd;
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HOOK_V4;
	sni_resolver_test_set_hook(test_hook, &cfg);
	sni_resolver_test_reset_stats();
	{
		sni_resolved_addr one;
		size_t n = 0;
		expect_int(sni_resolver_copy_upstream("127.0.0.1", 9, &one, &n), SNI_UP_READY,
				"numeric destination bypasses the resolver");
		expect_int((int)n, 1, "numeric address count");
		expect_int(cfg.calls, 0, "numeric lookup was not submitted");
	}
	wl = filter_from_list(allow, 1);
	expect_true(wl != NULL, "build whitelist");
	expect_true(echo_start(&echo) == 0, "resolver echo");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	fill_listener(&scfg, local, echo.port, 2, NULL, wl, NULL);
	expect_true(sni_listener_open(&scfg, &ls), "resolver listener");
	calls_before = cfg.calls;
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, EVIL_REQ, sizeof(EVIL_REQ) - 1) == 0, "evil write");
	if (fd >= 0) {
		uint8_t sinkb[8];
		size_t got = 0;
		read_eof_ms(fd, sinkb, sizeof(sinkb), &got, 1000);
		close(fd);
	}
	usleep(50000);
	expect_int(cfg.calls, calls_before, "whitelist rejection does not resolve");
	expect_true(echo_roundtrip(local, CASE_REQ, sizeof(CASE_REQ) - 1, 2000) == 0,
			"case and trailing dot match");
	expect_true(cfg.calls > calls_before, "direct hostname used the resolver");
	sni_resolver_test_hold_running(1);
	sni_test_reset_counters();
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "held resolve write");
	expect_true(fd >= 0 && write_full(fd, "XXXX", 4) == 0, "extra bytes during resolve");
	expect_true(sni_resolver_test_wait_running(1, 2000) != 0, "listener resolve is running");
	waits = sni_test_wait_calls();
	usleep(150000);
	expect_true(sni_test_wait_calls() - waits < 40, "resolve state does not busy-loop");
	shutdown(fd, SHUT_WR);
	usleep(50000);
	expect_int(__atomic_load_n(&echo.accepts, __ATOMIC_RELAXED),
			__atomic_load_n(&echo.accepts, __ATOMIC_RELAXED), "still resolving");
	{
		int accepts = __atomic_load_n(&echo.accepts, __ATOMIC_RELAXED);
		sni_resolver_test_hold_running(0);
		expect_true(accepts >= 0, "fin during resolve kept the connection");
		{
			uint8_t buf[128];
			size_t got = 0;
			expect_true(read_eof_ms(fd, buf, sizeof(buf), &got, 2000) == 0, "fin during resolve still relays");
		}
		close(fd);
	}
	{
		int live = connect_local(local, 1000);
		uint8_t buf[64];
		expect_true(live >= 0 && write_full(live, REQ, sizeof(REQ) - 1) == 0, "relay setup");
		expect_true(live >= 0 && read_full_ms(live, buf, sizeof(REQ) - 1, 2000) == 0, "relay up");
		sni_resolver_test_hold_running(1);
		fd = connect_local(local, 1000);
		expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "blocked lookup");
		expect_true(sni_resolver_test_wait_running(1, 2000) != 0, "lookup is blocked");
		expect_true(write_full(live, "PING", 4) == 0, "ping during lookup");
		expect_true(read_full_ms(live, buf, 4, 1000) == 0 && memcmp(buf, "PING", 4) == 0,
				"existing relay is not stalled by resolution");
		sni_resolver_test_hold_running(0);
		close(fd);
		close(live);
	}
	sni_listener_close(ls);
	ls = NULL;
	resolver_quiet();
	fill_listener(&scfg, local, local, 2, NULL, NULL, NULL);
	cfg.mode = HOOK_V4;
	cfg.calls = 0;
	sni_resolver_test_set_hook(test_hook, &cfg);
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	scfg.Port.local_port = local;
	scfg.Port.remote_port = local;
	expect_true(sni_listener_open(&scfg, &ls), "self listener");
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "self write");
	if (fd >= 0) {
		uint8_t sinkb[8];
		size_t got = 99;
		int64_t start = mono_ms();
		expect_true(read_eof_ms(fd, sinkb, sizeof(sinkb), &got, 1500) == 0, "self connect closes");
		expect_true(got == 0, "self connect sends nothing");
		expect_true(mono_ms() - start < 1500, "self connect fails promptly");
		close(fd);
	}
	expect_true(cfg.calls > 0, "self connect did resolve");
	sni_listener_close(ls);
	ls = NULL;
	cfg.mode = HOOK_MAPPED;
	sni_resolver_test_set_hook(test_hook, &cfg);
	expect_true(sni_listener_open(&scfg, &ls), "mapped listener");
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "mapped write");
	if (fd >= 0) {
		uint8_t sinkb[8];
		size_t got = 99;
		expect_true(read_eof_ms(fd, sinkb, sizeof(sinkb), &got, 1500) == 0, "mapped loopback closes");
		expect_true(got == 0, "mapped loopback sends nothing");
		close(fd);
	}
	sni_listener_close(ls);
	echo_stop(&echo);
	filter_free(wl);
	resolver_settle("sni resolver behavior");
}

static void test_socks_resolver_cache(void)
{
	hook_cfg cfg;
	echo_srv echo;
	socks_job job;
	pthread_t stid;
	sni_listener *ls = NULL;
	SniServer_t scfg;
	sockshost_t socks;
	uint16_t sport = 0;
	uint16_t local = 0;
	int binder;
	int slfd;
	int calls_after_prime;
	int fd;
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HOOK_V4;
	sni_resolver_test_set_hook(test_hook, &cfg);
	expect_true(echo_start(&echo) == 0, "socks echo");
	slfd = listen_loopback(&sport);
	expect_true(slfd >= 0, "socks listen");
	memset(&job, 0, sizeof(job));
	job.lfd = slfd;
	job.mode = SOCKS_NOAUTH;
	job.upstream_port = echo.port;
	expect_true(sni_resolver_prime_socks("socks.example", sport, 1000), "prime socks name");
	calls_after_prime = cfg.calls;
	expect_true(calls_after_prime > 0, "startup lookup ran");
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	memset(&socks, 0, sizeof(socks));
	socks.host = (char *)"socks.example";
	socks.port = sport;
	fill_listener(&scfg, local, echo.port, 3, NULL, NULL, &socks);
	expect_true(sni_listener_open(&scfg, &ls), "socks cache listener");
	expect_true(pthread_create(&stid, NULL, socks_thread, &job) == 0, "socks cache thread");
	expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "socks hostname uses the cache");
	expect_int(cfg.calls, calls_after_prime, "fresh cache did not resolve again");
	pthread_join(stid, NULL);
	{
		int64_t now = mono_ms();
		int live;
		uint8_t buf[64];
		sni_resolver_test_age_cache(now - 60000, now - 1000, now + 60000);
		live = connect_local(local, 1000);
		expect_true(live >= 0 && write_full(live, REQ, sizeof(REQ) - 1) == 0, "stale live write");
		expect_true(pthread_create(&stid, NULL, socks_thread, &job) == 0, "stale socks thread");
		expect_true(live >= 0 && read_full_ms(live, buf, sizeof(REQ) - 1, 2000) == 0, "stale cache still connects");
		pthread_join(stid, NULL);
		close(live);
		sni_resolver_test_hold_running(1);
		sni_resolver_test_age_cache(now - 60000, now - 1000, now + 60000);
		fd = connect_local(local, 1000);
		expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "refresh in flight");
		expect_true(pthread_create(&stid, NULL, socks_thread, &job) == 0, "inflight socks thread");
		{
			int64_t start = mono_ms();
			uint8_t body[64];
			expect_true(read_full_ms(fd, body, sizeof(REQ) - 1, 1000) == 0, "stale cache during refresh");
			expect_true(mono_ms() - start < 1000, "refresh did not block the connection");
		}
		sni_resolver_test_hold_running(0);
		pthread_join(stid, NULL);
		close(fd);
		cfg.mode = HOOK_ERR;
		cfg.err = EAI_FAIL;
		sni_resolver_test_age_cache(mono_ms() - 60000, mono_ms() - 1000, mono_ms() + 60000);
		expect_true(pthread_create(&stid, NULL, socks_thread, &job) == 0, "refresh fail thread");
		expect_true(echo_roundtrip(local, REQ, sizeof(REQ) - 1, 2000) == 0, "refresh failure keeps the cache");
		pthread_join(stid, NULL);
		sni_resolver_test_age_cache(mono_ms() - 200000, mono_ms() - 1000, mono_ms() - 1000);
		fd = connect_local(local, 1000);
		expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "stale max write");
		if (fd >= 0) {
			uint8_t sinkb[8];
			size_t got = 99;
			int64_t start = mono_ms();
			expect_true(read_eof_ms(fd, sinkb, sizeof(sinkb), &got, 1000) == 0, "max staleness closes");
			expect_true(got == 0 && mono_ms() - start < 1000, "max staleness fails immediately");
			close(fd);
		}
	}
	sni_listener_close(ls);
	close(slfd);
	echo_stop(&echo);
	cfg.mode = HOOK_ERR;
	cfg.err = EAI_FAIL;
	cfg.calls = 0;
	sni_resolver_test_set_hook(test_hook, &cfg);
	expect_true(sni_resolver_prime_socks("missing.example", 9, 300), "failed prime still returns");
	slfd = listen_loopback(&sport);
	binder = listen_loopback(&local);
	if (binder >= 0)
		close(binder);
	socks.host = (char *)"missing.example";
	socks.port = sport;
	fill_listener(&scfg, local, echo.port, 2, NULL, NULL, &socks);
	expect_true(echo_start(&echo) == 0, "unresolved echo");
	scfg.Port.remote_port = echo.port;
	expect_true(sni_listener_open(&scfg, &ls), "unresolved listener still starts");
	fd = connect_local(local, 1000);
	expect_true(fd >= 0 && write_full(fd, REQ, sizeof(REQ) - 1) == 0, "unresolved write");
	if (fd >= 0) {
		uint8_t sinkb[8];
		size_t got = 99;
		int64_t start = mono_ms();
		expect_true(read_eof_ms(fd, sinkb, sizeof(sinkb), &got, 1000) == 0, "socks_unresolved closes");
		expect_true(got == 0 && mono_ms() - start < 800, "unresolved does not wait on the event loop");
		close(fd);
	}
	sni_listener_close(ls);
	close(slfd);
	echo_stop(&echo);
	resolver_settle("socks cache");
}

int main(void)
{
	uint8_t hello[256];
	size_t hello_len = 0;
	struct sigaction sa;

	log_set_quiet(1);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	sa.sa_handler = on_alarm;
	sigaction(SIGALRM, &sa, NULL);
	alarm(180);
	raise_nofile();

	{
		int probe = socket(AF_INET, SOCK_STREAM, 0);
		if (probe < 0)
			return 0;
		close(probe);
	}

	test_stuck_worker_shutdown();
	test_production_spawn();
	test_normalize();
	test_policy_addresses();
	test_resolver_results();
	test_resolver_quota_and_cancel();
	test_sni_resolver_behavior();
	test_socks_resolver_cache();
	sni_resolver_test_set_hook(NULL, NULL);
	test_tls_hello_builds();
	expect_true(build_client_hello(hello, sizeof(hello), &hello_len, "localhost") == 0, "hello for splits");
	test_split_prefixes((const uint8_t *)REQ, sizeof(REQ) - 1, "http host");
	test_split_prefixes(hello, hello_len, "tls sni");
	test_partial_write_and_eagain();
	test_eintr_still_forwards();
	test_socks_mode(SOCKS_NOAUTH, 0, 0, "socks direct");
	test_socks_mode(SOCKS_AUTH, 1, 0, "socks auth");
	test_socks_mode(SOCKS_AUTH, 1, 1, "socks split bytes");
	test_socks_mode(SOCKS_BAD_VER, 0, 0, "socks bad version");
	test_socks_mode(SOCKS_BAD_METHOD, 0, 0, "socks bad method");
	test_socks_mode(SOCKS_BAD_AUTH, 1, 0, "socks bad auth");
	test_socks_mode(SOCKS_BAD_REP, 0, 0, "socks bad connect reply");
	test_connect_failure();
	test_handshake_timeout();
	test_idle_timeout();
	test_zero_timeout_relays();
	test_relay_budget();
	test_client_eof_during_hello();
	test_upstream_eof();
	test_half_close();
	test_upstream_half_close();
	test_oversize_hello();
	test_alloc_failure();
	test_stats_once();
	test_whitelist_and_ip();
	test_two_listeners();
	test_listener_self_exit();
	test_load_and_threads();
	test_stall_stays_responsive();
	test_connection_cap();
	test_stress_cycles();
	expect_true(slots_are_clear(), "process-wide slots are clear at the end");
	{
		sni_resolver_accounting a;
		int sum;
		expect_true(sni_resolver_test_accounting(&a), "final resolver accounting");
		sum = a.free_n + a.queued + a.running + a.done + a.cancelled + a.in_ring;
		expect_int(sum, SNI_RESOLVER_SLOTS, "final slot balance");
		expect_int(a.quota_used, 0, "final quota counters");
		expect_int(a.listener_quota_assigned, 0, "listener quotas released");
		expect_int(a.live_sinks, 0, "sinks released");
		expect_int(a.open_pipes, 0, "completion pipes closed");
		expect_int(a.double_free, 0, "no double free");
	}
	alarm(0);
	if (failures)
		fprintf(stderr, "%d failure(s)\n", failures);
	return failures == 0 ? 0 : 1;
}
