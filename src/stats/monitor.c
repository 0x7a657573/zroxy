#define _GNU_SOURCE
/*
 * monitor.c
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zroxy/monitor.h>
#include <zroxy/config.h>
#include <zroxy/log.h>
#include <zroxy/net.h>
#include <inttypes.h>
#include <zroxy/version.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <zroxy/net_io.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <limits.h>
#if defined(__OpenBSD__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif
#if defined(__FreeBSD__)
#include <sys/user.h>
#endif

#include "../core/reactor.h"

#define MON_MAX_CLIENTS 32
#define MON_MAX_HEADER 4096
/* JSON body limit, and room in front of it for the response head. */
#define MON_MAX_BODY 16384
#define MON_HEAD_ROOM 256

/* Set when the monitor starts, a few milliseconds after the process does. */
static time_t mon_process_start;

typedef enum
{
	MON_READ,
	MON_WRITE
} mon_phase;

typedef struct
{
	int fd;
	mon_phase phase;
	uint8_t header[MON_MAX_HEADER];
	size_t header_len;
	int64_t deadline_ms;
	uint8_t response[MON_HEAD_ROOM + MON_MAX_BODY];
	size_t out_len;
	size_t out_off;
} mon_client_t;

typedef struct mon_section
{
	char name[32];
	mon_section_fn fn;
	void *ctx;
	struct mon_section *next;
} mon_section_t;

struct mon
{
	int fd;
	uint16_t Port;
	statistics_t *state;
	mon_section_t *sections;    /* guarded by stats_lock; nodes are never freed */
	pthread_mutex_t stats_lock; /* guards the state list head only */
	char *token;                /* optional bearer secret; NULL disables authentication */
	int header_timeout;         /* seconds to wait for a complete header */
	pthread_t thread;           /* joined by monitor_stop */
	int wake[2];                /* pipe that wakes the monitor thread */
	reactor reactor;
	mon_client_t clients[MON_MAX_CLIENTS];
};

static bool http_headers_done(const uint8_t *buf, size_t len)
{
	size_t i;
	if (len < 4)
		return false;
	for (i = 0; i + 3 < len; i++)
	{
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		        buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return true;
	}
	return false;
}

static bool mon_crlf(const uint8_t *buf, size_t len, size_t *line_len)
{
	size_t i;
	for (i = 0; i + 1 < len; i++)
	{
		if (buf[i] == '\r' && buf[i + 1] == '\n')
		{
			*line_len = i;
			return true;
		}
	}
	return false;
}

/* 0 means the request line is acceptable. */
static int mon_classify_line(const uint8_t *buf, size_t line_len)
{
	const char *s = (const char *)buf;
	const char *sp1;
	const char *sp2;
	size_t method_len;
	size_t path_len;
	size_t ver_len;

	if (line_len == 0 || memchr(buf, 0, line_len) != NULL)
		return 400;
	sp1 = memchr(s, ' ', line_len);
	if (!sp1)
		return 400;
	method_len = (size_t)(sp1 - s);
	if (method_len + 1 >= line_len)
		return 400;
	sp2 = memchr(sp1 + 1, ' ', line_len - (method_len + 1));
	if (!sp2)
		return 400;
	path_len = (size_t)(sp2 - (sp1 + 1));
	ver_len = line_len - (method_len + 1 + path_len + 1);
	if (ver_len == 0)
		return 400;
	if (!(method_len == 3 && memcmp(s, "GET", 3) == 0))
		return 405;
	if (!(path_len == 1 && sp1[1] == '/'))
		return 404;
	if (!(ver_len == 8 &&
	            (memcmp(sp2 + 1, "HTTP/1.0", 8) == 0 || memcmp(sp2 + 1, "HTTP/1.1", 8) == 0)))
		return 400;
	return 0;
}

static bool mon_token_eq(const char *got, size_t got_len, const char *token)
{
	size_t token_len = strlen(token);
	size_t n = got_len > token_len ? got_len : token_len;
	unsigned char diff = (unsigned char)(got_len != token_len);
	size_t i;

	for (i = 0; i < n; i++)
	{
		unsigned char a = i < got_len ? (unsigned char)got[i] : 0;
		unsigned char b = i < token_len ? (unsigned char)token[i] : 0;
		diff |= (unsigned char)(a ^ b);
	}
	return diff == 0;
}

static bool mon_bearer_line(const uint8_t *line, size_t n, const char *token)
{
	static const char name[] = "authorization";
	size_t i;

	if (n < sizeof(name) - 1)
		return false;
	for (i = 0; i < sizeof(name) - 1; i++)
	{
		if (tolower(line[i]) != (unsigned char)name[i])
			return false;
	}
	i = sizeof(name) - 1;
	if (i >= n || line[i] != ':')
		return false;
	i++;
	while (i < n && (line[i] == ' ' || line[i] == '\t'))
		i++;
	if (n - i < 7 || memcmp(line + i, "Bearer ", 7) != 0)
		return false;
	i += 7;
	return mon_token_eq((const char *)line + i, n - i, token);
}

static bool mon_authorized(const uint8_t *buf, size_t len, const char *token)
{
	size_t i = 0;

	if (!token)
		return true;
	while (i + 1 < len && !(buf[i] == '\r' && buf[i + 1] == '\n'))
		i++;
	if (i + 1 >= len)
		return false;
	i += 2;
	while (i + 1 < len)
	{
		size_t line = i;
		if (buf[i] == '\r' && buf[i + 1] == '\n')
			break;
		while (i + 1 < len && !(buf[i] == '\r' && buf[i + 1] == '\n'))
			i++;
		if (mon_bearer_line(buf + line, i - line, token))
			return true;
		if (i + 1 < len)
			i += 2;
		else
			break;
	}
	return false;
}

#ifdef MON_TEST_HOOKS
/* The request checks monitor_client_thread runs on the bytes read so far. */
int monitor_test_classify(const uint8_t *buf, size_t len)
{
	size_t line_len = 0;
	if (!mon_crlf(buf, len, &line_len))
		return -1;
	return mon_classify_line(buf, line_len);
}

bool monitor_test_headers_done(const uint8_t *buf, size_t len)
{
	return http_headers_done(buf, len);
}

bool monitor_test_authorized(const uint8_t *buf, size_t len, const char *token)
{
	return mon_authorized(buf, len, token);
}
#endif

static size_t mon_send_empty(uint8_t *out, size_t cap, int code)
{
	const char *text = "400 Bad Request";
	int n;

	if (code == 401)
		text = "401 Unauthorized";
	else if (code == 404)
		text = "404 Not Found";
	else if (code == 405)
		text = "405 Method Not Allowed";
	else if (code == 500)
		text = "500 Internal Server Error";
	n = snprintf((char *)out, cap,
	        "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", text);
	if (n < 0 || (size_t)n >= cap)
		return 0;
	return (size_t)n;
}

static char *mon_dup_token(const char *src)
{
	size_t n;
	char *out;

	if (!src || src[0] == '\0')
		return NULL;
	n = strlen(src);
	if (n > 256)
		return NULL;
	out = malloc(n + 1);
	if (!out)
		return NULL;
	memcpy(out, src, n + 1);
	return out;
}

static void mon_free_token(char *token)
{
	if (token)
		zroxy_wipe(token, strlen(token));
	free(token);
}

static void *monitor_thread(void *vargp);
static int count_open_files(void);

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec)
{
	int sockfd;
	struct in_addr addr;
	mon_t *mon;
	const char *bind_text = bind_ip;

	if (!bind_text || bind_text[0] == '\0')
		bind_text = "127.0.0.1";
	if (inet_pton(AF_INET, bind_text, &addr) != 1)
	{
		log_error("monitor bind address invalid");
		return NULL;
	}

	if (net_listen_ipv4(addr.s_addr, port, &sockfd) == false)
	{
		log_error("monitor can not listen on Port %i", port);
		return NULL;
	}

	log_info("monitor listen on %s:%d", bind_text, port);
	mon = calloc(1, sizeof(mon_t));
	if (!mon)
	{
		log_error("monitor allocation failed");
		close(sockfd);
		return NULL;
	}
	for (int i = 0; i < MON_MAX_CLIENTS; i++)
		mon->clients[i].fd = -1;
	if (token && token[0] != '\0')
	{
		mon->token = mon_dup_token(token);
		if (!mon->token)
		{
			log_error("monitor token allocation failed");
			close(sockfd);
			free(mon);
			return NULL;
		}
	}
	if (pthread_mutex_init(&mon->stats_lock, NULL) != 0)
	{
		log_error("monitor mutex init failed");
		close(sockfd);
		mon_free_token(mon->token);
		free(mon);
		return NULL;
	}
	mon->state = NULL;
	if (mon_process_start == 0)
		time(&mon_process_start);
	mon->wake[0] = mon->wake[1] = -1;
	if (pipe2(mon->wake, O_CLOEXEC | O_NONBLOCK) != 0)
	{
		log_error("monitor wake pipe failed");
		close(sockfd);
		pthread_mutex_destroy(&mon->stats_lock);
		mon_free_token(mon->token);
		free(mon);
		return NULL;
	}
	/* The listener is nonblocking, so accept can drain it without blocking. */
	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
	mon->fd = sockfd;
	mon->Port = port;
	mon->header_timeout = header_timeout_sec < 1 ? 5 : header_timeout_sec;
	if (mon->header_timeout > 60)
		mon->header_timeout = 60;

	if (!reactor_open(&mon->reactor, MON_MAX_CLIENTS + 2, false))
	{
		log_error("monitor reactor open failed");
		close(sockfd);
		close(mon->wake[0]);
		close(mon->wake[1]);
		pthread_mutex_destroy(&mon->stats_lock);
		mon_free_token(mon->token);
		free(mon);
		return NULL;
	}
	if (!reactor_add(&mon->reactor, sockfd, RE_IN, mon) ||
	        !reactor_add(&mon->reactor, mon->wake[0], RE_IN, mon->wake) ||
	        pthread_create(&mon->thread, NULL, monitor_thread, (void *)mon) != 0)
	{
		log_error("monitor thread create failed");
		reactor_close(&mon->reactor);
		close(sockfd);
		close(mon->wake[0]);
		close(mon->wake[1]);
		pthread_mutex_destroy(&mon->stats_lock);
		mon_free_token(mon->token);
		free(mon);
		return NULL;
	}

	return mon;
}

bool monitor_attach_stat(mon_t *self, statistics_t *stat)
{
	if (!self || !stat)
		return false;
	pthread_mutex_lock(&self->stats_lock);
	stat->next = self->state; /* newest first, as the report lists them */
	self->state = stat;
	pthread_mutex_unlock(&self->stats_lock);
	return true;
}

bool monitor_add_section(mon_t *self, const char *name, mon_section_fn fn, void *ctx)
{
	mon_section_t *sec;
	mon_section_t **tail;

	if (!self || !name || !fn || strlen(name) >= sizeof(sec->name))
		return false;
	sec = calloc(1, sizeof(*sec));
	if (!sec)
		return false;
	memcpy(sec->name, name, strlen(name) + 1);
	sec->fn = fn;
	sec->ctx = ctx;
	/* Append, so the report lists sections in the order they were added. */
	pthread_mutex_lock(&self->stats_lock);
	for (tail = &self->sections; *tail; tail = &(*tail)->next)
		;
	*tail = sec;
	pthread_mutex_unlock(&self->stats_lock);
	return true;
}

static size_t mon_send_empty(uint8_t *out, size_t cap, int code);
static size_t monitor_send_report(uint8_t *out, size_t cap, mon_t *owner);

static void monitor_close_client(mon_t *mon, mon_client_t *client)
{
	if (client->fd < 0)
		return;
	log_trace("monitor client %i done", client->fd);
	reactor_del(&mon->reactor, client->fd);
	close(client->fd);
	client->fd = -1;
}

static mon_client_t *monitor_free_slot(mon_t *mon)
{
	int i;
	for (i = 0; i < MON_MAX_CLIENTS; i++)
		if (mon->clients[i].fd < 0)
			return &mon->clients[i];
	return NULL;
}

static void monitor_accept(mon_t *mon)
{
	for (;;)
	{
		int fd;
		mon_client_t *client;
		fd = accept4(mon->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0)
		{
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				log_error("server accept failed");
			return;
		}
		client = monitor_free_slot(mon);
		if (!client)
		{
			close(fd);
			continue;
		}
		memset(client, 0, sizeof(*client));
		client->fd = fd;
		client->phase = MON_READ;
		client->deadline_ms = net_mono_ms() + (int64_t)mon->header_timeout * 1000;
		if (!reactor_add(&mon->reactor, fd, RE_IN, client))
		{
			close(fd);
			client->fd = -1;
		}
	}
}

static bool monitor_read_client(mon_t *mon, mon_client_t *client)
{
	ssize_t n;
	size_t line_len = 0;
	int status;

	for (;;)
	{
		n = read(client->fd, client->header + client->header_len,
		        sizeof(client->header) - client->header_len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return true;
		if (n <= 0)
		{
			log_trace("client %i disconnect %zd", client->fd, n);
			monitor_close_client(mon, client);
			return false;
		}
		client->header_len += (size_t)n;
		if (mon_crlf(client->header, client->header_len, &line_len))
		{
			status = mon_classify_line(client->header, line_len);
			if (status != 0)
			{
				client->out_len = mon_send_empty(client->response,
				        sizeof(client->response), status);
				client->out_off = 0;
				client->phase = MON_WRITE;
				client->deadline_ms = net_mono_ms() + (int64_t)mon->header_timeout * 1000;
				if (reactor_mod(&mon->reactor, client->fd, RE_OUT, client))
					return true;
				monitor_close_client(mon, client);
				return false;
			}
		}
		if (http_headers_done(client->header, client->header_len))
		{
			if (!mon_authorized(client->header, client->header_len, mon->token))
				client->out_len = mon_send_empty(client->response,
				        sizeof(client->response), 401);
			else
				client->out_len = monitor_send_report(client->response,
				        sizeof(client->response), mon);
			client->out_off = 0;
			client->phase = MON_WRITE;
			client->deadline_ms = net_mono_ms() + (int64_t)mon->header_timeout * 1000;
			if (reactor_mod(&mon->reactor, client->fd, RE_OUT, client))
				return true;
			monitor_close_client(mon, client);
			return false;
		}
		if (client->header_len >= sizeof(client->header))
		{
			monitor_close_client(mon, client);
			return false;
		}
		return true;
	}
}

static bool monitor_write_client(mon_t *mon, mon_client_t *client)
{
	ssize_t n;
	(void)mon;
	while (client->out_off < client->out_len)
	{
		n = send(client->fd, client->response + client->out_off,
		        client->out_len - client->out_off, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return true;
		if (n <= 0)
		{
			monitor_close_client(mon, client);
			return false;
		}
		client->out_off += (size_t)n;
	}
	monitor_close_client(mon, client);
	return false;
}

static void *monitor_thread(void *vargp)
{
	mon_t *mon = (mon_t *)vargp;
	reactor_event events[MON_MAX_CLIENTS + 2];
	int timeout;
	int n;
	int i;

	log_info("Monitor thread start on socket %i Port %d", mon->fd, mon->Port);
	for (;;)
	{
		int64_t now = net_mono_ms();
		int64_t earliest = -1;
		timeout = -1;
		for (i = 0; i < MON_MAX_CLIENTS; i++)
			if (mon->clients[i].fd >= 0 &&
			        (earliest < 0 || mon->clients[i].deadline_ms < earliest))
				earliest = mon->clients[i].deadline_ms;
		if (earliest >= 0)
		{
			int64_t left = earliest - now;
			if (left <= 0)
				timeout = 0;
			else
				timeout = left > INT_MAX ? INT_MAX : (int)left;
		}
		n = reactor_wait(&mon->reactor, events, MON_MAX_CLIENTS + 2, timeout);
		if (n < 0)
		{
			if (errno != EINTR)
				log_error("monitor reactor wait failed");
			continue;
		}
		for (i = 0; i < n; i++)
		{
			mon_client_t *client;
			if (events[i].tag == mon->wake)
				continue;
			if (events[i].tag == mon)
				continue;
			client = (mon_client_t *)events[i].tag;
			if (!client || client->fd < 0)
				continue;
			/*
			 * RE_HUP includes a peer that only shut down its write side.
			 * Let read and write see it: reading to EOF closes with a FIN
			 * instead of a reset, and a half-closed client still gets its
			 * response.
			 */
			if (client->phase == MON_READ)
				monitor_read_client(mon, client);
			else
				monitor_write_client(mon, client);
		}
		for (i = 0; i < n; i++)
			if (events[i].tag == mon->wake)
				goto out;
		for (i = 0; i < n; i++)
			if (events[i].tag == mon)
				monitor_accept(mon);
		now = net_mono_ms();
		for (i = 0; i < MON_MAX_CLIENTS; i++)
			if (mon->clients[i].fd >= 0 && mon->clients[i].deadline_ms <= now)
				monitor_close_client(mon, &mon->clients[i]);
	}
out:
	for (i = 0; i < MON_MAX_CLIENTS; i++)
		monitor_close_client(mon, &mon->clients[i]);
	reactor_del(&mon->reactor, mon->fd);
	reactor_del(&mon->reactor, mon->wake[0]);
	reactor_close(&mon->reactor);
	return NULL;
}

void monitor_stop(mon_t *self)
{
	mon_section_t *sec;
	char b = 0;

	if (!self)
		return;
	while (write(self->wake[1], &b, 1) < 0 && errno == EINTR)
		;
	pthread_join(self->thread, NULL);
	close(self->fd);
	close(self->wake[0]);
	close(self->wake[1]);
	for (sec = self->sections; sec;)
	{
		mon_section_t *next = sec->next;
		free(sec);
		sec = next;
	}
	pthread_mutex_destroy(&self->stats_lock);
	mon_free_token(self->token);
	free(self);
}

static bool mon_append(char **ptr, char *end, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t left;
	if (*ptr >= end)
		return false;
	left = (size_t)(end - *ptr);
	va_start(ap, fmt);
	n = vsnprintf(*ptr, left, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
	return true;
}

#if defined(__linux__)
/*
 * Reads the integer after "key" (for example "\nThreads:") in the status
 * text. Returns -1 when the key is absent.
 */
static long long mon_status_value(const char *text, const char *key)
{
	const char *p = strstr(text, key);
	char *tail = NULL;
	long long v;

	if (!p)
		return -1;
	p += strlen(key);
	while (*p == ' ' || *p == '\t')
		p++;
	v = strtoll(p, &tail, 10);
	if (tail == p)
		return -1;
	return v;
}

/* Threads and current/peak resident set size; -1 when unreadable. */
static void mon_read_status(long long *threads, long long *rss_kib, long long *hwm_kib)
{
	char text[8192];
	ssize_t n;
	int fd;

	*threads = -1;
	*rss_kib = -1;
	*hwm_kib = -1;
	fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, text, sizeof(text) - 1);
	close(fd);
	if (n <= 0)
		return;
	text[n] = '\0';
	*threads = mon_status_value(text, "\nThreads:");
	*rss_kib = mon_status_value(text, "\nVmRSS:");
	*hwm_kib = mon_status_value(text, "\nVmHWM:");
}
#elif defined(__OpenBSD__)
/* Threads and resident pages from the BSD process sysctl interface. */
static void mon_read_status(long long *threads, long long *rss_kib, long long *hwm_kib)
{
	struct kinfo_proc kp;
	struct rusage ru;
	size_t len;
	int mib[6] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid(),
	        sizeof(struct kinfo_proc), 1};

	*threads = -1;
	*rss_kib = -1;
	*hwm_kib = -1;
	if (getrusage(RUSAGE_SELF, &ru) == 0)
		*hwm_kib = (long long)ru.ru_maxrss;
	len = sizeof(kp);
	if (sysctl(mib, 6, &kp, &len, NULL, 0) == 0 && len >= sizeof(kp))
		*rss_kib = (long long)kp.p_vm_rssize * (long long)getpagesize() / 1024;

	{
		struct kinfo_proc *all = NULL;
		size_t all_len = 0;
		int i;
		long long count = 0;

		mib[2] = KERN_PROC_PID | KERN_PROC_SHOW_THREADS;
		mib[5] = 0;
		if (sysctl(mib, 6, NULL, &all_len, NULL, 0) == 0 &&
		        all_len > 0 && all_len % sizeof(*all) == 0)
		{
			all = malloc(all_len);
			mib[5] = (int)(all_len / sizeof(*all));
			if (all && sysctl(mib, 6, all, &all_len, NULL, 0) == 0 &&
			        all_len % sizeof(*all) == 0)
			{
				for (i = 0; i < (int)(all_len / sizeof(*all)); i++)
					if (all[i].p_tid != -1)
						count++;
				*threads = count;
			}
		}
		free(all);
	}
}
#elif defined(__FreeBSD__)
/* FreeBSD exposes the process values through the kern.proc.pid mib. */
static void mon_read_status(long long *threads, long long *rss_kib, long long *hwm_kib)
{
	struct kinfo_proc kp;
	size_t len = sizeof(kp);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid()};

	*threads = -1;
	*rss_kib = -1;
	*hwm_kib = -1;
	if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0 && len >= sizeof(kp))
	{
		*threads = (long long)kp.ki_numthreads;
		*rss_kib = (long long)kp.ki_rssize * (long long)getpagesize() / 1024;
	}
}
#endif

static bool mon_process_json(char **ptr, char *end, int open_files)
{
	struct rlimit lim;
	struct rusage ru;
	long long max_files = -1;
	long long cpu_user = 0;
	long long cpu_sys = 0;
	long long peak_kib = 0;
	time_t now;
	bool ok;

	time(&now);
	if (getrlimit(RLIMIT_NOFILE, &lim) == 0 && lim.rlim_cur != RLIM_INFINITY)
		max_files = (long long)lim.rlim_cur;
	if (getrusage(RUSAGE_SELF, &ru) == 0)
	{
		cpu_user = (long long)ru.ru_utime.tv_sec * 1000 + (long long)ru.ru_utime.tv_usec / 1000;
		cpu_sys = (long long)ru.ru_stime.tv_sec * 1000 + (long long)ru.ru_stime.tv_usec / 1000;
		peak_kib = (long long)ru.ru_maxrss;
	}

	ok = mon_append(ptr, end, "\"Process\" : {\n") &&
	     mon_append(ptr, end, "\"Pid\" : %lld ,\n", (long long)getpid()) &&
	     mon_append(ptr, end, "\"StartTime\" : %lld ,\n", (long long)mon_process_start) &&
	     mon_append(ptr, end, "\"UpTime\" : %lld ,\n", (long long)(now - mon_process_start)) &&
	     mon_append(ptr, end, "\"OpenFiles\" : %i ,\n", open_files) &&
	     mon_append(ptr, end, "\"MaxOpenFiles\" : %lld ,\n", max_files);
#if defined(__linux__) || defined(__OpenBSD__) || defined(__FreeBSD__)
	if (ok)
	{
		long long threads;
		long long rss_kib;
		long long hwm_kib;

		mon_read_status(&threads, &rss_kib, &hwm_kib);
		/*
		 * ru_maxrss survives exec, so it can hold the parent's peak;
		 * VmHWM belongs to this process image only.
		 */
		if (hwm_kib >= 0)
			peak_kib = hwm_kib;
		if (threads >= 0)
			ok = mon_append(ptr, end, "\"Threads\" : %lld ,\n", threads);
		if (ok && rss_kib >= 0)
			ok = mon_append(ptr, end, "\"RssBytes\" : %lld ,\n", rss_kib * 1024);
	}
#endif
	if (ok)
		ok = mon_append(ptr, end, "\"PeakRssBytes\" : %lld ,\n", peak_kib * 1024) &&
		     mon_append(ptr, end, "\"CpuUserMs\" : %lld ,\n", cpu_user) &&
		     mon_append(ptr, end, "\"CpuSystemMs\" : %lld\n},\n", cpu_sys);
	return ok;
}

static int mon_overflow_logged;

/* Nothing has been written yet, so the client can still get a 500. */
static size_t mon_report_failed(uint8_t *out, size_t cap, mon_t *owner)
{
	(void)owner;
	if (!__atomic_exchange_n(&mon_overflow_logged, 1, __ATOMIC_RELAXED))
		log_error("monitor report does not fit in %d bytes", MON_MAX_BODY);
	return mon_send_empty(out, cap, 500);
}

static size_t monitor_send_report(uint8_t *response, size_t response_cap, mon_t *owner)
{
	/* The head is built in front of the body so one write sends both. */
	char *message = (char *)(response + MON_HEAD_ROOM);
	char *ptr = message;
	char *end = message + MON_MAX_BODY;
	statistics_t *stat = NULL;
	mon_section_t *section;
	bool sections_ok = true;
	int open_files;
	(void)response_cap;

	if (!owner)
		return 0;
	pthread_mutex_lock(&owner->stats_lock);
	stat = owner->state;
	pthread_mutex_unlock(&owner->stats_lock);

	open_files = count_open_files();
	if (!mon_append(&ptr, end, "{\n\"ZroxyVersion\" : \"%s\",\n", version) ||
	        !mon_append(&ptr, end, "\"CountOfOpenFile\" : %i,\n", open_files) ||
	        !mon_process_json(&ptr, end, open_files))
	{
		return mon_report_failed(response, response_cap, owner);
	}

	/* Sections are added while the monitor runs, so walk the list locked. */
	pthread_mutex_lock(&owner->stats_lock);
	for (section = owner->sections; section && sections_ok; section = section->next)
	{
		sections_ok = mon_append(&ptr, end, "\"%s\" : {\n", section->name) &&
		              section->fn(section->ctx, &ptr, end) &&
		              mon_append(&ptr, end, "\n},\n");
	}
	pthread_mutex_unlock(&owner->stats_lock);
	if (!sections_ok)
	{
		return mon_report_failed(response, response_cap, owner);
	}

	statistics_t *sta = stat;
	while (sta)
	{
		stat_t stdata;
		stats_extra_fn extra;
		void *extra_ctx;
		time_t CurrentTime;
		time_t LiveTime;
		bool ok;

		pthread_mutex_lock(&sta->Lock);
		stdata = sta->stat;
		extra = sta->extra;
		extra_ctx = sta->extra_ctx;
		time(&CurrentTime);
		LiveTime = CurrentTime - stdata.StartTime;

		ok = mon_append(&ptr, end, "\"%s\" : {\n", sta->name) &&
		     mon_append(&ptr, end, "\"UpTime\" : %lld ,\n", (long long)LiveTime) &&
		     mon_append(&ptr, end, "\"MaxConnection\" : %" PRIu32 " ,\n", stdata.MaxConnection) &&
		     mon_append(&ptr, end, "\"ActiveConnection\" : %" PRIu32 " ,\n", stdata.ActiveConnection) &&
		     mon_append(&ptr, end, "\"TotalConnection\" : %" PRIu32 " ,\n", stdata.TotalConnection) &&
		     mon_append(&ptr, end, "\"TotalRx\" : %" PRIu64 " ,\n", stdata.TotalRx) &&
		     mon_append(&ptr, end, "\"TotalTx\" : %" PRIu64, stdata.TotalTx);
		if (ok && extra)
			ok = extra(extra_ctx, &ptr, end);
		if (ok)
			ok = mon_append(&ptr, end, "\n},\n");
		pthread_mutex_unlock(&sta->Lock);
		if (!ok)
		{
			return mon_report_failed(response, response_cap, owner);
		}

		sta = (statistics_t *)sta->next;
	}

	if (ptr - message < 2)
	{
		return mon_report_failed(response, response_cap, owner);
	}
	memcpy(ptr - 2, "\n}", 3);

	{
		char head[MON_HEAD_ROOM];
		size_t body_len = (size_t)(ptr - message);
		int hlen;

		hlen = snprintf(head, sizeof(head),
		        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n"
		        "Content-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		        body_len);
		if (hlen < 0 || (size_t)hlen >= sizeof(head))
		{
			return mon_report_failed(response, response_cap, owner);
		}
		memcpy(message - hlen, head, (size_t)hlen);
		memmove(response, message - hlen, (size_t)hlen + body_len);
		return (size_t)hlen + body_len;
	}
}

static int count_open_files(void)
{
	struct dirent *entry;
	int count = 0;
	int self_fd;
	DIR *dp = NULL;

#ifdef __linux__
	dp = opendir("/proc/self/fd");
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	dp = opendir("/dev/fd/");
#endif

	if (dp == NULL)
	{
		log_error("monitor can not open the descriptor directory: %s", strerror(errno));
		return -1;
	}

	/* The directory stream holds a descriptor of its own; do not count it. */
	self_fd = dirfd(dp);
	while ((entry = readdir(dp)) != NULL)
	{
		char *tail = NULL;
		long fd;

		if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
			continue; /* "." and ".." */
		fd = strtol(entry->d_name, &tail, 10);
		if (*tail == '\0' && fd == (long)self_fd)
			continue;
		count++;
	}

	closedir(dp);
	return count;
}
