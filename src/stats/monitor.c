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
#include <zroxy/log.h>
#include <zroxy/net.h>
#include <inttypes.h>
#include <zroxy/version.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/time.h>
#include <zroxy/net_io.h>

#define MON_MAX_WORKERS 32
#define MON_MAX_HEADER 4096

static pthread_mutex_t mon_worker_mu = PTHREAD_MUTEX_INITIALIZER;
static int mon_workers = 0;

static bool mon_worker_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&mon_worker_mu);
	if (mon_workers < MON_MAX_WORKERS)
	{
		mon_workers++;
		ok = true;
	}
	pthread_mutex_unlock(&mon_worker_mu);
	return ok;
}

static void mon_worker_release(void)
{
	pthread_mutex_lock(&mon_worker_mu);
	if (mon_workers > 0)
		mon_workers--;
	pthread_mutex_unlock(&mon_worker_mu);
}

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

static void mon_send_empty(int fd, int code, int timeout_sec)
{
	const char *text = "400 Bad Request";
	char msg[160];
	int n;
	int ms;

	if (code == 401)
		text = "401 Unauthorized";
	else if (code == 404)
		text = "404 Not Found";
	else if (code == 405)
		text = "405 Method Not Allowed";
	n = snprintf(msg, sizeof(msg),
		"HTTP/1.1 %s\nContent-Length: 0\nConnection: Closed\n\n", text);
	if (n < 0 || (size_t)n >= sizeof(msg))
		return;
	ms = net_timeout_ms(timeout_sec);
	net_write_all_ms(fd, msg, (size_t)n, ms);
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

static void *monitor_accept_thread(void *vargp);
static int count_open_files(void);

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec)
{
	int sockfd;
	struct in_addr addr;
	mon_t *mon;
	pthread_t thread_id;
	const char *bind_text = bind_ip;

	if (!bind_text || bind_text[0] == '\0')
		bind_text = "127.0.0.1";
	if (inet_pton(AF_INET, bind_text, &addr) != 1)
	{
		log_error("monitor bind address invalid");
		return NULL;
	}

	if(net_listen_ipv4(addr.s_addr, port, &sockfd)==false)
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
		free(mon->token);
		free(mon);
		return NULL;
	}
	mon->state = NULL;
	mon->fd = sockfd;
	mon->Port = port;
	mon->header_timeout = header_timeout_sec < 1 ? 5 : header_timeout_sec;
	if (mon->header_timeout > 60)
		mon->header_timeout = 60;

	if (pthread_create(&thread_id, NULL, monitor_accept_thread, (void*)mon) != 0)
	{
		log_error("monitor thread create failed");
		close(sockfd);
		pthread_mutex_destroy(&mon->stats_lock);
		free(mon->token);
		free(mon);
		return NULL;
	}
	pthread_detach(thread_id);

	return mon;
}

statistics_t *monitor_add_stat(mon_t *self,char *name)
{
	statistics_t *stat;
	statistics_t *created;
	if (!self)
		return NULL;
	pthread_mutex_lock(&self->stats_lock);
	stat = self->state;
	stats_init(&self->state,name);		/*create statistics var*/
	self->state->next = stat;
	created = self->state;
	pthread_mutex_unlock(&self->stats_lock);
	return created;
}

static void *monitor_client_thread(void *arg);
static void monitor_send_report(int fd,uint8_t *data,int len,mon_t *owner);
static void *monitor_accept_thread(void *vargp)
{
	mon_t *mon = (mon_t*)vargp;
	int sockfd = mon->fd;	  /* listening socket descriptor */

	log_info("Monitor thread start on socket %i Port %d",sockfd,mon->Port);
	monclient_t *client;
	while(1)
	{
		client = (monclient_t *)calloc(1, sizeof(monclient_t));
		if (!client)
			continue;
		client->owner = mon;
		client->addr_len = sizeof(client->cli);
		client->connid = accept(sockfd, (struct sockaddr*)&client->cli, &client->addr_len);
		if (client->connid < 0)
		{
			if (errno != EINTR)
				log_error("server accept failed");
			free(client);
			continue;
		}

		if (client->connid >= FD_SETSIZE || !mon_worker_acquire())
		{
			close(client->connid);
			free(client);
			continue;
		}

		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, monitor_client_thread, (void*)client) != 0)
		{
			mon_worker_release();
			close(client->connid);
			free(client);
			continue;
		}
		pthread_detach(thread_id);
	}
	return NULL;
}

static void *monitor_client_thread(void *arg)
{
	if (!arg) pthread_exit(0);
	monclient_t *client = (monclient_t*)arg;
	uint8_t buffer[MON_MAX_HEADER];
	uint32_t Windex = 0;
	int header_timeout = 5;
	int64_t deadline;
	int64_t started;

	fd_set rfds;
	struct timeval tv;
	if (client->owner && client->owner->header_timeout >= 1)
		header_timeout = client->owner->header_timeout;
	started = net_mono_ms();
	if (started < 0)
		goto out;
	deadline = started + (int64_t)header_timeout * 1000;
	while(1)
	{
		size_t line_len = 0;
		int line_status;
		int64_t now;
		int64_t remain_ms;

		if (client->connid < 0 || client->connid >= FD_SETSIZE)
			break;

		now = net_mono_ms();
		if (now < 0 || now >= deadline)
			break;
		remain_ms = deadline - now;

		FD_ZERO(&rfds);
		tv.tv_sec = (time_t)(remain_ms / 1000);
		tv.tv_usec = (suseconds_t)((remain_ms % 1000) * 1000);
		FD_SET(client->connid,&rfds);

		if (select(client->connid + 1, &rfds, NULL, NULL, &tv) < 0)	/*wait for socket data ready*/
		{
			if (errno == EINTR)
				continue;
			log_error("monitor select failed");
			break;
		}

		if(!FD_ISSET( client->connid, &rfds ))
		{
			log_trace("TimeOut tid:%i",client->connid);
			break;
		}

		ssize_t newData = read(client->connid, &buffer[Windex], sizeof(buffer) - Windex);/* read length of message */
		if (newData < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (newData <= 0)
		{
			log_trace("client %i disconnect %zd",client->connid,newData);
			break;
		}
		if ((uint32_t)newData > sizeof(buffer) - Windex)
			break;
		Windex += (uint32_t)newData;

		if (mon_crlf(buffer, Windex, &line_len))
		{
			line_status = mon_classify_line(buffer, line_len);
			if (line_status != 0)
			{
				mon_send_empty(client->connid, line_status, header_timeout);
				break;
			}
		}

		if (http_headers_done(buffer, Windex))
		{
			if (!client->owner || !mon_authorized(buffer, Windex, client->owner->token))
			{
				mon_send_empty(client->connid, 401, header_timeout);
				break;
			}
			monitor_send_report(client->connid, buffer, (int)Windex, client->owner);
			break;
		}
		if (Windex >= sizeof(buffer))
			break;
	}

out:
	log_trace("monitor client %i done",client->connid);
	if (client->connid >= 0)
		close(client->connid);
	mon_worker_release();
	free(client);
	return NULL;
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

static void monitor_send_report(int fd,uint8_t *data,int len,mon_t *owner)
{
	char message[2048];
	char *ptr = message;
	char *end = message + sizeof(message);
	statistics_t *stat = NULL;
	(void)data;
	(void)len;

	if (!owner)
		return;
	pthread_mutex_lock(&owner->stats_lock);
	stat = owner->state;
	pthread_mutex_unlock(&owner->stats_lock);

	memset(message, 0, sizeof(message));
	if (!mon_append(&ptr, end, "{\n\"ZroxyVersion\" : \"%s\",\n", version) ||
	    !mon_append(&ptr, end, "\"CountOfOpenFile\" : %i,\n", count_open_files()))
		return;
	
	statistics_t *sta = stat;
	while(sta)
	{
		stat_t stdata;
		stats_get(sta,&stdata);
		time_t CurrentTime;
		time ( &CurrentTime );
		time_t LiveTime = CurrentTime - stdata.StartTime;

		if (!mon_append(&ptr, end, "\"%s\" : {\n", sta->name) ||
		    !mon_append(&ptr, end, "\"UpTime\" : %lu ,\n", LiveTime) ||
		    !mon_append(&ptr, end, "\"MaxConnection\" : %i ,\n", stdata.MaxConnection) ||
		    !mon_append(&ptr, end, "\"ActiveConnection\" : %i ,\n", stdata.ActiveConnection) ||
		    !mon_append(&ptr, end, "\"TotalConnection\" : %i ,\n", stdata.TotalConnection) ||
		    !mon_append(&ptr, end, "\"TotalRx\" : %lu ,\n", stdata.TotalRx) ||
		    !mon_append(&ptr, end, "\"TotalTx\" : %lu", stdata.TotalTx) ||
		    !mon_append(&ptr, end, "\n},\n"))
			return;

		sta = (statistics_t*)sta->next;
	}

	if (ptr - message < 2)
		return;
	memcpy(ptr - 2, "\n}", 3);

	{
		char httpMessage[8000];
		int body_len = (int)(ptr - message);
		int slen;
		if (body_len < 0)
			return;
		slen = snprintf(httpMessage, sizeof(httpMessage),
			"HTTP/1.1 200 OK\nContent-Type: application/json; charset=UTF-8\nContent-Length: %i\nConnection: Closed\n\n%s",
			body_len, message);
		if (slen < 0 || (size_t)slen >= sizeof(httpMessage))
			return;
		net_write_all_ms(fd, httpMessage, (size_t)slen,
			net_timeout_ms(owner->header_timeout));
	}
}

static int count_open_files(void)
{
    struct dirent *entry;
    int count = 0;

	DIR *dp = NULL;
#ifdef __linux__
    dp = opendir("/proc/self/fd");
#elif __FreeBSD__
    dp = opendir("/dev/fd/");
#endif

    if (dp == NULL) 
	{
        perror("opendir");
        return -1;
    }

    // The number of files in the directory '/proc/self/fd'
    while ((entry = readdir(dp)) != NULL) 
	{
        count++;
    }

    closedir(dp);
    
	// because "." and ".." are also in the directory, we need to reduce by 2
    return count - 2;
}
