/*
 * monitor.h
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#ifndef MONITOR_H_
#define MONITOR_H_
#include <stdbool.h>
#include <zroxy/statistics.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * Appends the members of a top-level report object as `"Key" : value` pairs
 * separated by ",\n", with no trailing separator. The monitor adds the braces.
 */
typedef bool (*mon_section_fn)(void *ctx, char **ptr, char *end);

typedef struct mon_section
{
	char name[32];
	mon_section_fn fn;
	void *ctx;
	struct mon_section *next;
}mon_section_t;

typedef struct
{
	int fd;
	uint16_t Port;
	statistics_t *state;
	mon_section_t *sections; /* guarded by stats_lock; nodes are never freed */
	pthread_mutex_t stats_lock; /* guards the state list head only */
	char *token; /* optional bearer secret; NULL disables authentication */
	int header_timeout; /* seconds to wait for a complete header */
	pthread_t accept_thread; /* joined by monitor_stop */
	int wake[2]; /* pipe that wakes the accept thread */
	int stopping; /* set by monitor_stop; workers give up at their next slice */
}mon_t;

typedef struct
{
	int		 			connid;
	struct sockaddr_in	cli;
	socklen_t 			addr_len;
	mon_t 			*owner;
}monclient_t;

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec);
statistics_t *monitor_add_stat(mon_t *self,char *name);
/* Adds a top-level object written by fn. ctx must outlive the monitor. */
bool monitor_add_section(mon_t *self, const char *name, mon_section_fn fn, void *ctx);
/*
 * Stops accepting, joins the accept thread, closes the listener, waits for the
 * active clients (at most the header timeout plus a margin), then frees the
 * sections, the statistics objects, the token and the monitor itself. If a
 * client is still running after that wait, nothing it can touch is freed.
 *
 * Call it only after every service that writes to the statistics objects
 * (SNI, DNS) has stopped, and once the sections' contexts are still valid.
 */
void monitor_stop(mon_t *self);

#ifdef MON_TEST_HOOKS
#include <stddef.h>
#include <stdint.h>
/* -1 while the request line is incomplete, else 0 or the HTTP status to send. */
int monitor_test_classify(const uint8_t *buf, size_t len);
bool monitor_test_headers_done(const uint8_t *buf, size_t len);
bool monitor_test_authorized(const uint8_t *buf, size_t len, const char *token);
#endif

#endif /* MONITOR_H_ */
