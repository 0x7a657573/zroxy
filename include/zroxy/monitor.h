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
	pthread_t thread; /* joined by monitor_stop */
	int wake[2]; /* pipe that wakes the monitor thread */
	void *private_data; /* monitor reactor and private client slots */
}mon_t;

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec);
/*
 * Adds a caller-owned statistics object to the report, newest first. The
 * monitor only borrows it: stat must outlive the monitor and is never freed
 * here. Returns false for a NULL argument.
 */
bool monitor_attach_stat(mon_t *self,statistics_t *stat);
/* Adds a top-level object written by fn. ctx must outlive the monitor. */
bool monitor_add_section(mon_t *self, const char *name, mon_section_fn fn, void *ctx);
/*
 * Stops accepting, joins the monitor thread, closes the listener and pipe,
 * then frees the sections, token and monitor itself. The attached statistics
 * objects stay the caller's. Returns true when stopped (also for NULL).
 *
 * Call it only after every service that writes to the statistics objects
 * (SNI, DNS) has stopped, and once the sections' contexts are still valid.
 */
bool monitor_stop(mon_t *self);

#ifdef MON_TEST_HOOKS
#include <stddef.h>
#include <stdint.h>
/* -1 while the request line is incomplete, else 0 or the HTTP status to send. */
int monitor_test_classify(const uint8_t *buf, size_t len);
bool monitor_test_headers_done(const uint8_t *buf, size_t len);
bool monitor_test_authorized(const uint8_t *buf, size_t len, const char *token);
#endif

#endif /* MONITOR_H_ */
