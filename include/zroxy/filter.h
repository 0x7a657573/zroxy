/*
 * filter.h
 *
 *  Created on: Mar 8, 2020
 *      Author: zeus
 *
 * Hostname whitelist. One name or pattern per line; blank lines and lines
 * starting with '#' are ignored. Matching is ASCII case-insensitive and a
 * trailing dot on the queried name is ignored.
 *
 *   example.com      exact name             (hash lookup)
 *   *.example.com    any name ending in ".example.com"  (hash lookup per label)
 *   api?.ex*.com     any other '*' / '?' pattern        (linear scan)
 */

#ifndef FILTER_FILTER_H_
#define FILTER_FILTER_H_
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <zroxy/config.h>

typedef struct filter_set filter_set_t;

typedef struct
{
	char   *filepath;		/* NULL for an in-memory list */
	filter_set_t *set;		/* immutable snapshot, swapped on reload */
	pthread_rwlock_t lock;	/* readers: lookups; writer: reload swap */
	/* Reload outcomes, updated with relaxed atomics; word-sized for 32-bit targets. */
	uint32_t reloads;			/* successful reloads since start */
	uint32_t reload_failures;	/* reloads that kept the previous list */
	uint32_t last_reload;		/* unix time of the last successful reload, 0 = never */
}filter_t;

/* Load a file and start watching it for changes. NULL on any error. */
filter_t *filter_init(char *filename);
/* Build from entries in memory, with no file and no watcher. */
filter_t *filter_from_list(const char *const *entries, size_t count);
/* Only for lists without a watcher (filter_from_list). */
void filter_free(filter_t *self);

#ifdef FILTER_TEST_HOOKS
/* Load a file like filter_init, but start no watcher. Release with filter_free. */
filter_t *filter_test_open(const char *filename);
#endif

bool filter_match(filter_t *self,const char *host);
/* Re-read the file; on any error the current list is kept. */
void filter_reload(filter_t *self);
/* Number of entries in the current list. */
size_t filter_count(filter_t *self);
/*
 * Monitor section: appends "Entries", "Reloads", "ReloadFailures" and
 * "LastReload" as `"Key" : value` pairs separated by ",\n".
 */
bool filter_stats_json(void *ctx, char **ptr, char *end);
#endif /* FILTER_FILTER_H_ */
