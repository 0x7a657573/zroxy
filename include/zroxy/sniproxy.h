/*
 *
 */

#ifndef SNIPROXY_H_
#define SNIPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zroxy/config.h>
#include <zroxy/acl.h>
#include <zroxy/statistics.h>
#include <zroxy/filter.h>
#include <zroxy/socks.h>
#include <zroxy/settings.h>

typedef struct
{
	lport_t port;
	sockshost_t *socks;
	statistics_t *stats;
	filter_t *whitelist;
	int snitimeout;
	/* Relay idle limit in seconds; 0 falls back to snitimeout. */
	int sniidletimeout;
	/* Dial resolved loopback addresses (default off). */
	bool allow_loopback;
	/* Refuse resolved private addresses (default off). */
	bool deny_private;
	/* Client networks allowed to connect; owned by the caller. No list allows all. */
	const zroxy_cidr_t *acl;
	size_t acl_count;
} sni_server_t;

typedef struct sni_listener sni_listener;

/* Listen and start the event loop. NULL on failure. */
sni_listener *sniproxy_start(sni_server_t *cfg);
/* Stop accepting, close every connection, join the loop and free. */
void sniproxy_stop(sni_listener *ls);
bool sni_conn_acquire(void);
void sni_conn_release(void);
/* The connection cap shared by every listener. */
int sni_conn_limit(void);
/* Set the cap, clamped to 1..SNI_CONN_LIMIT_MAX. Call before listeners start. */
void sni_conn_set_limit(int limit);

/*
 * stats_extra_fn for the SNI_Server monitor object: appends the connection
 * limit and the counters that say how connections ended.
 */
bool sni_stats_json(void *ctx, char **ptr, char *end);

#endif /* SNIPROXY_H_ */
