#ifndef ZROXY_FDLIMIT_H
#define ZROXY_FDLIMIT_H

/*
 * Sizing of the open-file limit (RLIMIT_NOFILE) from the configured caps.
 * Each SNI connection holds two descriptors, a client and an upstream.
 */

#include <stdbool.h>

/* Descriptors the DNS service may hold for local TCP clients. */
#define FDLIMIT_DNS_CLIENTS 128ul
/* Descriptors the monitor may hold for its workers. */
#define FDLIMIT_MONITOR_WORKERS 32ul
/* Listeners, pipes, epoll, log and anything not counted elsewhere. */
#define FDLIMIT_MARGIN 64ul
/* Extra descriptors each SNI listener keeps (listen, wake pipe, reactor, resolver pipe). */
#define FDLIMIT_PER_LISTENER 8ul

typedef struct
{
	int sni_conns; /* configured SNI connection cap */
	int sni_listeners;
	bool dns_enabled;
	int dns_upstreams; /* DNS upstream connection cap, used when dns_enabled */
	bool monitor_enabled;
} fdlimit_plan;

/* Descriptors needed by everything except SNI connections. */
unsigned long fdlimit_other_need(const fdlimit_plan *plan);
/* Total descriptors needed with the configured SNI cap. */
unsigned long fdlimit_needed(const fdlimit_plan *plan);
/*
 * The SNI connection cap a soft limit can serve: (soft - other) / 2,
 * at least 1 and never above the configured cap.
 */
int fdlimit_sni_cap(const fdlimit_plan *plan, unsigned long soft);

/*
 * Raise the soft RLIMIT_NOFILE toward fdlimit_needed, never above the hard
 * limit, and store the SNI cap the resulting limit can serve in *sni_cap.
 * Never fails: when the limit can not be read, the configured cap is kept.
 * Returns the soft limit in effect (0 when unknown).
 */
unsigned long fdlimit_apply(const fdlimit_plan *plan, int *sni_cap);

#endif
