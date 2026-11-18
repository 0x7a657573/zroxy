#ifndef RESOLVER_INTERNAL_H_
#define RESOLVER_INTERNAL_H_

#include "resolver.h"

#define RESOLVER_QUOTA_LISTENER 1
#define RESOLVER_QUOTA_DIRECT 2
#define RESOLVER_QUOTA_INFRA 3
#define RESOLVER_BIND_MAX 32
#define RESOLVER_GAI_ATTEMPTS 8

typedef struct sni_bind_rec {
	int used;
	int wildcard;
	uint32_t listener_id;
	uint16_t port;
	struct in_addr ip;
} sni_bind_rec;

typedef struct resolver_pool {
	pthread_mutex_t mu;
	pthread_cond_t work_cv;
	pthread_cond_t infra_cv;
	pthread_t threads[RESOLVER_THREADS];
	int started;
	int stopping;
	int abandoned;
	int exited;
	int pause_dequeue;
	resolve_slot slots[RESOLVER_SLOTS];
	resolve_slot *free_head;
	resolve_slot *client_head;
	resolve_slot *client_tail;
	resolve_slot *infra_head;
	resolve_slot *infra_tail;
	int free_count;
	int direct_used;
	int infra_used;
	int listener_used;
	int listener_quota_assigned;
	int live_sinks;
	int open_pipes;
	int double_free;
	unsigned sink_refs;
	uint64_t next_req_id;
	uint32_t next_listener_id;
	int cache_valid;
	char cache_host[RESOLVER_HOST_MAX + 1];
	uint16_t cache_port;
	size_t cache_count;
	resolver_addr cache_addrs[RESOLVER_ADDR_MAX];
	int64_t cache_last_success;
	int64_t cache_refresh_after;
	int64_t cache_max_stale;
	int cache_refresh_inflight;
	uint64_t cache_refresh_req;
	sni_bind_rec binds[RESOLVER_BIND_MAX];
	uint32_t calls;
	uint32_t skipped_expired;
	uint32_t skipped_cancelled;
	uint32_t eagain_wakeups;
	uint32_t closed_drops;
	uint32_t ring_full;
	uint32_t lookup_failures;
#ifdef SNI_TEST_HOOKS
	resolver_hook hook;
	void *hook_cookie;
	int hold_running;
	int running_entered;
	pthread_mutex_t test_mu;
	pthread_cond_t test_cv;
#endif
} resolver_pool;

extern resolver_pool *g_resolver_pool;

#endif /* RESOLVER_INTERNAL_H_ */
