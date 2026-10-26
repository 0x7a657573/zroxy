/*
 * Process-wide DNS resolver for the SNI data plane.
 *
 * Four worker threads and 128 slots are created once. Nothing in this pool
 * grows with the connection count. Workers call getaddrinfo() and never touch
 * connection or socket memory. The event loop owns completion pipes and
 * applies results.
 *
 * Slot ownership is exclusive:
 *   FREE        free list, pool
 *   QUEUED      client or infrastructure queue, pool
 *   RUNNING     the worker that dequeued it
 *   DONE        the completion ring, then the event loop until release
 *   CANCELLED   still on the queue; the worker frees it and does not complete
 *
 * Cancel and release take a slot index and req_id. An index alone is never
 * enough, because slots are recycled.
 *
 * The pool mutex and a completion-sink mutex are never held together.
 * getaddrinfo(), pipe writes, and socket calls happen with neither lock held.
 */
#ifndef SNI_RESOLVER_H_
#define SNI_RESOLVER_H_

#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define SNI_RESOLVER_THREADS 4
#define SNI_RESOLVER_SLOTS 128
#define SNI_RESOLVER_DIRECT_RESERVE 3
#define SNI_RESOLVER_INFRA_RESERVE 8
/*
 * One listener may hold this many client lookups. The rest of the client
 * budget stays available for listeners that register later, so one listener
 * cannot take every slot. 104 leaves 13 client slots after the 3 direct and
 * 8 infrastructure reserves (104 + 13 + 3 + 8 = 128) and covers the existing
 * 100-connection burst on a single listener.
 */
#define SNI_RESOLVER_LISTENER_QUOTA 104
#define SNI_RESOLVER_ADDR_MAX 8
#define SNI_RESOLVER_HOST_MAX 253
#define SNI_INFRA_REFRESH_MS 30000
#define SNI_INFRA_MAX_STALE_MS 120000
#define SNI_INFRA_STARTUP_MS 1500

#define SNI_SINK_LISTENER 1
#define SNI_SINK_DIRECT 2

#define SNI_RESOLVE_CLIENT 1
#define SNI_RESOLVE_INFRA 2

#define SNI_SUBMIT_OK 0
#define SNI_SUBMIT_OVERFLOW -1
#define SNI_SUBMIT_BADNAME -2

#define SNI_UP_READY 0
#define SNI_UP_UNRESOLVED 1
#define SNI_UP_NEED_RESOLVE 2

typedef enum {
	RESOLVE_FREE = 0,
	RESOLVE_QUEUED,
	RESOLVE_RUNNING,
	RESOLVE_DONE,
	RESOLVE_CANCELLED
} resolve_state;

typedef struct sni_completion_sink sni_completion_sink;

typedef struct sni_resolved_addr {
	struct sockaddr_storage address;
	socklen_t length;
} sni_resolved_addr;

typedef struct resolve_slot {
	uint64_t req_id;
	uint32_t listener_id;
	uint32_t connection_index;
	uint64_t connection_generation;
	resolve_state state;
	int request_class;
	int gai_error;
	int64_t deadline_ms;
	char hostname[SNI_RESOLVER_HOST_MAX + 1];
	uint16_t port;
	int family_policy;
	size_t address_count;
	sni_resolved_addr addresses[SNI_RESOLVER_ADDR_MAX];
	sni_completion_sink *sink;
	int index;
	int in_ring;
	int holds_ref;
	int quota_kind;
	struct resolve_slot *qnext;
} resolve_slot;

struct sni_completion_sink {
	pthread_mutex_t mutex;
	int pipe_read;
	int pipe_write;
	bool closed;
	unsigned refcount;
	resolve_slot **ring;
	size_t ring_capacity;
	size_t ring_head;
	size_t ring_tail;
	size_t ring_count;
	int kind;
	uint32_t listener_id;
	int quota_limit;
	int quota_used;
};

typedef struct sni_resolver_accounting {
	int free_n;
	int queued;
	int running;
	int done;
	int cancelled;
	int in_ring;
	int quota_used;
	int direct_used;
	int infra_used;
	int listener_used;
	int sink_refs;
	int open_pipes;
	int double_free;
	int live_sinks;
	int abandoned;
	int listener_quota_assigned;
} sni_resolver_accounting;

bool sni_resolver_start(void);

/*
 * Bounded wait for workers to leave getaddrinfo(). On timeout the pool is
 * left allocated: mutexes, slots, and threads stay valid until process exit.
 * Returns 0 when the pool was destroyed, 1 when it was abandoned.
 */
int sni_resolver_shutdown(int timeout_ms);

/* Lowercase ASCII, strip one trailing dot, reject a hostname the proxy will not resolve. */
bool sni_resolver_normalize(const char *in, char *out, size_t out_cap);

bool sni_resolver_sink_open(int kind, sni_completion_sink **out);
void sni_resolver_sink_mark_closed(sni_completion_sink *sink);
void sni_resolver_sink_release(sni_completion_sink *sink);

/* Drain the wakeup pipe, then every slot currently in the ring. */
size_t sni_resolver_drain(sni_completion_sink *sink, resolve_slot **out, size_t max_out);

int sni_resolver_submit(sni_completion_sink *sink, uint32_t connection_index,
		uint64_t connection_generation, const char *hostname, uint16_t port,
		int family, int64_t deadline_ms, int *slot_index, uint64_t *req_id);

void sni_resolver_cancel(int slot_index, uint64_t req_id);
void sni_resolver_release(int slot_index, uint64_t req_id);

/* Register the listener bind used for self-connect checks. IPv4 only. */
void sni_resolver_watch_bind(uint32_t listener_id, const char *bindip, uint16_t port);
void sni_resolver_unwatch_bind(uint32_t listener_id);

/*
 * Rewrite IPv4-mapped IPv6 to IPv4, drop addresses the proxy must not dial,
 * and compact the array. Private ranges are kept. Link-local, multicast,
 * unspecified, and self-connect targets are removed.
 */
size_t sni_resolver_policy_keep(sni_resolved_addr *addrs, size_t count);

/*
 * SOCKS startup. A numeric host is stored as a bypass. A hostname is looked
 * up once, waiting at most wait_ms outside any event loop. Listeners still
 * start when the lookup fails; new SOCKS connections then fail immediately.
 * Returns false only when the pool itself cannot start.
 */
bool sni_resolver_prime_socks(const char *host, uint16_t port, int wait_ms);

/* Numeric bypass, fresh or stale cache, or "still needs a client lookup". */
int sni_resolver_copy_upstream(const char *host, uint16_t port,
		sni_resolved_addr *out, size_t *count);

#ifdef SNI_TEST_HOOKS
typedef int (*sni_resolve_hook)(const char *hostname, int family,
		sni_resolved_addr *out, size_t max_out, size_t *count, void *cookie);

typedef struct sni_resolver_counters {
	uint32_t calls;
	uint32_t skipped_expired;
	uint32_t skipped_cancelled;
	uint32_t eagain_wakeups;
	uint32_t closed_drops;
	uint32_t ring_full;
} sni_resolver_counters;

void sni_resolver_test_set_hook(sni_resolve_hook hook, void *cookie);
void sni_resolver_test_stats(sni_resolver_counters *out);
void sni_resolver_test_reset_stats(void);
void sni_resolver_test_pause_dequeue(int pause);
void sni_resolver_test_hold_running(int hold);
int sni_resolver_test_wait_running(int want, int timeout_ms);
bool sni_resolver_test_accounting(sni_resolver_accounting *out);
int sni_resolver_test_mutex_ok(void);
void sni_resolver_test_age_cache(int64_t last_success_ms, int64_t refresh_after_ms,
		int64_t max_stale_ms);
int sni_resolver_sink_quota(const sni_completion_sink *sink);
/* Queue infrastructure slots until the reserve is full. Caller should pause dequeue. */
int sni_resolver_test_fill_infra(void);
/* Mark queued slots cancelled and let workers free them. */
void sni_resolver_test_reap(void);
int sni_resolver_test_wait_idle(int timeout_ms);
#endif

#endif /* SNI_RESOLVER_H_ */
