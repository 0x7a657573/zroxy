/*
 * Process-wide hostname resolver shared by the SNI and DNS data planes.
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
#ifndef RESOLVER_H_
#define RESOLVER_H_

#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define RESOLVER_THREADS 4
#define RESOLVER_SLOTS 128
#define RESOLVER_DIRECT_RESERVE 3
#define RESOLVER_INFRA_RESERVE 8
/*
 * One listener may hold this many client lookups. The rest of the client
 * budget stays available for listeners that register later, so one listener
 * cannot take every slot. 104 leaves 13 client slots after the 3 direct and
 * 8 infrastructure reserves (104 + 13 + 3 + 8 = 128) and covers the existing
 * 100-connection burst on a single listener.
 */
#define RESOLVER_LISTENER_QUOTA 104
#define RESOLVER_ADDR_MAX 8
#define RESOLVER_HOST_MAX 253
#define RESOLVER_INFRA_REFRESH_MS 30000
#define RESOLVER_INFRA_MAX_STALE_MS 120000
#define RESOLVER_INFRA_STARTUP_MS 1500

#define RESOLVER_SINK_LISTENER 1
#define RESOLVER_SINK_DIRECT 2

#define RESOLVER_KIND_CLIENT 1
#define RESOLVER_KIND_INFRA 2

#define RESOLVER_SUBMIT_OK 0
#define RESOLVER_SUBMIT_OVERFLOW -1
#define RESOLVER_SUBMIT_BADNAME -2

#define RESOLVER_UP_READY 0
#define RESOLVER_UP_UNRESOLVED 1
#define RESOLVER_UP_NEED_RESOLVE 2

typedef enum {
	RESOLVE_FREE = 0,
	RESOLVE_QUEUED,
	RESOLVE_RUNNING,
	RESOLVE_DONE,
	RESOLVE_CANCELLED
} resolve_state;

typedef struct resolver_sink resolver_sink;

typedef struct resolver_addr {
	struct sockaddr_storage address;
	socklen_t length;
} resolver_addr;

typedef struct resolve_slot {
	uint64_t req_id;
	uint32_t listener_id;
	uint32_t connection_index;
	uint64_t connection_generation;
	resolve_state state;
	int request_class;
	int gai_error;
	int64_t deadline_ms;
	char hostname[RESOLVER_HOST_MAX + 1];
	uint16_t port;
	int family_policy;
	size_t address_count;
	resolver_addr addresses[RESOLVER_ADDR_MAX];
	resolver_sink *sink;
	int index;
	int in_ring;
	int holds_ref;
	int quota_kind;
	struct resolve_slot *qnext;
} resolve_slot;

struct resolver_sink {
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

typedef struct resolver_accounting {
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
} resolver_accounting;

bool resolver_start(void);

typedef struct resolver_stats {
	int threads;
	int slots;
	int slots_in_use;
	uint32_t lookups;         /* getaddrinfo calls, retries after EINTR included */
	uint32_t lookup_failures; /* lookups that returned an error or no address */
	uint32_t ring_full;       /* completions dropped because a sink's ring was full */
} resolver_stats;

/*
 * Snapshot for the monitor. Takes the pool mutex once; before the pool is
 * started only the fixed sizes are filled in. Safe to call at any time.
 */
void resolver_get_stats(resolver_stats *out);

/*
 * Bounded wait for workers to leave getaddrinfo(). On timeout the pool is
 * left allocated: mutexes, slots, and threads stay valid until process exit.
 * Returns 0 when the pool was destroyed, 1 when it was abandoned.
 */
int resolver_shutdown(int timeout_ms);

/* Lowercase ASCII, strip one trailing dot, reject a hostname the proxy will not resolve. */
bool resolver_normalize(const char *in, char *out, size_t out_cap);

bool resolver_sink_open(int kind, resolver_sink **out);
void resolver_sink_mark_closed(resolver_sink *sink);
void resolver_sink_release(resolver_sink *sink);

/* Drain the wakeup pipe, then every slot currently in the ring. */
size_t resolver_drain(resolver_sink *sink, resolve_slot **out, size_t max_out);

int resolver_submit(resolver_sink *sink, uint32_t connection_index,
		uint64_t connection_generation, const char *hostname, uint16_t port,
		int family, int64_t deadline_ms, int *slot_index, uint64_t *req_id);

void resolver_cancel(int slot_index, uint64_t req_id);
void resolver_release(int slot_index, uint64_t req_id);

/* Register the listener bind used for self-connect checks. IPv4 only. */
void resolver_watch_bind(uint32_t listener_id, const char *bindip, uint16_t port);
void resolver_unwatch_bind(uint32_t listener_id);

/* Destination policy flags for resolver_policy_keep. */
#define RESOLVER_POLICY_ALLOW_LOOPBACK 0x1u	/* dial 127.0.0.0/8 and ::1 */
#define RESOLVER_POLICY_DENY_PRIVATE   0x2u	/* also refuse private ranges */

/*
 * Rewrite IPv4-mapped IPv6 to IPv4, drop addresses the proxy must not dial,
 * and compact the array. Always removed: unspecified and 0.0.0.0/8,
 * 255.255.255.255, 169.254/16, multicast, 240/4, fe80::/10, fec0::/10,
 * IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::/96) forms of those, and
 * self-connect targets. Loopback is removed unless RESOLVER_POLICY_ALLOW_LOOPBACK
 * is set (a loopback target on a listener's own port still goes). Private
 * ranges (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) are kept unless
 * RESOLVER_POLICY_DENY_PRIVATE is set. Only used for addresses resolved from
 * client-supplied names, never for the operator's SOCKS or DNS upstream.
 */
size_t resolver_policy_keep(resolver_addr *addrs, size_t count, unsigned flags);

/*
 * SOCKS startup. A numeric host is stored as a bypass. A hostname is looked
 * up once, waiting at most wait_ms outside any event loop. Listeners still
 * start when the lookup fails; new SOCKS connections then fail immediately.
 * Returns false only when the pool itself cannot start.
 */
bool resolver_prime_socks(const char *host, uint16_t port, int wait_ms);

/* Numeric bypass, fresh or stale cache, or "still needs a client lookup". */
int resolver_copy_upstream(const char *host, uint16_t port,
		resolver_addr *out, size_t *count);

#ifdef RESOLVER_TEST_HOOKS
typedef int (*resolver_hook)(const char *hostname, int family,
		resolver_addr *out, size_t max_out, size_t *count, void *cookie);

typedef struct resolver_counters {
	uint32_t calls;
	uint32_t skipped_expired;
	uint32_t skipped_cancelled;
	uint32_t eagain_wakeups;
	uint32_t closed_drops;
	uint32_t ring_full;
} resolver_counters;

void resolver_test_set_hook(resolver_hook hook, void *cookie);
void resolver_test_stats(resolver_counters *out);
void resolver_test_reset_stats(void);
void resolver_test_pause_dequeue(int pause);
void resolver_test_hold_running(int hold);
int resolver_test_wait_running(int want, int timeout_ms);
bool resolver_test_accounting(resolver_accounting *out);
int resolver_test_mutex_ok(void);
void resolver_test_age_cache(int64_t last_success_ms, int64_t refresh_after_ms,
		int64_t max_stale_ms);
int resolver_sink_quota(const resolver_sink *sink);
/* Queue infrastructure slots until the reserve is full. Caller should pause dequeue. */
int resolver_test_fill_infra(void);
/* Mark queued slots cancelled and let workers free them. */
void resolver_test_reap(void);
int resolver_test_wait_idle(int timeout_ms);
#endif

#endif /* RESOLVER_H_ */
