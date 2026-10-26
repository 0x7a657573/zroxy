#define _GNU_SOURCE

#include "sni_resolver.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>

#include <log.h>
#include <net_io.h>

#define SNI_QUOTA_LISTENER 1
#define SNI_QUOTA_DIRECT 2
#define SNI_QUOTA_INFRA 3
#define SNI_BIND_MAX 32
#define SNI_GAI_ATTEMPTS 8

typedef struct sni_bind_rec {
	int used;
	int wildcard;
	uint32_t listener_id;
	uint16_t port;
	struct in_addr ip;
} sni_bind_rec;

typedef struct sni_resolver_pool {
	pthread_mutex_t mu;
	pthread_cond_t work_cv;
	pthread_cond_t infra_cv;
	pthread_t threads[SNI_RESOLVER_THREADS];
	int started;
	int stopping;
	int abandoned;
	int exited;
	int pause_dequeue;
	resolve_slot slots[SNI_RESOLVER_SLOTS];
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
	char cache_host[SNI_RESOLVER_HOST_MAX + 1];
	uint16_t cache_port;
	size_t cache_count;
	sni_resolved_addr cache_addrs[SNI_RESOLVER_ADDR_MAX];
	int64_t cache_last_success;
	int64_t cache_refresh_after;
	int64_t cache_max_stale;
	int cache_refresh_inflight;
	uint64_t cache_refresh_req;
	sni_bind_rec binds[SNI_BIND_MAX];
	uint32_t calls;
	uint32_t skipped_expired;
	uint32_t skipped_cancelled;
	uint32_t eagain_wakeups;
	uint32_t closed_drops;
	uint32_t ring_full;
#ifdef SNI_TEST_HOOKS
	sni_resolve_hook hook;
	void *hook_cookie;
	int hold_running;
	int running_entered;
	pthread_mutex_t test_mu;
	pthread_cond_t test_cv;
#endif
} sni_resolver_pool;

static sni_resolver_pool *g_pool;
static pthread_mutex_t g_start_mu = PTHREAD_MUTEX_INITIALIZER;

static void sink_destroy(sni_completion_sink *sink);
static sni_completion_sink *slot_free_locked(resolve_slot *slot);

static void ignore_sigpipe(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

static int mono_deadline(int timeout_ms, struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) != 0)
		return -1;
	ts->tv_sec += timeout_ms / 1000;
	ts->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (ts->tv_nsec >= 1000000000L) {
		ts->tv_sec += 1;
		ts->tv_nsec -= 1000000000L;
	}
	return 0;
}

static int init_mono_cond(pthread_cond_t *cv)
{
	pthread_condattr_t attr;
	if (pthread_condattr_init(&attr) != 0)
		return -1;
	if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
		pthread_condattr_destroy(&attr);
		return -1;
	}
	if (pthread_cond_init(cv, &attr) != 0) {
		pthread_condattr_destroy(&attr);
		return -1;
	}
	pthread_condattr_destroy(&attr);
	return 0;
}

static void enqueue(resolve_slot **head, resolve_slot **tail, resolve_slot *slot)
{
	slot->qnext = NULL;
	if (*tail)
		(*tail)->qnext = slot;
	else
		*head = slot;
	*tail = slot;
}

static resolve_slot *dequeue(resolve_slot **head, resolve_slot **tail)
{
	resolve_slot *slot = *head;
	if (!slot)
		return NULL;
	*head = slot->qnext;
	if (*head == NULL)
		*tail = NULL;
	slot->qnext = NULL;
	return slot;
}

static uint64_t alloc_req_id_locked(sni_resolver_pool *pool)
{
	pool->next_req_id++;
	if (pool->next_req_id == 0)
		pool->next_req_id = 1;
	return pool->next_req_id;
}

static sni_completion_sink *ref_drop_locked(sni_completion_sink *sink)
{
	if (!sink || sink->refcount == 0)
		return NULL;
	sink->refcount--;
	g_pool->sink_refs--;
	if (sink->refcount == 0)
		return sink;
	return NULL;
}

static void quota_dec_locked(resolve_slot *slot)
{
	if (slot->quota_kind == SNI_QUOTA_DIRECT) {
		if (g_pool->direct_used > 0)
			g_pool->direct_used--;
	} else if (slot->quota_kind == SNI_QUOTA_INFRA) {
		if (g_pool->infra_used > 0)
			g_pool->infra_used--;
	} else if (slot->quota_kind == SNI_QUOTA_LISTENER) {
		if (g_pool->listener_used > 0)
			g_pool->listener_used--;
		if (slot->sink && slot->sink->quota_used > 0)
			slot->sink->quota_used--;
	}
	slot->quota_kind = 0;
}

static sni_completion_sink *slot_free_locked(resolve_slot *slot)
{
	sni_completion_sink *die = NULL;
	if (!slot)
		return NULL;
	if (slot->state == RESOLVE_FREE) {
		g_pool->double_free++;
		return NULL;
	}
	quota_dec_locked(slot);
	if (slot->holds_ref && slot->sink) {
		slot->holds_ref = 0;
		die = ref_drop_locked(slot->sink);
	}
	slot->state = RESOLVE_FREE;
	slot->in_ring = 0;
	slot->sink = NULL;
	slot->hostname[0] = '\0';
	slot->address_count = 0;
	slot->gai_error = 0;
	slot->qnext = g_pool->free_head;
	g_pool->free_head = slot;
	g_pool->free_count++;
	return die;
}

static void destroy_later(sni_completion_sink *sink)
{
	if (sink)
		sink_destroy(sink);
}

static int set_pipe_flags(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	int fdflags;
	if (flags < 0)
		return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	fdflags = fcntl(fd, F_GETFD, 0);
	if (fdflags < 0)
		return -1;
	if (fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) < 0)
		return -1;
	return 0;
}

static int open_pipe(int fds[2])
{
#if defined(__linux__) || defined(__FreeBSD__)
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0)
		return 0;
	if (errno != ENOSYS)
		return -1;
#endif
	if (pipe(fds) != 0)
		return -1;
	if (set_pipe_flags(fds[0]) != 0 || set_pipe_flags(fds[1]) != 0) {
		close(fds[0]);
		close(fds[1]);
		fds[0] = -1;
		fds[1] = -1;
		return -1;
	}
	return 0;
}

static void sink_wakeup(sni_completion_sink *sink)
{
	char byte = 1;
	for (;;) {
		ssize_t n = write(sink->pipe_write, &byte, 1);
		if (n >= 0)
			return;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (g_pool)
				__atomic_fetch_add(&g_pool->eagain_wakeups, 1u, __ATOMIC_RELAXED);
			return;
		}
		return;
	}
}

static int ring_push(sni_completion_sink *sink, resolve_slot *slot)
{
	if (sink->ring_count >= sink->ring_capacity)
		return -1;
	sink->ring[sink->ring_tail] = slot;
	sink->ring_tail++;
	if (sink->ring_tail == sink->ring_capacity)
		sink->ring_tail = 0;
	sink->ring_count++;
	return 0;
}

/*
 * holds_ref is already clear, so the event loop will not drop the sink ref.
 * The worker still owns that ref until publish_slot returns, which keeps the
 * sink alive across the ring push.
 */
static void push_completion(resolve_slot *slot, sni_completion_sink *sink)
{
	int pushed = 0;
	sni_completion_sink *die = NULL;
	pthread_mutex_lock(&sink->mutex);
	if (!sink->closed && ring_push(sink, slot) == 0) {
		pushed = 1;
	} else if (sink->closed) {
		if (g_pool)
			__atomic_fetch_add(&g_pool->closed_drops, 1u, __ATOMIC_RELAXED);
	} else if (g_pool) {
		__atomic_fetch_add(&g_pool->ring_full, 1u, __ATOMIC_RELAXED);
	}
	pthread_mutex_unlock(&sink->mutex);
	if (pushed) {
		sink_wakeup(sink);
		return;
	}
	pthread_mutex_lock(&g_pool->mu);
	die = slot_free_locked(slot);
	pthread_mutex_unlock(&g_pool->mu);
	destroy_later(die);
}

static void publish_slot(resolve_slot *slot, sni_completion_sink *sink)
{
	sni_completion_sink *die;
	push_completion(slot, sink);
	pthread_mutex_lock(&g_pool->mu);
	die = ref_drop_locked(sink);
	pthread_mutex_unlock(&g_pool->mu);
	destroy_later(die);
}

static int copy_numeric(const char *host, uint16_t port, sni_resolved_addr *out, size_t *count)
{
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	memset(&in, 0, sizeof(in));
	memset(&in6, 0, sizeof(in6));
	if (inet_pton(AF_INET, host, &in.sin_addr) == 1) {
		in.sin_family = AF_INET;
		in.sin_port = htons(port);
		memset(out, 0, sizeof(*out));
		memcpy(&out->address, &in, sizeof(in));
		out->length = (socklen_t)sizeof(in);
		*count = 1;
		return 1;
	}
	if (inet_pton(AF_INET6, host, &in6.sin6_addr) == 1) {
		in6.sin6_family = AF_INET6;
		in6.sin6_port = htons(port);
		memset(out, 0, sizeof(*out));
		memcpy(&out->address, &in6, sizeof(in6));
		out->length = (socklen_t)sizeof(in6);
		*count = 1;
		return 1;
	}
	return 0;
}

static void apply_port_one(sni_resolved_addr *addr, uint16_t port)
{
	struct sockaddr *sa = (struct sockaddr *)&addr->address;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		in->sin_port = htons(port);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
		in6->sin6_port = htons(port);
	}
}

static int do_resolve(const char *host, int family, sni_resolved_addr *out, size_t *count)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	int st = EAI_FAIL;
	int attempts = 0;
	*count = 0;
	memset(&hints, 0, sizeof(hints));
	/* Family is recorded for tests. The lookup itself is always dual-stack. */
	(void)family;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	do {
		res = NULL;
#ifdef SNI_TEST_HOOKS
		if (g_pool->hook) {
			st = g_pool->hook(host, family, out, SNI_RESOLVER_ADDR_MAX, count,
					g_pool->hook_cookie);
		} else
#endif
		{
			st = getaddrinfo(host, NULL, &hints, &res);
		}
		attempts++;
		if (st == EAI_SYSTEM && errno == EINTR && res) {
			freeaddrinfo(res);
			res = NULL;
		}
	} while (st == EAI_SYSTEM && errno == EINTR && attempts < SNI_GAI_ATTEMPTS);
	__atomic_fetch_add(&g_pool->calls, (uint32_t)attempts, __ATOMIC_RELAXED);
#ifdef SNI_TEST_HOOKS
	if (g_pool->hook)
		return st;
#endif
	if (st != 0) {
		if (res)
			freeaddrinfo(res);
		*count = 0;
		return st;
	}
	for (ai = res; ai != NULL && *count < SNI_RESOLVER_ADDR_MAX; ai = ai->ai_next) {
		sni_resolved_addr *dst;
		if (!ai->ai_addr || ai->ai_addrlen <= 0)
			continue;
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if ((size_t)ai->ai_addrlen > sizeof(out[0].address))
			continue;
		dst = &out[*count];
		memset(dst, 0, sizeof(*dst));
		memcpy(&dst->address, ai->ai_addr, (size_t)ai->ai_addrlen);
		dst->length = (socklen_t)ai->ai_addrlen;
		(*count)++;
	}
	freeaddrinfo(res);
	if (*count == 0)
		return EAI_NONAME;
	return 0;
}

#ifdef SNI_TEST_HOOKS
static void wait_if_held(void)
{
	pthread_mutex_lock(&g_pool->test_mu);
	g_pool->running_entered++;
	pthread_cond_broadcast(&g_pool->test_cv);
	while (g_pool->hold_running)
		pthread_cond_wait(&g_pool->test_cv, &g_pool->test_mu);
	pthread_mutex_unlock(&g_pool->test_mu);
}
#endif

static void commit_infra_locked(resolve_slot *slot, int gai_error)
{
	if (slot->req_id != g_pool->cache_refresh_req && g_pool->cache_refresh_req != 0 &&
			slot->req_id != g_pool->cache_refresh_req) {
		/* A newer refresh owns the cache. This result is stale. */
	}
	if (slot->req_id == g_pool->cache_refresh_req || g_pool->cache_refresh_inflight) {
		if (slot->req_id == g_pool->cache_refresh_req) {
			g_pool->cache_refresh_inflight = 0;
			if (gai_error == 0 && slot->address_count > 0) {
				int64_t now = net_mono_ms();
				memcpy(g_pool->cache_addrs, slot->addresses,
						slot->address_count * sizeof(slot->addresses[0]));
				g_pool->cache_count = slot->address_count;
				g_pool->cache_valid = 1;
				if (now < 0)
					now = 0;
				g_pool->cache_last_success = now;
				g_pool->cache_refresh_after = now + (int64_t)SNI_INFRA_REFRESH_MS;
				g_pool->cache_max_stale = now + (int64_t)SNI_INFRA_MAX_STALE_MS;
			}
			pthread_cond_broadcast(&g_pool->infra_cv);
		}
	}
}

static void worker_finish(resolve_slot *slot, int gai_error, const sni_resolved_addr *addrs,
		size_t count)
{
	sni_completion_sink *sink;
	sni_completion_sink *die = NULL;
	pthread_mutex_lock(&g_pool->mu);
	if (g_pool->stopping && slot->request_class == SNI_RESOLVE_INFRA) {
		if (slot->req_id == g_pool->cache_refresh_req)
			g_pool->cache_refresh_inflight = 0;
		pthread_cond_broadcast(&g_pool->infra_cv);
		die = slot_free_locked(slot);
		pthread_mutex_unlock(&g_pool->mu);
		destroy_later(die);
		return;
	}
	slot->gai_error = gai_error;
	slot->address_count = count;
	if (count > 0)
		memcpy(slot->addresses, addrs, count * sizeof(*addrs));
	slot->state = RESOLVE_DONE;
	sink = slot->sink;
	if (!sink) {
		commit_infra_locked(slot, gai_error);
		die = slot_free_locked(slot);
		pthread_mutex_unlock(&g_pool->mu);
		destroy_later(die);
		return;
	}
	slot->in_ring = 1;
	slot->holds_ref = 0;
	pthread_mutex_unlock(&g_pool->mu);
	publish_slot(slot, sink);
}

static void resolve_and_finish(resolve_slot *slot, const char *host, int family)
{
	sni_resolved_addr addrs[SNI_RESOLVER_ADDR_MAX];
	size_t count = 0;
	int gai_error;
#ifdef SNI_TEST_HOOKS
	wait_if_held();
#endif
	if (g_pool->stopping) {
		worker_finish(slot, EAI_AGAIN, NULL, 0);
		return;
	}
	gai_error = do_resolve(host, family, addrs, &count);
	worker_finish(slot, gai_error, addrs, count);
}

static void worker_one(resolve_slot *slot)
{
	char host[SNI_RESOLVER_HOST_MAX + 1];
	int family;
	int64_t now;
	sni_completion_sink *die = NULL;
	pthread_mutex_lock(&g_pool->mu);
	if (slot->state == RESOLVE_CANCELLED) {
		__atomic_fetch_add(&g_pool->skipped_cancelled, 1u, __ATOMIC_RELAXED);
		die = slot_free_locked(slot);
		pthread_mutex_unlock(&g_pool->mu);
		destroy_later(die);
		return;
	}
	now = net_mono_ms();
	if (now >= 0 && slot->deadline_ms > 0 && now >= slot->deadline_ms) {
		__atomic_fetch_add(&g_pool->skipped_expired, 1u, __ATOMIC_RELAXED);
		slot->gai_error = EAI_AGAIN;
		slot->address_count = 0;
		slot->state = RESOLVE_DONE;
		if (!slot->sink) {
			if (slot->req_id == g_pool->cache_refresh_req) {
				g_pool->cache_refresh_inflight = 0;
				pthread_cond_broadcast(&g_pool->infra_cv);
			}
			die = slot_free_locked(slot);
			pthread_mutex_unlock(&g_pool->mu);
			destroy_later(die);
			return;
		}
		slot->in_ring = 1;
		slot->holds_ref = 0;
		{
			sni_completion_sink *sink = slot->sink;
			pthread_mutex_unlock(&g_pool->mu);
			publish_slot(slot, sink);
			return;
		}
	}
	if (g_pool->stopping) {
		die = slot_free_locked(slot);
		pthread_mutex_unlock(&g_pool->mu);
		destroy_later(die);
		return;
	}
	slot->state = RESOLVE_RUNNING;
	memcpy(host, slot->hostname, sizeof(host));
	family = slot->family_policy;
	pthread_mutex_unlock(&g_pool->mu);
	resolve_and_finish(slot, host, family);
}

static void *worker_main(void *arg)
{
	sni_resolver_pool *pool = (sni_resolver_pool *)arg;
	for (;;) {
		resolve_slot *slot;
		pthread_mutex_lock(&pool->mu);
		while (!pool->stopping &&
				(pool->pause_dequeue ||
				 (pool->client_head == NULL && pool->infra_head == NULL)))
			pthread_cond_wait(&pool->work_cv, &pool->mu);
		if (pool->stopping && pool->client_head == NULL && pool->infra_head == NULL) {
			pool->exited++;
			pthread_cond_broadcast(&pool->infra_cv);
			pthread_mutex_unlock(&pool->mu);
			break;
		}
		if (pool->infra_head)
			slot = dequeue(&pool->infra_head, &pool->infra_tail);
		else
			slot = dequeue(&pool->client_head, &pool->client_tail);
		pthread_mutex_unlock(&pool->mu);
		if (slot)
			worker_one(slot);
	}
	return NULL;
}

static int pool_create(void)
{
	sni_resolver_pool *pool;
	pthread_condattr_t attr;
	int i;
	ignore_sigpipe();
	pool = (sni_resolver_pool *)calloc(1, sizeof(*pool));
	if (!pool)
		return -1;
	if (pthread_mutex_init(&pool->mu, NULL) != 0) {
		free(pool);
		return -1;
	}
	if (init_mono_cond(&pool->work_cv) != 0 || init_mono_cond(&pool->infra_cv) != 0) {
		pthread_mutex_destroy(&pool->mu);
		free(pool);
		return -1;
	}
#ifdef SNI_TEST_HOOKS
	if (pthread_mutex_init(&pool->test_mu, NULL) != 0) {
		pthread_cond_destroy(&pool->work_cv);
		pthread_cond_destroy(&pool->infra_cv);
		pthread_mutex_destroy(&pool->mu);
		free(pool);
		return -1;
	}
	if (pthread_condattr_init(&attr) != 0 ||
			pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0 ||
			pthread_cond_init(&pool->test_cv, &attr) != 0) {
		pthread_condattr_destroy(&attr);
		pthread_mutex_destroy(&pool->test_mu);
		pthread_cond_destroy(&pool->work_cv);
		pthread_cond_destroy(&pool->infra_cv);
		pthread_mutex_destroy(&pool->mu);
		free(pool);
		return -1;
	}
	pthread_condattr_destroy(&attr);
#else
	(void)attr;
#endif
	for (i = 0; i < SNI_RESOLVER_SLOTS; i++) {
		pool->slots[i].index = i;
		pool->slots[i].state = RESOLVE_FREE;
		pool->slots[i].qnext = pool->free_head;
		pool->free_head = &pool->slots[i];
	}
	pool->free_count = SNI_RESOLVER_SLOTS;
	pool->next_req_id = 1;
	pool->next_listener_id = 1;
	g_pool = pool;
	for (i = 0; i < SNI_RESOLVER_THREADS; i++) {
		if (pthread_create(&pool->threads[i], NULL, worker_main, pool) != 0) {
			int j;
			pthread_mutex_lock(&pool->mu);
			pool->stopping = 1;
			pthread_cond_broadcast(&pool->work_cv);
			pthread_mutex_unlock(&pool->mu);
			for (j = 0; j < i; j++)
				pthread_join(pool->threads[j], NULL);
			pthread_cond_destroy(&pool->work_cv);
			pthread_cond_destroy(&pool->infra_cv);
			pthread_mutex_destroy(&pool->mu);
#ifdef SNI_TEST_HOOKS
			pthread_cond_destroy(&pool->test_cv);
			pthread_mutex_destroy(&pool->test_mu);
#endif
			free(pool);
			g_pool = NULL;
			return -1;
		}
	}
	pool->started = 1;
	return 0;
}

bool sni_resolver_start(void)
{
	int rc;
	pthread_mutex_lock(&g_start_mu);
	if (g_pool && g_pool->started && !g_pool->abandoned) {
		pthread_mutex_unlock(&g_start_mu);
		return true;
	}
	if (g_pool && g_pool->abandoned) {
		pthread_mutex_unlock(&g_start_mu);
		return false;
	}
	rc = pool_create();
	pthread_mutex_unlock(&g_start_mu);
	return rc == 0;
}

int sni_resolver_shutdown(int timeout_ms)
{
	sni_resolver_pool *pool;
	struct timespec ts;
	int abandoned = 0;
	int i;
	pthread_mutex_lock(&g_start_mu);
	pool = g_pool;
	if (!pool || !pool->started) {
		pthread_mutex_unlock(&g_start_mu);
		return 0;
	}
	pthread_mutex_lock(&pool->mu);
	pool->stopping = 1;
	pool->pause_dequeue = 0;
	pthread_cond_broadcast(&pool->work_cv);
	if (mono_deadline(timeout_ms, &ts) != 0) {
		pool->abandoned = 1;
		pthread_mutex_unlock(&pool->mu);
		for (i = 0; i < SNI_RESOLVER_THREADS; i++)
			pthread_detach(pool->threads[i]);
		pthread_mutex_unlock(&g_start_mu);
		return 1;
	}
	while (pool->exited < SNI_RESOLVER_THREADS) {
		int wr = pthread_cond_timedwait(&pool->infra_cv, &pool->mu, &ts);
		if (wr == ETIMEDOUT) {
			pool->abandoned = 1;
			abandoned = 1;
			break;
		}
	}
	pthread_mutex_unlock(&pool->mu);
	if (abandoned) {
		/* Workers that already returned are reaped. A worker still inside
		 * getaddrinfo stays detached and keeps using this pool, so the
		 * mutex and slots are left allocated until process exit. */
		for (i = 0; i < SNI_RESOLVER_THREADS; i++)
			pthread_detach(pool->threads[i]);
		pthread_mutex_unlock(&g_start_mu);
		return 1;
	}
	for (i = 0; i < SNI_RESOLVER_THREADS; i++)
		pthread_join(pool->threads[i], NULL);
	pthread_cond_destroy(&pool->work_cv);
	pthread_cond_destroy(&pool->infra_cv);
	pthread_mutex_destroy(&pool->mu);
#ifdef SNI_TEST_HOOKS
	pthread_cond_destroy(&pool->test_cv);
	pthread_mutex_destroy(&pool->test_mu);
#endif
	g_pool = NULL;
	free(pool);
	pthread_mutex_unlock(&g_start_mu);
	return 0;
}

bool sni_resolver_normalize(const char *in, char *out, size_t out_cap)
{
	size_t n = 0;
	size_t i;
	size_t label = 0;
	if (!in || !out || out_cap < 2)
		return false;
	while (in[n] != '\0') {
		if (n >= (size_t)SNI_RESOLVER_HOST_MAX + 1u)
			return false;
		n++;
	}
	if (n == 0 || n > (size_t)SNI_RESOLVER_HOST_MAX + 1u)
		return false;
	if (in[n - 1] == '.') {
		n--;
		if (n == 0 || n > (size_t)SNI_RESOLVER_HOST_MAX)
			return false;
	}
	if (n > (size_t)SNI_RESOLVER_HOST_MAX || n + 1 > out_cap)
		return false;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)in[i];
		char prev;
		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c - 'A' + 'a');
		if (c == '.') {
			if (label == 0 || label > 63)
				return false;
			prev = (i == 0) ? '\0' : out[i - 1];
			if (prev == '-')
				return false;
			out[i] = '.';
			label = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
			return false;
		if (c == '-' && label == 0)
			return false;
		out[i] = (char)c;
		label++;
	}
	if (label == 0 || label > 63)
		return false;
	if (out[n - 1] == '-')
		return false;
	out[n] = '\0';
	return true;
}

static int quota_ok_locked(sni_completion_sink *sink)
{
	if (!sink || sink->closed)
		return 0;
	if (sink->kind == SNI_SINK_DIRECT)
		return g_pool->direct_used < SNI_RESOLVER_DIRECT_RESERVE;
	if (sink->quota_used < sink->quota_limit)
		return 1;
	return 0;
}

static void quota_inc_locked(sni_completion_sink *sink, resolve_slot *slot)
{
	if (sink->kind == SNI_SINK_DIRECT) {
		g_pool->direct_used++;
		slot->quota_kind = SNI_QUOTA_DIRECT;
		return;
	}
	sink->quota_used++;
	g_pool->listener_used++;
	slot->quota_kind = SNI_QUOTA_LISTENER;
}

bool sni_resolver_sink_open(int kind, sni_completion_sink **out)
{
	sni_completion_sink *sink;
	int fds[2] = {-1, -1};
	int quota;
	if (!out)
		return false;
	*out = NULL;
	if (!sni_resolver_start())
		return false;
	pthread_mutex_lock(&g_pool->mu);
	if (g_pool->stopping) {
		pthread_mutex_unlock(&g_pool->mu);
		return false;
	}
	if (kind == SNI_SINK_DIRECT) {
		quota = SNI_RESOLVER_DIRECT_RESERVE;
	} else {
		int remain = SNI_RESOLVER_SLOTS - SNI_RESOLVER_INFRA_RESERVE -
				SNI_RESOLVER_DIRECT_RESERVE - g_pool->listener_quota_assigned;
		if (remain <= 0) {
			pthread_mutex_unlock(&g_pool->mu);
			return false;
		}
		quota = SNI_RESOLVER_LISTENER_QUOTA;
		if (quota > remain)
			quota = remain;
		g_pool->listener_quota_assigned += quota;
	}
	pthread_mutex_unlock(&g_pool->mu);
	sink = (sni_completion_sink *)calloc(1, sizeof(*sink));
	if (!sink)
		goto fail_quota;
	sink->pipe_read = -1;
	sink->pipe_write = -1;
	sink->kind = kind;
	sink->quota_limit = quota;
	sink->ring_capacity = (size_t)quota;
	sink->ring = (resolve_slot **)calloc(sink->ring_capacity, sizeof(*sink->ring));
	if (!sink->ring)
		goto fail_sink;
	if (open_pipe(fds) != 0)
		goto fail_sink;
	sink->pipe_read = fds[0];
	sink->pipe_write = fds[1];
	if (pthread_mutex_init(&sink->mutex, NULL) != 0)
		goto fail_sink;
	pthread_mutex_lock(&g_pool->mu);
	sink->listener_id = g_pool->next_listener_id++;
	if (g_pool->next_listener_id == 0)
		g_pool->next_listener_id = 1;
	sink->refcount = 1;
	g_pool->sink_refs++;
	g_pool->live_sinks++;
	g_pool->open_pipes += 2;
	pthread_mutex_unlock(&g_pool->mu);
	*out = sink;
	return true;
fail_sink:
	if (sink) {
		if (sink->pipe_read >= 0)
			close(sink->pipe_read);
		if (sink->pipe_write >= 0)
			close(sink->pipe_write);
		free(sink->ring);
		free(sink);
	}
fail_quota:
	pthread_mutex_lock(&g_pool->mu);
	if (kind != SNI_SINK_DIRECT)
		g_pool->listener_quota_assigned -= quota;
	pthread_mutex_unlock(&g_pool->mu);
	return false;
}

void sni_resolver_sink_mark_closed(sni_completion_sink *sink)
{
	if (!sink)
		return;
	pthread_mutex_lock(&sink->mutex);
	sink->closed = true;
	pthread_mutex_unlock(&sink->mutex);
}

static void sink_destroy(sni_completion_sink *sink)
{
	resolve_slot *batch[SNI_RESOLVER_SLOTS];
	size_t n = 0;
	size_t i;
	if (!sink)
		return;
	pthread_mutex_lock(&sink->mutex);
	while (sink->ring_count > 0 && n < SNI_RESOLVER_SLOTS) {
		batch[n++] = sink->ring[sink->ring_head];
		sink->ring[sink->ring_head] = NULL;
		sink->ring_head++;
		if (sink->ring_head == sink->ring_capacity)
			sink->ring_head = 0;
		sink->ring_count--;
	}
	pthread_mutex_unlock(&sink->mutex);
	for (i = 0; i < n; i++) {
		sni_completion_sink *die = NULL;
		pthread_mutex_lock(&g_pool->mu);
		if (batch[i])
			die = slot_free_locked(batch[i]);
		pthread_mutex_unlock(&g_pool->mu);
		if (die && die != sink)
			sink_destroy(die);
	}
	if (sink->pipe_read >= 0) {
		close(sink->pipe_read);
		sink->pipe_read = -1;
	}
	if (sink->pipe_write >= 0) {
		close(sink->pipe_write);
		sink->pipe_write = -1;
	}
	pthread_mutex_lock(&g_pool->mu);
	if (sink->kind != SNI_SINK_DIRECT)
		g_pool->listener_quota_assigned -= sink->quota_limit;
	if (g_pool->live_sinks > 0)
		g_pool->live_sinks--;
	if (g_pool->open_pipes >= 2)
		g_pool->open_pipes -= 2;
	pthread_mutex_unlock(&g_pool->mu);
	sni_resolver_unwatch_bind(sink->listener_id);
	pthread_mutex_destroy(&sink->mutex);
	free(sink->ring);
	free(sink);
}

void sni_resolver_sink_release(sni_completion_sink *sink)
{
	sni_completion_sink *die = NULL;
	if (!sink || !g_pool)
		return;
	pthread_mutex_lock(&g_pool->mu);
	die = ref_drop_locked(sink);
	pthread_mutex_unlock(&g_pool->mu);
	destroy_later(die);
}

size_t sni_resolver_drain(sni_completion_sink *sink, resolve_slot **out, size_t max_out)
{
	char buf[64];
	size_t n = 0;
	size_t i;
	if (!sink || !out || max_out == 0)
		return 0;
	for (;;) {
		ssize_t r = read(sink->pipe_read, buf, sizeof(buf));
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
	}
	pthread_mutex_lock(&sink->mutex);
	while (sink->ring_count > 0 && n < max_out) {
		out[n++] = sink->ring[sink->ring_head];
		sink->ring[sink->ring_head] = NULL;
		sink->ring_head++;
		if (sink->ring_head == sink->ring_capacity)
			sink->ring_head = 0;
		sink->ring_count--;
	}
	pthread_mutex_unlock(&sink->mutex);
	if (!g_pool)
		return n;
	pthread_mutex_lock(&g_pool->mu);
	for (i = 0; i < n; i++) {
		if (out[i])
			out[i]->in_ring = 0;
	}
	pthread_mutex_unlock(&g_pool->mu);
	return n;
}

int sni_resolver_submit(sni_completion_sink *sink, uint32_t connection_index,
		uint64_t connection_generation, const char *hostname, uint16_t port,
		int family, int64_t deadline_ms, int *slot_index, uint64_t *req_id)
{
	resolve_slot *slot;
	char norm[SNI_RESOLVER_HOST_MAX + 1];
	if (slot_index)
		*slot_index = -1;
	if (req_id)
		*req_id = 0;
	if (!sink || !hostname || !slot_index || !req_id)
		return SNI_SUBMIT_BADNAME;
	if (!sni_resolver_normalize(hostname, norm, sizeof(norm)))
		return SNI_SUBMIT_BADNAME;
	if (!g_pool)
		return SNI_SUBMIT_OVERFLOW;
	pthread_mutex_lock(&g_pool->mu);
	if (g_pool->stopping || !quota_ok_locked(sink) || g_pool->free_head == NULL) {
		pthread_mutex_unlock(&g_pool->mu);
		return SNI_SUBMIT_OVERFLOW;
	}
	slot = g_pool->free_head;
	g_pool->free_head = slot->qnext;
	slot->qnext = NULL;
	g_pool->free_count--;
	slot->req_id = alloc_req_id_locked(g_pool);
	slot->listener_id = sink->listener_id;
	slot->connection_index = connection_index;
	slot->connection_generation = connection_generation;
	slot->request_class = SNI_RESOLVE_CLIENT;
	slot->gai_error = 0;
	slot->deadline_ms = deadline_ms;
	memcpy(slot->hostname, norm, strlen(norm) + 1);
	slot->port = port;
	slot->family_policy = family;
	slot->address_count = 0;
	slot->sink = sink;
	slot->in_ring = 0;
	slot->holds_ref = 1;
	slot->state = RESOLVE_QUEUED;
	sink->refcount++;
	g_pool->sink_refs++;
	quota_inc_locked(sink, slot);
	enqueue(&g_pool->client_head, &g_pool->client_tail, slot);
	pthread_cond_signal(&g_pool->work_cv);
	*slot_index = slot->index;
	*req_id = slot->req_id;
	pthread_mutex_unlock(&g_pool->mu);
	return SNI_SUBMIT_OK;
}

static int submit_infra_locked(const char *norm, uint16_t port)
{
	resolve_slot *slot;
	if (g_pool->cache_refresh_inflight)
		return 0;
	if (g_pool->infra_used >= SNI_RESOLVER_INFRA_RESERVE || g_pool->free_head == NULL)
		return -1;
	slot = g_pool->free_head;
	g_pool->free_head = slot->qnext;
	slot->qnext = NULL;
	g_pool->free_count--;
	slot->req_id = alloc_req_id_locked(g_pool);
	slot->listener_id = 0;
	slot->connection_index = 0;
	slot->connection_generation = 0;
	slot->request_class = SNI_RESOLVE_INFRA;
	slot->gai_error = 0;
	slot->deadline_ms = net_mono_ms() + (int64_t)SNI_INFRA_STARTUP_MS;
	if (slot->deadline_ms < 0)
		slot->deadline_ms = 0;
	memcpy(slot->hostname, norm, strlen(norm) + 1);
	slot->port = port;
	slot->family_policy = AF_UNSPEC;
	slot->address_count = 0;
	slot->sink = NULL;
	slot->in_ring = 0;
	slot->holds_ref = 0;
	slot->quota_kind = SNI_QUOTA_INFRA;
	slot->state = RESOLVE_QUEUED;
	g_pool->infra_used++;
	g_pool->cache_refresh_inflight = 1;
	g_pool->cache_refresh_req = slot->req_id;
	memcpy(g_pool->cache_host, norm, strlen(norm) + 1);
	g_pool->cache_port = port;
	enqueue(&g_pool->infra_head, &g_pool->infra_tail, slot);
	pthread_cond_signal(&g_pool->work_cv);
	return 0;
}

void sni_resolver_cancel(int slot_index, uint64_t req_id)
{
	resolve_slot *slot;
	if (!g_pool || req_id == 0 || slot_index < 0 || slot_index >= SNI_RESOLVER_SLOTS)
		return;
	pthread_mutex_lock(&g_pool->mu);
	slot = &g_pool->slots[slot_index];
	if (slot->req_id != req_id) {
		pthread_mutex_unlock(&g_pool->mu);
		return;
	}
	if (slot->state == RESOLVE_QUEUED)
		slot->state = RESOLVE_CANCELLED;
	pthread_mutex_unlock(&g_pool->mu);
}

void sni_resolver_release(int slot_index, uint64_t req_id)
{
	resolve_slot *slot;
	sni_completion_sink *die = NULL;
	if (!g_pool || req_id == 0 || slot_index < 0 || slot_index >= SNI_RESOLVER_SLOTS)
		return;
	pthread_mutex_lock(&g_pool->mu);
	slot = &g_pool->slots[slot_index];
	if (slot->req_id != req_id || slot->state == RESOLVE_FREE) {
		pthread_mutex_unlock(&g_pool->mu);
		return;
	}
	if (slot->state == RESOLVE_QUEUED)
		slot->state = RESOLVE_CANCELLED;
	if (slot->state == RESOLVE_DONE || slot->state == RESOLVE_CANCELLED)
		die = slot_free_locked(slot);
	pthread_mutex_unlock(&g_pool->mu);
	destroy_later(die);
}

void sni_resolver_watch_bind(uint32_t listener_id, const char *bindip, uint16_t port)
{
	struct in_addr ip;
	int i;
	int free_i = -1;
	if (!bindip || listener_id == 0 || !sni_resolver_start())
		return;
	if (inet_pton(AF_INET, bindip, &ip) != 1)
		return;
	pthread_mutex_lock(&g_pool->mu);
	for (i = 0; i < SNI_BIND_MAX; i++) {
		if (g_pool->binds[i].used && g_pool->binds[i].listener_id == listener_id) {
			free_i = i;
			break;
		}
		if (!g_pool->binds[i].used && free_i < 0)
			free_i = i;
	}
	if (free_i >= 0) {
		g_pool->binds[free_i].used = 1;
		g_pool->binds[free_i].listener_id = listener_id;
		g_pool->binds[free_i].port = port;
		g_pool->binds[free_i].ip = ip;
		g_pool->binds[free_i].wildcard = (ip.s_addr == htonl(INADDR_ANY));
	}
	pthread_mutex_unlock(&g_pool->mu);
}

void sni_resolver_unwatch_bind(uint32_t listener_id)
{
	int i;
	if (!g_pool || listener_id == 0)
		return;
	pthread_mutex_lock(&g_pool->mu);
	for (i = 0; i < SNI_BIND_MAX; i++) {
		if (g_pool->binds[i].used && g_pool->binds[i].listener_id == listener_id)
			g_pool->binds[i].used = 0;
	}
	pthread_mutex_unlock(&g_pool->mu);
}

static int v4_rejected(uint32_t host, uint16_t port)
{
	int i;
	int wildcard = 0;
	int self = 0;
	if (host == 0 || host == 0xffffffffu)
		return 1;
	if ((host & 0xffff0000u) == 0xa9fe0000u)
		return 1;
	if ((host & 0xf0000000u) == 0xe0000000u)
		return 1;
	for (i = 0; i < SNI_BIND_MAX; i++) {
		sni_bind_rec *b = &g_pool->binds[i];
		uint32_t bip;
		if (!b->used)
			continue;
		bip = ntohl(b->ip.s_addr);
		if (b->wildcard)
			wildcard = 1;
		if (b->port == port && (b->wildcard || bip == host))
			self = 1;
		if (b->port == port && (host >> 24) == 127 && (b->wildcard || (bip >> 24) == 127))
			self = 1;
	}
	if (wildcard && ((host >> 24) == 127 || host == 0))
		return 1;
	if (self)
		return 1;
	return 0;
}

static int v6_rejected(const struct in6_addr *ip, uint16_t port)
{
	int i;
	if (IN6_IS_ADDR_UNSPECIFIED(ip) || IN6_IS_ADDR_MULTICAST(ip) || IN6_IS_ADDR_LINKLOCAL(ip))
		return 1;
	if (IN6_IS_ADDR_LOOPBACK(ip)) {
		int wildcard = 0;
		for (i = 0; i < SNI_BIND_MAX; i++) {
			if (!g_pool->binds[i].used)
				continue;
			if (g_pool->binds[i].wildcard)
				wildcard = 1;
			if (g_pool->binds[i].port == port)
				return 1;
		}
		if (wildcard)
			return 1;
	}
	return 0;
}

static int normalize_mapped(sni_resolved_addr *addr)
{
	struct sockaddr *sa = (struct sockaddr *)&addr->address;
	if (sa->sa_family != AF_INET6)
		return 0;
	{
		struct sockaddr_in6 in6;
		memcpy(&in6, &addr->address, sizeof(in6));
		if (!IN6_IS_ADDR_V4MAPPED(&in6.sin6_addr))
			return 0;
		{
			struct sockaddr_in in;
			memset(&in, 0, sizeof(in));
			in.sin_family = AF_INET;
			in.sin_port = in6.sin6_port;
			memcpy(&in.sin_addr, &in6.sin6_addr.s6_addr[12], 4);
			memset(addr, 0, sizeof(*addr));
			memcpy(&addr->address, &in, sizeof(in));
			addr->length = (socklen_t)sizeof(in);
		}
	}
	return 1;
}

size_t sni_resolver_policy_keep(sni_resolved_addr *addrs, size_t count)
{
	size_t i;
	size_t kept = 0;
	if (!addrs)
		return 0;
	if (!g_pool && !sni_resolver_start())
		return 0;
	pthread_mutex_lock(&g_pool->mu);
	for (i = 0; i < count; i++) {
		struct sockaddr *sa;
		int drop = 0;
		normalize_mapped(&addrs[i]);
		sa = (struct sockaddr *)&addrs[i].address;
		if (sa->sa_family == AF_INET) {
			struct sockaddr_in in;
			uint32_t host;
			uint16_t port;
			memcpy(&in, &addrs[i].address, sizeof(in));
			host = ntohl(in.sin_addr.s_addr);
			port = ntohs(in.sin_port);
			drop = v4_rejected(host, port);
		} else if (sa->sa_family == AF_INET6) {
			struct sockaddr_in6 in6;
			memcpy(&in6, &addrs[i].address, sizeof(in6));
			drop = v6_rejected(&in6.sin6_addr, ntohs(in6.sin6_port));
		} else {
			drop = 1;
		}
		if (!drop) {
			if (kept != i)
				addrs[kept] = addrs[i];
			kept++;
		}
	}
	pthread_mutex_unlock(&g_pool->mu);
	return kept;
}

static int cache_copy_locked(uint16_t port, sni_resolved_addr *out, size_t *count)
{
	size_t i;
	int64_t now = net_mono_ms();
	if (!g_pool->cache_valid || g_pool->cache_count == 0)
		return SNI_UP_UNRESOLVED;
	if (now >= 0 && g_pool->cache_max_stale > 0 && now > g_pool->cache_max_stale)
		return SNI_UP_UNRESOLVED;
	*count = g_pool->cache_count;
	memcpy(out, g_pool->cache_addrs, (*count) * sizeof(*out));
	for (i = 0; i < *count; i++)
		apply_port_one(&out[i], port);
	if (now >= 0 && now >= g_pool->cache_refresh_after)
		(void)submit_infra_locked(g_pool->cache_host, g_pool->cache_port);
	return SNI_UP_READY;
}

bool sni_resolver_prime_socks(const char *host, uint16_t port, int wait_ms)
{
	char norm[SNI_RESOLVER_HOST_MAX + 1];
	sni_resolved_addr numeric;
	size_t n = 0;
	struct timespec ts;
	if (!host || host[0] == '\0')
		return true;
	if (copy_numeric(host, port, &numeric, &n))
		return true;
	if (!sni_resolver_normalize(host, norm, sizeof(norm)))
		return true;
	if (!sni_resolver_start())
		return false;
	pthread_mutex_lock(&g_pool->mu);
	if (g_pool->cache_valid && strcmp(g_pool->cache_host, norm) == 0 &&
			g_pool->cache_port == port) {
		int64_t now = net_mono_ms();
		if (now >= 0 && now < g_pool->cache_refresh_after) {
			pthread_mutex_unlock(&g_pool->mu);
			return true;
		}
	}
	if (submit_infra_locked(norm, port) != 0 && !g_pool->cache_refresh_inflight) {
		pthread_mutex_unlock(&g_pool->mu);
		return true;
	}
	if (mono_deadline(wait_ms, &ts) == 0) {
		while (g_pool->cache_refresh_inflight) {
			int wr = pthread_cond_timedwait(&g_pool->infra_cv, &g_pool->mu, &ts);
			if (wr == ETIMEDOUT)
				break;
		}
	}
	pthread_mutex_unlock(&g_pool->mu);
	return true;
}

int sni_resolver_copy_upstream(const char *host, uint16_t port,
		sni_resolved_addr *out, size_t *count)
{
	char norm[SNI_RESOLVER_HOST_MAX + 1];
	int st;
	if (!host || !out || !count)
		return SNI_UP_UNRESOLVED;
	*count = 0;
	if (copy_numeric(host, port, out, count))
		return SNI_UP_READY;
	if (!sni_resolver_normalize(host, norm, sizeof(norm)))
		return SNI_UP_NEED_RESOLVE;
	if (!g_pool)
		return SNI_UP_NEED_RESOLVE;
	pthread_mutex_lock(&g_pool->mu);
	if (!g_pool->cache_valid || strcmp(g_pool->cache_host, norm) != 0) {
		if (g_pool->cache_host[0] != '\0' && strcmp(g_pool->cache_host, norm) == 0)
			(void)submit_infra_locked(norm, port);
		pthread_mutex_unlock(&g_pool->mu);
		return SNI_UP_NEED_RESOLVE;
	}
	st = cache_copy_locked(port, out, count);
	if (st == SNI_UP_UNRESOLVED)
		(void)submit_infra_locked(norm, port);
	pthread_mutex_unlock(&g_pool->mu);
	return st;
}

#ifdef SNI_TEST_HOOKS
void sni_resolver_test_set_hook(sni_resolve_hook hook, void *cookie)
{
	if (!sni_resolver_start())
		return;
	pthread_mutex_lock(&g_pool->mu);
	g_pool->hook = hook;
	g_pool->hook_cookie = cookie;
	pthread_mutex_unlock(&g_pool->mu);
}

void sni_resolver_test_stats(sni_resolver_counters *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!g_pool)
		return;
	out->calls = __atomic_load_n(&g_pool->calls, __ATOMIC_RELAXED);
	out->skipped_expired = __atomic_load_n(&g_pool->skipped_expired, __ATOMIC_RELAXED);
	out->skipped_cancelled = __atomic_load_n(&g_pool->skipped_cancelled, __ATOMIC_RELAXED);
	out->eagain_wakeups = __atomic_load_n(&g_pool->eagain_wakeups, __ATOMIC_RELAXED);
	out->closed_drops = __atomic_load_n(&g_pool->closed_drops, __ATOMIC_RELAXED);
	out->ring_full = __atomic_load_n(&g_pool->ring_full, __ATOMIC_RELAXED);
}

void sni_resolver_test_reset_stats(void)
{
	if (!g_pool)
		return;
	__atomic_store_n(&g_pool->calls, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_pool->skipped_expired, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_pool->skipped_cancelled, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_pool->eagain_wakeups, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_pool->closed_drops, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_pool->ring_full, 0u, __ATOMIC_RELAXED);
}

void sni_resolver_test_pause_dequeue(int pause)
{
	if (!sni_resolver_start())
		return;
	pthread_mutex_lock(&g_pool->mu);
	g_pool->pause_dequeue = pause ? 1 : 0;
	if (!pause)
		pthread_cond_broadcast(&g_pool->work_cv);
	pthread_mutex_unlock(&g_pool->mu);
}

void sni_resolver_test_hold_running(int hold)
{
	if (!sni_resolver_start())
		return;
	pthread_mutex_lock(&g_pool->test_mu);
	if (hold)
		g_pool->running_entered = 0;
	g_pool->hold_running = hold ? 1 : 0;
	if (!hold)
		pthread_cond_broadcast(&g_pool->test_cv);
	pthread_mutex_unlock(&g_pool->test_mu);
}

int sni_resolver_test_wait_running(int want, int timeout_ms)
{
	struct timespec ts;
	int ok = 0;
	if (!g_pool)
		return 0;
	if (mono_deadline(timeout_ms, &ts) != 0)
		return 0;
	pthread_mutex_lock(&g_pool->test_mu);
	while (g_pool->running_entered < want) {
		int wr = pthread_cond_timedwait(&g_pool->test_cv, &g_pool->test_mu, &ts);
		if (wr == ETIMEDOUT)
			break;
	}
	ok = g_pool->running_entered >= want;
	pthread_mutex_unlock(&g_pool->test_mu);
	return ok;
}

bool sni_resolver_test_accounting(sni_resolver_accounting *out)
{
	int i;
	if (!out)
		return false;
	memset(out, 0, sizeof(*out));
	if (!g_pool)
		return false;
	pthread_mutex_lock(&g_pool->mu);
	for (i = 0; i < SNI_RESOLVER_SLOTS; i++) {
		resolve_slot *slot = &g_pool->slots[i];
		if (slot->state == RESOLVE_FREE)
			out->free_n++;
		else if (slot->state == RESOLVE_QUEUED)
			out->queued++;
		else if (slot->state == RESOLVE_RUNNING)
			out->running++;
		else if (slot->state == RESOLVE_CANCELLED)
			out->cancelled++;
		else if (slot->state == RESOLVE_DONE && slot->in_ring)
			out->in_ring++;
		else if (slot->state == RESOLVE_DONE)
			out->done++;
	}
	out->quota_used = g_pool->direct_used + g_pool->infra_used + g_pool->listener_used;
	out->direct_used = g_pool->direct_used;
	out->infra_used = g_pool->infra_used;
	out->listener_used = g_pool->listener_used;
	out->sink_refs = (int)g_pool->sink_refs;
	out->open_pipes = g_pool->open_pipes;
	out->double_free = g_pool->double_free;
	out->live_sinks = g_pool->live_sinks;
	out->abandoned = g_pool->abandoned;
	out->listener_quota_assigned = g_pool->listener_quota_assigned;
	pthread_mutex_unlock(&g_pool->mu);
	return true;
}

int sni_resolver_test_mutex_ok(void)
{
	if (!g_pool)
		return 0;
	if (pthread_mutex_lock(&g_pool->mu) != 0)
		return 0;
	pthread_mutex_unlock(&g_pool->mu);
	return 1;
}

void sni_resolver_test_age_cache(int64_t last_success_ms, int64_t refresh_after_ms,
		int64_t max_stale_ms)
{
	if (!g_pool)
		return;
	pthread_mutex_lock(&g_pool->mu);
	g_pool->cache_last_success = last_success_ms;
	g_pool->cache_refresh_after = refresh_after_ms;
	g_pool->cache_max_stale = max_stale_ms;
	pthread_mutex_unlock(&g_pool->mu);
}

int sni_resolver_sink_quota(const sni_completion_sink *sink)
{
	if (!sink)
		return 0;
	return sink->quota_limit;
}

int sni_resolver_test_fill_infra(void)
{
	int n = 0;
	if (!g_pool)
		return 0;
	pthread_mutex_lock(&g_pool->mu);
	while (g_pool->infra_used < SNI_RESOLVER_INFRA_RESERVE && g_pool->free_head != NULL) {
		resolve_slot *slot = g_pool->free_head;
		int64_t now;
		g_pool->free_head = slot->qnext;
		slot->qnext = NULL;
		g_pool->free_count--;
		slot->req_id = alloc_req_id_locked(g_pool);
		slot->listener_id = 0;
		slot->connection_index = 0;
		slot->connection_generation = 0;
		slot->request_class = SNI_RESOLVE_INFRA;
		slot->gai_error = 0;
		now = net_mono_ms();
		slot->deadline_ms = (now < 0) ? 0 : now + 60000;
		memcpy(slot->hostname, "infra.example", sizeof("infra.example"));
		slot->port = 1;
		slot->family_policy = AF_UNSPEC;
		slot->address_count = 0;
		slot->sink = NULL;
		slot->in_ring = 0;
		slot->holds_ref = 0;
		slot->quota_kind = SNI_QUOTA_INFRA;
		slot->state = RESOLVE_QUEUED;
		g_pool->infra_used++;
		enqueue(&g_pool->infra_head, &g_pool->infra_tail, slot);
		n++;
	}
	pthread_mutex_unlock(&g_pool->mu);
	return n;
}

void sni_resolver_test_reap(void)
{
	int i;
	if (!g_pool)
		return;
	pthread_mutex_lock(&g_pool->mu);
	for (i = 0; i < SNI_RESOLVER_SLOTS; i++) {
		resolve_slot *slot = &g_pool->slots[i];
		if (slot->state == RESOLVE_QUEUED)
			slot->state = RESOLVE_CANCELLED;
	}
	g_pool->pause_dequeue = 0;
	pthread_cond_broadcast(&g_pool->work_cv);
	pthread_mutex_unlock(&g_pool->mu);
}

int sni_resolver_test_wait_idle(int timeout_ms)
{
	int64_t deadline = net_mono_ms();
	if (deadline < 0)
		return 0;
	deadline += timeout_ms;
	for (;;) {
		sni_resolver_accounting a;
		int64_t now;
		if (!sni_resolver_test_accounting(&a))
			return 0;
		if (a.free_n == SNI_RESOLVER_SLOTS && a.queued == 0 && a.running == 0 &&
				a.done == 0 && a.cancelled == 0 && a.in_ring == 0 &&
				a.quota_used == 0)
			return 1;
		now = net_mono_ms();
		if (now < 0 || now >= deadline)
			return 0;
		usleep(1000);
	}
}
#endif
