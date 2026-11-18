#include "resolver_internal.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test-only resolver hooks and accounting helpers. */

#include <zroxy/net_io.h>

#ifdef SNI_TEST_HOOKS
void resolver_test_set_hook(resolver_hook hook, void *cookie)
{
	if (!resolver_start())
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	g_resolver_pool->hook = hook;
	g_resolver_pool->hook_cookie = cookie;
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

void resolver_test_stats(resolver_counters *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!g_resolver_pool)
		return;
	out->calls = __atomic_load_n(&g_resolver_pool->calls, __ATOMIC_RELAXED);
	out->skipped_expired = __atomic_load_n(&g_resolver_pool->skipped_expired, __ATOMIC_RELAXED);
	out->skipped_cancelled = __atomic_load_n(&g_resolver_pool->skipped_cancelled, __ATOMIC_RELAXED);
	out->eagain_wakeups = __atomic_load_n(&g_resolver_pool->eagain_wakeups, __ATOMIC_RELAXED);
	out->closed_drops = __atomic_load_n(&g_resolver_pool->closed_drops, __ATOMIC_RELAXED);
	out->ring_full = __atomic_load_n(&g_resolver_pool->ring_full, __ATOMIC_RELAXED);
}

void resolver_test_reset_stats(void)
{
	if (!g_resolver_pool)
		return;
	__atomic_store_n(&g_resolver_pool->calls, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_resolver_pool->skipped_expired, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_resolver_pool->skipped_cancelled, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_resolver_pool->eagain_wakeups, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_resolver_pool->closed_drops, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_resolver_pool->ring_full, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_resolver_pool->lookup_failures, 0u, __ATOMIC_RELAXED);
}

void resolver_test_pause_dequeue(int pause)
{
	if (!resolver_start())
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	g_resolver_pool->pause_dequeue = pause ? 1 : 0;
	if (!pause)
		pthread_cond_broadcast(&g_resolver_pool->work_cv);
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

void resolver_test_hold_running(int hold)
{
	if (!resolver_start())
		return;
	pthread_mutex_lock(&g_resolver_pool->test_mu);
	if (hold)
		g_resolver_pool->running_entered = 0;
	g_resolver_pool->hold_running = hold ? 1 : 0;
	if (!hold)
		pthread_cond_broadcast(&g_resolver_pool->test_cv);
	pthread_mutex_unlock(&g_resolver_pool->test_mu);
}

int resolver_test_wait_running(int want, int timeout_ms)
{
	struct timespec ts;
	int ok = 0;
	if (!g_resolver_pool)
		return 0;
	if (resolver_mono_deadline(timeout_ms, &ts) != 0)
		return 0;
	pthread_mutex_lock(&g_resolver_pool->test_mu);
	while (g_resolver_pool->running_entered < want) {
		int wr = pthread_cond_timedwait(&g_resolver_pool->test_cv, &g_resolver_pool->test_mu, &ts);
		if (wr == ETIMEDOUT)
			break;
	}
	ok = g_resolver_pool->running_entered >= want;
	pthread_mutex_unlock(&g_resolver_pool->test_mu);
	return ok;
}

bool resolver_test_accounting(resolver_accounting *out)
{
	int i;
	if (!out)
		return false;
	memset(out, 0, sizeof(*out));
	if (!g_resolver_pool)
		return false;
	pthread_mutex_lock(&g_resolver_pool->mu);
	for (i = 0; i < RESOLVER_SLOTS; i++) {
		resolve_slot *slot = &g_resolver_pool->slots[i];
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
	out->quota_used = g_resolver_pool->direct_used + g_resolver_pool->infra_used + g_resolver_pool->listener_used;
	out->direct_used = g_resolver_pool->direct_used;
	out->infra_used = g_resolver_pool->infra_used;
	out->listener_used = g_resolver_pool->listener_used;
	out->sink_refs = (int)g_resolver_pool->sink_refs;
	out->open_pipes = g_resolver_pool->open_pipes;
	out->double_free = g_resolver_pool->double_free;
	out->live_sinks = g_resolver_pool->live_sinks;
	out->abandoned = g_resolver_pool->abandoned;
	out->listener_quota_assigned = g_resolver_pool->listener_quota_assigned;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return true;
}

int resolver_test_mutex_ok(void)
{
	if (!g_resolver_pool)
		return 0;
	if (pthread_mutex_lock(&g_resolver_pool->mu) != 0)
		return 0;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return 1;
}

void resolver_test_age_cache(int64_t last_success_ms, int64_t refresh_after_ms,
		int64_t max_stale_ms)
{
	if (!g_resolver_pool)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	g_resolver_pool->cache_last_success = last_success_ms;
	g_resolver_pool->cache_refresh_after = refresh_after_ms;
	g_resolver_pool->cache_max_stale = max_stale_ms;
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

int resolver_sink_quota(const resolver_sink *sink)
{
	if (!sink)
		return 0;
	return sink->quota_limit;
}

int resolver_test_fill_infra(void)
{
	int n = 0;
	if (!g_resolver_pool)
		return 0;
	pthread_mutex_lock(&g_resolver_pool->mu);
	while (g_resolver_pool->infra_used < RESOLVER_INFRA_RESERVE && g_resolver_pool->free_head != NULL) {
		resolve_slot *slot = g_resolver_pool->free_head;
		int64_t now;
		g_resolver_pool->free_head = slot->qnext;
		slot->qnext = NULL;
		g_resolver_pool->free_count--;
		slot->req_id = resolver_alloc_req_id_locked(g_resolver_pool);
		slot->listener_id = 0;
		slot->connection_index = 0;
		slot->connection_generation = 0;
		slot->request_class = RESOLVER_KIND_INFRA;
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
		slot->quota_kind = RESOLVER_QUOTA_INFRA;
		slot->state = RESOLVE_QUEUED;
		g_resolver_pool->infra_used++;
		resolver_enqueue(&g_resolver_pool->infra_head, &g_resolver_pool->infra_tail, slot);
		n++;
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return n;
}

void resolver_test_reap(void)
{
	int i;
	if (!g_resolver_pool)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	for (i = 0; i < RESOLVER_SLOTS; i++) {
		resolve_slot *slot = &g_resolver_pool->slots[i];
		if (slot->state == RESOLVE_QUEUED)
			slot->state = RESOLVE_CANCELLED;
	}
	g_resolver_pool->pause_dequeue = 0;
	pthread_cond_broadcast(&g_resolver_pool->work_cv);
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

int resolver_test_wait_idle(int timeout_ms)
{
	int64_t deadline = net_mono_ms();
	if (deadline < 0)
		return 0;
	deadline += timeout_ms;
	for (;;) {
		resolver_accounting a;
		int64_t now;
		if (!resolver_test_accounting(&a))
			return 0;
		if (a.free_n == RESOLVER_SLOTS && a.queued == 0 && a.running == 0 &&
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

