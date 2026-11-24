/*
 * Copyright (c) 2020-2026 zeus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include "resolver_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>

#include <zroxy/log.h>
#include <zroxy/net_io.h>

resolver_pool *g_resolver_pool;
static pthread_mutex_t g_start_mu = PTHREAD_MUTEX_INITIALIZER;

static void ignore_sigpipe(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

int resolver_mono_deadline(int timeout_ms, struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) != 0)
		return -1;
	ts->tv_sec += timeout_ms / 1000;
	ts->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (ts->tv_nsec >= 1000000000L)
	{
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
	if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0)
	{
		pthread_condattr_destroy(&attr);
		return -1;
	}
	if (pthread_cond_init(cv, &attr) != 0)
	{
		pthread_condattr_destroy(&attr);
		return -1;
	}
	pthread_condattr_destroy(&attr);
	return 0;
}

void resolver_enqueue(resolve_slot **head, resolve_slot **tail, resolve_slot *slot)
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

uint64_t resolver_alloc_req_id_locked(resolver_pool *pool)
{
	pool->next_req_id++;
	if (pool->next_req_id == 0)
		pool->next_req_id = 1;
	return pool->next_req_id;
}

resolver_sink *resolver_ref_drop_locked(resolver_sink *sink)
{
	if (!sink || sink->refcount == 0)
		return NULL;
	sink->refcount--;
	g_resolver_pool->sink_refs--;
	if (sink->refcount == 0)
		return sink;
	return NULL;
}

static void quota_dec_locked(resolve_slot *slot)
{
	if (slot->quota_kind == RESOLVER_QUOTA_DIRECT)
	{
		if (g_resolver_pool->direct_used > 0)
			g_resolver_pool->direct_used--;
	}
	else if (slot->quota_kind == RESOLVER_QUOTA_INFRA)
	{
		if (g_resolver_pool->infra_used > 0)
			g_resolver_pool->infra_used--;
	}
	else if (slot->quota_kind == RESOLVER_QUOTA_LISTENER)
	{
		if (g_resolver_pool->listener_used > 0)
			g_resolver_pool->listener_used--;
		if (slot->sink && slot->sink->quota_used > 0)
			slot->sink->quota_used--;
	}
	slot->quota_kind = 0;
}

resolver_sink *resolver_slot_free_locked(resolve_slot *slot)
{
	resolver_sink *die = NULL;
	if (!slot)
		return NULL;
	if (slot->state == RESOLVE_FREE)
	{
		g_resolver_pool->double_free++;
		return NULL;
	}
	quota_dec_locked(slot);
	if (slot->holds_ref && slot->sink)
	{
		slot->holds_ref = 0;
		die = resolver_ref_drop_locked(slot->sink);
	}
	slot->state = RESOLVE_FREE;
	slot->in_ring = 0;
	slot->sink = NULL;
	slot->hostname[0] = '\0';
	slot->address_count = 0;
	slot->gai_error = 0;
	slot->qnext = g_resolver_pool->free_head;
	g_resolver_pool->free_head = slot;
	g_resolver_pool->free_count++;
	return die;
}

static int do_resolve(const char *host, int family, resolver_addr *out, size_t *count)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	int st = EAI_FAIL;
	int attempts = 0;
	*count = 0;
	memset(&hints, 0, sizeof(hints));
	/*
	 * Family is recorded for tests. IPv6 is not proxied, so the lookup asks
	 * for A only and never waits on an AAAA query the upstream drops.
	 */
	(void)family;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	do
	{
		res = NULL;
#ifdef RESOLVER_TEST_HOOKS
		if (g_resolver_pool->hook)
		{
			st = g_resolver_pool->hook(host, family, out, RESOLVER_ADDR_MAX, count,
			        g_resolver_pool->hook_cookie);
		}
		else
#endif
		{
			st = getaddrinfo(host, NULL, &hints, &res);
		}
		attempts++;
		if (st == EAI_SYSTEM && errno == EINTR && res)
		{
			freeaddrinfo(res);
			res = NULL;
		}
	} while (st == EAI_SYSTEM && errno == EINTR && attempts < RESOLVER_GAI_ATTEMPTS);
	__atomic_fetch_add(&g_resolver_pool->calls, (uint32_t)attempts, __ATOMIC_RELAXED);
#ifdef RESOLVER_TEST_HOOKS
	if (g_resolver_pool->hook)
		return st;
#endif
	if (st != 0)
	{
		if (res)
			freeaddrinfo(res);
		*count = 0;
		return st;
	}
	for (ai = res; ai != NULL && *count < RESOLVER_ADDR_MAX; ai = ai->ai_next)
	{
		resolver_addr *dst;
		if (!ai->ai_addr || ai->ai_addrlen <= 0)
			continue;
		if (ai->ai_family != AF_INET)
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

#ifdef RESOLVER_TEST_HOOKS
static void wait_if_held(void)
{
	pthread_mutex_lock(&g_resolver_pool->test_mu);
	g_resolver_pool->running_entered++;
	pthread_cond_broadcast(&g_resolver_pool->test_cv);
	while (g_resolver_pool->hold_running)
		pthread_cond_wait(&g_resolver_pool->test_cv, &g_resolver_pool->test_mu);
	pthread_mutex_unlock(&g_resolver_pool->test_mu);
}
#endif

static void worker_finish(resolve_slot *slot, int gai_error, const resolver_addr *addrs,
        size_t count)
{
	resolver_sink *sink;
	resolver_sink *die = NULL;
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (g_resolver_pool->stopping && slot->request_class == RESOLVER_KIND_INFRA)
	{
		if (slot->req_id == g_resolver_pool->cache_refresh_req)
			g_resolver_pool->cache_refresh_inflight = 0;
		pthread_cond_broadcast(&g_resolver_pool->infra_cv);
		die = resolver_slot_free_locked(slot);
		pthread_mutex_unlock(&g_resolver_pool->mu);
		resolver_destroy_later(die);
		return;
	}
	slot->gai_error = gai_error;
	slot->address_count = count;
	if (count > 0)
		memcpy(slot->addresses, addrs, count * sizeof(*addrs));
	slot->state = RESOLVE_DONE;
	sink = slot->sink;
	if (!sink)
	{
		resolver_commit_infra_locked(slot, gai_error);
		die = resolver_slot_free_locked(slot);
		pthread_mutex_unlock(&g_resolver_pool->mu);
		resolver_destroy_later(die);
		return;
	}
	slot->in_ring = 1;
	slot->holds_ref = 0;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolver_publish_slot(slot, sink);
}

static void resolve_and_finish(resolve_slot *slot, const char *host, int family)
{
	resolver_addr addrs[RESOLVER_ADDR_MAX];
	size_t count = 0;
	int gai_error;
#ifdef RESOLVER_TEST_HOOKS
	wait_if_held();
#endif
	if (g_resolver_pool->stopping)
	{
		worker_finish(slot, EAI_AGAIN, NULL, 0);
		return;
	}
	gai_error = do_resolve(host, family, addrs, &count);
	if (gai_error != 0)
		__atomic_fetch_add(&g_resolver_pool->lookup_failures, 1u, __ATOMIC_RELAXED);
	worker_finish(slot, gai_error, addrs, count);
}

static void worker_one(resolve_slot *slot)
{
	char host[RESOLVER_HOST_MAX + 1];
	int family;
	int64_t now;
	resolver_sink *die = NULL;
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (slot->state == RESOLVE_CANCELLED)
	{
		__atomic_fetch_add(&g_resolver_pool->skipped_cancelled, 1u, __ATOMIC_RELAXED);
		die = resolver_slot_free_locked(slot);
		pthread_mutex_unlock(&g_resolver_pool->mu);
		resolver_destroy_later(die);
		return;
	}
	now = net_mono_ms();
	if (now >= 0 && slot->deadline_ms > 0 && now >= slot->deadline_ms)
	{
		__atomic_fetch_add(&g_resolver_pool->skipped_expired, 1u, __ATOMIC_RELAXED);
		slot->gai_error = EAI_AGAIN;
		slot->address_count = 0;
		slot->state = RESOLVE_DONE;
		if (!slot->sink)
		{
			if (slot->req_id == g_resolver_pool->cache_refresh_req)
			{
				g_resolver_pool->cache_refresh_inflight = 0;
				pthread_cond_broadcast(&g_resolver_pool->infra_cv);
			}
			die = resolver_slot_free_locked(slot);
			pthread_mutex_unlock(&g_resolver_pool->mu);
			resolver_destroy_later(die);
			return;
		}
		slot->in_ring = 1;
		slot->holds_ref = 0;
		{
			resolver_sink *sink = slot->sink;
			pthread_mutex_unlock(&g_resolver_pool->mu);
			resolver_publish_slot(slot, sink);
			return;
		}
	}
	if (g_resolver_pool->stopping)
	{
		die = resolver_slot_free_locked(slot);
		pthread_mutex_unlock(&g_resolver_pool->mu);
		resolver_destroy_later(die);
		return;
	}
	slot->state = RESOLVE_RUNNING;
	memcpy(host, slot->hostname, sizeof(host));
	family = slot->family_policy;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolve_and_finish(slot, host, family);
}

static void *worker_main(void *arg)
{
	resolver_pool *pool = (resolver_pool *)arg;
	for (;;)
	{
		resolve_slot *slot;
		pthread_mutex_lock(&pool->mu);
		while (!pool->stopping &&
		        (pool->pause_dequeue ||
		                (pool->client_head == NULL && pool->infra_head == NULL)))
			pthread_cond_wait(&pool->work_cv, &pool->mu);
		if (pool->stopping && pool->client_head == NULL && pool->infra_head == NULL)
		{
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
	resolver_pool *pool;
	pthread_condattr_t attr;
	int i;
	ignore_sigpipe();
	pool = (resolver_pool *)calloc(1, sizeof(*pool));
	if (!pool)
		return -1;
	if (pthread_mutex_init(&pool->mu, NULL) != 0)
	{
		free(pool);
		return -1;
	}
	if (init_mono_cond(&pool->work_cv) != 0 || init_mono_cond(&pool->infra_cv) != 0)
	{
		pthread_mutex_destroy(&pool->mu);
		free(pool);
		return -1;
	}
#ifdef RESOLVER_TEST_HOOKS
	if (pthread_mutex_init(&pool->test_mu, NULL) != 0)
	{
		pthread_cond_destroy(&pool->work_cv);
		pthread_cond_destroy(&pool->infra_cv);
		pthread_mutex_destroy(&pool->mu);
		free(pool);
		return -1;
	}
	if (pthread_condattr_init(&attr) != 0 ||
	        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0 ||
	        pthread_cond_init(&pool->test_cv, &attr) != 0)
	{
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
	for (i = 0; i < RESOLVER_SLOTS; i++)
	{
		pool->slots[i].index = i;
		pool->slots[i].state = RESOLVE_FREE;
		pool->slots[i].qnext = pool->free_head;
		pool->free_head = &pool->slots[i];
	}
	pool->free_count = RESOLVER_SLOTS;
	pool->next_req_id = 1;
	pool->next_listener_id = 1;
	g_resolver_pool = pool;
	for (i = 0; i < RESOLVER_THREADS; i++)
	{
		if (pthread_create(&pool->threads[i], NULL, worker_main, pool) != 0)
		{
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
#ifdef RESOLVER_TEST_HOOKS
			pthread_cond_destroy(&pool->test_cv);
			pthread_mutex_destroy(&pool->test_mu);
#endif
			free(pool);
			g_resolver_pool = NULL;
			return -1;
		}
	}
	pool->started = 1;
	return 0;
}

void resolver_get_stats(resolver_stats *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->threads = RESOLVER_THREADS;
	out->slots = RESOLVER_SLOTS;
	/* g_start_mu keeps the pool from being freed under us; it is taken first, as in shutdown. */
	pthread_mutex_lock(&g_start_mu);
	if (g_resolver_pool && g_resolver_pool->started)
	{
		pthread_mutex_lock(&g_resolver_pool->mu);
		out->slots_in_use = RESOLVER_SLOTS - g_resolver_pool->free_count;
		out->lookups = __atomic_load_n(&g_resolver_pool->calls, __ATOMIC_RELAXED);
		out->lookup_failures = __atomic_load_n(&g_resolver_pool->lookup_failures, __ATOMIC_RELAXED);
		out->ring_full = __atomic_load_n(&g_resolver_pool->ring_full, __ATOMIC_RELAXED);
		pthread_mutex_unlock(&g_resolver_pool->mu);
	}
	pthread_mutex_unlock(&g_start_mu);
}

bool resolver_stats_json(void *ctx, char **ptr, char *end)
{
	resolver_stats st;
	size_t left;
	int n;

	(void)ctx;
	if (!ptr || !*ptr || *ptr >= end)
		return false;
	resolver_get_stats(&st);
	left = (size_t)(end - *ptr);
	n = snprintf(*ptr, left, "\"Threads\" : %d ,\n"
	                         "\"Slots\" : %d ,\n"
	                         "\"SlotsInUse\" : %d ,\n"
	                         "\"Lookups\" : %" PRIu32 " ,\n"
	                         "\"LookupFailures\" : %" PRIu32 " ,\n"
	                         "\"RingFull\" : %" PRIu32,
	        st.threads, st.slots, st.slots_in_use,
	        st.lookups, st.lookup_failures, st.ring_full);
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
	return true;
}

bool resolver_start(void)
{
	int rc;
	pthread_mutex_lock(&g_start_mu);
	if (g_resolver_pool && g_resolver_pool->started && !g_resolver_pool->abandoned)
	{
		pthread_mutex_unlock(&g_start_mu);
		return true;
	}
	if (g_resolver_pool && g_resolver_pool->abandoned)
	{
		pthread_mutex_unlock(&g_start_mu);
		return false;
	}
	rc = pool_create();
	pthread_mutex_unlock(&g_start_mu);
	return rc == 0;
}

int resolver_shutdown(int timeout_ms)
{
	resolver_pool *pool;
	struct timespec ts;
	int abandoned = 0;
	int i;
	pthread_mutex_lock(&g_start_mu);
	pool = g_resolver_pool;
	if (!pool || !pool->started)
	{
		pthread_mutex_unlock(&g_start_mu);
		return 0;
	}
	pthread_mutex_lock(&pool->mu);
	pool->stopping = 1;
	pool->pause_dequeue = 0;
	pthread_cond_broadcast(&pool->work_cv);
	if (resolver_mono_deadline(timeout_ms, &ts) != 0)
	{
		pool->abandoned = 1;
		pthread_mutex_unlock(&pool->mu);
		for (i = 0; i < RESOLVER_THREADS; i++)
			pthread_detach(pool->threads[i]);
		pthread_mutex_unlock(&g_start_mu);
		return 1;
	}
	while (pool->exited < RESOLVER_THREADS)
	{
		int wr = pthread_cond_timedwait(&pool->infra_cv, &pool->mu, &ts);
		if (wr == ETIMEDOUT)
		{
			pool->abandoned = 1;
			abandoned = 1;
			break;
		}
	}
	pthread_mutex_unlock(&pool->mu);
	if (abandoned)
	{
		/* Workers that already returned are reaped. A worker still inside
		 * getaddrinfo stays detached and keeps using this pool, so the
		 * mutex and slots are left allocated until process exit. */
		for (i = 0; i < RESOLVER_THREADS; i++)
			pthread_detach(pool->threads[i]);
		pthread_mutex_unlock(&g_start_mu);
		return 1;
	}
	for (i = 0; i < RESOLVER_THREADS; i++)
		pthread_join(pool->threads[i], NULL);
	pthread_cond_destroy(&pool->work_cv);
	pthread_cond_destroy(&pool->infra_cv);
	pthread_mutex_destroy(&pool->mu);
#ifdef RESOLVER_TEST_HOOKS
	pthread_cond_destroy(&pool->test_cv);
	pthread_mutex_destroy(&pool->test_mu);
#endif
	g_resolver_pool = NULL;
	free(pool);
	pthread_mutex_unlock(&g_start_mu);
	return 0;
}

int resolver_submit(resolver_sink *sink, uint32_t connection_index,
        uint64_t connection_generation, const char *hostname, uint16_t port,
        int family, int64_t deadline_ms, int *slot_index, uint64_t *req_id)
{
	resolve_slot *slot;
	char norm[RESOLVER_HOST_MAX + 1];
	if (slot_index)
		*slot_index = -1;
	if (req_id)
		*req_id = 0;
	if (!sink || !hostname || !slot_index || !req_id)
		return RESOLVER_SUBMIT_BADNAME;
	if (!resolver_normalize(hostname, norm, sizeof(norm)))
		return RESOLVER_SUBMIT_BADNAME;
	if (!g_resolver_pool)
		return RESOLVER_SUBMIT_OVERFLOW;
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (g_resolver_pool->stopping || !resolver_quota_ok_locked(sink) || g_resolver_pool->free_head == NULL)
	{
		pthread_mutex_unlock(&g_resolver_pool->mu);
		return RESOLVER_SUBMIT_OVERFLOW;
	}
	slot = g_resolver_pool->free_head;
	g_resolver_pool->free_head = slot->qnext;
	slot->qnext = NULL;
	g_resolver_pool->free_count--;
	slot->req_id = resolver_alloc_req_id_locked(g_resolver_pool);
	slot->listener_id = sink->listener_id;
	slot->connection_index = connection_index;
	slot->connection_generation = connection_generation;
	slot->request_class = RESOLVER_KIND_CLIENT;
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
	g_resolver_pool->sink_refs++;
	resolver_quota_inc_locked(sink, slot);
	resolver_enqueue(&g_resolver_pool->client_head, &g_resolver_pool->client_tail, slot);
	pthread_cond_signal(&g_resolver_pool->work_cv);
	*slot_index = slot->index;
	*req_id = slot->req_id;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return RESOLVER_SUBMIT_OK;
}

void resolver_cancel(int slot_index, uint64_t req_id)
{
	resolve_slot *slot;
	if (!g_resolver_pool || req_id == 0 || slot_index < 0 || slot_index >= RESOLVER_SLOTS)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	slot = &g_resolver_pool->slots[slot_index];
	if (slot->req_id != req_id)
	{
		pthread_mutex_unlock(&g_resolver_pool->mu);
		return;
	}
	if (slot->state == RESOLVE_QUEUED)
		slot->state = RESOLVE_CANCELLED;
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

void resolver_release(int slot_index, uint64_t req_id)
{
	resolve_slot *slot;
	resolver_sink *die = NULL;
	if (!g_resolver_pool || req_id == 0 || slot_index < 0 || slot_index >= RESOLVER_SLOTS)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	slot = &g_resolver_pool->slots[slot_index];
	if (slot->req_id != req_id || slot->state == RESOLVE_FREE)
	{
		pthread_mutex_unlock(&g_resolver_pool->mu);
		return;
	}
	if (slot->state == RESOLVE_QUEUED)
		slot->state = RESOLVE_CANCELLED;
	if (slot->state == RESOLVE_DONE || slot->state == RESOLVE_CANCELLED)
		die = resolver_slot_free_locked(slot);
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolver_destroy_later(die);
}
