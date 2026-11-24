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
#include "resolver_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>

/* SOCKS upstream cache and listener bind tracking. */

#include <zroxy/net_io.h>

void resolver_commit_infra_locked(resolve_slot *slot, int gai_error)
{
	if (slot->req_id != g_resolver_pool->cache_refresh_req && g_resolver_pool->cache_refresh_req != 0 &&
	        slot->req_id != g_resolver_pool->cache_refresh_req)
	{
		/* A newer refresh owns the cache. This result is stale. */
	}
	if (slot->req_id == g_resolver_pool->cache_refresh_req || g_resolver_pool->cache_refresh_inflight)
	{
		if (slot->req_id == g_resolver_pool->cache_refresh_req)
		{
			g_resolver_pool->cache_refresh_inflight = 0;
			if (gai_error == 0 && slot->address_count > 0)
			{
				int64_t now = net_mono_ms();
				memcpy(g_resolver_pool->cache_addrs, slot->addresses,
				        slot->address_count * sizeof(slot->addresses[0]));
				g_resolver_pool->cache_count = slot->address_count;
				g_resolver_pool->cache_valid = 1;
				if (now < 0)
					now = 0;
				g_resolver_pool->cache_last_success = now;
				g_resolver_pool->cache_refresh_after = now + (int64_t)RESOLVER_INFRA_REFRESH_MS;
				g_resolver_pool->cache_max_stale = now + (int64_t)RESOLVER_INFRA_MAX_STALE_MS;
			}
			pthread_cond_broadcast(&g_resolver_pool->infra_cv);
		}
	}
}

static int submit_infra_locked(const char *norm, uint16_t port)
{
	resolve_slot *slot;
	if (g_resolver_pool->cache_refresh_inflight)
		return 0;
	if (g_resolver_pool->infra_used >= RESOLVER_INFRA_RESERVE || g_resolver_pool->free_head == NULL)
		return -1;
	slot = g_resolver_pool->free_head;
	g_resolver_pool->free_head = slot->qnext;
	slot->qnext = NULL;
	g_resolver_pool->free_count--;
	slot->req_id = resolver_alloc_req_id_locked(g_resolver_pool);
	slot->listener_id = 0;
	slot->connection_index = 0;
	slot->connection_generation = 0;
	slot->request_class = RESOLVER_KIND_INFRA;
	slot->gai_error = 0;
	slot->deadline_ms = net_mono_ms() + (int64_t)RESOLVER_INFRA_STARTUP_MS;
	if (slot->deadline_ms < 0)
		slot->deadline_ms = 0;
	memcpy(slot->hostname, norm, strlen(norm) + 1);
	slot->port = port;
	slot->family_policy = AF_INET;
	slot->address_count = 0;
	slot->sink = NULL;
	slot->in_ring = 0;
	slot->holds_ref = 0;
	slot->quota_kind = RESOLVER_QUOTA_INFRA;
	slot->state = RESOLVE_QUEUED;
	g_resolver_pool->infra_used++;
	g_resolver_pool->cache_refresh_inflight = 1;
	g_resolver_pool->cache_refresh_req = slot->req_id;
	memcpy(g_resolver_pool->cache_host, norm, strlen(norm) + 1);
	g_resolver_pool->cache_port = port;
	resolver_enqueue(&g_resolver_pool->infra_head, &g_resolver_pool->infra_tail, slot);
	pthread_cond_signal(&g_resolver_pool->work_cv);
	return 0;
}

void resolver_watch_bind(uint32_t listener_id, const char *bindip, uint16_t port)
{
	struct in_addr ip;
	int i;
	int free_i = -1;
	if (!bindip || listener_id == 0 || !resolver_start())
		return;
	if (inet_pton(AF_INET, bindip, &ip) != 1)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	for (i = 0; i < RESOLVER_BIND_MAX; i++)
	{
		if (g_resolver_pool->binds[i].used && g_resolver_pool->binds[i].listener_id == listener_id)
		{
			free_i = i;
			break;
		}
		if (!g_resolver_pool->binds[i].used && free_i < 0)
			free_i = i;
	}
	if (free_i >= 0)
	{
		g_resolver_pool->binds[free_i].used = 1;
		g_resolver_pool->binds[free_i].listener_id = listener_id;
		g_resolver_pool->binds[free_i].port = port;
		g_resolver_pool->binds[free_i].ip = ip;
		g_resolver_pool->binds[free_i].wildcard = (ip.s_addr == htonl(INADDR_ANY));
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

void resolver_unwatch_bind(uint32_t listener_id)
{
	int i;
	if (!g_resolver_pool || listener_id == 0)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	for (i = 0; i < RESOLVER_BIND_MAX; i++)
	{
		if (g_resolver_pool->binds[i].used && g_resolver_pool->binds[i].listener_id == listener_id)
			g_resolver_pool->binds[i].used = 0;
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
}

static int cache_copy_locked(uint16_t port, resolver_addr *out, size_t *count)
{
	size_t i;
	int64_t now = net_mono_ms();
	if (!g_resolver_pool->cache_valid || g_resolver_pool->cache_count == 0)
		return RESOLVER_UP_UNRESOLVED;
	if (now >= 0 && g_resolver_pool->cache_max_stale > 0 && now > g_resolver_pool->cache_max_stale)
		return RESOLVER_UP_UNRESOLVED;
	*count = g_resolver_pool->cache_count;
	memcpy(out, g_resolver_pool->cache_addrs, (*count) * sizeof(*out));
	for (i = 0; i < *count; i++)
		resolver_apply_port_one(&out[i], port);
	if (now >= 0 && now >= g_resolver_pool->cache_refresh_after)
		(void)submit_infra_locked(g_resolver_pool->cache_host, g_resolver_pool->cache_port);
	return RESOLVER_UP_READY;
}

bool resolver_prime_socks(const char *host, uint16_t port, int wait_ms)
{
	char norm[RESOLVER_HOST_MAX + 1];
	resolver_addr numeric;
	size_t n = 0;
	struct timespec ts;
	if (!host || host[0] == '\0')
		return true;
	if (resolver_copy_numeric(host, port, &numeric, &n))
		return true;
	if (!resolver_normalize(host, norm, sizeof(norm)))
		return true;
	if (!resolver_start())
		return false;
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (g_resolver_pool->cache_valid && strcmp(g_resolver_pool->cache_host, norm) == 0 &&
	        g_resolver_pool->cache_port == port)
	{
		int64_t now = net_mono_ms();
		if (now >= 0 && now < g_resolver_pool->cache_refresh_after)
		{
			pthread_mutex_unlock(&g_resolver_pool->mu);
			return true;
		}
	}
	if (submit_infra_locked(norm, port) != 0 && !g_resolver_pool->cache_refresh_inflight)
	{
		pthread_mutex_unlock(&g_resolver_pool->mu);
		return true;
	}
	if (resolver_mono_deadline(wait_ms, &ts) == 0)
	{
		while (g_resolver_pool->cache_refresh_inflight)
		{
			int wr = pthread_cond_timedwait(&g_resolver_pool->infra_cv, &g_resolver_pool->mu, &ts);
			if (wr == ETIMEDOUT)
				break;
		}
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return true;
}

int resolver_copy_upstream(const char *host, uint16_t port,
        resolver_addr *out, size_t *count)
{
	char norm[RESOLVER_HOST_MAX + 1];
	int st;
	if (!host || !out || !count)
		return RESOLVER_UP_UNRESOLVED;
	*count = 0;
	if (resolver_copy_numeric(host, port, out, count))
		return RESOLVER_UP_READY;
	if (!resolver_normalize(host, norm, sizeof(norm)))
		return RESOLVER_UP_NEED_RESOLVE;
	if (!g_resolver_pool)
		return RESOLVER_UP_NEED_RESOLVE;
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (!g_resolver_pool->cache_valid || strcmp(g_resolver_pool->cache_host, norm) != 0)
	{
		if (g_resolver_pool->cache_host[0] != '\0' && strcmp(g_resolver_pool->cache_host, norm) == 0)
			(void)submit_infra_locked(norm, port);
		pthread_mutex_unlock(&g_resolver_pool->mu);
		return RESOLVER_UP_NEED_RESOLVE;
	}
	st = cache_copy_locked(port, out, count);
	if (st == RESOLVER_UP_UNRESOLVED)
		(void)submit_infra_locked(norm, port);
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return st;
}
