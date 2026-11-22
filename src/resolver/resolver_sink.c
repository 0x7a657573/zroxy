#define _GNU_SOURCE

#include "resolver_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Completion pipes, rings, and resolver sink ownership. */

void resolver_destroy_later(resolver_sink *sink)
{
	if (sink)
		resolver_sink_destroy(sink);
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
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0)
		return 0;
	if (errno != ENOSYS)
		return -1;
#endif
	if (pipe(fds) != 0)
		return -1;
	if (set_pipe_flags(fds[0]) != 0 || set_pipe_flags(fds[1]) != 0)
	{
		close(fds[0]);
		close(fds[1]);
		fds[0] = -1;
		fds[1] = -1;
		return -1;
	}
	return 0;
}

static void sink_wakeup(resolver_sink *sink)
{
	char byte = 1;
	for (;;)
	{
		ssize_t n = write(sink->pipe_write, &byte, 1);
		if (n >= 0)
			return;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			if (g_resolver_pool)
				__atomic_fetch_add(&g_resolver_pool->eagain_wakeups, 1u, __ATOMIC_RELAXED);
			return;
		}
		return;
	}
}

static int ring_push(resolver_sink *sink, resolve_slot *slot)
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
static void push_completion(resolve_slot *slot, resolver_sink *sink)
{
	int pushed = 0;
	resolver_sink *die = NULL;
	pthread_mutex_lock(&sink->mutex);
	if (!sink->closed && ring_push(sink, slot) == 0)
	{
		pushed = 1;
	}
	else if (sink->closed)
	{
		if (g_resolver_pool)
			__atomic_fetch_add(&g_resolver_pool->closed_drops, 1u, __ATOMIC_RELAXED);
	}
	else if (g_resolver_pool)
	{
		__atomic_fetch_add(&g_resolver_pool->ring_full, 1u, __ATOMIC_RELAXED);
	}
	pthread_mutex_unlock(&sink->mutex);
	if (pushed)
	{
		sink_wakeup(sink);
		return;
	}
	pthread_mutex_lock(&g_resolver_pool->mu);
	die = resolver_slot_free_locked(slot);
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolver_destroy_later(die);
}

void resolver_publish_slot(resolve_slot *slot, resolver_sink *sink)
{
	resolver_sink *die;
	push_completion(slot, sink);
	pthread_mutex_lock(&g_resolver_pool->mu);
	die = resolver_ref_drop_locked(sink);
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolver_destroy_later(die);
}

int resolver_quota_ok_locked(resolver_sink *sink)
{
	if (!sink || sink->closed)
		return 0;
	if (sink->kind == RESOLVER_SINK_DIRECT)
		return g_resolver_pool->direct_used < RESOLVER_DIRECT_RESERVE;
	if (sink->quota_used < sink->quota_limit)
		return 1;
	return 0;
}

void resolver_quota_inc_locked(resolver_sink *sink, resolve_slot *slot)
{
	if (sink->kind == RESOLVER_SINK_DIRECT)
	{
		g_resolver_pool->direct_used++;
		slot->quota_kind = RESOLVER_QUOTA_DIRECT;
		return;
	}
	sink->quota_used++;
	g_resolver_pool->listener_used++;
	slot->quota_kind = RESOLVER_QUOTA_LISTENER;
}

bool resolver_sink_open(int kind, resolver_sink **out)
{
	resolver_sink *sink;
	int fds[2] = {-1, -1};
	int quota;
	if (!out)
		return false;
	*out = NULL;
	if (!resolver_start())
		return false;
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (g_resolver_pool->stopping)
	{
		pthread_mutex_unlock(&g_resolver_pool->mu);
		return false;
	}
	if (kind == RESOLVER_SINK_DIRECT)
	{
		quota = RESOLVER_DIRECT_RESERVE;
	}
	else
	{
		int remain = RESOLVER_SLOTS - RESOLVER_INFRA_RESERVE -
		             RESOLVER_DIRECT_RESERVE - g_resolver_pool->listener_quota_assigned;
		if (remain <= 0)
		{
			pthread_mutex_unlock(&g_resolver_pool->mu);
			return false;
		}
		quota = RESOLVER_LISTENER_QUOTA;
		if (quota > remain)
			quota = remain;
		g_resolver_pool->listener_quota_assigned += quota;
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
	sink = (resolver_sink *)calloc(1, sizeof(*sink));
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
	pthread_mutex_lock(&g_resolver_pool->mu);
	sink->listener_id = g_resolver_pool->next_listener_id++;
	if (g_resolver_pool->next_listener_id == 0)
		g_resolver_pool->next_listener_id = 1;
	sink->refcount = 1;
	g_resolver_pool->sink_refs++;
	g_resolver_pool->live_sinks++;
	g_resolver_pool->open_pipes += 2;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	*out = sink;
	return true;
fail_sink:
	if (sink)
	{
		if (sink->pipe_read >= 0)
			close(sink->pipe_read);
		if (sink->pipe_write >= 0)
			close(sink->pipe_write);
		free(sink->ring);
		free(sink);
	}
fail_quota:
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (kind != RESOLVER_SINK_DIRECT)
		g_resolver_pool->listener_quota_assigned -= quota;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return false;
}

void resolver_sink_mark_closed(resolver_sink *sink)
{
	if (!sink)
		return;
	pthread_mutex_lock(&sink->mutex);
	sink->closed = true;
	pthread_mutex_unlock(&sink->mutex);
}

void resolver_sink_destroy(resolver_sink *sink)
{
	resolve_slot *batch[RESOLVER_SLOTS];
	size_t n = 0;
	size_t i;
	if (!sink)
		return;
	pthread_mutex_lock(&sink->mutex);
	while (sink->ring_count > 0 && n < RESOLVER_SLOTS)
	{
		batch[n++] = sink->ring[sink->ring_head];
		sink->ring[sink->ring_head] = NULL;
		sink->ring_head++;
		if (sink->ring_head == sink->ring_capacity)
			sink->ring_head = 0;
		sink->ring_count--;
	}
	pthread_mutex_unlock(&sink->mutex);
	for (i = 0; i < n; i++)
	{
		resolver_sink *die = NULL;
		pthread_mutex_lock(&g_resolver_pool->mu);
		if (batch[i])
			die = resolver_slot_free_locked(batch[i]);
		pthread_mutex_unlock(&g_resolver_pool->mu);
		if (die && die != sink)
			resolver_sink_destroy(die);
	}
	if (sink->pipe_read >= 0)
	{
		close(sink->pipe_read);
		sink->pipe_read = -1;
	}
	if (sink->pipe_write >= 0)
	{
		close(sink->pipe_write);
		sink->pipe_write = -1;
	}
	pthread_mutex_lock(&g_resolver_pool->mu);
	if (sink->kind != RESOLVER_SINK_DIRECT)
		g_resolver_pool->listener_quota_assigned -= sink->quota_limit;
	if (g_resolver_pool->live_sinks > 0)
		g_resolver_pool->live_sinks--;
	if (g_resolver_pool->open_pipes >= 2)
		g_resolver_pool->open_pipes -= 2;
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolver_unwatch_bind(sink->listener_id);
	pthread_mutex_destroy(&sink->mutex);
	free(sink->ring);
	free(sink);
}

void resolver_sink_release(resolver_sink *sink)
{
	resolver_sink *die = NULL;
	if (!sink || !g_resolver_pool)
		return;
	pthread_mutex_lock(&g_resolver_pool->mu);
	die = resolver_ref_drop_locked(sink);
	pthread_mutex_unlock(&g_resolver_pool->mu);
	resolver_destroy_later(die);
}

size_t resolver_drain(resolver_sink *sink, resolve_slot **out, size_t max_out)
{
	char buf[64];
	size_t n = 0;
	size_t i;
	if (!sink || !out || max_out == 0)
		return 0;
	for (;;)
	{
		ssize_t r = read(sink->pipe_read, buf, sizeof(buf));
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
	}
	pthread_mutex_lock(&sink->mutex);
	while (sink->ring_count > 0 && n < max_out)
	{
		out[n++] = sink->ring[sink->ring_head];
		sink->ring[sink->ring_head] = NULL;
		sink->ring_head++;
		if (sink->ring_head == sink->ring_capacity)
			sink->ring_head = 0;
		sink->ring_count--;
	}
	pthread_mutex_unlock(&sink->mutex);
	if (!g_resolver_pool)
		return n;
	pthread_mutex_lock(&g_resolver_pool->mu);
	for (i = 0; i < n; i++)
	{
		if (out[i])
			out[i]->in_ring = 0;
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return n;
}
