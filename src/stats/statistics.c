/*
 *
 */
#include <zroxy/statistics.h>
#include <zroxy/log.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool stats_append(char **ptr, char *end, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t left;

	if (!ptr || !*ptr || *ptr >= end)
		return false;
	left = (size_t)(end - *ptr);
	va_start(ap, fmt);
	n = vsnprintf(*ptr, left, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
	return true;
}

void stats_init(statistics_t **self, char *name)
{
	*self = malloc(sizeof(statistics_t));
	if (!*self)
	{
		log_error("statistics allocation failed");
		exit(1);
	}
	memset(*self, 0, sizeof(statistics_t));
	if (pthread_mutex_init(&(*self)->lock, NULL) != 0)
	{
		log_error("statistics mutex init has failed");
		exit(1);
	}
	if (!name || strlen(name) >= sizeof((*self)->name))
	{
		log_error("statistics name rejected");
		exit(1);
	}
	memcpy((*self)->name, name, strlen(name) + 1);
	time(&(*self)->stat.start_time);
}

void stats_free(statistics_t *self)
{
	if (!self)
		return;
	pthread_mutex_destroy(&self->lock);
	free(self);
}

void stats_close_connection(statistics_t *self, uint32_t rx, uint32_t tx)
{
	if (!self)
		return;
	pthread_mutex_lock(&self->lock);
	self->stat.total_rx += rx;
	self->stat.total_tx += tx;
	if (self->stat.active_connections > 0)
		self->stat.active_connections--;
	self->stat.total_connections++;
	pthread_mutex_unlock(&self->lock);
}

void stats_open_connection(statistics_t *self)
{
	if (!self)
		return;
	pthread_mutex_lock(&self->lock);
	self->stat.active_connections++;
	if (self->stat.active_connections > self->stat.max_connections)
		self->stat.max_connections = self->stat.active_connections;
	pthread_mutex_unlock(&self->lock);
}

void stats_get(statistics_t *self, stat_t *st)
{
	if (!self)
	{
		memset(st, 0, sizeof(*st));
		return;
	}
	pthread_mutex_lock(&self->lock);
	*st = self->stat;
	pthread_mutex_unlock(&self->lock);
}

bool stats_json(void *ctx, char **ptr, char *end)
{
	statistics_t *self = ctx;
	stat_t stdata;
	stats_extra_fn extra;
	void *extra_ctx;
	time_t current_time;
	time_t live_time;
	bool ok;

	if (!self || !ptr || !*ptr || *ptr >= end)
		return false;
	pthread_mutex_lock(&self->lock);
	stdata = self->stat;
	extra = self->extra;
	extra_ctx = self->extra_ctx;
	time(&current_time);
	live_time = current_time - stdata.start_time;

	ok = stats_append(ptr, end, "\"UpTime\" : %lld ,\n", (long long)live_time) &&
	     stats_append(ptr, end, "\"MaxConnection\" : %" PRIu32 " ,\n", stdata.max_connections) &&
	     stats_append(ptr, end, "\"ActiveConnection\" : %" PRIu32 " ,\n", stdata.active_connections) &&
	     stats_append(ptr, end, "\"TotalConnection\" : %" PRIu32 " ,\n", stdata.total_connections) &&
	     stats_append(ptr, end, "\"TotalRx\" : %" PRIu64 " ,\n", stdata.total_rx) &&
	     stats_append(ptr, end, "\"TotalTx\" : %" PRIu64, stdata.total_tx);
	if (ok && extra)
		ok = extra(extra_ctx, ptr, end);
	pthread_mutex_unlock(&self->lock);
	return ok;
}

void stats_set_extra(statistics_t *self, stats_extra_fn fn, void *ctx)
{
	if (!self)
		return;
	pthread_mutex_lock(&self->lock);
	self->extra = fn;
	self->extra_ctx = ctx;
	pthread_mutex_unlock(&self->lock);
}
