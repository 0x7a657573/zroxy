/*
 *
 */
#include <zroxy/statistics.h>
#include <zroxy/log.h>
#include <stdlib.h>
#include <string.h>

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
	(*self)->next = NULL;
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

void stats_set_extra(statistics_t *self, stats_extra_fn fn, void *ctx)
{
	if (!self)
		return;
	pthread_mutex_lock(&self->lock);
	self->extra = fn;
	self->extra_ctx = ctx;
	pthread_mutex_unlock(&self->lock);
}
