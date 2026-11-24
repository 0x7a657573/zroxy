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
/*
 * statistics.h
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */

#ifndef STATISTICS_H_
#define STATISTICS_H_
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

typedef bool (*stats_extra_fn)(void *ctx, char **ptr, char *end);

typedef struct
{
	time_t start_time;
	uint64_t total_rx;
	uint64_t total_tx;
	uint32_t total_connections;
	uint32_t active_connections;
	uint32_t max_connections;
} stat_t;

typedef struct
{
	/*variable*/
	stat_t stat;
	char name[128];
	/*thered lock*/
	pthread_mutex_t lock;
	stats_extra_fn extra;
	void *extra_ctx;
} statistics_t;

void stats_init(statistics_t **self, char *name);

/* Only when no thread can touch it any more. */
void stats_free(statistics_t *self);

/* The functions below accept a NULL statistics object and do nothing. */
void stats_close_connection(statistics_t *self, uint32_t rx, uint32_t tx);
void stats_open_connection(statistics_t *self);

void stats_get(statistics_t *self, stat_t *st);

/* Appends the base statistics members and any configured extra members. */
bool stats_json(void *ctx, char **ptr, char *end);

/* Sets the extra callback and context under the stats lock. */
void stats_set_extra(statistics_t *self, stats_extra_fn fn, void *ctx);

#endif /* STATISTICS_H_ */
