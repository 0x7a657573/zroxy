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
#ifndef ZROXY_RESOLVER_H_
#define ZROXY_RESOLVER_H_
#include <stdbool.h>

/* Monitor section for the shared hostname resolver pool. */
bool resolver_stats_json(void *ctx, char **ptr, char *end);

#endif /* ZROXY_RESOLVER_H_ */
