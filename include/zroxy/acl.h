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
#ifndef ZROXY_ACL_H
#define ZROXY_ACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
	uint32_t net;
	uint32_t mask;
} zroxy_cidr_t;

bool acl_parse(const char *spec, zroxy_cidr_t *out, size_t cap, size_t *count);
bool acl_allows(const zroxy_cidr_t *acl, size_t n, uint32_t ip_host_order);

#endif
