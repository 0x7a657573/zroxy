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
#ifndef ZROXY_DNSRATE_H
#define ZROXY_DNSRATE_H

#include <stdbool.h>
#include <stdint.h>

#define DNS_RATE_SLOTS 1024

typedef struct
{
	uint32_t ip;
	uint32_t tokens_milli;
	int64_t last_ms;
} dns_rate_slot_t;

typedef struct
{
	uint32_t qps;
	dns_rate_slot_t slots[DNS_RATE_SLOTS];
} dns_rate_t;

/* Called only by the DNS receive thread; no lock is required. */
bool dns_rate_take(dns_rate_t *rate, uint32_t ip, int64_t now_ms);

#endif
