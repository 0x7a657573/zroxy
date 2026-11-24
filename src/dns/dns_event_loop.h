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
#ifndef DNS_EVENT_LOOP_H_
#define DNS_EVENT_LOOP_H_

#include <stdbool.h>
#include "dns_internal.h"

/* The loop owns all DNS sockets until dns_event_loop_stop joins it. */
bool dns_event_loop_start(dnsserver_t *dns);
void dns_event_loop_stop(dnsserver_t *dns);

#endif
