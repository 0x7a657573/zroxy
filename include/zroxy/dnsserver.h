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
 * DnsServer.h
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */

#ifndef DNSSERVER_H_
#define DNSSERVER_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/config.h>
#include <zroxy/socks.h>
#include <zroxy/statistics.h>
#include <sys/socket.h>
#include <zroxy/filter.h>
#include <zroxy/acl.h>
#include <zroxy/settings.h>
#include <zroxy/dnsrate.h>

struct dnsserver;

/* Bind the sockets and start the single event-loop thread. NULL on failure. */
struct dnsserver *dnsserver_start(dnshost_t *config);
/* Stop the event loop, join its thread and free. */
void dnsserver_stop(struct dnsserver *dns);

#endif /* DNSSERVER_H_ */
