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
/* Owns DNS upstream target resolution and resolver completions. */
#include "dns_event_internal.h"

#include <arpa/inet.h>
#include <string.h>

#include <zroxy/log.h>
#include <zroxy/net_io.h>

static bool addr_literal(const char *host, uint16_t port,
        struct sockaddr_storage *addr, socklen_t *len)
{
	struct sockaddr_in in;
	if (!host || !addr || !len || inet_pton(AF_INET, host, &in.sin_addr) != 1)
		return false;
	memset(&in, 0, sizeof(in));
	in.sin_family = AF_INET;
	in.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &in.sin_addr) != 1)
		return false;
	memset(addr, 0, sizeof(*addr));
	memcpy(addr, &in, sizeof(in));
	*len = sizeof(in);
	return true;
}
static dns_target_t *resolve_target(dns_event_t *event, uint32_t index,
        const char **host, uint16_t *port, uint64_t **generation)
{
	unsigned route;
	if (index < 1 || (index - 1) / 2 >= event->dns->route_count)
		return NULL;
	route = (index - 1) / 2;
	*generation = &event->routes[route].address_generation;
	if ((index - 1) % 2 == 0)
	{
		*host = event->dns->routes[route].upstream.ip;
		*port = event->dns->routes[route].upstream.port;
		return &event->routes[route].upstream;
	}
	if (!event->dns->routes[route].socks)
		return NULL;
	*host = event->dns->routes[route].socks->host;
	*port = event->dns->routes[route].socks->port;
	return &event->routes[route].socks;
}

bool dnsev_resolution_submit(dns_event_t *event, uint32_t index)
{
	const char *host;
	uint16_t port;
	uint64_t *generation;
	dns_target_t *target = resolve_target(event, index, &host, &port, &generation);

	if (!target)
		return false;
	if (target->literal || target->slot >= 0)
		return true;
	if (addr_literal(host, port, &target->addr, &target->len))
	{
		target->literal = 1;
		target->ready = 1;
		(*generation)++;
		return true;
	}
	if (resolver_submit(event->resolver, index, event->generation, host, port, AF_INET,
	            dnsev_mono_now() + net_timeout_ms((int)event->dns->timeout),
	            &target->slot, &target->req) == RESOLVER_SUBMIT_OK)
		return true;
	target->resolve_at_ms = dnsev_mono_now() + DNS_RESOLVE_RETRY_MS;
	return false;
}

void dnsev_resolution_tick(dns_event_t *event, int64_t now)
{
	uint32_t index;
	for (index = 1; index <= 2u * event->dns->route_count; index++)
	{
		const char *host;
		uint16_t port;
		uint64_t *generation;
		dns_target_t *target = resolve_target(event, index, &host, &port, &generation);
		if (target && !target->literal && target->slot < 0 && now >= target->resolve_at_ms)
			(void)dnsev_resolution_submit(event, index);
	}
}

void dnsev_dns_drain_resolver(dns_event_t *event)
{
	resolve_slot *done[RESOLVER_SLOTS];
	size_t n = resolver_drain(event->resolver, done, RESOLVER_SLOTS);
	size_t i;
	int64_t now = dnsev_mono_now();

	for (i = 0; i < n; i++)
	{
		resolve_slot *slot = done[i];
		const char *host;
		uint16_t port;
		uint64_t *generation;
		dns_target_t *target;

		if (!slot)
			continue;
		if (slot->connection_generation != event->generation)
		{
			resolver_release(slot->index, slot->req_id);
			continue;
		}
		target = resolve_target(event, slot->connection_index, &host, &port, &generation);
		if (!target)
		{
			resolver_release(slot->index, slot->req_id);
			continue;
		}
		if (target->slot == slot->index && target->req == slot->req_id)
		{
			target->slot = -1;
			target->req = 0;
		}
		if (slot->gai_error == 0 && slot->address_count > 0 &&
		        slot->addresses[0].address.ss_family == AF_INET)
		{
			/* The resolver returns addresses without a port; apply the configured one. */
			struct sockaddr_storage resolved = slot->addresses[0].address;
			bool changed;
			((struct sockaddr_in *)&resolved)->sin_port = htons(port);
			changed = !target->ready || target->len != slot->addresses[0].length ||
			          memcmp(&target->addr, &resolved, target->len) != 0;
			target->addr = resolved;
			target->len = slot->addresses[0].length;
			target->ready = 1;
			if (changed)
				(*generation)++;
			target->resolve_at_ms = now + DNS_RESOLVE_REFRESH_MS;
		}
		else
		{
			log_error("dns resolver failed for %s; retrying", host);
			target->resolve_at_ms = now + DNS_RESOLVE_RETRY_MS;
		}
		resolver_release(slot->index, slot->req_id);
	}
	dnsev_resolution_tick(event, now);
	dnsev_schedule(event);
}
