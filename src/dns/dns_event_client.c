/* Owns UDP and TCP DNS client handling. */
#include "dns_event_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zroxy/dns.h>
#include <zroxy/log.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>

void dnsev_send_udp(dns_event_t *event, const struct sockaddr_in *peer,
        const uint8_t *buf, size_t len)
{
	if (len > 0)
		(void)sendto(event->dns->local_sock, buf, len, 0,
		        (const struct sockaddr *)peer, sizeof(*peer));
}

void dnsev_client_close(dns_event_t *event, dns_client_t *client)
{
	dns_client_t **p;
	if (!client)
		return;
	if (client->request)
	{
		client->request->client = NULL;
		client->request = NULL;
	}
	if (client->registered)
		reactor_del(&event->re, client->fd);
	client->registered = 0;
	dnsev_close_fd(&client->fd);
	if (__atomic_load_n(&event->dns->tcp_active, __ATOMIC_RELAXED) > 0)
		__atomic_sub_fetch(&event->dns->tcp_active, 1, __ATOMIC_RELAXED);
	p = &event->clients;
	while (*p && *p != client)
		p = &(*p)->next;
	if (*p)
		*p = client->next;
	if (event->client_count > 0)
		event->client_count--;
	/*
	 * A ready batch may still hold an event for this client, so it is freed
	 * only after the batch (dnsev_client_reap); dispatch skips dead clients.
	 */
	client->dead = 1;
	client->dead_next = event->graveyard;
	event->graveyard = client;
}

void dnsev_client_reap(dns_event_t *event)
{
	while (event->graveyard)
	{
		dns_client_t *client = event->graveyard;
		event->graveyard = client->dead_next;
		free(client->output);
		free(client);
	}
}

bool dnsev_client_queue_reply(dns_client_t *client, const uint8_t *buf, size_t len)
{
	uint8_t *out;
	if (!client || client->fd < 0 || len > DNS_TCP_MSG_MAX || client->output)
		return false;
	out = malloc(len + 2u);
	if (!out)
		return false;
	out[0] = (uint8_t)(len >> 8);
	out[1] = (uint8_t)len;
	memcpy(out + 2, buf, len);
	client->output = out;
	client->output_len = len + 2u;
	client->output_off = 0;
	client->state = CLIENT_WRITE;
	client->deadline_ms = dnsev_mono_now() + net_timeout_ms((int)client->event->dns->timeout);
	return true;
}

void dnsev_client_pump(dns_event_t *event, dns_client_t *client, uint32_t revents)
{
	if (!client || client->fd < 0)
		return;
	/* A half-closed peer reports IN|HUP: read what it sent before giving up. */
	if ((revents & RE_ERR) || ((revents & RE_HUP) && !(revents & RE_IN)))
	{
		dnsev_client_close(event, client);
		return;
	}
	if (client->state == CLIENT_WRITE && revents & RE_OUT)
	{
		for (;;)
		{
			ssize_t n = write(client->fd, client->output + client->output_off,
			        client->output_len - client->output_off);
			if (n > 0)
			{
				client->output_off += (size_t)n;
				if (client->output_off < client->output_len)
					return;
				free(client->output);
				client->output = NULL;
				if (client->close_after_write || ++client->served >= DNS_TCP_MAX_QUERIES)
				{
					dnsev_client_close(event, client);
					return;
				}
				client->state = CLIENT_READ_LEN;
				client->input_off = 0;
				client->input_need = 2;
				client->deadline_ms = dnsev_mono_now() + DNS_TCP_IDLE_MS;
				return;
			}
			if (n < 0 && errno == EINTR)
				continue;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				return;
			dnsev_client_close(event, client);
			return;
		}
	}
	if ((client->state == CLIENT_READ_LEN || client->state == CLIENT_READ_QUERY) && revents & RE_IN)
	{
		for (;;)
		{
			ssize_t n = read(client->fd, client->input + client->input_off, client->input_need - client->input_off);
			if (n > 0)
			{
				client->input_off += (size_t)n;
				if (client->input_off < client->input_need)
					return;
				if (client->state == CLIENT_READ_LEN)
				{
					client->input_need = ((size_t)client->input[0] << 8) | client->input[1];
					if (client->input_need < DNS_HEADER_SIZE || client->input_need > DNS_MSG_SIZE)
					{
						dnsev_client_close(event, client);
						return;
					}
					client->input_off = 0;
					client->state = CLIENT_READ_QUERY;
					client->deadline_ms = dnsev_mono_now() + net_timeout_ms((int)event->dns->timeout);
					continue;
				}
				if ((client->input[2] & 0x80) != 0)
				{
					dnsev_client_close(event, client);
					return;
				}
				client->request = dnsev_request_new(event, REQ_TCP, client->input, client->input_need, NULL, client);
				if (!client->request)
				{
					dnsev_client_close(event, client);
					return;
				}
				client->state = CLIENT_WAIT;
				dnsev_request_start(event, client->request);
				dnsev_schedule(event);
				return;
			}
			if (n < 0 && errno == EINTR)
				continue;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				return;
			dnsev_client_close(event, client);
			return;
		}
	}
}

void dnsev_accept_clients(dns_event_t *event)
{
	for (;;)
	{
		dns_client_t *client;
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		int fd = accept(event->dns->tcp_sock, (struct sockaddr *)&peer, &peer_len);
		if (fd < 0)
		{
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				log_error("dns accept failed: %s", strerror(errno));
			return;
		}
		if ((event->dns->acl_count > 0 &&
		            !acl_allows(event->dns->acl, event->dns->acl_count,
		                    ntohl(peer.sin_addr.s_addr))) ||
		        event->client_count >= DNS_EVENT_CLIENTS || !net_set_nonblock_cloexec(fd))
		{
			(void)__atomic_fetch_add(&event->dns->tcp_refused, 1u, __ATOMIC_RELAXED);
			close(fd);
			continue;
		}
		client = calloc(1, sizeof(*client));
		if (!client)
		{
			close(fd);
			continue;
		}
		client->event = event;
		client->fd = fd;
		client->state = CLIENT_READ_LEN;
		client->input_need = 2;
		client->deadline_ms = dnsev_mono_now() + DNS_TCP_IDLE_MS;
		client->watch = (dns_watch_t){WATCH_CLIENT, client};
		if (!reactor_add(&event->re, fd, RE_IN, &client->watch))
		{
			free(client);
			close(fd);
			continue;
		}
		client->registered = 1;
		client->interest = RE_IN;
		client->next = event->clients;
		event->clients = client;
		event->client_count++;
		(void)__atomic_add_fetch(&event->dns->tcp_active, 1, __ATOMIC_RELAXED);
	}
}

void dnsev_pull_udp(dns_event_t *event)
{
	unsigned i;
	for (i = 0; i < DNS_EVENT_UDP_BURST; i++)
	{
		uint8_t query[DNS_MSG_SIZE];
		struct sockaddr_in peer;
		socklen_t plen = sizeof(peer);
		ssize_t n = recvfrom(event->dns->local_sock, query, sizeof(query), MSG_TRUNC,
		        (struct sockaddr *)&peer, &plen);
		dns_request_t *request;
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				log_error("dns recvfrom failed: %s", strerror(errno));
			return;
		}
		if (event->dns->acl_count > 0 && !acl_allows(event->dns->acl, event->dns->acl_count,
		                                         ntohl(peer.sin_addr.s_addr)))
		{
			__atomic_fetch_add(&event->dns->acl_dropped, 1u, __ATOMIC_RELAXED);
			continue;
		}
		if (!dns_rate_take(&event->dns->rate, ntohl(peer.sin_addr.s_addr), dnsev_mono_now()))
		{
			__atomic_fetch_add(&event->dns->rate_dropped, 1u, __ATOMIC_RELAXED);
			continue;
		}
		if (n < DNS_HEADER_SIZE || (size_t)n > sizeof(query) || (query[2] & 0x80) != 0)
			continue;
		request = dnsev_request_new(event, REQ_UDP, query, (size_t)n, &peer, NULL);
		if (!request)
		{
			uint8_t error[DNS_MSG_SIZE];
			size_t len = dns_build_error(query, (size_t)n, ServerFailure_ResponseType, error, sizeof(error));
			__atomic_fetch_add(&event->dns->queue_dropped, 1u, __ATOMIC_RELAXED);
			dnsev_send_udp(event, &peer, error, len);
			continue;
		}
		dnsev_request_start(event, request);
	}
	dnsev_schedule(event);
}

/*
 * Resolver connection_index: route i upstream is 1 + 2*i, its SOCKS proxy
 * 2 + 2*i. NULL for an index that names nothing.
 */
/* A waiting client has interest 0: the reactor still reports ERR and HUP. */
uint32_t dnsev_client_interest(const dns_client_t *client)
{
	if (client->state == CLIENT_WRITE)
		return RE_OUT;
	return client->state == CLIENT_WAIT ? 0 : RE_IN;
}
