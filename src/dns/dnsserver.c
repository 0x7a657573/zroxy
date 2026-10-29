/*
 * DnsServer.c
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */
#include <zroxy/dnsserver.h>

#include <zroxy/log.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <zroxy/dnsproxy.h>

/* Wait for a datagram or a stop request; hand datagrams to the queue. */
static void *dnsserver_receive_loop(void *arg)
{
	dnsserver_t *dns = (dnsserver_t *)arg;
	struct pollfd fds[3];

	fds[0].fd = dns->local_sock;
	fds[0].events = POLLIN;
	fds[1].fd = dns->wake[0];
	fds[1].events = POLLIN;
	/* poll ignores a negative descriptor, so a missing listener is skipped. */
	fds[2].fd = dns->tcp_sock;
	fds[2].events = POLLIN;

	for (;;)
	{
		fds[0].revents = 0;
		fds[1].revents = 0;
		fds[2].revents = 0;
		if (poll(fds, 3, -1) < 0)
		{
			if (errno == EINTR)
				continue;
			log_error("dns receive poll failed");
			break;
		}
		if (fds[1].revents || (fds[0].revents & POLLNVAL))
			break;
		if (fds[0].revents && !localdns_pull(dns))
			break;
		if (fds[2].revents & POLLIN)
			localdns_accept(dns);
	}
	return NULL;
}

struct dnsserver *dnsserver_start(dnshost_t *conf)
{
	dnsserver_t *dns = localdns_init_config(conf);
	if(!dns)
	{
		log_error("dns server config error...");
		return NULL;
	}

	if(!localdns_init_sockets(dns))
	{
		log_error("dns server socket error.");
		localdns_free(dns);
		return NULL;
	}

	if (!localdns_init_tcp(dns))
		log_error("dns TCP listener unavailable; truncated replies cannot be retried over TCP");

	if (pipe(dns->wake) != 0)
	{
		log_error("dns server wake pipe failed");
		localdns_free(dns);
		return NULL;
	}
	(void)fcntl(dns->wake[0], F_SETFD, FD_CLOEXEC);
	(void)fcntl(dns->wake[1], F_SETFD, FD_CLOEXEC);

	if(!localdns_start_workers(dns))
	{
		log_error("dns server worker error.");
		localdns_free(dns);
		return NULL;
	}

	if (pthread_create(&dns->rx_thread, NULL, dnsserver_receive_loop, dns) != 0)
	{
		log_error("dns server thread create failed");
		localdns_stop_workers(dns);
		localdns_free(dns);
		return NULL;
	}
	dns->rx_started = true;

	log_info("dns server start on %s:%d",conf->Local.ip,conf->Local.port);
	return dns;
}

void dnsserver_stop(struct dnsserver *dns)
{
	char byte = 1;
	ssize_t n;

	if (!dns)
		return;
	if (dns->rx_started)
	{
		do {
			n = write(dns->wake[1], &byte, 1);
		} while (n < 0 && errno == EINTR);
		pthread_join(dns->rx_thread, NULL);
		dns->rx_started = false;
	}
	localdns_stop_workers(dns);
	localdns_free(dns);
	log_info("dns server stopped");
}
