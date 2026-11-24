/*
 * socks_client.c - blocking SOCKS5 client, used by tests only.
 *
 *  Created on: Feb 1, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <unistd.h> /*Header file for sleep(). man 3 sleep for details.*/
#include <zroxy/log.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <zroxy/socks.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>
#include "test_support.h"

#define SOCKS_MAX_IDENT 255

static void socks5_close(int *sockfd)
{
	if (sockfd && *sockfd >= 0)
	{
		close(*sockfd);
		*sockfd = -1;
	}
}

bool socks5_connect(int *sockfd, sockshost_t *socks, const char *host, int port, int timeout_sec)
{
	int io_ms;
	char *socks5_host;
	uint8_t reply[SOCKS_MAX_IDENT + 2];
	socks5_client client;
	s5_step step;

	if (!sockfd || !socks || !socks->host || !host || host[0] == '\0')
		return false;

	*sockfd = -1;
	if (port < 0 || port > 65535 ||
	        !socks5_client_init(&client, socks->user, socks->pass, host, (uint16_t)port))
		return false;
	io_ms = net_timeout_ms(timeout_sec);
	socks5_host = socks->host;

	/*if host is domain need resolve domain*/
	if (!net_connect(sockfd, socks5_host, socks->port, timeout_sec))
	{
		log_error("Socks Error: Connect to %s Failed", socks5_host);
		socks5_close(sockfd);
		return false;
	}

	/* The codec says what to write and how much to read; this loop does the I/O. */
	step = socks5_client_start(&client);
	while (step == S5_SEND || step == S5_READ)
	{
		if (step == S5_SEND)
		{
			if (!net_write_all_ms(*sockfd, client.out, client.out_len, io_ms))
			{
				log_error("[!] Error writing SOCKS handshake to %s", socks5_host);
				socks5_close(sockfd);
				return false;
			}
			step = socks5_client_sent(&client);
		}
		else
		{
			if (client.need > sizeof(reply) ||
			        !net_read_exact_ms(*sockfd, reply, client.need, io_ms))
			{
				log_error("[!] Error reading SOCKS handshake from %s", socks5_host);
				socks5_close(sockfd);
				return false;
			}
			step = socks5_client_feed(&client, reply, client.need);
		}
	}

	if (step != S5_DONE)
	{
		log_error("[!] SOCKS server %s:%u: %s", socks5_host, (unsigned)socks->port,
		        socks5_client_strerror(&client));
		socks5_close(sockfd);
		return false;
	}
	return true;
}
