/*
 * dnsproxy.h
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */

#ifndef DNSPROXY_H_
#define DNSPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/config.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <zroxy/dnsserver.h>
#include <zroxy/fifo.h>
#include <zroxy/filter.h>
#include <zroxy/dnscache.h>
#include <pthread.h>

#define DNS_MSG_SIZE	512
typedef struct
{
	uint16_t len;
	char message[DNS_MSG_SIZE];
	struct sockaddr_in client;
}dnsMessage_t;


#define DNS_QUEUE_ITEM_SIZE	sizeof(dnsMessage_t)
#define DNS_QUEUE_LEN			128

/*
 * Fixed number of forwarding threads. Each handles one query at a time and
 * keeps its own upstream TCP connection open between queries.
 */
#define DNS_WORKER_COUNT	32

typedef struct dnsserver
{
	/* Fifo */
	fifo_t		  *fifo;

	/* answer cache and in-flight coalescing; NULL disables both */
	dnscache_t	  *cache;
	
	/* whitelist*/
	filter_t *whitelist;
	
	/*sni server ip*/
	uint8_t sni_ip[4];

	/*bind ip/port*/
	char 	 	  listen_addr[ZROXY_MAX_DNS_HOST + 1];
	char	 	  listen_port[ZROXY_MAX_PORT_TEXT];

	pthread_t	  workers[DNS_WORKER_COUNT];
	int			  worker_count;

	/* receive loop */
	pthread_t	  rx_thread;
	bool		  rx_started;
	int			  wake[2];

	dnsStream_t   upstream;
	sockshost_t	  *socks;
	uint32_t	  timeout;
	
	/*socket file handler*/
	int local_sock;
	statistics_t  *Stat;
}dnsserver_t;


dnsserver_t *localdns_init_config(dnshost_t *conf);
void localdns_free(dnsserver_t *dns);

bool localdns_init_sockets(dnsserver_t *dns);
bool localdns_start_workers(dnsserver_t *dns);
/* Close the queue, let workers drain it, and join them. */
void localdns_stop_workers(dnsserver_t *dns);
bool localdns_pull(dnsserver_t *dns);

/*
 * Answer one query: locally for whitelisted names, otherwise over
 * *upstream_fd (-1 = not connected), which stays open for the next call.
 */
void localdns_handle_request(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd);

#endif /* DNSPROXY_H_ */
