/*
 * monitor.h
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#ifndef MONITOR_H_
#define MONITOR_H_
#include <stdbool.h>
#include <zroxy/statistics.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct
{
	int fd;
	uint16_t Port;
	statistics_t *state;
	pthread_mutex_t stats_lock; /* guards the state list head only */
	char *token; /* optional bearer secret; NULL disables authentication */
	int header_timeout; /* seconds to wait for a complete header */
}mon_t;

typedef struct
{
	int		 			connid;
	struct sockaddr_in	cli;
	socklen_t 			addr_len;
	mon_t 			*owner;
}monclient_t;

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec);
statistics_t *monitor_add_stat(mon_t *self,char *name);

#endif /* MONITOR_H_ */
