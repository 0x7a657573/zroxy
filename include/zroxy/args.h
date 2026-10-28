/*
 * pargs.h
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */

#ifndef ARGS_H_
#define ARGS_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/sniproxy.h>
#include <zroxy/dnsserver.h>

#define DEF_CONFIG_PATH	"zroxy.conf"

typedef struct
{
	lport_t 	*ports;
	sockshost_t *socks;
	uint16_t	*monitorPort;
	char		monitor_bind[ZROXY_MAX_IP_TEXT];
	char		*monitor_token;
	int			monitor_header_timeout;
	char 		*WhitePath;
	dnshost_t	*dnsserver;
	int			snitimeout;
}zroxy_t;

bool args_init(zroxy_t *pgp,int argc, const char **argv);
void args_print_usage(void);
void args_free_ports(zroxy_t *ptr);
void args_free_dns(zroxy_t *ptr);


#endif /* ARGS_H_ */
