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
 * pargs.h
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */

#ifndef ARGS_H_
#define ARGS_H_
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <zroxy/settings.h>

#define DEF_CONFIG_PATH "zroxy.conf"

typedef struct
{
	lport_t *ports;
	sockshost_t *socks;
	uint16_t monitor_port;
	char monitor_bind[ZROXY_MAX_IP_TEXT];
	char *monitor_token;
	char *monitor_token_file;
	char *socks_pass_file;
	char *dsocks_pass_file;
	int monitor_header_timeout;
	char *whitelist_path;
	dnshost_t *dnsserver;
	int snitimeout;
	int sniidletimeout;
	int snimaxconn;
	zroxy_cidr_t *sacl;
	size_t sacl_count;
	bool allow_loopback;
	bool deny_private;
	bool open_proxy;
	char *run_user;
	char *run_group;
	bool drop_priv; /* set by args_validate: switch to drop_uid/drop_gid */
	uid_t drop_uid;
	gid_t drop_gid;
} zroxy_t;

bool args_init(zroxy_t *pgp, int argc, const char **argv);
bool args_validate(zroxy_t *pgp);
/* Parse the config file at str into ptr; false on any error. */
bool args_parse_config(zroxy_t *ptr, char *str);
void args_print_usage(void);
/* Free everything the parser allocated; safe after the partial frees below. */
void args_free(zroxy_t *ptr);
void args_free_ports(zroxy_t *ptr);
void args_free_dns(zroxy_t *ptr);
void args_free_sacl(zroxy_t *ptr);
void args_free_socks(zroxy_t *ptr);
void args_free_monitor_token(zroxy_t *ptr);
void args_scrub_argv(void);

#endif /* ARGS_H_ */
