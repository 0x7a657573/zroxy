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
 * net.h
 *
 *  Created on: Feb 9, 2020
 *      Author: zeus
 */

#ifndef NET_H_
#define NET_H_
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>

/* Listen ipv4
 * addr -> Ip Address For Listen
 * port -> port Number
 * sockfd -> Store Socket fd in this Pointer
 */
bool net_listen_ipv4(in_addr_t addr, uint16_t port, int *sockfd);

/*
 * net_get_host is smart function for extract host name from http/https packet
 */
bool net_get_host(uint8_t *buf, uint32_t len, char *HostName, uint16_t MaxHostName);

/*
 * Get String and check it's IP or Not
 */
bool net_is_ip_literal(const char *ipAddress);

/* set socket rx/tx timeout
 * sockfd -> socket handel
 * txTimeout -> tx timeout in sec
 * rxTimeout -> rx timeout in sec
 * 
 * return:
 * bool -> true if set timeout ok
 */

bool net_get_http_host(uint8_t *buf, uint32_t len, char *HostName, uint16_t MaxHostName);
bool net_get_https_host(uint8_t *buf, uint32_t len, char *HostName, uint16_t MaxHostName);
bool net_set_nonblock_cloexec(int fd);
bool net_set_nodelay(int fd);

#endif /* NET_H_ */
