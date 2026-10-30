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
 * Port -> Port Number
 * sockfd -> Store Socket fd in this Pointer
 */
bool net_listen_ipv4(in_addr_t addr, uint16_t Port,int *sockfd);

/* connect to host
 * host -> adress of host
 * Port -> Port Number
 * sockfd -> Store Socket fd in this Pointer
 * bool -> set keepalive tcp socket
 */
bool net_connect(int *sockfd,const char *hostname, uint16_t port, int timeout_sec);

/*
 * net_get_host is smart function for extract host name from http/https packet
 */
bool net_get_host(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName);

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

bool net_get_http_host(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName);
bool net_get_https_host(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName);
bool net_enable_keepalive(int sock);
bool net_set_nonblock_cloexec(int fd);

#endif /* NET_H_ */
