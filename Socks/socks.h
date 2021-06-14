/*
 * socks.h
 *
 *  Created on: Feb 1, 2020
 *      Author: zeus
 */

#ifndef SOCKS_H_
#define SOCKS_H_

#include <stdint.h>
#include <stdbool.h>
#include <config.h>

typedef struct
{
	char 	host[_MaxHostName_];
	uint16_t port;
}sockshost_t;

typedef struct
{
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
}SocksReplayHeader_t;


bool socks5_connect(int *sockfd,const char *socks5_host, int socks5_port, const char *host, int port);

#endif /* SOCKS_H_ */
