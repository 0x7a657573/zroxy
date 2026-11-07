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
#include <zroxy/config.h>

typedef struct
{
	char 	*host;
	uint16_t port;
	char	*user;
	char	*pass;
}sockshost_t;

typedef struct
{
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
}SocksReplayHeader_t;

typedef struct
{
	uint8_t ver;
	uint8_t status;
}SocksAuthenticationReplay_t;

/* Name of a SOCKS5 reply code (RFC 1928 REP, plus Tor's extended codes), for logs. */
const char *socks5_rep_name(uint8_t rep);

bool socks5_connect(int *sockfd,sockshost_t *socks, const char *host, int port,bool keepalive, int timeout_sec);

#endif /* SOCKS_H_ */
