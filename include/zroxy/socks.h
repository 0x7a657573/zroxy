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
#include <zroxy/socks5_codec.h>

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

#endif /* SOCKS_H_ */
