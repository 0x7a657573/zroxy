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
	char *host;
	uint16_t port;
	char *user;
	char *pass;
} sockshost_t;

typedef struct
{
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
} SocksReplayHeader_t;

typedef struct
{
	uint8_t ver;
	uint8_t status;
} SocksAuthenticationReplay_t;

#endif /* SOCKS_H_ */
