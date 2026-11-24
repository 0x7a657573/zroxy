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
 *
 * Sans-IO SOCKS5 client (RFC 1928 CONNECT, RFC 1929 username/password).
 *
 * The codec owns no descriptor and makes no system call. It follows one
 * pattern: write a whole message, then read exactly `need` bytes. The caller
 * performs the I/O, with whatever partial-I/O handling its loop needs:
 *
 *   step = socks5_client_start(&c);
 *   for (;;) {
 *       S5_SEND: write c.out[0..out_len), then step = socks5_client_sent(&c)
 *       S5_READ: read exactly c.need bytes, then step = socks5_client_feed(&c, in, c.need)
 *       S5_DONE: the tunnel is open
 *       S5_FAIL: log socks5_client_strerror(&c) and close
 *   }
 *
 * user, pass and host are borrowed and must outlive the handshake.
 */

#ifndef SOCKS5_CODEC_H_
#define SOCKS5_CODEC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define S5_OUT_MAX 600u

typedef enum
{
	S5_SEND,
	S5_READ,
	S5_DONE,
	S5_FAIL
} s5_step;

typedef enum
{
	S5_ERR_NONE,
	S5_ERR_ARGS,
	S5_ERR_VERSION,
	S5_ERR_NO_METHOD,
	S5_ERR_METHOD,
	S5_ERR_AUTH_UNOFFERED,
	S5_ERR_CREDS,
	S5_ERR_AUTH,
	S5_ERR_REPLY_VERSION,
	S5_ERR_REFUSED,
	S5_ERR_ATYP
} s5_error;

typedef struct
{
	int phase;        /* private */
	const char *user; /* borrowed; both needed to offer auth */
	const char *pass;
	const char *host; /* target: name or IPv4 literal */
	uint16_t port;
	uint8_t out[S5_OUT_MAX]; /* valid after S5_SEND */
	size_t out_len;
	size_t need;    /* valid after S5_READ */
	s5_error error; /* valid after S5_FAIL */
	uint8_t code;   /* offending byte: version, method, status, rep or atyp */
	char msg[112];
} socks5_client;

/* Name of a SOCKS5 reply code (RFC 1928 REP, plus Tor's extended codes), for logs. */
const char *socks5_rep_name(uint8_t rep);

/* user and pass may be NULL; auth is offered only when both are set. */
bool socks5_client_init(socks5_client *c, const char *user, const char *pass,
        const char *host, uint16_t port);
s5_step socks5_client_start(socks5_client *c);
s5_step socks5_client_sent(socks5_client *c);
s5_step socks5_client_feed(socks5_client *c, const uint8_t *in, size_t len);

/* Names the failing step and reply code, e.g. "refused CONNECT: reply 0x05 (...)". */
const char *socks5_client_strerror(const socks5_client *c);

#endif /* SOCKS5_CODEC_H_ */
