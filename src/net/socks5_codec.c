/*
 *
 * Sans-IO SOCKS5 client; see zroxy/socks5_codec.h.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <zroxy/net.h>
#include <zroxy/socks5_codec.h>

#define S5_MAX_FIELD 255u

enum
{
	PH_GREET_OUT = 1,
	PH_GREET_IN,
	PH_AUTH_OUT,
	PH_AUTH_IN,
	PH_REQ_OUT,
	PH_REP_HDR,
	PH_REP_LEN,
	PH_REP_REST,
	PH_DONE,
	PH_FAILED
};

const char *socks5_rep_name(uint8_t rep)
{
	switch (rep)
	{
	case 0x00: return "succeeded";
	case 0x01: return "general SOCKS server failure";
	case 0x02: return "connection not allowed by ruleset";
	case 0x03: return "network unreachable";
	case 0x04: return "host unreachable";
	case 0x05: return "connection refused";
	case 0x06: return "TTL expired";
	case 0x07: return "command not supported";
	case 0x08: return "address type not supported";
	case 0xF0: return "onion service descriptor not found";
	case 0xF1: return "onion service descriptor invalid";
	case 0xF2: return "onion service introduction failed";
	case 0xF3: return "onion service rendezvous failed";
	case 0xF4: return "onion service missing client authorization";
	case 0xF5: return "onion service wrong client authorization";
	case 0xF6: return "invalid onion service address";
	case 0xF7: return "onion service introduction timed out";
	default: return "unknown";
	}
}

static s5_step fail(socks5_client *c, s5_error error, uint8_t code)
{
	const char *why;

	c->phase = PH_FAILED;
	c->error = error;
	c->code = code;
	switch (error)
	{
	case S5_ERR_ARGS:
		snprintf(c->msg, sizeof(c->msg), "CONNECT target host or port is unusable");
		return S5_FAIL;
	case S5_ERR_VERSION:
		snprintf(c->msg, sizeof(c->msg), "greeting reply has bad version %u", (unsigned)code);
		return S5_FAIL;
	case S5_ERR_NO_METHOD:
		snprintf(c->msg, sizeof(c->msg), "replied: no acceptable authentication method");
		return S5_FAIL;
	case S5_ERR_METHOD:
		snprintf(c->msg, sizeof(c->msg), "selected unsupported method 0x%02X", (unsigned)code);
		return S5_FAIL;
	case S5_ERR_AUTH_UNOFFERED:
		snprintf(c->msg, sizeof(c->msg),
		        "selected username/password auth, which we did not offer");
		return S5_FAIL;
	case S5_ERR_CREDS:
		snprintf(c->msg, sizeof(c->msg), "username/password length rejected");
		return S5_FAIL;
	case S5_ERR_AUTH:
		snprintf(c->msg, sizeof(c->msg),
		        "rejected username/password authentication (status 0x%02X)", (unsigned)code);
		return S5_FAIL;
	case S5_ERR_REPLY_VERSION:
		snprintf(c->msg, sizeof(c->msg), "CONNECT reply has bad version %u", (unsigned)code);
		return S5_FAIL;
	case S5_ERR_REFUSED:
		why = socks5_rep_name(code);
		snprintf(c->msg, sizeof(c->msg), "refused CONNECT: reply 0x%02X (%s)",
		        (unsigned)code, why);
		return S5_FAIL;
	case S5_ERR_ATYP:
		snprintf(c->msg, sizeof(c->msg), "CONNECT reply has unsupported address type 0x%02X",
		        (unsigned)code);
		return S5_FAIL;
	case S5_ERR_NONE:
	default:
		snprintf(c->msg, sizeof(c->msg), "failed");
		return S5_FAIL;
	}
}

static bool offers_auth(const socks5_client *c)
{
	return c->user && c->pass;
}

static s5_step send_out(socks5_client *c, size_t len, int phase)
{
	c->out_len = len;
	c->phase = phase;
	return S5_SEND;
}

static s5_step read_in(socks5_client *c, size_t need, int phase)
{
	c->need = need;
	c->phase = phase;
	return S5_READ;
}

static s5_step queue_auth(socks5_client *c)
{
	size_t ulen;
	size_t plen;

	if (!offers_auth(c))
		return fail(c, S5_ERR_AUTH_UNOFFERED, 0);
	ulen = strlen(c->user);
	plen = strlen(c->pass);
	if (ulen == 0 || ulen > S5_MAX_FIELD || plen > S5_MAX_FIELD)
		return fail(c, S5_ERR_CREDS, 0);
	/* VER | ULEN | UNAME | PLEN | PASSWD */
	c->out[0] = 0x01;
	c->out[1] = (uint8_t)ulen;
	memcpy(c->out + 2, c->user, ulen);
	c->out[2 + ulen] = (uint8_t)plen;
	if (plen > 0)
		memcpy(c->out + 3 + ulen, c->pass, plen);
	return send_out(c, 3 + ulen + plen, PH_AUTH_OUT);
}

static s5_step queue_request(socks5_client *c)
{
	size_t hlen = c->host ? strlen(c->host) : 0;
	uint16_t be = htons(c->port);

	if (hlen == 0 || hlen > S5_MAX_FIELD)
		return fail(c, S5_ERR_ARGS, 0);
	/* VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT */
	c->out[0] = 0x05;
	c->out[1] = 0x01;
	c->out[2] = 0x00;
	if (net_is_ip_literal(c->host))
	{
		struct in_addr ip;

		if (inet_pton(AF_INET, c->host, &ip) != 1)
			return fail(c, S5_ERR_ARGS, 0);
		c->out[3] = 0x01;
		memcpy(c->out + 4, &ip, 4);
		memcpy(c->out + 8, &be, sizeof(be));
		return send_out(c, 10, PH_REQ_OUT);
	}
	c->out[3] = 0x03;
	c->out[4] = (uint8_t)hlen;
	memcpy(c->out + 5, c->host, hlen);
	memcpy(c->out + 5 + hlen, &be, sizeof(be));
	return send_out(c, 5 + hlen + 2, PH_REQ_OUT);
}

bool socks5_client_init(socks5_client *c, const char *user, const char *pass,
        const char *host, uint16_t port)
{
	if (!c || !host)
		return false;
	memset(c, 0, sizeof(*c));
	c->user = user;
	c->pass = pass;
	c->host = host;
	c->port = port;
	c->phase = PH_GREET_OUT;
	return true;
}

s5_step socks5_client_start(socks5_client *c)
{
	if (!c || c->phase != PH_GREET_OUT)
		return S5_FAIL;
	/* Offer user/pass only when configured: Tor picks it whenever offered. */
	c->out[0] = 0x05;
	if (offers_auth(c))
	{
		c->out[1] = 0x02;
		c->out[2] = 0x00;
		c->out[3] = 0x02;
		return send_out(c, 4, PH_GREET_OUT);
	}
	c->out[1] = 0x01;
	c->out[2] = 0x00;
	return send_out(c, 3, PH_GREET_OUT);
}

s5_step socks5_client_sent(socks5_client *c)
{
	if (!c)
		return S5_FAIL;
	switch (c->phase)
	{
	case PH_GREET_OUT: return read_in(c, 2, PH_GREET_IN);
	case PH_AUTH_OUT: return read_in(c, 2, PH_AUTH_IN);
	case PH_REQ_OUT: return read_in(c, 4, PH_REP_HDR);
	default: return fail(c, S5_ERR_NONE, 0);
	}
}

s5_step socks5_client_feed(socks5_client *c, const uint8_t *in, size_t len)
{
	if (!c || !in || len != c->need)
		return c ? fail(c, S5_ERR_NONE, 0) : S5_FAIL;
	switch (c->phase)
	{
	case PH_GREET_IN:
		if (in[0] != 5)
			return fail(c, S5_ERR_VERSION, in[0]);
		if (in[1] == 0x00)
			return queue_request(c);
		if (in[1] == 0x02)
			return queue_auth(c);
		if (in[1] == 0xFF)
			return fail(c, S5_ERR_NO_METHOD, in[1]);
		return fail(c, S5_ERR_METHOD, in[1]);
	case PH_AUTH_IN:
		if (in[1] != 0)
			return fail(c, S5_ERR_AUTH, in[1]);
		return queue_request(c);
	case PH_REP_HDR:
		if (in[0] != 5)
			return fail(c, S5_ERR_REPLY_VERSION, in[0]);
		if (in[1] != 0)
			return fail(c, S5_ERR_REFUSED, in[1]);
		if (in[3] == 0x01)
			return read_in(c, 6, PH_REP_REST);
		if (in[3] == 0x04)
			return read_in(c, 18, PH_REP_REST);
		if (in[3] == 0x03)
			return read_in(c, 1, PH_REP_LEN);
		return fail(c, S5_ERR_ATYP, in[3]);
	case PH_REP_LEN:
		return read_in(c, (size_t)in[0] + 2u, PH_REP_REST);
	case PH_REP_REST:
		c->phase = PH_DONE;
		return S5_DONE;
	default:
		return fail(c, S5_ERR_NONE, 0);
	}
}

const char *socks5_client_strerror(const socks5_client *c)
{
	return c && c->msg[0] ? c->msg : "no error";
}
