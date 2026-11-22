#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zroxy/socks5_codec.h>

static int failures = 0;

static void expect(bool value, const char *name)
{
	if (!value)
	{
		fprintf(stderr, "FAIL: %s\n", name);
		failures++;
	}
}

static void expect_step(s5_step got, s5_step want, const char *name)
{
	if (got != want)
	{
		fprintf(stderr, "FAIL: %s: step %d, want %d\n", name, (int)got, (int)want);
		failures++;
	}
}

static s5_step feed(socks5_client *c, const void *in, size_t len)
{
	return socks5_client_feed(c, (const uint8_t *)in, len);
}

/* Greeting round trip, ending with the connect request queued. */
static void greet(socks5_client *c, const uint8_t *method_reply, s5_step want, const char *name)
{
	expect_step(socks5_client_start(c), S5_SEND, name);
	expect_step(socks5_client_sent(c), S5_READ, name);
	expect(c->need == 2, name);
	expect_step(feed(c, method_reply, 2), want, name);
}

static void test_greeting(void)
{
	socks5_client c;
	static const uint8_t noauth[] = {5, 1, 0};
	static const uint8_t withauth[] = {5, 2, 0, 2};

	expect(socks5_client_init(&c, NULL, NULL, "example.com", 443), "init");
	expect_step(socks5_client_start(&c), S5_SEND, "greeting without auth");
	expect(c.out_len == 3 && memcmp(c.out, noauth, 3) == 0, "greeting without auth bytes");

	expect(socks5_client_init(&c, "user", "pass", "example.com", 443), "init auth");
	expect_step(socks5_client_start(&c), S5_SEND, "greeting with auth");
	expect(c.out_len == 4 && memcmp(c.out, withauth, 4) == 0, "greeting with auth bytes");

	/* Auth is offered only when both user and pass are configured. */
	expect(socks5_client_init(&c, "user", NULL, "example.com", 443), "init user only");
	expect_step(socks5_client_start(&c), S5_SEND, "user only");
	expect(c.out_len == 3, "user only offers no auth");
	expect(socks5_client_init(&c, NULL, "pass", "example.com", 443), "init pass only");
	expect_step(socks5_client_start(&c), S5_SEND, "pass only");
	expect(c.out_len == 3, "pass only offers no auth");

	expect(!socks5_client_init(&c, NULL, NULL, NULL, 443), "NULL host rejected");
}

static void test_greeting_errors(void)
{
	socks5_client c;
	static const uint8_t bad_ver[] = {4, 0};
	static const uint8_t none[] = {5, 0xFF};
	static const uint8_t gssapi[] = {5, 1};
	static const uint8_t unoffered[] = {5, 2};

	socks5_client_init(&c, NULL, NULL, "example.com", 443);
	greet(&c, bad_ver, S5_FAIL, "bad greeting version");
	expect(c.error == S5_ERR_VERSION && c.code == 4, "bad greeting version error");

	socks5_client_init(&c, NULL, NULL, "example.com", 443);
	greet(&c, none, S5_FAIL, "no acceptable method");
	expect(c.error == S5_ERR_NO_METHOD, "no acceptable method error");

	socks5_client_init(&c, NULL, NULL, "example.com", 443);
	greet(&c, gssapi, S5_FAIL, "unsupported method");
	expect(c.error == S5_ERR_METHOD && c.code == 1, "unsupported method error");
	expect(strstr(socks5_client_strerror(&c), "0x01") != NULL, "unsupported method text");

	socks5_client_init(&c, NULL, NULL, "example.com", 443);
	greet(&c, unoffered, S5_FAIL, "method 2 not offered");
	expect(c.error == S5_ERR_AUTH_UNOFFERED, "method 2 not offered error");

	/* One half of the credentials is not an offer either. */
	socks5_client_init(&c, "user", NULL, "example.com", 443);
	greet(&c, unoffered, S5_FAIL, "method 2 with user only");
	expect(c.error == S5_ERR_AUTH_UNOFFERED, "method 2 with user only error");
}

static void test_auth(void)
{
	socks5_client c;
	static const uint8_t method2[] = {5, 2};
	static const uint8_t ok[] = {1, 0};
	static const uint8_t bad[] = {1, 1};
	static const uint8_t packet[] = {1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'};

	socks5_client_init(&c, "user", "pass", "example.com", 443);
	greet(&c, method2, S5_SEND, "auth sent");
	expect(c.out_len == sizeof(packet) && memcmp(c.out, packet, sizeof(packet)) == 0,
	        "auth packet bytes");
	expect_step(socks5_client_sent(&c), S5_READ, "auth written");
	expect(c.need == 2, "auth reply size");
	expect_step(feed(&c, ok, 2), S5_SEND, "auth accepted queues request");
	expect(c.out[0] == 5 && c.out[1] == 1 && c.out[3] == 3, "request follows auth");

	socks5_client_init(&c, "user", "pass", "example.com", 443);
	greet(&c, method2, S5_SEND, "auth sent again");
	socks5_client_sent(&c);
	expect_step(feed(&c, bad, 2), S5_FAIL, "auth rejected");
	expect(c.error == S5_ERR_AUTH && c.code == 1, "auth rejected error");
	expect(strstr(socks5_client_strerror(&c), "0x01") != NULL, "auth rejected text");

	/* Empty password is legal; empty user is not. */
	socks5_client_init(&c, "user", "", "example.com", 443);
	greet(&c, method2, S5_SEND, "empty password");
	expect(c.out_len == 3 + 4 && c.out[6] == 0, "empty password packet");
	socks5_client_init(&c, "", "pass", "example.com", 443);
	greet(&c, method2, S5_FAIL, "empty user");
	expect(c.error == S5_ERR_CREDS, "empty user error");
}

static void test_long_credentials(void)
{
	socks5_client c;
	static const uint8_t method2[] = {5, 2};
	char big[257];
	char max[256];

	memset(big, 'a', 256);
	big[256] = '\0';
	memset(max, 'a', 255);
	max[255] = '\0';

	socks5_client_init(&c, big, "pass", "example.com", 443);
	greet(&c, method2, S5_FAIL, "over-long user");
	expect(c.error == S5_ERR_CREDS, "over-long user error");
	socks5_client_init(&c, "user", big, "example.com", 443);
	greet(&c, method2, S5_FAIL, "over-long pass");
	expect(c.error == S5_ERR_CREDS, "over-long pass error");
	socks5_client_init(&c, max, max, "example.com", 443);
	greet(&c, method2, S5_SEND, "maximum user and pass");
	expect(c.out_len == 3 + 255 + 255, "maximum auth packet size");
}

static void test_request(void)
{
	socks5_client c;
	static const uint8_t method0[] = {5, 0};
	static const uint8_t domain[] = {5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	        0x01, 0xBB};
	static const uint8_t ipv4[] = {5, 1, 0, 1, 192, 0, 2, 1, 0x1F, 0x90};
	char host[300];

	socks5_client_init(&c, NULL, NULL, "example.com", 443);
	greet(&c, method0, S5_SEND, "domain request");
	expect(c.out_len == sizeof(domain) && memcmp(c.out, domain, sizeof(domain)) == 0,
	        "domain request bytes");

	socks5_client_init(&c, NULL, NULL, "192.0.2.1", 8080);
	greet(&c, method0, S5_SEND, "ipv4 request");
	expect(c.out_len == sizeof(ipv4) && memcmp(c.out, ipv4, sizeof(ipv4)) == 0,
	        "ipv4 request bytes");

	memset(host, 'h', 255);
	host[255] = '\0';
	socks5_client_init(&c, NULL, NULL, host, 443);
	greet(&c, method0, S5_SEND, "maximum host");
	expect(c.out_len == 5 + 255 + 2, "maximum host request size");

	host[255] = 'h';
	host[256] = '\0';
	socks5_client_init(&c, NULL, NULL, host, 443);
	greet(&c, method0, S5_FAIL, "over-long host");
	expect(c.error == S5_ERR_ARGS, "over-long host error");

	socks5_client_init(&c, NULL, NULL, "", 443);
	greet(&c, method0, S5_FAIL, "empty host");
	expect(c.error == S5_ERR_ARGS, "empty host error");
}

/* Drive the codec to the connect-reply header with a no-auth server. */
static void to_reply(socks5_client *c)
{
	static const uint8_t method0[] = {5, 0};

	socks5_client_init(c, NULL, NULL, "example.com", 443);
	greet(c, method0, S5_SEND, "to reply");
	expect_step(socks5_client_sent(c), S5_READ, "request written");
	expect(c->need == 4, "reply header size");
}

static void test_reply(void)
{
	socks5_client c;
	static const uint8_t v4[] = {5, 0, 0, 1};
	static const uint8_t v6[] = {5, 0, 0, 4};
	static const uint8_t dom[] = {5, 0, 0, 3};
	static const uint8_t refused[] = {5, 5, 0, 1};
	static const uint8_t bad_ver[] = {4, 0, 0, 1};
	static const uint8_t bad_atyp[] = {5, 0, 0, 9};
	static const uint8_t zeros[32] = {0};
	static const uint8_t len7[] = {7};

	to_reply(&c);
	expect_step(feed(&c, v4, 4), S5_READ, "ipv4 reply header");
	expect(c.need == 6, "ipv4 bound address and port");
	expect_step(feed(&c, zeros, 6), S5_DONE, "ipv4 reply done");

	to_reply(&c);
	expect_step(feed(&c, v6, 4), S5_READ, "ipv6 reply header");
	expect(c.need == 18, "ipv6 bound address and port");
	expect_step(feed(&c, zeros, 18), S5_DONE, "ipv6 reply done");

	to_reply(&c);
	expect_step(feed(&c, dom, 4), S5_READ, "domain reply header");
	expect(c.need == 1, "domain length byte");
	expect_step(feed(&c, len7, 1), S5_READ, "domain length");
	expect(c.need == 9, "domain name and port");
	expect_step(feed(&c, zeros, 9), S5_DONE, "domain reply done");

	to_reply(&c);
	expect_step(feed(&c, dom, 4), S5_READ, "empty domain reply header");
	expect_step(feed(&c, zeros, 1), S5_READ, "empty domain length");
	expect(c.need == 2, "empty domain keeps the port");

	to_reply(&c);
	expect_step(feed(&c, refused, 4), S5_FAIL, "refused");
	expect(c.error == S5_ERR_REFUSED && c.code == 5, "refused error");
	expect(strstr(socks5_client_strerror(&c), "0x05") != NULL, "refused text has the code");
	expect(strstr(socks5_client_strerror(&c), socks5_rep_name(5)) != NULL,
	        "refused text has the name");

	to_reply(&c);
	expect_step(feed(&c, bad_ver, 4), S5_FAIL, "bad reply version");
	expect(c.error == S5_ERR_REPLY_VERSION && c.code == 4, "bad reply version error");

	to_reply(&c);
	expect_step(feed(&c, bad_atyp, 4), S5_FAIL, "bad atyp");
	expect(c.error == S5_ERR_ATYP && c.code == 9, "bad atyp error");
	expect(strstr(socks5_client_strerror(&c), "0x09") != NULL, "bad atyp text");
}

static void test_misuse(void)
{
	socks5_client c;
	static const uint8_t two[] = {5, 0};

	to_reply(&c);
	feed(&c, (const uint8_t[]){5, 0, 0, 1}, 4);
	feed(&c, (const uint8_t[6]){0}, 6);
	expect_step(socks5_client_sent(&c), S5_FAIL, "sent after done");

	socks5_client_init(&c, NULL, NULL, "example.com", 443);
	socks5_client_start(&c);
	socks5_client_sent(&c);
	expect_step(feed(&c, two, 1), S5_FAIL, "short feed");

	expect(strlen(socks5_rep_name(0x00)) > 0 && strcmp(socks5_rep_name(0xEE), "unknown") == 0,
	        "rep names");
}

int main(void)
{
	test_greeting();
	test_greeting_errors();
	test_auth();
	test_long_credentials();
	test_request();
	test_reply();
	test_misuse();
	if (failures)
	{
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	return 0;
}
