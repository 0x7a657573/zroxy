/*
 * SOCKS5 server replies, parsed by the sans-IO client codec.
 *
 * The input is the byte stream a server would send. The harness plays the
 * transport: it "writes" every message the codec asks for, then hands the
 * codec exactly the number of bytes it asks to read, taken from the input in
 * order. The run ends when the codec finishes, fails, or the input runs out.
 * Every combination of offered authentication and request form is tried.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/socks5_codec.h>

#include "fuzz_common.h"

#define MAX_REPLY 4096u

static void run(const uint8_t *in, size_t size, const char *user, const char *pass,
		const char *target)
{
	socks5_client c;
	size_t off = 0;
	s5_step step;
	unsigned guard = 0;

	if (!socks5_client_init(&c, user, pass, target, 443))
		abort();
	step = socks5_client_start(&c);
	while (guard++ < 64)
	{
		if (step == S5_SEND)
		{
			if (c.out_len == 0 || c.out_len > sizeof(c.out))
				abort();
			step = socks5_client_sent(&c);
		}
		else if (step == S5_READ)
		{
			if (c.need == 0 || size - off < c.need)
				return;
			step = socks5_client_feed(&c, in + off, c.need);
			off += c.need;
		}
		else
		{
			if (step == S5_FAIL && socks5_client_strerror(&c)[0] == '\0')
				abort();
			return;
		}
	}
	abort();	/* a handshake has at most 8 steps */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char *const targets[] = { "example.com", "192.0.2.1" };
	uint8_t *in;
	size_t i;

	fuzz_init_once();
	if (size > MAX_REPLY)
		size = MAX_REPLY;
	in = fuzz_dup(data, size);

	/* Both request forms, with and without credentials to offer. */
	for (i = 0; i < sizeof(targets) / sizeof(targets[0]); i++)
	{
		run(in, size, NULL, NULL, targets[i]);
		run(in, size, "user", "pass", targets[i]);
	}
	free(in);
	return 0;
}
