#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zroxy/dnsproxy.h>

static int failures;

static void expect_true(bool value, const char *name)
{
	if (!value)
	{
		fprintf(stderr, "FAIL: %s\n", name);
		failures++;
	}
}

static void expect_u32(uint32_t actual, uint32_t expected, const char *name)
{
	if (actual != expected)
	{
		fprintf(stderr, "FAIL: %s expected %u, got %u\n", name, expected, actual);
		failures++;
	}
}

int main(void)
{
	log_throttle_t throttle = {0};
	uint32_t dropped = 99;

	expect_true(dnsproxy_test_throttle_take(&throttle, 1000, 1000, &dropped),
			"first throttle call logs");
	expect_u32(dropped, 0, "first call has no suppressed messages");
	expect_true(!dnsproxy_test_throttle_take(&throttle, 1001, 1000, &dropped),
			"same-second call is suppressed");
	expect_true(!dnsproxy_test_throttle_take(&throttle, 1999, 1000, &dropped),
			"last in-window call is suppressed");
	expect_true(dnsproxy_test_throttle_take(&throttle, 2000, 1000, &dropped),
			"next window logs");
	expect_u32(dropped, 2, "next window reports suppressed messages");
	expect_true(dnsproxy_test_throttle_take(&throttle, 3000, 1000, &dropped),
			"empty window logs");
	expect_u32(dropped, 0, "empty window has no suppressed messages");

	/* Long uptime: the low 32 bits of the clock have the top bit set. */
	memset(&throttle, 0, sizeof(throttle));
	expect_true(dnsproxy_test_throttle_take(&throttle, 3000000000LL, 1000, &dropped),
			"fresh throttle logs after long uptime");
	expect_true(!dnsproxy_test_throttle_take(&throttle, 3000000500LL, 1000, &dropped),
			"long uptime still throttles within the window");

	/* Silence longer than 2^31 ms must not look like a time in the future. */
	memset(&throttle, 0, sizeof(throttle));
	expect_true(dnsproxy_test_throttle_take(&throttle, 1000, 1000, &dropped),
			"log before a long quiet period");
	expect_true(dnsproxy_test_throttle_take(&throttle, 1000 + 2592000000LL, 1000, &dropped),
			"first message after 30 quiet days logs");

	/* Across the 32-bit wrap of the clock. */
	memset(&throttle, 0, sizeof(throttle));
	expect_true(dnsproxy_test_throttle_take(&throttle, (int64_t)UINT32_MAX - 200, 1000, &dropped),
			"log just before the 32-bit wrap");
	expect_true(!dnsproxy_test_throttle_take(&throttle, (int64_t)UINT32_MAX + 300, 1000, &dropped),
			"wrap does not reopen the window early");
	expect_true(dnsproxy_test_throttle_take(&throttle, (int64_t)UINT32_MAX + 1300, 1000, &dropped),
			"window reopens after the wrap");
	expect_u32(dropped, 1, "suppressed count survives the wrap");

	/* A clock value whose low 32 bits are 0 is not mistaken for "never logged". */
	memset(&throttle, 0, sizeof(throttle));
	expect_true(dnsproxy_test_throttle_take(&throttle, 4294967296LL, 1000, &dropped),
			"log at a zero low word");
	expect_true(!dnsproxy_test_throttle_take(&throttle, 4294967296LL + 10, 1000, &dropped),
			"zero low word still throttles");
	return failures == 0 ? 0 : 1;
}
