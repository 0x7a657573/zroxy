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
	return failures == 0 ? 0 : 1;
}
