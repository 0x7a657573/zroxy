#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <zroxy/dnsrate.h>

static int failures;

static void expect_true(bool value, const char *name)
{
	if (!value)
	{
		fprintf(stderr, "FAIL: %s expected true\n", name);
		failures++;
	}
}

static void expect_false(bool value, const char *name)
{
	if (value)
	{
		fprintf(stderr, "FAIL: %s expected false\n", name);
		failures++;
	}
}

static void test_burst_and_refill(void)
{
	dns_rate_t rate = {0};
	int i;

	rate.qps = 5;
	for (i = 0; i < 10; i++)
		expect_true(dns_rate_take(&rate, 0x7f000001u, 1000), "full burst token accepted");
	expect_false(dns_rate_take(&rate, 0x7f000001u, 1000), "token beyond burst rejected");
	expect_false(dns_rate_take(&rate, 0x7f000001u, 1099), "partial token is not enough");
	expect_true(dns_rate_take(&rate, 0x7f000001u, 1200), "refill after 200 ms");
}

static void test_sources_and_large_time(void)
{
	dns_rate_t rate = {0};
	uint32_t second_ip = 0x7f000002u;
	uint32_t first_slot = (0x7f000001u * 2654435761u) >> 22;
	uint32_t second_slot = (second_ip * 2654435761u) >> 22;

	rate.qps = 1;
	expect_true(first_slot != second_slot, "test sources use independent slots");
	expect_true(dns_rate_take(&rate, 0x7f000001u, INT64_MAX - 2), "large time accepts burst");
	expect_true(dns_rate_take(&rate, second_ip, INT64_MAX - 2), "second source has its own burst");
	expect_true(dns_rate_take(&rate, 0x7f000001u, INT64_MAX), "large time does not overflow refill");
}

int main(void)
{
	test_burst_and_refill();
	test_sources_and_large_time();
	return failures == 0 ? 0 : 1;
}
