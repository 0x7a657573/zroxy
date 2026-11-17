#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>

#include <zroxy/fdlimit.h>

static int failures;

static void expect_ul(unsigned long actual, unsigned long expected, const char *name)
{
	if (actual != expected)
	{
		fprintf(stderr, "FAIL: %s expected %lu, got %lu\n", name, expected, actual);
		failures++;
	}
}

static void test_need(void)
{
	fdlimit_plan plan = { .sni_conns = 1024, .sni_listeners = 1 };

	expect_ul(fdlimit_other_need(&plan), FDLIMIT_MARGIN + FDLIMIT_PER_LISTENER, "SNI only: other need");
	expect_ul(fdlimit_needed(&plan), 2048ul + 64ul + 8ul, "SNI only: total need");

	plan.dns_enabled = true;
	plan.dns_upstreams = 96;
	plan.monitor_enabled = true;
	expect_ul(fdlimit_other_need(&plan), 64ul + 8ul + 128ul + 96ul + 32ul, "SNI, DNS and monitor: other need");

	plan.sni_listeners = 3;
	plan.dns_enabled = false;
	plan.monitor_enabled = false;
	expect_ul(fdlimit_other_need(&plan), 64ul + 24ul, "per-listener need grows");
}

static void test_cap(void)
{
	fdlimit_plan plan = { .sni_conns = 1024, .sni_listeners = 1 };
	unsigned long other = fdlimit_other_need(&plan);

	expect_ul((unsigned long)fdlimit_sni_cap(&plan, 65536), 1024, "ample limit keeps the configured cap");
	expect_ul((unsigned long)fdlimit_sni_cap(&plan, fdlimit_needed(&plan)), 1024, "exact limit keeps the cap");
	expect_ul((unsigned long)fdlimit_sni_cap(&plan, 1024), (1024ul - other) / 2ul, "1024 descriptors halve the cap");
	expect_ul((unsigned long)fdlimit_sni_cap(&plan, other + 1), 1, "one spare descriptor still allows one connection");
	expect_ul((unsigned long)fdlimit_sni_cap(&plan, other), 1, "no spare descriptor floors at one");
	expect_ul((unsigned long)fdlimit_sni_cap(&plan, 0), 1, "zero limit floors at one");
	expect_ul((unsigned long)fdlimit_sni_cap(&plan, other + 5), 2, "odd spare descriptors round down");
}

static void test_apply(void)
{
	fdlimit_plan plan = { .sni_conns = 100, .sni_listeners = 1 };
	struct rlimit before;
	struct rlimit lim;
	int cap = 0;

	if (getrlimit(RLIMIT_NOFILE, &before) != 0)
		return;
	/* A hard limit just under the need: the cap must shrink, never fail. */
	lim = before;
	lim.rlim_cur = 150;
	lim.rlim_max = 150;
	if (setrlimit(RLIMIT_NOFILE, &lim) == 0)
	{
		unsigned long soft = fdlimit_apply(&plan, &cap);
		expect_ul(soft, 150, "soft limit stays at the hard limit");
		expect_ul((unsigned long)cap, (150ul - fdlimit_other_need(&plan)) / 2ul, "cap shrinks to the limit");
		lim.rlim_cur = 120;
		if (setrlimit(RLIMIT_NOFILE, &lim) == 0)
		{
			soft = fdlimit_apply(&plan, &cap);
			expect_ul(soft, 150, "soft limit is raised up to the hard limit");
			expect_ul((unsigned long)cap, (150ul - fdlimit_other_need(&plan)) / 2ul, "cap follows the raised limit");
		}
	}
	/* The hard limit can not be raised again without privilege; the test ends here. */
}

int main(void)
{
	test_need();
	test_cap();
	test_apply();
	return failures == 0 ? 0 : 1;
}
