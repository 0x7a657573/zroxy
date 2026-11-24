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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <zroxy/acl.h>

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

static void test_parse(void)
{
	zroxy_cidr_t acl[4];
	size_t count = 0;

	expect_true(acl_parse(" 0.0.0.0/0, 192.168.1.10/32 ", acl, 4, &count),
	        "parse /0 and /32 with spaces");
	expect_true(count == 2, "parse count");
	expect_true(acl[0].mask == 0 && acl[0].net == 0, "parse /0 values");
	expect_true(acl[1].mask == UINT32_MAX && acl[1].net == 0xc0a8010a, "parse /32 values");
	expect_false(acl_parse("192.168.1.0/33", acl, 4, &count), "reject prefix above 32");
	expect_false(acl_parse("192.168.1.0", acl, 4, &count), "reject missing prefix");
	expect_false(acl_parse("192.168.1.0/24,,10.0.0.0/8", acl, 4, &count), "reject empty entry");
	expect_false(acl_parse("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", acl, 2, &count),
	        "reject more than capacity");
}

static void test_boundaries(void)
{
	zroxy_cidr_t acl[2];
	size_t count = 0;

	expect_true(acl_parse("172.16.0.0/12,192.168.0.0/16", acl, 2, &count),
	        "parse boundary networks");
	expect_false(acl_allows(acl, count, 0xac0fffff), "reject 172.15.255.255");
	expect_true(acl_allows(acl, count, 0xac100000), "allow 172.16.0.0");
	expect_true(acl_allows(acl, count, 0xc0a8ffff), "allow 192.168.255.255");
	expect_false(acl_allows(acl, count, 0xc0a90000), "reject 192.169.0.0");
}

int main(void)
{
	test_parse();
	test_boundaries();
	return failures == 0 ? 0 : 1;
}
