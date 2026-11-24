#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zroxy/dns.h>
#include <zroxy/log.h>

static int failures = 0;

static void expect_true(bool value, const char *name)
{
	if (!value)
	{
		fprintf(stderr, "FAIL: %s expected true\n", name);
		failures++;
	}
}

static void expect_u16(uint16_t actual, uint16_t expected, const char *name)
{
	if (actual != expected)
	{
		fprintf(stderr, "FAIL: %s expected %u, got %u\n", name, expected, actual);
		failures++;
	}
}

static void expect_u8(uint8_t actual, uint8_t expected, const char *name)
{
	if (actual != expected)
	{
		fprintf(stderr, "FAIL: %s expected 0x%02x, got 0x%02x\n", name, expected, actual);
		failures++;
	}
}

static void expect_string(const char *actual, const char *expected, const char *name)
{
	if (strcmp(actual, expected) != 0)
	{
		fprintf(stderr, "FAIL: %s expected '%s', got '%s'\n", name, expected, actual);
		failures++;
	}
}

static const uint8_t k_query_example_com[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01};

static void put_query_header(uint8_t *pkt, uint16_t qdcount)
{
	memset(pkt, 0, 12);
	pkt[2] = 0x01;
	pkt[4] = (uint8_t)(qdcount >> 8);
	pkt[5] = (uint8_t)qdcount;
}

static void test_question_name(void)
{
	char name[256];
	uint8_t pkt[512];
	uint8_t short_header[11] = {0};

	expect_true(dns_question_name(k_query_example_com, sizeof(k_query_example_com), name,
	                    sizeof(name)),
	        "question name basic");
	expect_string(name, "example.com", "question name text");
	memcpy(pkt, k_query_example_com, sizeof(k_query_example_com));
	pkt[13] = 'E';
	pkt[14] = 'x';
	pkt[15] = 'A';
	pkt[16] = 'm';
	pkt[17] = 'p';
	pkt[18] = 'l';
	pkt[19] = 'e';
	pkt[21] = 'C';
	memset(name, 0, sizeof(name));
	expect_true(dns_question_name(pkt, sizeof(k_query_example_com), name, sizeof(name)),
	        "question name preserves case");
	expect_string(name, "ExAmple.Com", "question name case");
	expect_true(!dns_question_name(short_header, sizeof(short_header), name, sizeof(name)),
	        "question name rejects short header");
	memcpy(pkt, k_query_example_com, sizeof(k_query_example_com));
	pkt[5] = 0;
	expect_true(!dns_question_name(pkt, sizeof(k_query_example_com), name, sizeof(name)),
	        "question name rejects zero qdcount");
	pkt[5] = 2;
	expect_true(!dns_question_name(pkt, sizeof(k_query_example_com), name, sizeof(name)),
	        "question name rejects multiple questions");
	memcpy(pkt, k_query_example_com, sizeof(k_query_example_com));
	pkt[12] = 8;
	expect_true(!dns_question_name(pkt, sizeof(k_query_example_com), name, sizeof(name)),
	        "question name rejects truncated label");
	pkt[12] = 0xc0;
	pkt[13] = 0x0c;
	expect_true(!dns_question_name(pkt, sizeof(k_query_example_com), name, sizeof(name)),
	        "question name rejects compression pointer");
	memset(pkt, 0, sizeof(pkt));
	put_query_header(pkt, 1);
	pkt[14] = 1;
	pkt[15] = 0;
	pkt[16] = 1;
	expect_true(!dns_question_name(pkt, 17, name, sizeof(name)), "question name rejects root");
	pkt[12] = 0x40;
	expect_true(!dns_question_name(pkt, 17, name, sizeof(name)),
	        "question name rejects reserved label type 40");
	pkt[12] = 0x80;
	expect_true(!dns_question_name(pkt, 17, name, sizeof(name)),
	        "question name rejects reserved label type 80");
	expect_true(!dns_question_name(k_query_example_com, sizeof(k_query_example_com), name, 11),
	        "question name rejects small capacity");
}

static size_t make_max_name_query(uint8_t *pkt)
{
	size_t pos = 12;
	unsigned i;

	put_query_header(pkt, 1);
	for (i = 0; i < 4; i++)
	{
		unsigned len = i == 3 ? 61 : 63;
		pkt[pos++] = (uint8_t)len;
		memset(pkt + pos, (int)('a' + i), len);
		pos += len;
	}
	pkt[pos++] = 0;
	pkt[pos++] = 0;
	pkt[pos++] = 1;
	pkt[pos++] = 0;
	pkt[pos++] = 1;
	return pos;
}

static void test_build_local_answer(void)
{
	static const uint8_t addr[4] = {192, 0, 2, 10};
	static const uint8_t expected_a[] = {
	        0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01,
	        0x00, 0x00, 0x00, 0x00,
	        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	        0x00, 0x01, 0x00, 0x01,
	        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
	        192, 0, 2, 10};
	static const uint8_t expected_soa[] = {
	        0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x00,
	        0x00, 0x01, 0x00, 0x00,
	        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	        0x00, 0x1c, 0x00, 0x01,
	        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x18,
	        0xc0, 0x0c, 0xc0, 0x0c,
	        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x02, 0x58,
	        0x00, 0x01, 0x51, 0x80, 0x00, 0x00, 0x00, 0x3c};
	uint8_t query[512];
	uint8_t out[512];
	uint8_t opt_query[sizeof(k_query_example_com) + 11];
	size_t n;

	n = dns_build_local_answer(k_query_example_com, sizeof(k_query_example_com), addr, 300, out,
	        sizeof(out));
	expect_u16((uint16_t)n, (uint16_t)sizeof(expected_a), "local A answer length");
	expect_true(memcmp(out, expected_a, sizeof(expected_a)) == 0, "local A answer exact bytes");

	memcpy(query, k_query_example_com, sizeof(k_query_example_com));
	query[25] = 0;
	query[26] = AAAA_Resource_RecordType;
	n = dns_build_local_answer(query, sizeof(k_query_example_com), addr, 60, out, sizeof(out));
	expect_u16((uint16_t)n, (uint16_t)sizeof(expected_soa), "local SOA answer length");
	expect_true(memcmp(out, expected_soa, sizeof(expected_soa)) == 0,
	        "local SOA answer exact bytes");

	memcpy(query, k_query_example_com, sizeof(k_query_example_com));
	query[28] = 3;
	n = dns_build_local_answer(query, sizeof(k_query_example_com), addr, 60, out, sizeof(out));
	expect_true(n == sizeof(expected_soa), "CH query gets SOA authority");

	memcpy(opt_query, k_query_example_com, sizeof(k_query_example_com));
	opt_query[11] = 1;
	memcpy(opt_query + sizeof(k_query_example_com),
	        (const uint8_t[]){0, 0, 0x29, 0x02, 0x00, 0, 0, 0, 0, 0, 0}, 11);
	n = dns_build_local_answer(opt_query, sizeof(opt_query), addr, 300, out, sizeof(out));
	expect_true(n == sizeof(expected_a) && out[11] == 0, "local answer drops OPT");
	expect_true(dns_build_local_answer(k_query_example_com, sizeof(k_query_example_com), addr, 300,
	                    out, sizeof(expected_a) - 1) == 0,
	        "local answer respects capacity");

	n = make_max_name_query(query);
	expect_true(dns_question_name(query, n, (char *)out, 256), "maximum wire name fits");
	expect_true(dns_build_local_answer(query, n, addr, 300, out, sizeof(out)) > 0,
	        "maximum wire name answer fits");
	query[12] = 5;
	query[13] = 'a';
	expect_true(dns_build_local_answer(query, n, addr, 300, out, sizeof(out)) == 0,
	        "malformed local query returns zero");
}

static void test_wire_error_and_truncation(void)
{
	uint8_t out[64];
	uint8_t garbage[16];
	uint8_t resp[sizeof(k_query_example_com) + 16];
	size_t n;

	n = dns_build_error(k_query_example_com, sizeof(k_query_example_com),
	        ServerFailure_ResponseType, out, sizeof(out));
	expect_true(n == sizeof(k_query_example_com), "error reply keeps header and question");
	expect_u8(out[0], 0x12, "error reply id hi");
	expect_u8(out[1], 0x34, "error reply id lo");
	expect_u8(out[2], 0x81, "error reply QR and RD");
	expect_u8(out[3], 0x82, "error reply RA and SERVFAIL");
	expect_true(memcmp(out + 12, k_query_example_com + 12, n - 12) == 0, "error reply question bytes");
	expect_true(dns_build_error(k_query_example_com, 11, 2, out, sizeof(out)) == 0, "error reply needs a header");
	expect_true(dns_build_error(k_query_example_com, sizeof(k_query_example_com), 2, out, 20) == 0,
	        "error reply respects capacity");

	/* A question that does not parse is left out and QDCOUNT becomes 0. */
	memset(garbage, 0xff, sizeof(garbage));
	memcpy(garbage, k_query_example_com, 12);
	n = dns_build_error(garbage, sizeof(garbage), FormatError_ResponseType, out, sizeof(out));
	expect_true(n == 12, "error reply without a parsable question");
	expect_u8(out[5], 0, "error reply QDCOUNT 0");
	expect_u8(out[3], 0x81, "error reply FORMERR");

	/* A response with records and an OPT is cut to header and question with TC. */
	memcpy(resp, k_query_example_com, sizeof(k_query_example_com));
	resp[2] = 0x81;
	resp[3] = 0x80;
	resp[7] = 1;
	resp[11] = 1;
	memset(resp + sizeof(k_query_example_com), 0xee, 16);
	n = dns_build_truncated(resp, sizeof(resp), out, sizeof(out));
	expect_true(n == sizeof(k_query_example_com), "truncated reply length");
	expect_u8(out[2], 0x83, "truncated reply sets TC and keeps QR/RD");
	expect_u8(out[3], 0x80, "truncated reply keeps RA and rcode");
	expect_u8(out[7], 0, "truncated reply ANCOUNT 0");
	expect_u8(out[11], 0, "truncated reply ARCOUNT 0");
}

static void test_wire_udp_limit(void)
{
	uint8_t q[sizeof(k_query_example_com) + 11];
	const uint8_t opt[] = {0x00, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0, 0};

	expect_true(dns_udp_limit(k_query_example_com, sizeof(k_query_example_com), 1232) == 512,
	        "no EDNS gives 512");
	memcpy(q, k_query_example_com, sizeof(k_query_example_com));
	memcpy(q + sizeof(k_query_example_com), opt, sizeof(opt));
	q[11] = 1;
	expect_true(dns_udp_limit(q, sizeof(q), 1232) == 1232, "EDNS 4096 clamped to 1232");
	q[sizeof(k_query_example_com) + 3] = 0x04;
	q[sizeof(k_query_example_com) + 4] = 0x00;
	expect_true(dns_udp_limit(q, sizeof(q), 1232) == 1024, "EDNS 1024 honoured");
	q[sizeof(k_query_example_com) + 3] = 0x00;
	q[sizeof(k_query_example_com) + 4] = 0x10;
	expect_true(dns_udp_limit(q, sizeof(q), 1232) == 512, "EDNS below 512 gives 512");
	expect_true(dns_udp_limit(q, sizeof(q) - 3, 1232) == 512, "cut OPT record gives 512");
}

/* example.com A response: one answer (TTL 120) and one authority record (TTL 90). */
static size_t build_reply(uint8_t *out, uint8_t rcode)
{
	const uint8_t rrs[] = {
	        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 1, 2, 3, 4,
	        0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x02, 0xc0, 0x0c};
	size_t n = sizeof(k_query_example_com);
	memcpy(out, k_query_example_com, n);
	out[2] = 0x81;
	out[3] = (uint8_t)(0x80 | rcode);
	out[7] = 1;
	out[9] = 1;
	memcpy(out + n, rrs, sizeof(rrs));
	return n + sizeof(rrs);
}

static void test_wire_cache_helpers(void)
{
	uint8_t q[sizeof(k_query_example_com) + 11];
	uint8_t key_a[300];
	uint8_t key_b[300];
	uint8_t resp[128];
	size_t ka;
	size_t kb;
	size_t rlen;
	uint32_t ttl = 0;
	const uint8_t opt_do[] = {0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00};

	/* Key ignores case and id, and separates EDNS, DO and CD. */
	memcpy(q, k_query_example_com, sizeof(k_query_example_com));
	ka = dns_cache_key(q, sizeof(k_query_example_com), key_a, sizeof(key_a));
	q[0] = 0x55;
	q[13] = 'E';
	q[21] = 'C';
	kb = dns_cache_key(q, sizeof(k_query_example_com), key_b, sizeof(key_b));
	expect_true(ka > 0 && ka == kb && memcmp(key_a, key_b, ka) == 0, "cache key ignores id and case");
	q[3] = 0x10;
	kb = dns_cache_key(q, sizeof(k_query_example_com), key_b, sizeof(key_b));
	expect_true(kb == ka && memcmp(key_a, key_b, ka) != 0, "cache key separates CD");
	q[3] = 0x00;
	memcpy(q + sizeof(k_query_example_com), opt_do, sizeof(opt_do));
	q[11] = 1;
	kb = dns_cache_key(q, sizeof(q), key_b, sizeof(key_b));
	expect_true(kb == ka && key_b[kb - 1] == (key_a[ka - 1] | 0x0c), "cache key records EDNS and DO");
	expect_true(dns_cache_key(q, sizeof(q), key_b, 4) == 0, "cache key respects capacity");
	q[5] = 2;
	expect_true(dns_cache_key(q, sizeof(q), key_b, sizeof(key_b)) == 0, "two questions are not cacheable");

	/* Reply matching */
	rlen = build_reply(resp, 0);
	expect_true(dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, rlen),
	        "reply matches its query");
	resp[14] = 'X';
	expect_true(dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, rlen),
	        "reply match ignores case");
	resp[14] = 'q';
	expect_true(!dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, rlen),
	        "reply for another name does not match");
	rlen = build_reply(resp, 0);
	resp[1] = 0x35;
	expect_true(!dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, rlen),
	        "reply with another id does not match");
	resp[1] = 0x34;
	resp[2] = 0x01;
	expect_true(!dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, rlen),
	        "a query is not a reply");
	memcpy(resp, k_query_example_com, 12);
	resp[2] = 0x81;
	resp[3] = 0x85;
	resp[5] = 0;
	expect_true(dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, 12),
	        "error reply without question matches");
	resp[3] = 0x80;
	expect_true(!dns_reply_matches(k_query_example_com, sizeof(k_query_example_com), resp, 12),
	        "NOERROR reply without question does not match");

	/* TTL */
	rlen = build_reply(resp, 0);
	expect_true(dns_reply_ttl(resp, rlen, &ttl) && ttl == 90, "reply TTL is the smallest record TTL");
	rlen = build_reply(resp, 3);
	expect_true(dns_reply_ttl(resp, rlen, &ttl), "NXDOMAIN reply has a TTL");
	rlen = build_reply(resp, 2);
	expect_true(!dns_reply_ttl(resp, rlen, &ttl), "SERVFAIL is not cacheable");
	rlen = build_reply(resp, 0);
	resp[2] |= 0x02;
	expect_true(!dns_reply_ttl(resp, rlen, &ttl), "truncated reply is not cacheable");
	rlen = build_reply(resp, 0);
	resp[7] = 0;
	resp[9] = 0;
	expect_true(!dns_reply_ttl(resp, sizeof(k_query_example_com), &ttl), "reply without records has no TTL");
	rlen = build_reply(resp, 0);
	expect_true(!dns_reply_ttl(resp, rlen - 1, &ttl), "cut reply has no TTL");

	/* Aging and adoption */
	rlen = build_reply(resp, 0);
	dns_reply_age(resp, rlen, 100);
	expect_true(dns_reply_ttl(resp, rlen, &ttl) && ttl == 0, "aging stops at zero");
	rlen = build_reply(resp, 0);
	dns_reply_age(resp, rlen, 30);
	expect_true(dns_reply_ttl(resp, rlen, &ttl) && ttl == 60, "aging lowers every TTL");
	expect_u8(resp[sizeof(k_query_example_com) + 9], 0x5a, "answer TTL 120 aged to 90");

	memcpy(q, k_query_example_com, sizeof(k_query_example_com));
	q[0] = 0xab;
	q[13] = 'E';
	expect_true(dns_reply_adopt(resp, rlen, q, sizeof(k_query_example_com)), "adopt reply");
	expect_u8(resp[0], 0xab, "adopted id");
	expect_u8(resp[13], 'E', "adopted question spelling");
}

int main(void)
{
	log_set_quiet(1);

	test_question_name();
	test_build_local_answer();
	test_wire_error_and_truncation();
	test_wire_udp_limit();
	test_wire_cache_helpers();

	return failures == 0 ? 0 : 1;
}
