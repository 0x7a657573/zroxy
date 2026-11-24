/*
 * DNS wire handling for queries from clients and replies from the upstream.
 *
 * The input is one byte N followed by two packets: the first N bytes are the
 * "query", the rest is the "reply". N larger than the input leaves the reply
 * empty. Each packet is also fed alone to every single-packet helper.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/dns.h>

#include "fuzz_common.h"

#define MAX_PACKET 65535u
#define ANSWER_CAP 512u

static void exercise_local_helpers(const uint8_t *data, size_t size)
{
	uint8_t *in = fuzz_dup(data, size);
	uint8_t out[ANSWER_CAP];
	char name[256] = {0};
	static const uint8_t addr[4] = {192, 0, 2, 10};
	size_t written;

	if (dns_question_name(in, size, name, sizeof(name)) &&
	        !memchr(name, '\0', sizeof(name)))
		abort();
	written = dns_build_local_answer(in, size, addr, 300, out, sizeof(out));
	if (written > sizeof(out))
		abort();
	if (written > 0)
	{
		size_t tight_cap = written - 1;
		written = dns_build_local_answer(in, size, addr, 300, out, tight_cap);
		if (written > tight_cap)
			abort();
	}
	free(in);
}

static void single_packet(const uint8_t *data, size_t size)
{
	uint8_t *in = fuzz_dup(data, size);
	uint8_t *out = malloc(ANSWER_CAP);
	uint16_t udp_size;
	uint32_t flags;
	uint32_t ttl;
	size_t n;

	if (!out)
		abort();
	n = dns_build_error(in, size, Refused_ResponseType, out, ANSWER_CAP);
	if (n > ANSWER_CAP)
		abort();
	n = dns_build_error(in, size, ServerFailure_ResponseType, out, 12);
	if (n > 12)
		abort();
	n = dns_build_truncated(in, size, out, ANSWER_CAP);
	if (n > ANSWER_CAP)
		abort();
	(void)dns_udp_limit(in, size, DNS_UDP_MAX_PAYLOAD);
	(void)dns_query_opt(in, size, &udp_size, &flags);
	n = dns_cache_key(in, size, out, ANSWER_CAP);
	if (n > ANSWER_CAP)
		abort();
	(void)dns_cache_key(in, size, out, 16);
	(void)dns_reply_ttl(in, size, &ttl);
	dns_reply_age(in, size, 7);
	dns_reply_age(in, size, 0xffffffffu);
	free(out);
	free(in);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *q;
	const uint8_t *r;
	size_t qlen;
	size_t rlen;
	uint8_t *qc;
	uint8_t *rc;
	uint8_t *rc2;

	fuzz_init_once();
	if (size == 0)
		return 0;
	if (size > MAX_PACKET)
		size = MAX_PACKET;
	qlen = data[0];
	q = data + 1;
	if (qlen > size - 1)
		qlen = size - 1;
	r = q + qlen;
	rlen = size - 1 - qlen;

	exercise_local_helpers(q, qlen);
	exercise_local_helpers(r, rlen);
	single_packet(q, qlen);
	single_packet(r, rlen);

	qc = fuzz_dup(q, qlen);
	rc = fuzz_dup(r, rlen);
	(void)dns_reply_matches(qc, qlen, rc, rlen);
	(void)dns_reply_matches(rc, rlen, qc, qlen);
	/* Adopt rewrites the reply in place, so give it its own copy. */
	rc2 = fuzz_dup(r, rlen);
	(void)dns_reply_adopt(rc2, rlen, qc, qlen);
	free(rc2);
	free(rc);
	free(qc);
	return 0;
}
