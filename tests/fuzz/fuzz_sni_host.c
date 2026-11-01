/*
 * Host name extraction from a client's first bytes (TLS ClientHello SNI or
 * HTTP Host), then the normalization and whitelist step that host_ready in
 * src/sni/sni_event_loop.c runs on the result.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/config.h>
#include <zroxy/filter.h>
#include <zroxy/net.h>

#include "fuzz_common.h"
#include "sni_event_loop.h"
#include "sni_resolver.h"

typedef bool (*extract_fn)(uint8_t *buf, uint32_t len, char *host, uint16_t max);

static filter_t *whitelist;

/* The engine's steps after a host was extracted. */
static void after_extract(const char *raw)
{
	char norm[SNI_RESOLVER_HOST_MAX + 1];
	size_t n;

	if (!sni_resolver_normalize(raw, norm, sizeof(norm)))
		return;
	n = strlen(norm);
	if (n == 0 || n >= ZROXY_MAX_HOSTNAME)
		return;
	(void)filter_match(whitelist, norm);
	(void)net_is_ip_literal(norm);
}

static void run_one(extract_fn fn, const uint8_t *data, size_t size, uint16_t cap)
{
	uint8_t *in = fuzz_dup(data, size);
	char *host = malloc(cap);

	if (!host)
		abort();
	if (fn(in, (uint32_t)size, host, cap))
	{
		/* A success must leave a terminated string inside the buffer. */
		if (memchr(host, '\0', cap) == NULL)
			abort();
		after_extract(host);
	}
	free(host);
	free(in);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char *const entries[] = {
		"example.com", "*.example.org", "api?.wild*.net",
	};

	fuzz_init_once();
	if (!whitelist)
	{
		whitelist = filter_from_list(entries, sizeof(entries) / sizeof(entries[0]));
		if (!whitelist)
			abort();
	}
	if (size > SNI_HELLO_CAP)
		size = SNI_HELLO_CAP;

	run_one(net_get_host, data, size, (uint16_t)ZROXY_MAX_HOSTNAME);
	run_one(net_get_https_host, data, size, (uint16_t)ZROXY_MAX_HOSTNAME);
	run_one(net_get_http_host, data, size, (uint16_t)ZROXY_MAX_HOSTNAME);
	/* A small buffer sized from the input, to hit the truncation checks. */
	if (size > 0)
		run_one(net_get_host, data + 1, size - 1, (uint16_t)(1 + data[0] % 32));
	return 0;
}
