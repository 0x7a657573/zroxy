/*
 * Monitor HTTP request checks: the request line classifier, the end-of-header
 * scan and the Bearer authorization match. These are static in monitor.c and
 * reached through the MON_TEST_HOOKS wrappers.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/monitor.h>

#include "fuzz_common.h"

#define MAX_REQUEST 4096u	/* MON_MAX_HEADER */

/* Parts of the input that the harness also tries as the token. */
#define TOKEN "s3cret-token"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *in;
	char *token;
	size_t cut;
	size_t i;

	fuzz_init_once();
	if (size > MAX_REQUEST)
		size = MAX_REQUEST;
	in = fuzz_dup(data, size);

	/* The monitor re-checks after every read, so try every prefix length. */
	for (cut = 0; cut <= size; cut += (size > 64 ? 7 : 1))
	{
		uint8_t *part = fuzz_dup(in, cut);
		(void)monitor_test_classify(part, cut);
		(void)monitor_test_headers_done(part, cut);
		(void)monitor_test_authorized(part, cut, NULL);
		(void)monitor_test_authorized(part, cut, TOKEN);
		free(part);
	}
	(void)monitor_test_classify(in, size);
	(void)monitor_test_headers_done(in, size);

	/* A token cut from the input's tail, so the Bearer path can match. */
	i = size ? in[size - 1] % (size + 1) : 0;
	token = malloc(size - i + 1);
	if (!token)
		abort();
	memcpy(token, in + i, size - i);
	token[size - i] = '\0';
	(void)monitor_test_authorized(in, size, token);
	free(token);
	free(in);
	return 0;
}
