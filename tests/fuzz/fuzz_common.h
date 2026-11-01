/*
 * Shared helpers for the fuzz harnesses.
 *
 * Every harness copies its input into a heap block of exactly the input
 * size, so AddressSanitizer reports a read or write past the end.
 */
#ifndef FUZZ_COMMON_H_
#define FUZZ_COMMON_H_

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/log.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Quiet logging and ignore SIGPIPE, once per process. */
static inline void fuzz_init_once(void)
{
	static int done;
	if (done)
		return;
	done = 1;
	log_init();
	log_set_quiet(1);
	signal(SIGPIPE, SIG_IGN);
}

/* malloc(size) holding a copy of data; malloc(1) when size is 0. */
static inline uint8_t *fuzz_dup(const uint8_t *data, size_t size)
{
	uint8_t *p = malloc(size ? size : 1);
	if (!p)
		abort();
	if (size)
		memcpy(p, data, size);
	return p;
}

#endif /* FUZZ_COMMON_H_ */
