#include <zroxy/net_io.h>

#include <time.h>

int net_timeout_ms(int timeout_sec)
{
	if (timeout_sec < 1)
		timeout_sec = 1;
	if (timeout_sec > 86400)
		timeout_sec = 86400;
	return timeout_sec * 1000;
}

int64_t net_mono_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return -1;
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
