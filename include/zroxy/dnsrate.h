#ifndef ZROXY_DNSRATE_H
#define ZROXY_DNSRATE_H

#include <stdbool.h>
#include <stdint.h>

#define DNS_RATE_SLOTS 1024

typedef struct
{
	uint32_t ip;
	uint32_t tokens_milli;
	int64_t last_ms;
} dns_rate_slot_t;

typedef struct
{
	uint32_t qps;
	dns_rate_slot_t slots[DNS_RATE_SLOTS];
} dns_rate_t;

/* Called only by the DNS receive thread; no lock is required. */
bool dns_rate_take(dns_rate_t *rate, uint32_t ip, int64_t now_ms);

#endif
