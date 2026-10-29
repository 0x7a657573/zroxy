#include <stdint.h>

#include <zroxy/dnsrate.h>

static uint32_t rate_slot(uint32_t ip)
{
	return (ip * 2654435761u) >> 22;
}

bool dns_rate_take(dns_rate_t *rate, uint32_t ip, int64_t now_ms)
{
	dns_rate_slot_t *slot;
	uint32_t burst;
	uint32_t index;

	if (!rate || rate->qps == 0)
		return true;
	burst = rate->qps * 2u * 1000u;
	index = rate_slot(ip);
	slot = &rate->slots[index];
	if (slot->tokens_milli == 0 && slot->last_ms == 0)
	{
		slot->tokens_milli = burst;
		slot->last_ms = now_ms == 0 ? 1 : now_ms;
	}
	else if (now_ms > slot->last_ms)
	{
		uint64_t elapsed = (uint64_t)(now_ms - slot->last_ms);
		uint64_t refill = elapsed > UINT64_MAX / (uint64_t)rate->qps
			? UINT64_MAX
			: elapsed * (uint64_t)rate->qps;
		uint64_t tokens = refill > UINT64_MAX - (uint64_t)slot->tokens_milli
			? UINT64_MAX
			: (uint64_t)slot->tokens_milli + refill;
		if (tokens > burst)
			tokens = burst;
		slot->tokens_milli = (uint32_t)tokens;
		slot->last_ms = now_ms;
	}
	if (slot->tokens_milli < 1000u)
		return false;
	slot->tokens_milli -= 1000u;
	return true;
}
