/*
 * dnscache.h
 *
 * Answer cache and in-flight coalescing for forwarded DNS queries.
 *
 * Entries are complete upstream replies of at most DNS_UDP_MAX_PAYLOAD bytes,
 * kept for their smallest TTL (capped) and evicted least recently used first.
 * While one worker fetches a name, workers with the same query wait for its
 * reply instead of asking upstream again.
 *
 * One mutex guards everything; no upstream I/O happens with it held.
 */
#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DNSCACHE_ENTRIES	2048
#define DNSCACHE_MAX_TTL	3600
/* NXDOMAIN and NODATA (RFC 2308) */
#define DNSCACHE_NEG_TTL	300
/* Queries fetched at the same time; beyond this a query is forwarded alone. */
#define DNSCACHE_FLIGHTS	64

typedef struct dnscache dnscache_t;
typedef struct dnscache_flight dnscache_flight;

typedef enum
{
	DNSCACHE_HIT = 0,	/* the reply is in out */
	DNSCACHE_LEAD,		/* fetch it, then call dnscache_finish */
	DNSCACHE_FOLLOW,	/* another worker fetches it; call dnscache_follow */
	DNSCACHE_BYPASS		/* not cacheable or no flight slot: forward alone */
} dnscache_result;

dnscache_t *dnscache_create(size_t max_entries);
void dnscache_free(dnscache_t *cache);

/*
 * On HIT, *out_len bytes in out are the reply with the query's id and
 * question and aged TTLs. LEAD and FOLLOW set *flight.
 */
dnscache_result dnscache_begin(dnscache_t *cache, const uint8_t *query, size_t qlen, int64_t now_ms,
		uint8_t *out, size_t cap, size_t *out_len, dnscache_flight **flight);

/*
 * Leader: publish the reply (resp holds the first stored of full_len bytes;
 * full_len 0 means the fetch failed) and store it when cacheable. Followers
 * see at most DNS_UDP_MAX_PAYLOAD bytes of it.
 */
void dnscache_finish(dnscache_t *cache, dnscache_flight *flight, const uint8_t *resp,
		size_t stored, size_t full_len, int64_t now_ms);

/*
 * Follower: wait for the leader until deadline_ms. Returns the reply's full
 * length, or 0 when the leader failed or the wait timed out. The first
 * min(full, cap) bytes are in out, with the query's id and question.
 */
size_t dnscache_follow(dnscache_t *cache, dnscache_flight *flight, const uint8_t *query, size_t qlen,
		int64_t deadline_ms, uint8_t *out, size_t cap);

size_t dnscache_count(dnscache_t *cache);

#endif /* DNSCACHE_H_ */
