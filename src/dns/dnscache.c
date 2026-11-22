/*
 * dnscache.c
 *
 * Answer cache and in-flight coalescing for forwarded DNS queries.
 */
#include <zroxy/dnscache.h>
#include <zroxy/dns.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Wire name (255) + TYPE + CLASS + flag byte */
#define DNSCACHE_KEY_MAX 264

typedef struct dnscache_entry
{
	struct dnscache_entry *hnext; /* hash chain */
	struct dnscache_entry *prev;  /* LRU, most recent at head */
	struct dnscache_entry *next;
	uint32_t hash;
	int64_t stored_ms;
	int64_t expires_ms;
	uint16_t key_len;
	uint16_t len;
	uint8_t data[]; /* key, then reply */
} dnscache_entry;

enum
{
	FLIGHT_FREE = 0,
	FLIGHT_PENDING,
	FLIGHT_DONE
};

struct dnscache_flight
{
	int state;
	int refs;
	uint32_t hash;
	uint16_t key_len;
	uint8_t key[DNSCACHE_KEY_MAX];
};

struct dnscache
{
	pthread_mutex_t mu;
	dnscache_entry **buckets;
	size_t bucket_mask;
	size_t max_entries;
	size_t count;
	dnscache_entry *lru_head;
	dnscache_entry *lru_tail;
	dnscache_flight flights[DNSCACHE_FLIGHTS];
	dnscache_counters counters;
};

static uint32_t key_hash(const uint8_t *key, size_t len)
{
	uint32_t h = 2166136261u;
	size_t i;
	for (i = 0; i < len; i++)
	{
		h ^= key[i];
		h *= 16777619u;
	}
	return h;
}

dnscache_t *dnscache_create(size_t max_entries)
{
	dnscache_t *c;
	size_t buckets = 16;

	if (max_entries == 0)
		return NULL;
	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	while (buckets < max_entries && buckets < ((size_t)1 << 20))
		buckets <<= 1;
	c->buckets = calloc(buckets, sizeof(*c->buckets));
	if (!c->buckets)
	{
		free(c);
		return NULL;
	}
	if (pthread_mutex_init(&c->mu, NULL) != 0)
	{
		free(c->buckets);
		free(c);
		return NULL;
	}
	c->bucket_mask = buckets - 1;
	c->max_entries = max_entries;
	return c;
}

void dnscache_free(dnscache_t *c)
{
	dnscache_entry *e;
	if (!c)
		return;
	e = c->lru_head;
	while (e)
	{
		dnscache_entry *next = e->next;
		free(e);
		e = next;
	}
	pthread_mutex_destroy(&c->mu);
	free(c->buckets);
	free(c);
}

static void lru_unlink(dnscache_t *c, dnscache_entry *e)
{
	if (e->prev)
		e->prev->next = e->next;
	else
		c->lru_head = e->next;
	if (e->next)
		e->next->prev = e->prev;
	else
		c->lru_tail = e->prev;
	e->prev = NULL;
	e->next = NULL;
}

static void lru_push_head(dnscache_t *c, dnscache_entry *e)
{
	e->prev = NULL;
	e->next = c->lru_head;
	if (c->lru_head)
		c->lru_head->prev = e;
	c->lru_head = e;
	if (!c->lru_tail)
		c->lru_tail = e;
}

static void entry_remove_locked(dnscache_t *c, dnscache_entry *e)
{
	dnscache_entry **pp = &c->buckets[e->hash & c->bucket_mask];
	while (*pp && *pp != e)
		pp = &(*pp)->hnext;
	if (*pp)
		*pp = e->hnext;
	lru_unlink(c, e);
	c->count--;
	free(e);
}

static dnscache_entry *entry_find_locked(dnscache_t *c, const uint8_t *key, size_t key_len, uint32_t hash)
{
	dnscache_entry *e;
	for (e = c->buckets[hash & c->bucket_mask]; e; e = e->hnext)
	{
		if (e->hash == hash && e->key_len == key_len && memcmp(e->data, key, key_len) == 0)
			return e;
	}
	return NULL;
}

static dnscache_flight *flight_find_locked(dnscache_t *c, const uint8_t *key, size_t key_len, uint32_t hash)
{
	int i;
	for (i = 0; i < DNSCACHE_FLIGHTS; i++)
	{
		dnscache_flight *f = &c->flights[i];
		/* A finished flight stays allocated until its followers let go. */
		if (f->state == FLIGHT_PENDING && f->hash == hash && f->key_len == key_len &&
		        memcmp(f->key, key, key_len) == 0)
			return f;
	}
	return NULL;
}

static dnscache_flight *flight_claim_locked(dnscache_t *c, const uint8_t *key, size_t key_len, uint32_t hash)
{
	int i;
	for (i = 0; i < DNSCACHE_FLIGHTS; i++)
	{
		dnscache_flight *f = &c->flights[i];
		if (f->state != FLIGHT_FREE)
			continue;
		f->state = FLIGHT_PENDING;
		f->refs = 1;
		f->hash = hash;
		f->key_len = (uint16_t)key_len;
		memcpy(f->key, key, key_len);
		return f;
	}
	return NULL;
}

static void flight_release_locked(dnscache_flight *f)
{
	if (--f->refs == 0)
		f->state = FLIGHT_FREE;
}

dnscache_result dnscache_begin(dnscache_t *c, const uint8_t *query, size_t qlen, int64_t now_ms,
        uint8_t *out, size_t cap, size_t *out_len, dnscache_flight **flight)
{
	uint8_t key[DNSCACHE_KEY_MAX];
	size_t key_len;
	uint32_t hash;
	dnscache_entry *e;
	dnscache_result result = DNSCACHE_BYPASS;

	*flight = NULL;
	*out_len = 0;
	if (!c || now_ms < 0)
		return DNSCACHE_BYPASS;
	key_len = dns_cache_key(query, qlen, key, sizeof(key));
	if (key_len == 0)
	{
		pthread_mutex_lock(&c->mu);
		c->counters.bypass++;
		pthread_mutex_unlock(&c->mu);
		return DNSCACHE_BYPASS;
	}
	hash = key_hash(key, key_len);

	pthread_mutex_lock(&c->mu);
	e = entry_find_locked(c, key, key_len, hash);
	if (e && now_ms >= e->expires_ms)
	{
		entry_remove_locked(c, e);
		e = NULL;
	}
	if (e && e->len <= cap)
	{
		c->counters.hits++;
		memcpy(out, e->data + e->key_len, e->len);
		*out_len = e->len;
		lru_unlink(c, e);
		lru_push_head(c, e);
		dns_reply_age(out, *out_len, (uint32_t)((now_ms - e->stored_ms) / 1000));
		pthread_mutex_unlock(&c->mu);
		if (!dns_reply_adopt(out, *out_len, query, qlen))
		{
			*out_len = 0;
			return DNSCACHE_BYPASS;
		}
		return DNSCACHE_HIT;
	}
	c->counters.misses++;

	*flight = flight_find_locked(c, key, key_len, hash);
	if (*flight)
	{
		c->counters.shared++;
		(*flight)->refs++;
		result = DNSCACHE_FOLLOW;
	}
	else
	{
		*flight = flight_claim_locked(c, key, key_len, hash);
		if (*flight)
			result = DNSCACHE_LEAD;
		else
			c->counters.bypass++;
	}
	pthread_mutex_unlock(&c->mu);
	return result;
}

static void store_locked(dnscache_t *c, const dnscache_flight *f, const uint8_t *resp, size_t len,
        int64_t now_ms)
{
	uint32_t ttl;
	uint32_t cap = DNSCACHE_MAX_TTL;
	dnscache_entry *e;

	if (!dns_reply_ttl(resp, len, &ttl))
		return;
	/* NXDOMAIN, or NOERROR without answers (NODATA) */
	if ((resp[3] & RCODE_MASK) != 0 || (resp[6] == 0 && resp[7] == 0))
		cap = DNSCACHE_NEG_TTL;
	if (ttl > cap)
		ttl = cap;
	if (ttl == 0)
		return;

	e = entry_find_locked(c, f->key, f->key_len, f->hash);
	if (e)
		entry_remove_locked(c, e);
	while (c->count >= c->max_entries && c->lru_tail)
	{
		c->counters.evicted++;
		entry_remove_locked(c, c->lru_tail);
	}

	e = malloc(sizeof(*e) + f->key_len + len);
	if (!e)
		return;
	memset(e, 0, sizeof(*e));
	e->hash = f->hash;
	e->stored_ms = now_ms;
	e->expires_ms = now_ms + (int64_t)ttl * 1000;
	e->key_len = f->key_len;
	e->len = (uint16_t)len;
	memcpy(e->data, f->key, f->key_len);
	memcpy(e->data + f->key_len, resp, len);
	e->hnext = c->buckets[e->hash & c->bucket_mask];
	c->buckets[e->hash & c->bucket_mask] = e;
	lru_push_head(c, e);
	c->count++;
	c->counters.stored++;
}

void dnscache_finish(dnscache_t *c, dnscache_flight *f, const uint8_t *resp,
        size_t stored, size_t full_len, int64_t now_ms)
{
	if (!c || !f)
		return;
	if (stored > full_len)
		full_len = 0;
	pthread_mutex_lock(&c->mu);
	/* Only a complete reply is cached. */
	if (full_len > 0 && stored == full_len && now_ms >= 0)
		store_locked(c, f, resp, stored, now_ms);
	f->state = FLIGHT_DONE;
	flight_release_locked(f);
	pthread_mutex_unlock(&c->mu);
}

void dnscache_abandon_follower(dnscache_t *c, dnscache_flight *f)
{
	if (!c || !f)
		return;
	pthread_mutex_lock(&c->mu);
	flight_release_locked(f);
	pthread_mutex_unlock(&c->mu);
}

size_t dnscache_count(dnscache_t *c)
{
	size_t n;
	if (!c)
		return 0;
	pthread_mutex_lock(&c->mu);
	n = c->count;
	pthread_mutex_unlock(&c->mu);
	return n;
}

void dnscache_get_counters(dnscache_t *c, dnscache_counters *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!c)
		return;
	pthread_mutex_lock(&c->mu);
	*out = c->counters;
	out->entries = c->count;
	pthread_mutex_unlock(&c->mu);
}
