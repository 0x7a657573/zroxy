#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <zroxy/dns.h>
#include <zroxy/dnscache.h>
#include <zroxy/log.h>
#include <zroxy/net_io.h>

static int failures = 0;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void expect_int(long actual, long expected, const char *name)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL: %s expected %ld, got %ld\n", name, expected, actual);
        failures++;
    }
}

/* Query for <c>.test A with the given id. */
static size_t build_query(uint8_t *out, char c, uint16_t id)
{
    const uint8_t q[] = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 'a', 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01
    };
    memcpy(out, q, sizeof(q));
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[13] = (uint8_t)c;
    return sizeof(q);
}

/* The query plus one A record with ttl, as upstream would answer it. */
static size_t build_reply(uint8_t *out, const uint8_t *query, size_t qlen, uint8_t rcode, uint32_t ttl)
{
    const uint8_t rr[] = { 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
                           (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
                           0x00, 0x04, 9, 9, 9, 9 };
    memcpy(out, query, qlen);
    out[2] = 0x81;
    out[3] = (uint8_t)(0x80 | rcode);
    out[7] = 1;
    memcpy(out + qlen, rr, sizeof(rr));
    return qlen + sizeof(rr);
}

static uint32_t answer_ttl(const uint8_t *reply, size_t qlen)
{
    const uint8_t *p = reply + qlen + 6;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Begin as leader and publish reply at now_ms. */
static void lead_and_store(dnscache_t *c, const uint8_t *q, size_t qlen, const uint8_t *r, size_t rlen,
                           int64_t now_ms)
{
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t n = 0;
    dnscache_flight *f = NULL;
    expect_int(dnscache_begin(c, q, qlen, now_ms, out, sizeof(out), &n, &f), DNSCACHE_LEAD, "lead a miss");
    dnscache_finish(c, f, r, rlen, rlen, now_ms);
}

static void test_hit_age_and_expiry(void)
{
    dnscache_t *c = dnscache_create(16);
    uint8_t q[64];
    uint8_t r[128];
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t qlen = build_query(q, 'a', 0x1111);
    size_t rlen = build_reply(r, q, qlen, 0, 60);
    size_t n = 0;
    dnscache_flight *f = NULL;

    expect_true(c != NULL, "create cache");
    if (!c)
        return;
    lead_and_store(c, q, qlen, r, rlen, 1000);
    expect_int((long)dnscache_count(c), 1, "reply stored");

    /* Another id and spelling, 20 s later. */
    qlen = build_query(q, 'A', 0x2222);
    expect_int(dnscache_begin(c, q, qlen, 21000, out, sizeof(out), &n, &f), DNSCACHE_HIT, "hit");
    expect_int((long)n, (long)rlen, "hit length");
    expect_true(out[0] == 0x22 && out[1] == 0x22, "hit carries the new id");
    expect_true(out[13] == 'A', "hit carries the new spelling");
    expect_int((long)answer_ttl(out, qlen), 40, "hit TTL aged by 20 s");

    {
        dnscache_counters counters;
        dnscache_get_counters(c, &counters);
        expect_int((long)counters.hits, 1, "cache hit counter");
        expect_int((long)counters.misses, 1, "cache miss counter");
        expect_int((long)counters.stored, 1, "cache store counter");
        expect_int((long)counters.entries, 1, "cache entry counter");
    }

    expect_int(dnscache_begin(c, q, qlen, 61000, out, sizeof(out), &n, &f), DNSCACHE_LEAD, "expired entry is a miss");
    expect_int((long)dnscache_count(c), 0, "expired entry removed");
    dnscache_finish(c, f, NULL, 0, 0, 61000);
    dnscache_free(c);
}

static void test_what_is_not_cached(void)
{
    dnscache_t *c = dnscache_create(16);
    uint8_t q[64];
    uint8_t r[128];
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t qlen = build_query(q, 'b', 1);
    size_t rlen;
    size_t n = 0;
    dnscache_flight *f = NULL;

    if (!c)
        return;
    rlen = build_reply(r, q, qlen, ServerFailure_ResponseType, 60);
    lead_and_store(c, q, qlen, r, rlen, 1000);
    expect_int((long)dnscache_count(c), 0, "SERVFAIL not stored");

    rlen = build_reply(r, q, qlen, 0, 0);
    lead_and_store(c, q, qlen, r, rlen, 1000);
    expect_int((long)dnscache_count(c), 0, "TTL 0 not stored");

    rlen = build_reply(r, q, qlen, 0, 60);
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_LEAD, "lead partial");
    dnscache_finish(c, f, r, rlen, rlen + 500, 1000);
    expect_int((long)dnscache_count(c), 0, "partial reply not stored");

    /* NXDOMAIN with a day-long TTL is kept for the negative cap only. */
    rlen = build_reply(r, q, qlen, NameError_ResponseType, 86400);
    lead_and_store(c, q, qlen, r, rlen, 1000);
    expect_int(dnscache_begin(c, q, qlen, 1000 + DNSCACHE_NEG_TTL * 1000 - 1, out, sizeof(out), &n, &f),
               DNSCACHE_HIT, "NXDOMAIN cached");
    expect_int(dnscache_begin(c, q, qlen, 1000 + DNSCACHE_NEG_TTL * 1000, out, sizeof(out), &n, &f),
               DNSCACHE_LEAD, "NXDOMAIN capped at the negative TTL");
    dnscache_finish(c, f, NULL, 0, 0, 0);

    q[5] = 2;
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_BYPASS,
               "two questions bypass the cache");
    expect_int(dnscache_begin(NULL, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_BYPASS,
               "no cache bypasses");
    dnscache_free(c);
}

static void test_lru_eviction(void)
{
    dnscache_t *c = dnscache_create(2);
    uint8_t q[64];
    uint8_t r[128];
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t qlen;
    size_t rlen;
    size_t n = 0;
    dnscache_flight *f = NULL;
    char name;

    if (!c)
        return;
    for (name = 'a'; name <= 'b'; name++)
    {
        qlen = build_query(q, name, 1);
        rlen = build_reply(r, q, qlen, 0, 60);
        lead_and_store(c, q, qlen, r, rlen, 1000);
    }
    /* Touch a so that b is the least recently used. */
    qlen = build_query(q, 'a', 1);
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_HIT, "a cached");
    qlen = build_query(q, 'c', 1);
    rlen = build_reply(r, q, qlen, 0, 60);
    lead_and_store(c, q, qlen, r, rlen, 1000);
    expect_int((long)dnscache_count(c), 2, "cache stays at its limit");
    qlen = build_query(q, 'a', 1);
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_HIT, "recent entry kept");
    qlen = build_query(q, 'b', 1);
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_LEAD, "LRU entry evicted");
    dnscache_finish(c, f, NULL, 0, 0, 0);
    {
        dnscache_counters counters;
        dnscache_get_counters(c, &counters);
        expect_int((long)counters.evicted, 1, "cache eviction counter");
    }
    dnscache_free(c);
}

typedef struct
{
    dnscache_t *cache;
    dnscache_flight *flight;
    uint8_t query[64];
    size_t qlen;
    int64_t deadline;
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t full;
} follower_t;

static void *follow_thread(void *arg)
{
    follower_t *fw = (follower_t *)arg;
    fw->full = dnscache_follow(fw->cache, fw->flight, fw->query, fw->qlen, fw->deadline,
                               fw->out, sizeof(fw->out));
    return NULL;
}

static void test_coalescing(void)
{
    dnscache_t *c = dnscache_create(16);
    uint8_t q[64];
    uint8_t r[128];
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t qlen;
    size_t rlen;
    size_t n = 0;
    dnscache_flight *lead = NULL;
    follower_t fw;
    pthread_t tid;

    if (!c)
        return;
    qlen = build_query(q, 'd', 0x0101);
    expect_int(dnscache_begin(c, q, qlen, net_mono_ms(), out, sizeof(out), &n, &lead), DNSCACHE_LEAD,
               "first query leads");

    memset(&fw, 0, sizeof(fw));
    fw.cache = c;
    fw.qlen = build_query(fw.query, 'D', 0x0202);
    fw.deadline = net_mono_ms() + 2000;
    expect_int(dnscache_begin(c, fw.query, fw.qlen, net_mono_ms(), out, sizeof(out), &n, &fw.flight),
               DNSCACHE_FOLLOW, "same question follows");
    expect_true(pthread_create(&tid, NULL, follow_thread, &fw) == 0, "start follower");
    usleep(50000);
    rlen = build_reply(r, q, qlen, 0, 60);
    dnscache_finish(c, lead, r, rlen, rlen, net_mono_ms());
    pthread_join(tid, NULL);
    expect_int((long)fw.full, (long)rlen, "follower gets the leader's reply");
    expect_true(fw.out[0] == 0x02 && fw.out[1] == 0x02 && fw.out[13] == 'D',
                "follower reply carries its own id and spelling");

    /* A failed fetch fails its followers too. */
    qlen = build_query(q, 'e', 1);
    dnscache_begin(c, q, qlen, net_mono_ms(), out, sizeof(out), &n, &lead);
    fw.qlen = build_query(fw.query, 'e', 2);
    expect_int(dnscache_begin(c, fw.query, fw.qlen, net_mono_ms(), out, sizeof(out), &n, &fw.flight),
               DNSCACHE_FOLLOW, "follow a fetch that will fail");
    dnscache_finish(c, lead, NULL, 0, 0, net_mono_ms());
    fw.deadline = net_mono_ms() + 2000;
    expect_int((long)dnscache_follow(c, fw.flight, fw.query, fw.qlen, fw.deadline, out, sizeof(out)), 0,
               "follower of a failed fetch gets nothing");

    /* A follower stops waiting at its deadline. */
    qlen = build_query(q, 'f', 1);
    dnscache_begin(c, q, qlen, net_mono_ms(), out, sizeof(out), &n, &lead);
    fw.qlen = build_query(fw.query, 'f', 2);
    dnscache_begin(c, fw.query, fw.qlen, net_mono_ms(), out, sizeof(out), &n, &fw.flight);
    {
        int64_t start = net_mono_ms();
        expect_int((long)dnscache_follow(c, fw.flight, fw.query, fw.qlen, start + 100, out, sizeof(out)), 0,
                   "follower times out");
        expect_true(net_mono_ms() - start < 1000, "follower timeout is bounded");
    }
    rlen = build_reply(r, q, qlen, 0, 60);
    dnscache_finish(c, lead, r, rlen, rlen, net_mono_ms());
    expect_int(dnscache_begin(c, q, qlen, net_mono_ms(), out, sizeof(out), &n, &lead), DNSCACHE_HIT,
               "late leader still fills the cache");
    dnscache_free(c);
}

static void test_flight_exhaustion(void)
{
    dnscache_t *c = dnscache_create(16);
    dnscache_flight *flights[DNSCACHE_FLIGHTS];
    uint8_t q[64];
    uint8_t out[DNS_UDP_MAX_PAYLOAD];
    size_t qlen;
    size_t n = 0;
    dnscache_flight *f = NULL;
    int i;

    if (!c)
        return;
    for (i = 0; i < DNSCACHE_FLIGHTS; i++)
    {
        /* <letter><digit>.test: a distinct two-byte first label per flight */
        const uint8_t name[] = { 0x02, (uint8_t)('a' + i % 26), (uint8_t)('0' + i / 26),
                                 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01 };
        build_query(q, 'a', 1);
        memcpy(q + 12, name, sizeof(name));
        qlen = 12 + sizeof(name);
        expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &flights[i]), DNSCACHE_LEAD,
                   "claim a flight");
    }
    qlen = build_query(q, 'z', 1);
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_BYPASS,
               "no free flight bypasses");
    for (i = 0; i < DNSCACHE_FLIGHTS; i++)
        dnscache_finish(c, flights[i], NULL, 0, 0, 1000);
    expect_int(dnscache_begin(c, q, qlen, 1000, out, sizeof(out), &n, &f), DNSCACHE_LEAD,
               "flights are reusable");
    dnscache_finish(c, f, NULL, 0, 0, 1000);
    dnscache_free(c);
}

int main(void)
{
    log_set_quiet(1);
    test_hit_age_and_expiry();
    test_what_is_not_cached();
    test_lru_eviction();
    test_coalescing();
    test_flight_exhaustion();
    return failures == 0 ? 0 : 1;
}
