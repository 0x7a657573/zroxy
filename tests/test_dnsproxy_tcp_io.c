#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <zroxy/dnsproxy.h>
#include <zroxy/dns.h>
#include <zroxy/filter.h>
#include <zroxy/log.h>
#include <zroxy/net_io.h>

typedef struct
{
    dnsserver_t *dns;
    dnsMessage_t msg;
} dnsThread_test_t;

static void *handle_request_thread(void *arg)
{
    dnsThread_test_t *in = (dnsThread_test_t *)arg;
    int upstream_fd = -1;
    localdns_handle_request(in->dns, &in->msg, &upstream_fd);
    if (upstream_fd >= 0)
        close(upstream_fd);
    free(in);
    return NULL;
}

static int failures = 0;

#define REPLY_MAX 2048

static const uint8_t k_dns_query_example_com[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
};

static const uint8_t k_dns_response_payload[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
};

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static bool write_all_fd(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (n == 0)
        {
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static bool read_exact_fd(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (n == 0)
        {
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static bool can_run_loopback_socket_test(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return false;
    }
    close(fd);
    return true;
}

typedef struct
{
    int listen_fd;
    bool close_after_one_len_byte;
    size_t query_len;
    const uint8_t *response;
    size_t response_len;
    bool ok;
} upstream_server_t;

static void *upstream_server_thread(void *arg)
{
    upstream_server_t *srv = (upstream_server_t *)arg;
    srv->ok = false;

    int fd = accept(srv->listen_fd, NULL, NULL);
    if (fd < 0)
    {
        return NULL;
    }

    uint8_t req[2 + DNS_MSG_SIZE];
    if (srv->query_len > DNS_MSG_SIZE || !read_exact_fd(fd, req, 2 + srv->query_len))
    {
        close(fd);
        return NULL;
    }

    if (srv->close_after_one_len_byte)
    {
        uint8_t len_hi = (uint8_t)((srv->response_len >> 8) & 0xff);
        if (!write_all_fd(fd, &len_hi, 1))
        {
            close(fd);
            return NULL;
        }
        close(fd);
        srv->ok = true;
        return NULL;
    }

    uint8_t len_prefix[2] = {
        (uint8_t)((srv->response_len >> 8) & 0xff),
        (uint8_t)(srv->response_len & 0xff)
    };

    if (!write_all_fd(fd, len_prefix, 1) || !write_all_fd(fd, len_prefix + 1, 1))
    {
        close(fd);
        return NULL;
    }

    for (size_t i = 0; i < srv->response_len; i += 3)
    {
        size_t chunk = srv->response_len - i;
        if (chunk > 3)
        {
            chunk = 3;
        }
        if (!write_all_fd(fd, srv->response + i, chunk))
        {
            close(fd);
            return NULL;
        }
    }

    close(fd);
    srv->ok = true;
    return NULL;
}

static bool make_udp_bound_socket(int *fd, struct sockaddr_in *bound_addr)
{
    *fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*fd < 0)
    {
        return false;
    }

    memset(bound_addr, 0, sizeof(*bound_addr));
    bound_addr->sin_family = AF_INET;
    bound_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bound_addr->sin_port = htons(0);
    if (bind(*fd, (struct sockaddr *)bound_addr, sizeof(*bound_addr)) != 0)
    {
        close(*fd);
        *fd = -1;
        return false;
    }

    socklen_t addr_len = sizeof(*bound_addr);
    if (getsockname(*fd, (struct sockaddr *)bound_addr, &addr_len) != 0)
    {
        close(*fd);
        *fd = -1;
        return false;
    }
    return true;
}

typedef struct
{
    const uint8_t *query;
    size_t query_len;
    const uint8_t *response;
    size_t response_len;
    bool close_mid_prefix;
} dns_case_t;

/* Forward one query through a fake upstream; *reply_len is -1 when no UDP reply came. */
static bool run_dnsproxy_case(const dns_case_t *in, bool *server_ok, uint8_t *reply, ssize_t *reply_len)
{
    int listen_fd = -1;
    int local_udp_fd = -1;
    int client_udp_fd = -1;
    pthread_t upstream_tid;
    pthread_t handler_tid;
    struct sockaddr_in upstream_addr;
    struct sockaddr_in local_addr;
    struct sockaddr_in client_addr;
    socklen_t upstream_len = sizeof(upstream_addr);
    upstream_server_t server = {0};
    dnsserver_t dns = {0};
    dnsThread_test_t *worker_input = NULL;
    struct timeval tv = {0};

    *server_ok = false;
    *reply_len = -1;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        return false;
    }
    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    upstream_addr.sin_port = htons(0);
    if (bind(listen_fd, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) != 0 ||
        listen(listen_fd, 1) != 0 ||
        getsockname(listen_fd, (struct sockaddr *)&upstream_addr, &upstream_len) != 0)
    {
        close(listen_fd);
        return false;
    }

    if (!make_udp_bound_socket(&local_udp_fd, &local_addr) ||
        !make_udp_bound_socket(&client_udp_fd, &client_addr))
    {
        if (local_udp_fd >= 0) close(local_udp_fd);
        if (client_udp_fd >= 0) close(client_udp_fd);
        close(listen_fd);
        return false;
    }

    server.listen_fd = listen_fd;
    server.close_after_one_len_byte = in->close_mid_prefix;
    server.query_len = in->query_len;
    server.response = in->response;
    server.response_len = in->response_len;
    server.ok = false;
    if (pthread_create(&upstream_tid, NULL, upstream_server_thread, &server) != 0)
    {
        close(client_udp_fd);
        close(local_udp_fd);
        close(listen_fd);
        return false;
    }

    dns.local_sock = local_udp_fd;
    strcpy(dns.upstream.ip, "127.0.0.1");
    dns.upstream.port = ntohs(upstream_addr.sin_port);
    dns.timeout = 1;
    dns.socks = NULL;
    dns.whitelist = NULL;
    dns.Stat = NULL;

    worker_input = (dnsThread_test_t *)calloc(1, sizeof(*worker_input));
    if (!worker_input)
    {
        pthread_join(upstream_tid, NULL);
        close(client_udp_fd);
        close(local_udp_fd);
        close(listen_fd);
        return false;
    }

    worker_input->dns = &dns;
    worker_input->msg.len = (uint16_t)in->query_len;
    worker_input->msg.message[0] = (char)((worker_input->msg.len >> 8) & 0xff);
    worker_input->msg.message[1] = (char)(worker_input->msg.len & 0xff);
    memcpy(worker_input->msg.message + 2, in->query, in->query_len);
    worker_input->msg.client = client_addr;

    if (pthread_create(&handler_tid, NULL, handle_request_thread, worker_input) != 0)
    {
        free(worker_input);
        pthread_join(upstream_tid, NULL);
        close(client_udp_fd);
        close(local_udp_fd);
        close(listen_fd);
        return false;
    }

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(client_udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    *reply_len = recvfrom(client_udp_fd, reply, REPLY_MAX, 0, NULL, NULL);

    pthread_join(handler_tid, NULL);
    pthread_join(upstream_tid, NULL);
    *server_ok = server.ok;

    close(client_udp_fd);
    close(local_udp_fd);
    close(listen_fd);
    return true;
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void expect_rcode(const uint8_t *reply, ssize_t n, uint16_t id, unsigned rcode, const char *name)
{
    if (n < DNS_HEADER_SIZE)
    {
        fprintf(stderr, "FAIL: %s: no DNS reply (%zd)\n", name, n);
        failures++;
        return;
    }
    if (be16(reply) != id || (reply[2] & 0x80) == 0 || (reply[3] & 0x0F) != rcode)
    {
        fprintf(stderr, "FAIL: %s: id %04x flags %02x%02x, want id %04x rcode %u\n",
                name, be16(reply), reply[2], reply[3], id, rcode);
        failures++;
    }
}

static void test_dnsproxy_split_prefix_and_payload_forwarding(void)
{
    dns_case_t in = { k_dns_query_example_com, sizeof(k_dns_query_example_com),
                      k_dns_response_payload, sizeof(k_dns_response_payload), false };
    uint8_t reply[REPLY_MAX];
    ssize_t n = -1;
    bool server_ok = false;
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run dnsproxy split I/O case");
    expect_true(server_ok, "upstream server completed split response");
    expect_true(n == (ssize_t)sizeof(k_dns_response_payload) &&
                memcmp(reply, k_dns_response_payload, sizeof(k_dns_response_payload)) == 0,
                "udp client received forwarded dns payload");
}

static void test_dnsproxy_close_mid_prefix_servfail(void)
{
    dns_case_t in = { k_dns_query_example_com, sizeof(k_dns_query_example_com),
                      k_dns_response_payload, sizeof(k_dns_response_payload), true };
    uint8_t reply[REPLY_MAX];
    ssize_t n = -1;
    bool server_ok = false;
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run dnsproxy close-mid-prefix case");
    expect_true(server_ok, "upstream server closed mid-prefix as planned");
    expect_rcode(reply, n, 0x1234, ServerFailure_ResponseType, "upstream failure answers SERVFAIL");
    expect_true(n == (ssize_t)sizeof(k_dns_query_example_com), "SERVFAIL carries the question");
}

/* Query for example.com A, optionally with an EDNS0 OPT record advertising size. */
static size_t build_query(uint8_t *out, uint16_t qtype, uint16_t edns_size)
{
    size_t n = sizeof(k_dns_query_example_com);
    memcpy(out, k_dns_query_example_com, n);
    out[n - 4] = (uint8_t)(qtype >> 8);
    out[n - 3] = (uint8_t)qtype;
    if (edns_size)
    {
        const uint8_t opt[] = { 0x00, 0x00, 0x29, (uint8_t)(edns_size >> 8), (uint8_t)edns_size,
                                0, 0, 0, 0, 0, 0 };
        out[11] = 1;
        memcpy(out + n, opt, sizeof(opt));
        n += sizeof(opt);
    }
    return n;
}

/* A 1500-byte response: the question plus TXT records. */
static size_t build_large_response(uint8_t *out, size_t cap)
{
    size_t n = sizeof(k_dns_response_payload);
    uint16_t an = 0;
    memcpy(out, k_dns_response_payload, n);
    while (n + 12 + 200 <= cap && n < 1500)
    {
        const uint8_t rr[] = { 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 60, 0x00, 200 };
        memcpy(out + n, rr, sizeof(rr));
        n += sizeof(rr);
        out[n] = 199;
        memset(out + n + 1, 't', 199);
        n += 200;
        an++;
    }
    out[6] = (uint8_t)(an >> 8);
    out[7] = (uint8_t)an;
    return n;
}

static void test_dnsproxy_large_response(void)
{
    uint8_t query[64];
    uint8_t big[2048];
    uint8_t reply[REPLY_MAX];
    size_t big_len = build_large_response(big, sizeof(big));
    ssize_t n = -1;
    bool server_ok = false;
    dns_case_t in = { query, 0, big, big_len, false };

    /* Plain UDP client: larger than 512, so TC with the question only. */
    in.query_len = build_query(query, A_Resource_RecordType, 0);
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run large response without EDNS");
    expect_true(server_ok, "upstream sent large response");
    expect_rcode(reply, n, 0x1234, 0, "truncated large response");
    if (n >= DNS_HEADER_SIZE)
    {
        expect_true((reply[2] & 0x02) != 0, "large response sets TC");
        expect_true(be16(reply + 6) == 0, "truncated response drops records");
        expect_true(n == (ssize_t)sizeof(k_dns_query_example_com), "truncated response keeps the question");
    }

    /* EDNS 4096 is clamped to 1232; 1500 bytes still do not fit. */
    in.query_len = build_query(query, A_Resource_RecordType, 4096);
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run large response with EDNS 4096");
    expect_true(n >= DNS_HEADER_SIZE && (reply[2] & 0x02) != 0, "EDNS size is clamped to 1232");

    /* An 1100-byte answer fits an EDNS client and is delivered whole. */
    big_len = sizeof(k_dns_response_payload) + 5 * 212;
    big[7] = 5;
    in.response_len = big_len;
    in.query_len = build_query(query, A_Resource_RecordType, 1232);
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run 1100-byte response with EDNS");
    expect_true(n == (ssize_t)big_len && memcmp(reply, big, big_len) == 0,
                "EDNS client receives the whole 1100-byte response");
}

/* Answer one query locally and return the UDP reply length, or -1. */
static ssize_t local_exchange_at(filter_t *white, const uint8_t *query, size_t qlen, uint8_t *reply,
                                 int64_t received_ms)
{
    int local_fd = -1;
    int client_fd = -1;
    struct sockaddr_in local_addr;
    dnsserver_t dns = {0};
    dnsMessage_t msg = {0};
    struct timeval tv = {1, 0};
    int upstream_fd = -1;
    ssize_t n;

    if (!make_udp_bound_socket(&local_fd, &local_addr) ||
        !make_udp_bound_socket(&client_fd, &msg.client))
    {
        if (local_fd >= 0) close(local_fd);
        return -1;
    }
    dns.local_sock = local_fd;
    dns.whitelist = white;
    dns.sni_ip[0] = 10; dns.sni_ip[1] = 9; dns.sni_ip[2] = 8; dns.sni_ip[3] = 7;
    /* Nothing listens here, so a forwarded query fails fast. */
    strcpy(dns.upstream.ip, "127.0.0.1");
    dns.upstream.port = 9;
    dns.timeout = 1;
    msg.len = (uint16_t)qlen;
    msg.received_ms = received_ms;
    memcpy(msg.message + 2, query, qlen);

    localdns_handle_request(&dns, &msg, &upstream_fd);
    if (upstream_fd >= 0)
        close(upstream_fd);
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    n = recvfrom(client_fd, reply, REPLY_MAX, 0, NULL, NULL);
    close(client_fd);
    close(local_fd);
    return n;
}

static ssize_t local_exchange(filter_t *white, const uint8_t *query, size_t qlen, uint8_t *reply)
{
    return local_exchange_at(white, query, qlen, reply, 0);
}

static void test_dnsproxy_stale_query_dropped(void)
{
    uint8_t reply[REPLY_MAX];
    ssize_t n = local_exchange_at(NULL, k_dns_query_example_com, sizeof(k_dns_query_example_com), reply,
                                  net_mono_ms() - DNS_QUEUE_MAX_AGE_MS - 1000);
    expect_true(n < 0, "a query older than the queue limit is dropped without a reply");
}

static void test_dnsproxy_mismatched_reply(void)
{
    uint8_t wrong[sizeof(k_dns_response_payload)];
    uint8_t reply[REPLY_MAX];
    ssize_t n = -1;
    bool server_ok = false;
    dns_case_t in = { k_dns_query_example_com, sizeof(k_dns_query_example_com),
                      wrong, sizeof(wrong), false };

    memcpy(wrong, k_dns_response_payload, sizeof(wrong));
    wrong[1] ^= 0xff;
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run mismatched id case");
    expect_rcode(reply, n, 0x1234, ServerFailure_ResponseType, "reply with another id becomes SERVFAIL");

    memcpy(wrong, k_dns_response_payload, sizeof(wrong));
    wrong[14] = 'z';
    expect_true(run_dnsproxy_case(&in, &server_ok, reply, &n), "run mismatched question case");
    expect_rcode(reply, n, 0x1234, ServerFailure_ResponseType, "reply for another name becomes SERVFAIL");
}

static void test_dnsproxy_local_answers(void)
{
    const char *const entries[] = { "example.com" };
    filter_t *white = filter_from_list(entries, 1);
    uint8_t query[64];
    uint8_t reply[REPLY_MAX];
    size_t qlen;
    ssize_t n;
    size_t qend = sizeof(k_dns_query_example_com);

    expect_true(white != NULL, "whitelist for local answers");
    if (!white)
        return;

    qlen = build_query(query, A_Resource_RecordType, 0);
    n = local_exchange(white, query, qlen, reply);
    expect_rcode(reply, n, 0x1234, 0, "whitelisted A");
    if (n >= (ssize_t)(qend + 16))
    {
        expect_true(be16(reply + 6) == 1, "whitelisted A has one answer");
        expect_true((reply[3] & 0x80) != 0, "local answer sets RA");
        /* TTL sits before RDLENGTH (2) and the IPv4 address (4). */
        expect_true(memcmp(reply + n - 10, "\x00\x00\x01\x2c", 4) == 0, "local answer TTL is 300");
        expect_true(memcmp(reply + n - 4, "\x0a\x09\x08\x07", 4) == 0, "whitelisted A is the SNI address");
    }
    else
    {
        fprintf(stderr, "FAIL: whitelisted A reply too short (%zd)\n", n);
        failures++;
    }

    {
        const uint16_t nodata_types[] = { AAAA_Resource_RecordType, HTTPS_Resource_RecordType,
                                          SVCB_Resource_RecordType, MX_Resource_RecordType };
        size_t i;
        for (i = 0; i < sizeof(nodata_types) / sizeof(nodata_types[0]); i++)
        {
            qlen = build_query(query, nodata_types[i], 0);
            n = local_exchange(white, query, qlen, reply);
            expect_rcode(reply, n, 0x1234, 0, "whitelisted non-A is NOERROR");
            expect_true(n >= DNS_HEADER_SIZE && be16(reply + 6) == 0, "whitelisted non-A is NODATA");
        }
    }

    /* An EDNS query for a whitelisted name is answered locally too. */
    qlen = build_query(query, AAAA_Resource_RecordType, 1232);
    n = local_exchange(white, query, qlen, reply);
    expect_true(n >= DNS_HEADER_SIZE && be16(reply + 6) == 0 && (reply[3] & 0x0F) == 0,
                "whitelisted AAAA with EDNS is NODATA");

    qlen = build_query(query, A_Resource_RecordType, 0);
    query[2] = (uint8_t)(0x01 | (NOTIFY_OperationCode << 3));
    n = local_exchange(white, query, qlen, reply);
    expect_rcode(reply, n, 0x1234, NotImplemented_ResponseType, "non-QUERY opcode is NOTIMP");
    expect_true(n >= DNS_HEADER_SIZE && ((reply[2] >> 3) & 0x0F) == NOTIFY_OperationCode,
                "NOTIMP keeps the opcode");

    qlen = build_query(query, A_Resource_RecordType, 0);
    query[5] = 2;
    n = local_exchange(white, query, qlen, reply);
    expect_rcode(reply, n, 0x1234, FormatError_ResponseType, "two questions are FORMERR");

    qlen = build_query(query, A_Resource_RecordType, 0);
    query[5] = 0;
    n = local_exchange(white, query, qlen, reply);
    expect_rcode(reply, n, 0x1234, FormatError_ResponseType, "no question is FORMERR");

    filter_free(white);
}

typedef struct
{
    dnsserver_t *dns;
    int fd;
} tcp_serve_arg_t;

static void *serve_tcp_thread(void *arg)
{
    tcp_serve_arg_t *a = (tcp_serve_arg_t *)arg;
    int upstream_fd = -1;
    localdns_serve_tcp(a->dns, a->fd, &upstream_fd);
    if (upstream_fd >= 0)
        close(upstream_fd);
    return NULL;
}

/* Read one length-prefixed message; returns its length or -1. */
static ssize_t read_framed(int fd, uint8_t *buf, size_t cap)
{
    uint8_t prefix[2];
    size_t len;
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (!read_exact_fd(fd, prefix, 2))
        return -1;
    len = be16(prefix);
    if (len > cap || !read_exact_fd(fd, buf, len))
        return -1;
    return (ssize_t)len;
}

static size_t frame(uint8_t *out, const uint8_t *msg, size_t len)
{
    out[0] = (uint8_t)(len >> 8);
    out[1] = (uint8_t)len;
    memcpy(out + 2, msg, len);
    return len + 2;
}

static void tcp_test_dns(dnsserver_t *dns, filter_t *white, int wake[2])
{
    memset(dns, 0, sizeof(*dns));
    dns->local_sock = -1;
    dns->tcp_sock = -1;
    dns->whitelist = white;
    dns->sni_ip[0] = 10; dns->sni_ip[1] = 9; dns->sni_ip[2] = 8; dns->sni_ip[3] = 7;
    strcpy(dns->upstream.ip, "127.0.0.1");
    dns->upstream.port = 9;
    dns->timeout = 1;
    dns->wake[0] = wake[0];
    dns->wake[1] = wake[1];
}

static void test_dnsproxy_tcp_local_pipelined(void)
{
    const char *const entries[] = { "example.com" };
    filter_t *white = filter_from_list(entries, 1);
    int sv[2] = {-1, -1};
    int wake[2] = {-1, -1};
    dnsserver_t dns;
    tcp_serve_arg_t arg;
    pthread_t tid;
    uint8_t q[64];
    uint8_t out[256];
    uint8_t reply[REPLY_MAX];
    size_t qlen;
    size_t n = 0;
    ssize_t r;

    if (!white || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || pipe(wake) != 0)
    {
        fprintf(stderr, "FAIL: TCP local test setup\n");
        failures++;
        filter_free(white);
        return;
    }
    tcp_test_dns(&dns, white, wake);
    arg.dns = &dns;
    arg.fd = sv[1];
    expect_true(pthread_create(&tid, NULL, serve_tcp_thread, &arg) == 0, "start TCP server");

    /* Two queries in one write: RFC 7766 pipelining. */
    qlen = build_query(q, A_Resource_RecordType, 0);
    n = frame(out, q, qlen);
    q[1] = 0x35;
    q[sizeof(k_dns_query_example_com) - 3] = AAAA_Resource_RecordType;
    n += frame(out + n, q, qlen);
    expect_true(write_all_fd(sv[0], out, n), "send two framed queries");

    r = read_framed(sv[0], reply, sizeof(reply));
    expect_rcode(reply, r, 0x1234, 0, "TCP whitelisted A");
    expect_true(r >= DNS_HEADER_SIZE && be16(reply + 6) == 1 &&
                memcmp(reply + r - 4, "\x0a\x09\x08\x07", 4) == 0, "TCP A answer is the SNI address");
    r = read_framed(sv[0], reply, sizeof(reply));
    expect_rcode(reply, r, 0x1235, 0, "TCP whitelisted AAAA");
    expect_true(r >= DNS_HEADER_SIZE && be16(reply + 6) == 0, "TCP AAAA is NODATA");

    /* A response sent as a query ends the connection. */
    qlen = build_query(q, A_Resource_RecordType, 0);
    q[2] |= 0x80;
    n = frame(out, q, qlen);
    expect_true(write_all_fd(sv[0], out, n), "send a response as a query");
    r = read_framed(sv[0], reply, sizeof(reply));
    expect_true(r < 0, "connection closed after a QR message");
    pthread_join(tid, NULL);

    /* A stop request ends an idle connection at once. */
    close(sv[0]);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0)
    {
        int64_t start = net_mono_ms();
        arg.fd = sv[1];
        expect_true(write(wake[1], "x", 1) == 1, "signal stop");
        expect_true(pthread_create(&tid, NULL, serve_tcp_thread, &arg) == 0, "start TCP server for stop");
        pthread_join(tid, NULL);
        expect_true(net_mono_ms() - start < 1000, "stop ends an idle TCP connection quickly");
        close(sv[0]);
    }
    close(wake[0]);
    close(wake[1]);
    filter_free(white);
}

static void test_dnsproxy_tcp_large_reply(void)
{
    int listen_fd = -1;
    int sv[2] = {-1, -1};
    int wake[2] = {-1, -1};
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    upstream_server_t server = {0};
    pthread_t up_tid;
    pthread_t tid;
    dnsserver_t dns;
    tcp_serve_arg_t arg;
    uint8_t q[64];
    uint8_t out[128];
    uint8_t big[2048];
    uint8_t reply[REPLY_MAX];
    size_t big_len = build_large_response(big, sizeof(big));
    size_t qlen = build_query(q, A_Resource_RecordType, 0);
    ssize_t r;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 1) != 0 || getsockname(listen_fd, (struct sockaddr *)&addr, &alen) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || pipe(wake) != 0)
    {
        fprintf(stderr, "FAIL: TCP large reply setup\n");
        failures++;
        if (listen_fd >= 0) close(listen_fd);
        return;
    }
    server.listen_fd = listen_fd;
    server.query_len = qlen;
    server.response = big;
    server.response_len = big_len;
    pthread_create(&up_tid, NULL, upstream_server_thread, &server);

    tcp_test_dns(&dns, NULL, wake);
    dns.upstream.port = ntohs(addr.sin_port);
    arg.dns = &dns;
    arg.fd = sv[1];
    pthread_create(&tid, NULL, serve_tcp_thread, &arg);

    expect_true(write_all_fd(sv[0], out, frame(out, q, qlen)), "send framed query for a large reply");
    r = read_framed(sv[0], reply, sizeof(reply));
    expect_true(r == (ssize_t)big_len && memcmp(reply, big, big_len) == 0,
                "TCP client receives the whole 1500-byte reply");
    if (r >= DNS_HEADER_SIZE)
        expect_true((reply[2] & 0x02) == 0, "TCP reply is not truncated");

    close(sv[0]);
    pthread_join(tid, NULL);
    pthread_join(up_tid, NULL);
    close(listen_fd);
    close(wake[0]);
    close(wake[1]);
}

int main(void)
{
    log_set_quiet(1);

    if (!can_run_loopback_socket_test())
    {
        return 0;
    }

    test_dnsproxy_split_prefix_and_payload_forwarding();
    test_dnsproxy_close_mid_prefix_servfail();
    test_dnsproxy_large_response();
    test_dnsproxy_local_answers();
    test_dnsproxy_stale_query_dropped();
    test_dnsproxy_mismatched_reply();
    test_dnsproxy_tcp_local_pipelined();
    test_dnsproxy_tcp_large_reply();
    return failures == 0 ? 0 : 1;
}
