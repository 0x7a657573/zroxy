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

#include "dnsproxy.h"
#include "log.h"

void *DNS_HandleIncomingRequset(void *ptr);

typedef struct
{
    dnsserver_t *dns;
    dnsMessage_t msg;
} dnsThread_test_t;

static int failures = 0;

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

static void expect_false(bool value, const char *name)
{
    if (value)
    {
        fprintf(stderr, "FAIL: %s expected false\n", name);
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

    uint8_t req[2 + sizeof(k_dns_query_example_com)];
    if (!read_exact_fd(fd, req, sizeof(req)))
    {
        close(fd);
        return NULL;
    }

    if (srv->close_after_one_len_byte)
    {
        uint8_t len_hi = (uint8_t)((sizeof(k_dns_response_payload) >> 8) & 0xff);
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
        (uint8_t)((sizeof(k_dns_response_payload) >> 8) & 0xff),
        (uint8_t)(sizeof(k_dns_response_payload) & 0xff)
    };

    if (!write_all_fd(fd, len_prefix, 1) || !write_all_fd(fd, len_prefix + 1, 1))
    {
        close(fd);
        return NULL;
    }

    for (size_t i = 0; i < sizeof(k_dns_response_payload); i += 3)
    {
        size_t chunk = sizeof(k_dns_response_payload) - i;
        if (chunk > 3)
        {
            chunk = 3;
        }
        if (!write_all_fd(fd, k_dns_response_payload + i, chunk))
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

static bool run_dnsproxy_case(bool close_mid_prefix, bool *server_ok, bool *received_udp)
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
    uint8_t udp_rx[DNS_MSG_SIZE];
    struct timeval tv = {0};

    *server_ok = false;
    *received_udp = false;

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
    server.close_after_one_len_byte = close_mid_prefix;
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
    worker_input->msg.len = sizeof(k_dns_query_example_com);
    worker_input->msg.message[0] = (uint8_t)((worker_input->msg.len >> 8) & 0xff);
    worker_input->msg.message[1] = (uint8_t)(worker_input->msg.len & 0xff);
    memcpy(worker_input->msg.message + 2, k_dns_query_example_com, sizeof(k_dns_query_example_com));
    worker_input->msg.client = client_addr;

    if (pthread_create(&handler_tid, NULL, DNS_HandleIncomingRequset, worker_input) != 0)
    {
        free(worker_input);
        pthread_join(upstream_tid, NULL);
        close(client_udp_fd);
        close(local_udp_fd);
        close(listen_fd);
        return false;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    setsockopt(client_udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recvfrom(client_udp_fd, udp_rx, sizeof(udp_rx), 0, NULL, NULL);
    if (n > 0)
    {
        *received_udp = true;
        if (!close_mid_prefix)
        {
            if ((size_t)n != sizeof(k_dns_response_payload) ||
                memcmp(udp_rx, k_dns_response_payload, sizeof(k_dns_response_payload)) != 0)
            {
                failures++;
                fprintf(stderr, "FAIL: forwarded UDP payload mismatch\n");
            }
        }
    }

    pthread_join(handler_tid, NULL);
    pthread_join(upstream_tid, NULL);
    *server_ok = server.ok;

    close(client_udp_fd);
    close(local_udp_fd);
    close(listen_fd);
    return true;
}

static void test_dnsproxy_split_prefix_and_payload_forwarding(void)
{
    bool server_ok = false;
    bool received_udp = false;
    expect_true(run_dnsproxy_case(false, &server_ok, &received_udp), "run dnsproxy split I/O case");
    expect_true(server_ok, "upstream server completed split response");
    expect_true(received_udp, "udp client received forwarded dns payload");
}

static void test_dnsproxy_close_mid_prefix_no_udp_reply(void)
{
    bool server_ok = false;
    bool received_udp = false;
    expect_true(run_dnsproxy_case(true, &server_ok, &received_udp), "run dnsproxy close-mid-prefix case");
    expect_true(server_ok, "upstream server closed mid-prefix as planned");
    expect_false(received_udp, "no udp reply when upstream closes mid-prefix");
}

int main(void)
{
    log_set_quiet(1);

    if (!can_run_loopback_socket_test())
    {
        return 0;
    }

    test_dnsproxy_split_prefix_and_payload_forwarding();
    test_dnsproxy_close_mid_prefix_no_udp_reply();
    return failures == 0 ? 0 : 1;
}
