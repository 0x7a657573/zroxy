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

#include "log.h"
#include "sniproxy.h"
#include "sniclient.h"

static int failures = 0;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void expect_bytes_eq(const uint8_t *actual, const uint8_t *expected, size_t len, const char *name)
{
    if (memcmp(actual, expected, len) != 0)
    {
        fprintf(stderr, "FAIL: %s mismatch\n", name);
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

typedef struct
{
    int listen_fd;
    const uint8_t *expected_req;
    size_t expected_req_len;
    const uint8_t *response;
    size_t response_len;
    bool ok;
} upstream_server_t;

static void *upstream_thread(void *arg)
{
    upstream_server_t *srv = (upstream_server_t *)arg;
    srv->ok = false;

    int fd = accept(srv->listen_fd, NULL, NULL);
    if (fd < 0)
    {
        return NULL;
    }

    uint8_t req_buf[1024];
    if (srv->expected_req_len > sizeof(req_buf))
    {
        close(fd);
        return NULL;
    }
    if (!read_exact_fd(fd, req_buf, srv->expected_req_len))
    {
        close(fd);
        return NULL;
    }
    if (memcmp(req_buf, srv->expected_req, srv->expected_req_len) != 0)
    {
        close(fd);
        return NULL;
    }

    if (!write_all_fd(fd, srv->response, srv->response_len))
    {
        close(fd);
        return NULL;
    }

    close(fd);
    srv->ok = true;
    return NULL;
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

static void test_sni_forwarding_basic(void)
{
    static const uint8_t request[] =
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n";
    static const uint8_t response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK";

    int listen_fd = -1;
    int pair[2] = {-1, -1};
    int one = 1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    pthread_t up_tid;
    pthread_t sni_tid;
    upstream_server_t server = {0};
    sniclient_t *client = NULL;
    uint8_t resp_buf[sizeof(response)];
    struct timeval tv = {0};

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    expect_true(listen_fd >= 0, "create upstream listen socket");
    if (listen_fd < 0)
    {
        return;
    }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    expect_true(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind upstream listen");
    expect_true(listen(listen_fd, 1) == 0, "listen upstream");
    expect_true(getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) == 0, "getsockname upstream");

    if (failures != 0)
    {
        close(listen_fd);
        return;
    }

    server.listen_fd = listen_fd;
    server.expected_req = request;
    server.expected_req_len = sizeof(request) - 1;
    server.response = response;
    server.response_len = sizeof(response) - 1;
    expect_true(pthread_create(&up_tid, NULL, upstream_thread, &server) == 0, "start upstream thread");
    if (failures != 0)
    {
        close(listen_fd);
        return;
    }

    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "create socketpair");
    if (failures != 0)
    {
        close(listen_fd);
        pthread_join(up_tid, NULL);
        return;
    }

    client = (sniclient_t *)calloc(1, sizeof(*client));
    expect_true(client != NULL, "alloc sniclient");
    if (!client)
    {
        close(pair[0]);
        close(pair[1]);
        close(listen_fd);
        pthread_join(up_tid, NULL);
        return;
    }

    client->connid = pair[1];
    strcpy(client->SniConfig.Port.bindip, "127.0.0.1");
    client->SniConfig.Port.local_port = 0;
    client->SniConfig.Port.remote_port = ntohs(addr.sin_port);
    client->SniConfig.Socks = NULL;
    client->SniConfig.sta = NULL;
    client->SniConfig.wlist = NULL;
    client->SniConfig.snitimeout = 2;

    expect_true(pthread_create(&sni_tid, NULL, SniClientHandler, client) == 0, "start sniclient handler");
    if (failures != 0)
    {
        close(pair[0]);
        close(pair[1]);
        close(listen_fd);
        pthread_join(up_tid, NULL);
        free(client);
        return;
    }

    expect_true(write_all_fd(pair[0], request, sizeof(request) - 1), "write request to client socket");
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    expect_true(read_exact_fd(pair[0], resp_buf, sizeof(response) - 1), "read response from client socket");
    if (failures == 0)
    {
        expect_bytes_eq(resp_buf, response, sizeof(response) - 1, "response bytes forwarded");
    }

    close(pair[0]);
    close(listen_fd);
    pthread_join(sni_tid, NULL);
    pthread_join(up_tid, NULL);
    expect_true(server.ok, "upstream received full request and sent response");
}

int main(void)
{
    log_set_quiet(1);

    if (!can_run_loopback_socket_test())
    {
        return 0;
    }

    test_sni_forwarding_basic();
    return failures == 0 ? 0 : 1;
}
