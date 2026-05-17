#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "config.h"
#include "log.h"
#include "net.h"

static int failures = 0;

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

static void expect_string(const char *actual, const char *expected, const char *name)
{
    if (strcmp(actual, expected) != 0)
    {
        fprintf(stderr, "FAIL: %s expected '%s', got '%s'\n", name, expected, actual);
        failures++;
    }
}

static void test_http_host_valid(void)
{
    uint8_t request[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n"
        "\r\n";
    char host[_MaxHostName_] = {0};

    expect_true(net_GetHttpHost(request, (uint32_t)strlen((char *)request), host, sizeof(host)),
                "valid HTTP Host");
    expect_string(host, "example.com", "valid HTTP Host value");
}

static void test_http_without_host(void)
{
    uint8_t request[] =
        "GET / HTTP/1.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    char host[_MaxHostName_] = "unchanged";

    expect_false(net_GetHttpHost(request, (uint32_t)strlen((char *)request), host, sizeof(host)),
                 "HTTP without Host");
    expect_string(host, "", "HTTP without Host clears output");
}

static void test_http_host_with_port(void)
{
    uint8_t request[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com:443\r\n"
        "Connection: close\r\n"
        "\r\n";
    char host[_MaxHostName_] = {0};

    expect_true(net_GetHttpHost(request, (uint32_t)strlen((char *)request), host, sizeof(host)),
                "HTTP Host with port");
    expect_string(host, "example.com:443", "HTTP Host with port value");
}

static void test_tls_sni_valid(void)
{
    static const uint8_t client_hello[] = {
        0x16, 0x03, 0x03, 0x00, 0x43,
        0x01, 0x00, 0x00, 0x3f,
        0x03, 0x03,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        0x00, 0x02, 0x13, 0x01,
        0x01, 0x00,
        0x00, 0x14,
        0x00, 0x00, 0x00, 0x10,
        0x00, 0x0e,
        0x00,
        0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };
    char host[_MaxHostName_] = {0};

    expect_true(net_GetHttpsHost((uint8_t *)client_hello, sizeof(client_hello), host, sizeof(host)),
                "valid TLS SNI");
    expect_string(host, "example.com", "valid TLS SNI value");
}

static void test_net_connect_failure_sets_invalid_fd(void)
{
    int fd = 12345;
    expect_false(net_connect(&fd, "127.0.0.1", 1), "connect to closed port fails");
    if (fd != -1)
    {
        fprintf(stderr, "FAIL: failed connect should set fd=-1, got %d\n", fd);
        failures++;
    }
}

static void test_net_connect_success_loopback(void)
{
    int listen_fd = -1;
    int client_fd = -1;
    int accepted_fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    expect_true(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind loopback listener");
    expect_true(listen(listen_fd, 1) == 0, "listen loopback");
    expect_true(getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) == 0, "getsockname loopback");
    if (failures != 0)
    {
        close(listen_fd);
        return;
    }

    expect_true(net_connect(&client_fd, "127.0.0.1", ntohs(addr.sin_port)), "connect to loopback listener");
    expect_true(client_fd >= 0, "successful connect returns valid fd");
    if (client_fd >= 0)
    {
        accepted_fd = accept(listen_fd, NULL, NULL);
        expect_true(accepted_fd >= 0, "accept loopback client");
    }

    if (accepted_fd >= 0) close(accepted_fd);
    if (client_fd >= 0) close(client_fd);
    close(listen_fd);
}

int main(void)
{
    log_set_quiet(1);

    test_http_host_valid();
    test_http_without_host();
    test_http_host_with_port();
    test_tls_sni_valid();
    test_net_connect_failure_sets_invalid_fd();
    test_net_connect_success_loopback();

    return failures == 0 ? 0 : 1;
}
