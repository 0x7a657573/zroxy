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
#include <unistd.h>

#include "log.h"
#include "socks.h"

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

static bool write_split_bytes(int fd, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (!write_all_fd(fd, buf + i, 1))
        {
            return false;
        }
    }
    return true;
}

enum scenario_mode
{
    SCENARIO_NO_AUTH = 1,
    SCENARIO_USERPASS = 2,
    SCENARIO_CLOSE_MID_REPLY = 3
};

typedef struct
{
    int listen_fd;
    enum scenario_mode mode;
    bool server_ok;
    int stage;
} scenario_t;

static bool expect_connect_request_ipv4(int fd, const char *ip, uint16_t port)
{
    uint8_t req[10];
    uint8_t expected[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    in_addr_t host_ip = inet_addr(ip);
    memcpy(expected + 4, &host_ip, 4);
    expected[8] = (uint8_t)((port >> 8) & 0xff);
    expected[9] = (uint8_t)(port & 0xff);

    if (!read_exact_fd(fd, req, sizeof(req)))
    {
        return false;
    }
    return memcmp(req, expected, sizeof(req)) == 0;
}

static void *server_thread(void *arg)
{
    scenario_t *sc = (scenario_t *)arg;
    sc->server_ok = false;
    sc->stage = 0;

    int client_fd = accept(sc->listen_fd, NULL, NULL);
    if (client_fd < 0)
    {
        sc->stage = -1;
        return NULL;
    }
    sc->stage = 1;

    uint8_t hello[4];
    const uint8_t expected_hello[4] = {0x05, 0x02, 0x00, 0x02};
    if (!read_exact_fd(client_fd, hello, sizeof(hello)))
    {
        sc->stage = -2;
        close(client_fd);
        return NULL;
    }
    if (memcmp(hello, expected_hello, sizeof(hello)) != 0)
    {
        sc->stage = -3;
        close(client_fd);
        return NULL;
    }
    sc->stage = 2;

    if (sc->mode == SCENARIO_NO_AUTH)
    {
        const uint8_t method_reply[2] = {0x05, 0x00};
        const uint8_t connect_reply[] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90};
        if (!write_split_bytes(client_fd, method_reply, sizeof(method_reply)))
        {
            sc->stage = -4;
            close(client_fd);
            return NULL;
        }
        if (!expect_connect_request_ipv4(client_fd, "1.2.3.4", 443))
        {
            sc->stage = -5;
            close(client_fd);
            return NULL;
        }
        if (!write_split_bytes(client_fd, connect_reply, sizeof(connect_reply)))
        {
            sc->stage = -6;
            close(client_fd);
            return NULL;
        }
        sc->server_ok = true;
    }
    else if (sc->mode == SCENARIO_USERPASS)
    {
        const uint8_t method_reply[2] = {0x05, 0x02};
        const uint8_t expected_auth[] = {
            0x01, 0x08, 'U', 's', 'e', 'r', 'N', 'a', 'm', 'e',
            0x08, 'P', 'a', 's', 's', 'W', 'o', 'r', 'd'
        };
        const uint8_t auth_reply[2] = {0x01, 0x00};
        const uint8_t connect_reply[] = {0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x04, 0x38};
        uint8_t auth_buf[sizeof(expected_auth)];
        if (!write_split_bytes(client_fd, method_reply, sizeof(method_reply)))
        {
            sc->stage = -7;
            close(client_fd);
            return NULL;
        }
        if (!read_exact_fd(client_fd, auth_buf, sizeof(auth_buf)))
        {
            sc->stage = -8;
            close(client_fd);
            return NULL;
        }
        if (memcmp(auth_buf, expected_auth, sizeof(expected_auth)) != 0)
        {
            sc->stage = -9;
            close(client_fd);
            return NULL;
        }
        if (!write_split_bytes(client_fd, auth_reply, sizeof(auth_reply)))
        {
            sc->stage = -10;
            close(client_fd);
            return NULL;
        }
        if (!expect_connect_request_ipv4(client_fd, "8.8.8.8", 53))
        {
            sc->stage = -11;
            close(client_fd);
            return NULL;
        }
        if (!write_split_bytes(client_fd, connect_reply, sizeof(connect_reply)))
        {
            sc->stage = -12;
            close(client_fd);
            return NULL;
        }
        sc->server_ok = true;
    }
    else if (sc->mode == SCENARIO_CLOSE_MID_REPLY)
    {
        const uint8_t method_reply[2] = {0x05, 0x00};
        const uint8_t partial_reply[2] = {0x05, 0x00};
        if (!write_split_bytes(client_fd, method_reply, sizeof(method_reply)))
        {
            sc->stage = -13;
            close(client_fd);
            return NULL;
        }
        if (!expect_connect_request_ipv4(client_fd, "9.9.9.9", 443))
        {
            sc->stage = -14;
            close(client_fd);
            return NULL;
        }
        if (!write_split_bytes(client_fd, partial_reply, sizeof(partial_reply)))
        {
            sc->stage = -15;
            close(client_fd);
            return NULL;
        }
        sc->server_ok = true;
    }

    close(client_fd);
    return NULL;
}

static bool run_scenario(enum scenario_mode mode, sockshost_t *socks, const char *dst_host, int dst_port, bool *server_ok, int *stage)
{
    int listen_fd = -1;
    int client_fd = -1;
    pthread_t tid;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    scenario_t sc = {0};

    *server_ok = false;
    *stage = 0;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        *stage = -1;
        return false;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        *stage = -2;
        close(listen_fd);
        return false;
    }
    if (listen(listen_fd, 1) != 0)
    {
        *stage = -3;
        close(listen_fd);
        return false;
    }
    if (getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) != 0)
    {
        *stage = -4;
        close(listen_fd);
        return false;
    }

    sc.listen_fd = listen_fd;
    sc.mode = mode;
    sc.server_ok = false;
    if (pthread_create(&tid, NULL, server_thread, &sc) != 0)
    {
        *stage = -5;
        close(listen_fd);
        return false;
    }

    socks->host = "127.0.0.1";
    socks->port = ntohs(addr.sin_port);

    bool ok = socks5_connect(&client_fd, socks, dst_host, dst_port, false);
    if (ok)
    {
        close(client_fd);
    }

    pthread_join(tid, NULL);
    close(listen_fd);

    *server_ok = sc.server_ok;
    *stage = sc.stage;
    return ok;
}

static void test_no_auth_split_reply_success(void)
{
    sockshost_t socks = {0};
    bool server_ok = false;
    int stage = 0;
    bool ok = run_scenario(SCENARIO_NO_AUTH, &socks, "1.2.3.4", 443, &server_ok, &stage);
    (void)stage;
    expect_true(server_ok, "no-auth server observed expected bytes");
    expect_true(ok, "no-auth split reply handshake success");
}

static void test_userpass_split_reply_success(void)
{
    sockshost_t socks = {0};
    bool server_ok = false;
    int stage = 0;
    socks.user = "UserName";
    socks.pass = "PassWord";
    bool ok = run_scenario(SCENARIO_USERPASS, &socks, "8.8.8.8", 53, &server_ok, &stage);
    (void)stage;
    expect_true(server_ok, "user/pass server observed expected bytes");
    expect_true(ok, "user/pass split reply handshake success");
}

static void test_close_mid_reply_fails(void)
{
    sockshost_t socks = {0};
    bool server_ok = false;
    int stage = 0;
    bool ok = run_scenario(SCENARIO_CLOSE_MID_REPLY, &socks, "9.9.9.9", 443, &server_ok, &stage);
    (void)stage;
    expect_true(server_ok, "mid-reply-close server observed expected bytes");
    expect_false(ok, "server close mid-reply should fail cleanly");
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

int main(void)
{
    log_set_quiet(1);

    if (!can_run_loopback_socket_test())
    {
        return 0;
    }

    test_no_auth_split_reply_success();
    test_userpass_split_reply_success();
    test_close_mid_reply_fails();

    return failures == 0 ? 0 : 1;
}
