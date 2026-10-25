#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifndef ZROXY_BIN
#error ZROXY_BIN is required
#endif

/* Matches MON_MAX_WORKERS in statistics/monitor.c. */
#define MON_CAP 32

static int failures = 0;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void dump_log(const char *path)
{
    FILE *fp;
    char buf[4096];
    size_t n;

    fp = fopen(path, "r");
    if (!fp)
        return;
    fprintf(stderr, "---- zroxy log ----\n");
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fputs(buf, stderr);
    fputs("\n---- end log ----\n", stderr);
    fclose(fp);
}

static pid_t spawn_child(char *const argv[], const char *logpath)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
    {
        int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0)
        {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO)
                close(fd);
        }
        execv(ZROXY_BIN, argv);
        _exit(127);
    }
    return pid;
}

static void stop_child(pid_t pid)
{
    int status;
    int i;
    if (pid <= 0)
        return;
    kill(pid, SIGTERM);
    for (i = 0; i < 40; i++)
    {
        if (waitpid(pid, &status, WNOHANG) == pid)
            return;
        usleep(50000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
}

static bool wait_code(pid_t pid, int *code)
{
    int status;
    int i;
    for (i = 0; i < 60; i++)
    {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid)
        {
            if (!WIFEXITED(status))
            {
                *code = -1;
                return false;
            }
            *code = WEXITSTATUS(status);
            return true;
        }
        if (got < 0)
            return false;
        usleep(50000);
    }
    stop_child(pid);
    return false;
}

static int connect_port(uint16_t port, int timeout_ms)
{
    int fd;
    int flags;
    int err = 0;
    socklen_t elen = sizeof(err);
    struct sockaddr_in addr;
    struct pollfd pfd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 && errno != EINPROGRESS)
    {
        close(fd);
        return -1;
    }
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, timeout_ms) <= 0 ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0)
    {
        close(fd);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int wait_connect(uint16_t port)
{
    int i;
    for (i = 0; i < 50; i++)
    {
        int fd = connect_port(port, 200);
        if (fd >= 0)
            return fd;
        usleep(50000);
    }
    return -1;
}

static bool reserve_port(uint16_t *port)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return false;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
    {
        close(fd);
        return false;
    }
    *port = ntohs(addr.sin_port);
    close(fd);
    return *port != 0;
}

static bool send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

static bool read_until_close(int fd, char *buf, size_t cap, size_t *out)
{
    size_t n = 0;
    int waited = 0;

    while (n + 1 < cap && waited < 2000)
    {
        struct pollfd pfd;
        ssize_t r;
        pfd.fd = fd;
        pfd.events = POLLIN;
        int rc = poll(&pfd, 1, 200);
        if (rc < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (rc == 0)
        {
            waited += 200;
            continue;
        }
        r = recv(fd, buf + n, cap - 1 - n, 0);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (r == 0)
        {
            buf[n] = '\0';
            *out = n;
            return true;
        }
        n += (size_t)r;
    }
    buf[n] = '\0';
    *out = n;
    return false;
}

static bool log_has_sanitizer(const char *path)
{
    FILE *fp;
    char buf[8192];
    size_t n;

    fp = fopen(path, "r");
    if (!fp)
        return false;
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return strstr(buf, "Sanitizer") != NULL;
}

static void test_exit_code(char *const argv[], const char *logpath, const char *name)
{
    pid_t pid;
    int code = -1;
    int before = failures;

    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, name);
    if (pid <= 0)
        return;
    expect_true(wait_code(pid, &code), name);
    expect_true(code == 1, name);
    expect_true(!log_has_sanitizer(logpath), name);
    if (failures != before)
        dump_log(logpath);
}

static void test_missing_whitelist(const char *logpath)
{
    char *argv[] = {ZROXY_BIN, "-w", "/no/such/zroxy-whitelist", NULL};
    test_exit_code(argv, logpath, "missing whitelist exits 1");
}

static void test_invalid_configuration(const char *logpath)
{
    char bad_port[] = "127.0.0.1:99999@80";
    char bad_ip[] = "not-an-ip:80@80";
    char *argv_port[] = {ZROXY_BIN, "-p", bad_port, NULL};
    char *argv_ip[] = {ZROXY_BIN, "-p", bad_ip, NULL};

    test_exit_code(argv_port, logpath, "port 99999 exits 1");
    test_exit_code(argv_ip, logpath, "non-IP bind address exits 1");
}

static bool content_length_matches(const char *response)
{
    const char *hdr = strstr(response, "Content-Length:");
    const char *body;
    char *end = NULL;
    long declared;
    size_t actual;

    if (!hdr)
        return false;
    declared = strtol(hdr + strlen("Content-Length:"), &end, 10);
    body = strstr(response, "\n\n");
    if (!body || declared < 0)
        return false;
    body += 2;
    actual = strlen(body);
    if ((size_t)declared != actual)
    {
        fprintf(stderr, "FAIL: Content-Length %ld, body %zu\n", declared, actual);
        return false;
    }
    return strstr(body, "ZroxyVersion") != NULL;
}

static void test_monitor_requests(const char *logpath)
{
    uint16_t port = 0;
    char port_text[8];
    char *argv[4];
    pid_t pid;
    int fd;
    int before;
    char response[8192];
    size_t n = 0;
    char partial[] = "GET / HTTP/1.1\r\nHost: x";
    char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    char *filled;
    int fds[MON_CAP + 1];
    struct pollfd pfds[MON_CAP + 1];
    int i;
    int closed = 0;

    before = failures;
    expect_true(reserve_port(&port), "reserve monitor port");
    snprintf(port_text, sizeof(port_text), "%u", port);
    argv[0] = ZROXY_BIN;
    argv[1] = "-m";
    argv[2] = port_text;
    argv[3] = NULL;
    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start monitor");
    if (pid <= 0)
        return;

    fd = wait_connect(port);
    expect_true(fd >= 0, "monitor accepts a connection");
    if (fd >= 0)
    {
        expect_true(send_all(fd, partial, strlen(partial)), "send a header fragment");
        shutdown(fd, SHUT_WR);
        expect_true(read_until_close(fd, response, sizeof(response), &n), "incomplete header is closed");
        expect_true(strstr(response, "ZroxyVersion") == NULL, "incomplete header has no JSON");
        close(fd);
    }

    filled = malloc(16384);
    expect_true(filled != NULL, "allocate a full monitor buffer");
    if (filled)
    {
        memset(filled, 'A', 16384);
        fd = wait_connect(port);
        expect_true(fd >= 0, "monitor accepts the full-buffer connection");
        if (fd >= 0)
        {
            expect_true(send_all(fd, filled, 16384), "send 16384 bytes without a header terminator");
            expect_true(read_until_close(fd, response, sizeof(response), &n), "full buffer is closed");
            expect_true(strstr(response, "ZroxyVersion") == NULL, "full buffer has no JSON");
            close(fd);
        }
        free(filled);
    }

    fd = wait_connect(port);
    expect_true(fd >= 0, "monitor accepts a complete request");
    if (fd >= 0)
    {
        expect_true(send_all(fd, request, strlen(request)), "send a complete monitor request");
        expect_true(read_until_close(fd, response, sizeof(response), &n), "complete request returns a body");
        expect_true(content_length_matches(response), "monitor Content-Length matches the JSON body");
        close(fd);
    }

    usleep(200000);
    for (i = 0; i < MON_CAP + 1; i++)
        fds[i] = -1;
    for (i = 0; i < MON_CAP + 1; i++)
    {
        fds[i] = connect_port(port, 2000);
        if (fds[i] < 0)
            break;
        if (!send_all(fds[i], "A", 1))
            break;
    }
    expect_true(i == MON_CAP + 1, "opened one connection past the monitor cap");
    for (i = 0; i < MON_CAP + 1; i++)
    {
        pfds[i].fd = fds[i];
        pfds[i].events = POLLIN;
    }
    poll(pfds, MON_CAP + 1, 2000);
    for (i = 0; i < MON_CAP + 1; i++)
    {
        char scratch;
        ssize_t nread;
        if (fds[i] < 0)
            continue;
        nread = recv(fds[i], &scratch, 1, MSG_DONTWAIT);
        if (nread == 0 || (nread < 0 && errno == ECONNRESET))
            closed++;
    }
    if (closed != 1)
        fprintf(stderr, "FAIL: monitor cap closed %d connections\n", closed);
    expect_true(closed == 1, "monitor cap closes the connection past 32 workers");
    for (i = 0; i < MON_CAP + 1; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }

    expect_true(!log_has_sanitizer(logpath), "monitor run stays free of sanitizer reports");
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
}

static int listen_localhost(uint16_t *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd = -1;
    int on = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo("localhost", NULL, &hints, &res) != 0 || !res)
        return -1;
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0)
    {
        freeaddrinfo(res);
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (res->ai_family == AF_INET)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        memcpy(&addr, res->ai_addr, sizeof(addr));
        addr.sin_port = 0;
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            listen(fd, 1) != 0 ||
            getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
        {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        *port = ntohs(addr.sin_port);
    }
    else if (res->ai_family == AF_INET6)
    {
        struct sockaddr_in6 addr;
        socklen_t len = sizeof(addr);
        memcpy(&addr, res->ai_addr, sizeof(addr));
        addr.sin6_port = 0;
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            listen(fd, 1) != 0 ||
            getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
        {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        *port = ntohs(addr.sin6_port);
    }
    else
    {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void test_sigpipe_does_not_kill_process(const char *logpath)
{
    uint16_t backend_port = 0;
    uint16_t zport = 0;
    int backend;
    int client;
    int second;
    int accepted = -1;
    pid_t pid;
    char spec[64];
    char timeout[] = "2";
    char *argv[6];
    struct pollfd pfd;
    char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    char extra[] = "MORE";
    char scratch[128];
    int before = failures;

    backend = listen_localhost(&backend_port);
    expect_true(backend >= 0, "backend listens on localhost");
    expect_true(reserve_port(&zport), "reserve SNI port");
    if (backend < 0 || zport == 0)
        return;
    snprintf(spec, sizeof(spec), "127.0.0.1:%u@%u", zport, backend_port);
    argv[0] = ZROXY_BIN;
    argv[1] = "-o";
    argv[2] = timeout;
    argv[3] = "-p";
    argv[4] = spec;
    argv[5] = NULL;
    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start SNI listener");
    if (pid <= 0)
    {
        close(backend);
        return;
    }

    client = wait_connect(zport);
    expect_true(client >= 0, "SNI listener accepts");
    if (client >= 0)
        expect_true(send_all(client, request, strlen(request)), "send Host localhost");

    pfd.fd = backend;
    pfd.events = POLLIN;
    expect_true(poll(&pfd, 1, 3000) > 0, "upstream received the forwarded connection");
    if (pfd.revents & POLLIN)
    {
        accepted = accept(backend, NULL, NULL);
        expect_true(accepted >= 0, "accept upstream connection");
        if (accepted >= 0)
        {
            struct pollfd up;
            up.fd = accepted;
            up.events = POLLIN;
            if (poll(&up, 1, 1000) > 0)
                recv(accepted, scratch, sizeof(scratch), 0);
            close(accepted);
        }
    }
    if (client >= 0)
        send_all(client, extra, sizeof(extra) - 1);
    usleep(200000);
    expect_true(kill(pid, 0) == 0, "SIGPIPE does not kill the process");
    second = connect_port(zport, 1000);
    expect_true(second >= 0, "listener still accepts after a closed upstream");
    if (second >= 0)
        close(second);
    if (client >= 0)
        close(client);
    close(backend);
    expect_true(!log_has_sanitizer(logpath), "SNI run stays free of sanitizer reports");
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
}

int main(void)
{
    char logpath[] = "/tmp/zroxy-verify-XXXXXX";
    int logfd = mkstemp(logpath);

    if (logfd < 0)
        return 1;
    close(logfd);

    test_missing_whitelist(logpath);
    test_invalid_configuration(logpath);
    test_monitor_requests(logpath);
    test_sigpipe_does_not_kill_process(logpath);

    unlink(logpath);
    return failures == 0 ? 0 : 1;
}
