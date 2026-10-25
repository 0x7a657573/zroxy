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
#include <sys/time.h>
#include <time.h>
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
    for (i = 0; i < 40; i++)
    {
        if (waitpid(pid, &status, WNOHANG) == pid)
            return;
        usleep(50000);
    }
    fprintf(stderr, "FAIL: child %d survived SIGKILL\n", (int)pid);
    _exit(2);
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
    {
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        {
            close(fd);
            return -1;
        }
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

static bool log_has(const char *path, const char *needle)
{
    FILE *fp;
    char buf[1024];

    fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(buf, sizeof(buf), fp))
    {
        if (strstr(buf, needle))
        {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

static bool proc_tcp_local(uint16_t port, const char *ip_hex)
{
    FILE *fp;
    char line[512];
    char needle[32];

    snprintf(needle, sizeof(needle), "%s:%04X", ip_hex, port);
    fp = fopen("/proc/net/tcp", "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp))
    {
        if (strstr(line, needle))
        {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
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

static void test_exit_code_log(char *const argv[], const char *logpath, const char *name, const char *needle)
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
    expect_true(log_has(logpath, needle), name);
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
    expect_true(proc_tcp_local(port, "0100007F"), "default monitor binds localhost");
    if (fd >= 0)
    {
        expect_true(send_all(fd, partial, strlen(partial)), "send a header fragment");
        shutdown(fd, SHUT_WR);
        expect_true(read_until_close(fd, response, sizeof(response), &n), "incomplete header is closed");
        expect_true(strstr(response, "ZroxyVersion") == NULL, "incomplete header has no JSON");
        close(fd);
    }

    filled = malloc(5000);
    expect_true(filled != NULL, "allocate an oversized monitor header");
    if (filled)
    {
        memset(filled, 'A', 5000);
        fd = wait_connect(port);
        expect_true(fd >= 0, "monitor accepts the oversized-header connection");
        if (fd >= 0)
        {
            response[0] = '\0';
            n = 0;
            send_all(fd, filled, 5000);
            read_until_close(fd, response, sizeof(response), &n);
            expect_true(strstr(response, "ZroxyVersion") == NULL, "oversized header has no JSON");
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

static int listen_loopback_v4(uint16_t *port)
{
    int fd;
    int on = 1;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
    {
        close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

static int bind_udp_loopback(uint16_t *port)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
    {
        close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

static bool http_exchange(uint16_t port, const char *req, char *response, size_t cap, size_t *out)
{
    int fd = wait_connect(port);
    if (fd < 0)
        return false;
    if (!send_all(fd, req, strlen(req)))
    {
        close(fd);
        return false;
    }
    if (!read_until_close(fd, response, cap, out))
    {
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

static void test_absent_services_stay_up(const char *logpath)
{
    char *argv[] = {ZROXY_BIN, "-l", "0", NULL};
    pid_t pid;
    int before = failures;

    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start with no optional services");
    if (pid <= 0)
        return;
    usleep(300000);
    expect_true(kill(pid, 0) == 0, "absent optional services stay running");
    expect_true(!log_has(logpath, "monitor listen"), "absent monitor does not start");
    expect_true(!log_has(logpath, "dns server start"), "absent dns does not start");
    expect_true(!log_has(logpath, "socket listen"), "absent sni does not start");
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
}

static void test_occupied_service_ports(const char *logpath)
{
    uint16_t udp_port = 0;
    uint16_t sni_port = 0;
    uint16_t mon_port = 0;
    int udp = -1;
    int sni = -1;
    int mon = -1;
    char dns_spec[64];
    char sni_spec[64];
    char mon_text[8];
    char *dns_argv[6];
    char *sni_argv[4];
    char *mon_argv[4];

    udp = bind_udp_loopback(&udp_port);
    expect_true(udp >= 0, "occupy a udp port");
    if (udp >= 0)
    {
        snprintf(dns_spec, sizeof(dns_spec), "127.0.0.1:%u", udp_port);
        dns_argv[0] = ZROXY_BIN;
        dns_argv[1] = "-d";
        dns_argv[2] = dns_spec;
        dns_argv[3] = "-u";
        dns_argv[4] = "127.0.0.1:9";
        dns_argv[5] = NULL;
        test_exit_code_log(dns_argv, logpath, "occupied dns port exits 1", "Can't bind address");
        close(udp);
    }

    sni = listen_loopback_v4(&sni_port);
    expect_true(sni >= 0, "occupy an sni port");
    if (sni >= 0)
    {
        snprintf(sni_spec, sizeof(sni_spec), "127.0.0.1:%u@80", sni_port);
        sni_argv[0] = ZROXY_BIN;
        sni_argv[1] = "-p";
        sni_argv[2] = sni_spec;
        sni_argv[3] = NULL;
        test_exit_code_log(sni_argv, logpath, "occupied sni port exits 1", "can not listen");
        close(sni);
    }

    mon = listen_loopback_v4(&mon_port);
    expect_true(mon >= 0, "occupy a monitor port");
    if (mon >= 0)
    {
        snprintf(mon_text, sizeof(mon_text), "%u", mon_port);
        mon_argv[0] = ZROXY_BIN;
        mon_argv[1] = "-m";
        mon_argv[2] = mon_text;
        mon_argv[3] = NULL;
        test_exit_code_log(mon_argv, logpath, "occupied monitor port exits 1", "can not listen");
        close(mon);
    }
}

static void test_monitor_explicit_bind(const char *logpath)
{
    uint16_t port = 0;
    char spec[32];
    char *argv[4];
    pid_t pid;
    int fd;
    int before = failures;

    expect_true(reserve_port(&port), "reserve explicit monitor port");
    snprintf(spec, sizeof(spec), "0.0.0.0:%u", port);
    argv[0] = ZROXY_BIN;
    argv[1] = "-m";
    argv[2] = spec;
    argv[3] = NULL;
    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start monitor on all interfaces");
    if (pid <= 0)
        return;
    fd = wait_connect(port);
    expect_true(fd >= 0, "explicit bind accepts on localhost");
    if (fd >= 0)
        close(fd);
    expect_true(proc_tcp_local(port, "00000000"), "explicit 0.0.0.0 monitor bind");
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
}

static void test_monitor_auth_and_path(const char *logpath)
{
    uint16_t port = 0;
    char port_text[8];
    char *argv[6];
    pid_t pid;
    char response[8192];
    size_t n = 0;
    int before = failures;
    char missing[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    char wrong[] = "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer nope\r\n\r\n";
    char ok[] = "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n";
    char bad_path[] = "GET /nope HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n";

    expect_true(reserve_port(&port), "reserve authenticated monitor port");
    snprintf(port_text, sizeof(port_text), "%u", port);
    argv[0] = ZROXY_BIN;
    argv[1] = "-k";
    argv[2] = "secret";
    argv[3] = "-m";
    argv[4] = port_text;
    argv[5] = NULL;
    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start authenticated monitor");
    if (pid <= 0)
        return;

    expect_true(http_exchange(port, missing, response, sizeof(response), &n), "missing token returns a response");
    expect_true(strncmp(response, "HTTP/1.1 401", 12) == 0, "missing token is 401");
    expect_true(strstr(response, "ZroxyVersion") == NULL, "missing token has no JSON");

    expect_true(http_exchange(port, wrong, response, sizeof(response), &n), "wrong token returns a response");
    expect_true(strncmp(response, "HTTP/1.1 401", 12) == 0, "wrong token is 401");
    expect_true(strstr(response, "ZroxyVersion") == NULL, "wrong token has no JSON");

    expect_true(http_exchange(port, bad_path, response, sizeof(response), &n), "invalid path returns a response");
    expect_true(strncmp(response, "HTTP/1.1 404", 12) == 0, "invalid path is 404");
    expect_true(strstr(response, "ZroxyVersion") == NULL, "invalid path has no JSON");

    expect_true(http_exchange(port, ok, response, sizeof(response), &n), "authorized request returns a body");
    expect_true(content_length_matches(response), "authorized monitor Content-Length matches the JSON body");
    expect_true(!log_has_sanitizer(logpath), "authenticated monitor stays free of sanitizer reports");
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
}

static void test_monitor_slow_clients(const char *logpath)
{
    uint16_t port = 0;
    char port_text[8];
    char *argv[6];
    pid_t pid;
    int fds[MON_CAP];
    struct pollfd pfds[MON_CAP];
    int i;
    int open_count = 0;
    int before = failures;
    char response[8192];
    size_t n = 0;
    char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    struct timespec start;
    struct timespec now;

    for (i = 0; i < MON_CAP; i++)
        fds[i] = -1;
    expect_true(reserve_port(&port), "reserve slow-client monitor port");
    snprintf(port_text, sizeof(port_text), "%u", port);
    argv[0] = ZROXY_BIN;
    argv[1] = "-a";
    argv[2] = "1";
    argv[3] = "-m";
    argv[4] = port_text;
    argv[5] = NULL;
    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start monitor with a 1s header timeout");
    if (pid <= 0)
        return;

    for (i = 0; i < MON_CAP; i++)
    {
        fds[i] = wait_connect(port);
        if (fds[i] < 0 || !send_all(fds[i], "A", 1))
            break;
        open_count++;
    }
    expect_true(open_count == MON_CAP, "opened one stalled client per monitor worker");
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (open_count > 0)
    {
        int64_t elapsed;
        int ready;
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
                  (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed > 3000)
            break;
        ready = 0;
        for (i = 0; i < MON_CAP; i++)
        {
            pfds[i].fd = fds[i];
            pfds[i].events = POLLIN;
            pfds[i].revents = 0;
            if (fds[i] >= 0)
                ready++;
        }
        if (ready == 0)
            break;
        poll(pfds, MON_CAP, 200);
        for (i = 0; i < MON_CAP; i++)
        {
            char scratch;
            ssize_t nread;
            if (fds[i] < 0)
                continue;
            if ((pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0)
                continue;
            nread = recv(fds[i], &scratch, 1, MSG_DONTWAIT);
            if (nread == 0 || (nread < 0 && (errno == ECONNRESET || errno == EAGAIN || errno == EWOULDBLOCK)))
            {
                if (nread == 0 || errno == ECONNRESET)
                {
                    close(fds[i]);
                    fds[i] = -1;
                    open_count--;
                }
            }
        }
    }
    expect_true(open_count == 0, "stalled monitor clients are closed within the header timeout");
    expect_true(http_exchange(port, request, response, sizeof(response), &n), "monitor accepts work after slow clients");
    expect_true(content_length_matches(response), "monitor JSON still matches after slow clients");
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
    for (i = 0; i < MON_CAP; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }
}

static const char *test_phase = "startup";

static void on_process_alarm(int sig)
{
    (void)sig;
    fprintf(stderr, "FAIL: watchdog expired during %s\n", test_phase);
    _exit(2);
}

static int64_t elapsed_ms(const struct timespec *start, const struct timespec *now)
{
    return (int64_t)(now->tv_sec - start->tv_sec) * 1000 +
           (now->tv_nsec - start->tv_nsec) / 1000000;
}

static void test_monitor_header_absolute_deadline(const char *logpath)
{
    uint16_t port = 0;
    char port_text[8];
    char *argv[6];
    pid_t pid;
    int fd = -1;
    struct timespec start;
    struct timespec now;
    int sent_late = 0;
    int closed = 0;
    int sends = 0;
    char scratch[64];
    int before = failures;
    int64_t elapsed = 0;

    expect_true(reserve_port(&port), "reserve deadline monitor port");
    snprintf(port_text, sizeof(port_text), "%u", port);
    argv[0] = ZROXY_BIN;
    argv[1] = "-a";
    argv[2] = "2";
    argv[3] = "-m";
    argv[4] = port_text;
    argv[5] = NULL;
    pid = spawn_child(argv, logpath);
    expect_true(pid > 0, "start monitor with a 2s header deadline");
    if (pid <= 0)
        return;
    fd = wait_connect(port);
    expect_true(fd >= 0, "deadline monitor accepts");
    if (fd < 0)
    {
        stop_child(pid);
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (1)
    {
        struct pollfd pfd;
        ssize_t nread;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = elapsed_ms(&start, &now);
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0)
        {
            nread = recv(fd, scratch, sizeof(scratch), MSG_DONTWAIT);
            if (nread == 0 || (nread < 0 && errno == ECONNRESET))
            {
                closed = 1;
                break;
            }
        }
        if (elapsed >= 3200)
            break;
        if (elapsed >= (int64_t)sends * 400 && elapsed < 1700)
        {
            if (send(fd, "A", 1, MSG_NOSIGNAL) == 1)
            {
                if (elapsed >= 1000)
                    sent_late = 1;
                sends++;
            }
            else
            {
                closed = 1;
                break;
            }
        }
        usleep(50000);
    }

    expect_true(sent_late != 0, "a drip byte was accepted after 1s");
    expect_true(closed != 0, "a dripping client is closed at the absolute deadline");
    expect_true(elapsed < 3200, "drip bytes did not extend the header deadline past 3.2s");
    expect_true(elapsed >= 1500, "the header deadline did not close the client early");
    close(fd);
    if (failures != before)
        dump_log(logpath);
    stop_child(pid);
}

int main(void)
{
    char logpath[] = "/tmp/zroxy-verify-XXXXXX";
    int logfd = mkstemp(logpath);
    struct sigaction sa;

    if (logfd < 0)
        return 1;
    close(logfd);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_process_alarm;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) != 0)
        return 1;
    alarm(40);

    test_phase = "missing whitelist";
    test_missing_whitelist(logpath);
    test_phase = "invalid configuration";
    test_invalid_configuration(logpath);
    test_phase = "absent services";
    test_absent_services_stay_up(logpath);
    test_phase = "occupied ports";
    test_occupied_service_ports(logpath);
    test_phase = "monitor requests";
    test_monitor_requests(logpath);
    test_phase = "explicit monitor bind";
    test_monitor_explicit_bind(logpath);
    test_phase = "monitor authentication";
    test_monitor_auth_and_path(logpath);
    test_phase = "slow monitor clients";
    test_monitor_slow_clients(logpath);
    test_phase = "header deadline";
    test_monitor_header_absolute_deadline(logpath);
    test_phase = "SIGPIPE";
    test_sigpipe_does_not_kill_process(logpath);
    alarm(0);

    unlink(logpath);
    return failures == 0 ? 0 : 1;
}
