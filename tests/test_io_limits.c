#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dnsproxy.h"
#include "log.h"
#include "net_io.h"
#include "sniproxy.h"

static int failures = 0;
static pthread_t main_thread;
static volatile sig_atomic_t in_call;
static volatile sig_atomic_t hit_during_call;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void expect_int(int actual, int expected, const char *name)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL: %s expected %d, got %d\n", name, expected, actual);
        failures++;
    }
}

static void on_usr1(int sig)
{
    (void)sig;
    if (in_call)
        hit_during_call = 1;
}

static const char *test_phase = "startup";

static void on_alarm(int sig)
{
    (void)sig;
    fprintf(stderr, "FAIL: watchdog expired during %s\n", test_phase);
    _exit(2);
}

static bool set_recv_timeout(int fd, int seconds)
{
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

struct io_job
{
    int fd;
    uint8_t *buf;
    size_t len;
    int rc;
};

static void *read_one_by_one(void *arg)
{
    struct io_job *job = (struct io_job *)arg;
    size_t off = 0;

    job->rc = 0;
    while (off < job->len)
    {
        ssize_t n = read(job->fd, job->buf + off, 1);
        if (n != 1)
        {
            job->rc = -1;
            return NULL;
        }
        off++;
    }
    return NULL;
}

static void *write_one_by_one(void *arg)
{
    struct io_job *job = (struct io_job *)arg;
    size_t off = 0;

    job->rc = 0;
    while (off < job->len)
    {
        ssize_t n = write(job->fd, job->buf + off, 1);
        if (n != 1)
        {
            job->rc = -1;
            return NULL;
        }
        off++;
    }
    return NULL;
}

static void *signal_during_call(void *arg)
{
    int i;
    int spins = 0;
    (void)arg;
    while (!in_call && spins < 2000)
    {
        usleep(1000);
        spins++;
    }
    if (!in_call)
        return NULL;
    usleep(30000);
    for (i = 0; i < 40; i++)
    {
        pthread_kill(main_thread, SIGUSR1);
        usleep(1000);
    }
    return NULL;
}

static void test_partial_read_and_write(void)
{
    int sv[2] = {-1, -1};
    int wr[2] = {-1, -1};
    uint8_t payload[8] = {'p', 'a', 'r', 't', 'i', 'a', 'l', '!'};
    uint8_t got[8];
    uint8_t big[8192];
    uint8_t big_got[8192];
    struct io_job job;
    pthread_t tid;
    int snd = 1024;
    size_t i;

    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair for partial read");
    job.fd = sv[1];
    job.buf = payload;
    job.len = sizeof(payload);
    job.rc = -1;
    expect_true(pthread_create(&tid, NULL, write_one_by_one, &job) == 0, "start byte writer");
    expect_true(net_read_exact(sv[0], got, sizeof(got)), "partial reads assemble one buffer");
    pthread_join(tid, NULL);
    expect_int(job.rc, 0, "byte writer completed");
    expect_true(memcmp(got, payload, sizeof(payload)) == 0, "partial read bytes match");
    close(sv[0]);
    close(sv[1]);

    for (i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)(i & 0xFF);
    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, wr) == 0, "socketpair for partial write");
    setsockopt(wr[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    setsockopt(wr[1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
    job.fd = wr[1];
    job.buf = big_got;
    job.len = sizeof(big_got);
    job.rc = -1;
    expect_true(pthread_create(&tid, NULL, read_one_by_one, &job) == 0, "start byte reader");
    expect_true(net_write_all(wr[0], big, sizeof(big)), "partial writes send the whole buffer");
    pthread_join(tid, NULL);
    expect_int(job.rc, 0, "byte reader completed");
    expect_true(memcmp(big, big_got, sizeof(big)) == 0, "partial write bytes match");
    close(wr[0]);
    close(wr[1]);
}

static void *eintr_writer(void *arg)
{
    struct io_job *job = (struct io_job *)arg;
    size_t off = 0;
    int spins = 0;

    while (!hit_during_call && spins < 3000)
    {
        usleep(1000);
        spins++;
    }
    if (!hit_during_call)
    {
        job->rc = -1;
        return NULL;
    }
    while (off < job->len)
    {
        ssize_t n = write(job->fd, job->buf + off, 1);
        if (n != 1)
        {
            job->rc = -1;
            return NULL;
        }
        off++;
    }
    job->rc = 0;
    return NULL;
}

static void test_read_retries_eintr_real(void)
{
    int sv[2] = {-1, -1};
    uint8_t payload[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
    uint8_t got[8];
    struct io_job job;
    pthread_t killer;
    pthread_t writer;
    bool have_killer = false;
    bool have_writer = false;
    bool ok = false;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    {
        fprintf(stderr, "FAIL: socketpair for EINTR read: %s\n", strerror(errno));
        failures++;
        return;
    }
    if (!set_recv_timeout(sv[0], 2))
    {
        fprintf(stderr, "FAIL: bound the EINTR read: %s\n", strerror(errno));
        failures++;
        close(sv[0]);
        close(sv[1]);
        return;
    }
    job.fd = sv[1];
    job.buf = payload;
    job.len = sizeof(payload);
    job.rc = -1;
    hit_during_call = 0;
    if (pthread_create(&killer, NULL, signal_during_call, NULL) != 0)
    {
        fprintf(stderr, "FAIL: start read signal thread: %s\n", strerror(errno));
        failures++;
    }
    else
        have_killer = true;
    if (have_killer && pthread_create(&writer, NULL, eintr_writer, &job) != 0)
    {
        fprintf(stderr, "FAIL: start EINTR writer: %s\n", strerror(errno));
        failures++;
    }
    else if (have_killer)
    {
        have_writer = true;
        in_call = 1;
        ok = net_read_exact(sv[0], got, sizeof(got));
        in_call = 0;
    }
    if (have_killer)
        pthread_join(killer, NULL);
    if (have_writer)
        pthread_join(writer, NULL);
    expect_true(ok, "net_read_exact completes after EINTR");
    expect_true(hit_during_call != 0, "SIGUSR1 arrived during net_read_exact");
    expect_int(job.rc, 0, "EINTR writer completed");
    expect_true(memcmp(got, payload, sizeof(payload)) == 0, "EINTR read bytes match");
    close(sv[0]);
    close(sv[1]);
}

static bool bind_udp(int *fd, struct sockaddr_in *addr)
{
    socklen_t len = sizeof(*addr);
    *fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*fd < 0)
        return false;
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr->sin_port = 0;
    if (bind(*fd, (struct sockaddr *)addr, sizeof(*addr)) != 0)
    {
        close(*fd);
        *fd = -1;
        return false;
    }
    if (getsockname(*fd, (struct sockaddr *)addr, &len) != 0)
    {
        close(*fd);
        *fd = -1;
        return false;
    }
    return true;
}

static void test_recvfrom_failure_and_eintr(void)
{
    fifo_t fifo;
    dnsserver_t dns;
    int closed_fd = -1;
    int udp = -1;
    int sender = -1;
    struct sockaddr_in addr;
    uint8_t query[12];
    dnsMessage_t got;
    pthread_t killer;
    bool have_killer = false;
    bool ok = false;
    bool have_fifo = false;

    memset(&dns, 0, sizeof(dns));
    memset(&addr, 0, sizeof(addr));
    if (!fifo_init(&fifo, (uint16_t)sizeof(dnsMessage_t), 4))
    {
        fprintf(stderr, "FAIL: fifo for recvfrom tests: %s\n", strerror(errno));
        failures++;
        return;
    }
    have_fifo = true;
    dns.fifo = &fifo;
    dns.local_sock = -1;
    expect_true(localdns_pull(&dns), "recvfrom on a closed descriptor returns");
    expect_int(fifo_UnreadMessage(&fifo), 0, "failed recvfrom does not enqueue");

    closed_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (closed_fd < 0)
    {
        fprintf(stderr, "FAIL: temporary udp socket: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    close(closed_fd);
    dns.local_sock = closed_fd;
    closed_fd = -1;
    expect_true(localdns_pull(&dns), "recvfrom EBADF returns");
    expect_int(fifo_UnreadMessage(&fifo), 0, "EBADF does not enqueue");
    dns.local_sock = -1;

    if (!bind_udp(&udp, &addr))
    {
        fprintf(stderr, "FAIL: bind udp for a successful recvfrom: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    if (!set_recv_timeout(udp, 1))
    {
        fprintf(stderr, "FAIL: SO_RCVTIMEO on udp recvfrom socket: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    dns.local_sock = udp;
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender < 0)
    {
        fprintf(stderr, "FAIL: udp sender: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    memset(query, 0xAB, sizeof(query));
    if (sendto(sender, query, sizeof(query), 0, (struct sockaddr *)&addr, sizeof(addr)) != (ssize_t)sizeof(query))
    {
        fprintf(stderr, "FAIL: send one datagram: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    expect_true(localdns_pull(&dns), "successful recvfrom returns");
    expect_int(fifo_UnreadMessage(&fifo), 1, "successful recvfrom enqueues one message");
    memset(&got, 0, sizeof(got));
    expect_true(fifo_Read(&fifo, &got), "read the enqueued datagram");
    expect_int(got.len, (int)sizeof(query), "recvfrom length is the datagram size");
    expect_true(memcmp(got.message + 2, query, sizeof(query)) == 0, "recvfrom payload is unchanged");
    close(sender);
    sender = -1;
    close(udp);
    udp = -1;
    dns.local_sock = -1;

    if (!bind_udp(&udp, &addr))
    {
        fprintf(stderr, "FAIL: bind udp for EINTR recvfrom: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    if (!set_recv_timeout(udp, 2))
    {
        fprintf(stderr, "FAIL: SO_RCVTIMEO on EINTR udp socket: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    dns.local_sock = udp;
    hit_during_call = 0;
    if (pthread_create(&killer, NULL, signal_during_call, NULL) != 0)
    {
        fprintf(stderr, "FAIL: start recvfrom signal thread: %s\n", strerror(errno));
        failures++;
        goto done;
    }
    have_killer = true;
    in_call = 1;
    ok = localdns_pull(&dns);
    in_call = 0;
    pthread_join(killer, NULL);
    have_killer = false;
    expect_true(ok, "recvfrom EINTR returns without failing the listener");
    expect_true(hit_during_call != 0, "SIGUSR1 arrived during recvfrom");
    expect_int(fifo_UnreadMessage(&fifo), 0, "interrupted recvfrom does not enqueue");

done:
    in_call = 0;
    if (have_killer)
        pthread_join(killer, NULL);
    if (sender >= 0)
        close(sender);
    if (udp >= 0)
        close(udp);
    dns.local_sock = -1;
    if (have_fifo)
        fifo_deinit(&fifo);
}

static void *write_then_pause(void *arg)
{
    struct io_job *job = (struct io_job *)arg;

    if (job->len < 4 || write(job->fd, job->buf, 3) != 3)
    {
        job->rc = -1;
        return NULL;
    }
    usleep(80000);
    if (write(job->fd, job->buf + 3, job->len - 3) != (ssize_t)(job->len - 3))
    {
        job->rc = -1;
        return NULL;
    }
    job->rc = 0;
    return NULL;
}

static int64_t elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    return (int64_t)(end->tv_sec - start->tv_sec) * 1000 +
           (end->tv_nsec - start->tv_nsec) / 1000000;
}

static void test_timed_io_deadlines(void)
{
    int sv[2] = {-1, -1};
    uint8_t payload[8] = {'d', 'e', 'a', 'd', 'l', 'i', 'n', 'e'};
    uint8_t got[8];
    uint8_t big[256 * 1024];
    struct io_job job;
    pthread_t tid;
    struct timespec start;
    struct timespec end;
    int snd = 1024;
    bool ok;

    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair for timed read");
    job.fd = sv[1];
    job.buf = payload;
    job.len = sizeof(payload);
    job.rc = -1;
    expect_true(pthread_create(&tid, NULL, write_then_pause, &job) == 0, "start paused writer");
    expect_true(net_read_exact_ms(sv[0], got, sizeof(got), 2000), "split write assembles inside the deadline");
    pthread_join(tid, NULL);
    expect_int(job.rc, 0, "paused writer completed");
    expect_true(memcmp(got, payload, sizeof(payload)) == 0, "timed read bytes match");
    close(sv[0]);
    close(sv[1]);

    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair for stalled read");
    expect_true(write(sv[1], payload, 3) == 3, "write a short prefix");
    clock_gettime(CLOCK_MONOTONIC, &start);
    ok = net_read_exact_ms(sv[0], got, sizeof(got), 400);
    clock_gettime(CLOCK_MONOTONIC, &end);
    expect_true(!ok, "stalled read fails at the deadline");
    expect_true(elapsed_ms(&start, &end) < 2000, "stalled read does not hang");
    close(sv[0]);
    close(sv[1]);

    memset(big, 0x5a, sizeof(big));
    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair for stalled write");
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
    clock_gettime(CLOCK_MONOTONIC, &start);
    ok = net_write_all_ms(sv[0], big, sizeof(big), 400);
    clock_gettime(CLOCK_MONOTONIC, &end);
    expect_true(!ok, "stalled write fails at the deadline");
    expect_true(elapsed_ms(&start, &end) < 2000, "stalled write does not hang");
    close(sv[0]);
    close(sv[1]);
}

static void test_sni_thread_cap(void)
{
    int n = 0;
    int i;

    /* Matches SNI_MAX_WORKERS in sniproxy/sniclient.c. */
    while (sni_worker_acquire())
        n++;
    expect_int(n, 1024, "SNI worker cap is 1024");
    expect_true(!sni_worker_acquire(), "SNI worker cap stays closed");
    for (i = 0; i < n; i++)
        sni_worker_release();
    expect_true(sni_worker_acquire(), "releasing the SNI cap frees one slot");
    sni_worker_release();
}

int main(void)
{
    struct sigaction sa;

    log_set_quiet(1);
    main_thread = pthread_self();
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) != 0)
        return 1;
    sa.sa_handler = on_alarm;
    if (sigaction(SIGALRM, &sa, NULL) != 0)
        return 1;
    alarm(12);

    test_phase = "partial read and write";
    test_partial_read_and_write();
    test_phase = "timed I/O deadlines";
    test_timed_io_deadlines();
    test_phase = "EINTR read";
    test_read_retries_eintr_real();
    test_phase = "recvfrom";
    test_recvfrom_failure_and_eintr();
    test_phase = "SNI worker cap";
    test_sni_thread_cap();
    alarm(0);

    return failures == 0 ? 0 : 1;
}
