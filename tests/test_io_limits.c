#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

static void on_alarm(int sig)
{
    (void)sig;
    fprintf(stderr, "FAIL: watchdog timeout\n");
    _exit(2);
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
    (void)arg;
    while (!in_call)
        usleep(1000);
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

    while (!hit_during_call)
        usleep(1000);
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
    bool ok;

    expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair for EINTR read");
    job.fd = sv[1];
    job.buf = payload;
    job.len = sizeof(payload);
    job.rc = -1;
    hit_during_call = 0;
    expect_true(pthread_create(&killer, NULL, signal_during_call, NULL) == 0, "start read signal thread");
    expect_true(pthread_create(&writer, NULL, eintr_writer, &job) == 0, "start EINTR writer");
    in_call = 1;
    ok = net_read_exact(sv[0], got, sizeof(got));
    in_call = 0;
    pthread_join(killer, NULL);
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
    int closed_fd;
    int udp = -1;
    int sender = -1;
    struct sockaddr_in addr;
    uint8_t query[12];
    dnsMessage_t got;
    pthread_t killer;
    bool ok;

    memset(&dns, 0, sizeof(dns));
    expect_true(fifo_init(&fifo, (uint16_t)sizeof(dnsMessage_t), 4), "fifo for recvfrom tests");
    dns.fifo = &fifo;
    dns.local_sock = -1;
    expect_true(localdns_pull(&dns), "recvfrom on a closed descriptor returns");
    expect_int(fifo_UnreadMessage(&fifo), 0, "failed recvfrom does not enqueue");

    closed_fd = socket(AF_INET, SOCK_DGRAM, 0);
    expect_true(closed_fd >= 0, "temporary udp socket");
    close(closed_fd);
    dns.local_sock = closed_fd;
    expect_true(localdns_pull(&dns), "recvfrom EBADF returns");
    expect_int(fifo_UnreadMessage(&fifo), 0, "EBADF does not enqueue");

    expect_true(bind_udp(&udp, &addr), "bind udp for a successful recvfrom");
    dns.local_sock = udp;
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    memset(query, 0xAB, sizeof(query));
    expect_true(sender >= 0, "udp sender");
    expect_true(sendto(sender, query, sizeof(query), 0, (struct sockaddr *)&addr, sizeof(addr)) == (ssize_t)sizeof(query),
                "send one datagram");
    expect_true(localdns_pull(&dns), "successful recvfrom returns");
    expect_int(fifo_UnreadMessage(&fifo), 1, "successful recvfrom enqueues one message");
    memset(&got, 0, sizeof(got));
    expect_true(fifo_Read(&fifo, &got), "read the enqueued datagram");
    expect_int(got.len, (int)sizeof(query), "recvfrom length is the datagram size");
    expect_true(memcmp(got.message + 2, query, sizeof(query)) == 0, "recvfrom payload is unchanged");
    close(sender);
    close(udp);

    expect_true(bind_udp(&udp, &addr), "bind udp for EINTR recvfrom");
    dns.local_sock = udp;
    hit_during_call = 0;
    expect_true(pthread_create(&killer, NULL, signal_during_call, NULL) == 0, "start recvfrom signal thread");
    in_call = 1;
    ok = localdns_pull(&dns);
    in_call = 0;
    pthread_join(killer, NULL);
    expect_true(ok, "recvfrom EINTR returns without failing the listener");
    expect_true(hit_during_call != 0, "SIGUSR1 arrived during recvfrom");
    expect_int(fifo_UnreadMessage(&fifo), 0, "interrupted recvfrom does not enqueue");
    close(udp);
    fifo_deinit(&fifo);
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
    alarm(60);

    test_partial_read_and_write();
    test_read_retries_eintr_real();
    test_recvfrom_failure_and_eintr();
    test_sni_thread_cap();
    alarm(0);

    return failures == 0 ? 0 : 1;
}
