#include "net_io.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

bool net_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t written = 0;
    while (written < len)
    {
        ssize_t n = write(fd, p + written, len - written);
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
        written += (size_t)n;
    }
    return true;
}

bool net_read_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t read_total = 0;
    while (read_total < len)
    {
        ssize_t n = read(fd, p + read_total, len - read_total);
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
        read_total += (size_t)n;
    }
    return true;
}

int net_timeout_ms(int timeout_sec)
{
    if (timeout_sec < 1)
        timeout_sec = 1;
    if (timeout_sec > 86400)
        timeout_sec = 86400;
    return timeout_sec * 1000;
}

int64_t net_mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool net_wait_fd(int fd, int events, int64_t deadline_ms)
{
    for (;;)
    {
        int64_t now = net_mono_ms();
        int64_t left64;
        int left;
        struct pollfd pfd;
        int rc;

        if (now < 0 || now >= deadline_ms)
            return false;
        left64 = deadline_ms - now;
        if (left64 > INT_MAX)
            left = INT_MAX;
        else
            left = (int)left64;
        pfd.fd = fd;
        pfd.events = (short)events;
        pfd.revents = 0;
        rc = poll(&pfd, 1, left);
        if (rc < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (rc == 0)
            return false;
        if (pfd.revents & POLLNVAL)
            return false;
        if (pfd.revents & (events | POLLERR | POLLHUP))
            return true;
    }
}

static bool io_set_nonblock(int fd, int *saved_flags)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return false;
    *saved_flags = flags;
    if (flags & O_NONBLOCK)
        return true;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void io_restore_flags(int fd, int saved_flags)
{
    (void)fcntl(fd, F_SETFL, saved_flags);
}

bool net_write_all_ms(int fd, const void *buf, size_t len, int timeout_ms)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t written = 0;
    int saved = 0;
    int64_t now;
    int64_t deadline;
    bool ok = false;

    if (timeout_ms < 0)
        timeout_ms = 0;
    now = net_mono_ms();
    if (now < 0 || !io_set_nonblock(fd, &saved))
        return false;
    deadline = now + (int64_t)timeout_ms;
    while (written < len)
    {
        ssize_t n;
        if (!net_wait_fd(fd, POLLOUT, deadline))
            goto out;
        n = write(fd, p + written, len - written);
        if (n < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            goto out;
        }
        if (n == 0)
            goto out;
        written += (size_t)n;
    }
    ok = true;
out:
    io_restore_flags(fd, saved);
    return ok;
}

bool net_read_exact_ms(int fd, void *buf, size_t len, int timeout_ms)
{
    uint8_t *p = (uint8_t *)buf;
    size_t read_total = 0;
    int saved = 0;
    int64_t now;
    int64_t deadline;
    bool ok = false;

    if (timeout_ms < 0)
        timeout_ms = 0;
    now = net_mono_ms();
    if (now < 0 || !io_set_nonblock(fd, &saved))
        return false;
    deadline = now + (int64_t)timeout_ms;
    while (read_total < len)
    {
        ssize_t n;
        if (!net_wait_fd(fd, POLLIN, deadline))
            goto out;
        n = read(fd, p + read_total, len - read_total);
        if (n < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            goto out;
        }
        if (n == 0)
            goto out;
        read_total += (size_t)n;
    }
    ok = true;
out:
    io_restore_flags(fd, saved);
    return ok;
}
