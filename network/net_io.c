#include "net_io.h"

#include <errno.h>
#include <stdint.h>
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
