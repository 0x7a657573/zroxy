/*
 * net_blocking.c - blocking dial and read helpers, used by tests only.
 */
#include "test_support.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zroxy/log.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>

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

static bool net_connect_one(int sfd, const struct sockaddr *addr, socklen_t len, int64_t deadline_ms)
{
    int flags;
    int rc;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags < 0)
        return false;
    if (fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0)
        return false;

    do
    {
        rc = connect(sfd, addr, len);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0 && errno != EINPROGRESS && errno != EALREADY)
    {
        fcntl(sfd, F_SETFL, flags);
        return false;
    }

    if (rc < 0)
    {
        int err = 0;
        socklen_t elen = sizeof(err);
        if (!net_wait_fd(sfd, POLLOUT, deadline_ms) ||
            getsockopt(sfd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 ||
            err != 0)
        {
            fcntl(sfd, F_SETFL, flags);
            return false;
        }
    }

    if (fcntl(sfd, F_SETFL, flags) < 0)
        return false;
    return true;
}

bool net_connect(int *sockfd,const char *hostname, uint16_t port, int timeout_sec)
{
    int64_t deadline;
    int64_t now;

    *sockfd = -1;
    now = net_mono_ms();
    if (now < 0)
        return false;
    deadline = now + net_timeout_ms(timeout_sec);

    /*check Hostname is IP or Domain*/
    if(net_is_ip_literal(hostname))
	{
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sfd < 0)
	    {
	        log_error("Socks Error : Could not create socket");
	        return false;
	    }

        struct sockaddr_in serv_addr;
	    serv_addr.sin_family = AF_INET;
	    serv_addr.sin_port = htons(port);

        if(inet_pton(AF_INET, hostname, &serv_addr.sin_addr)<=0)
		{
			log_error("inet_pton error occured");
            close(sfd);
			return false;
		}

		if(!net_connect_one(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr), deadline))
		{
			log_error("net_connect Error : Connect Failed");
            close(sfd);
			return false;
		}

        *sockfd = sfd;
        return true;
	}

    char port_str[8] = {0};
    struct addrinfo hints;
    struct addrinfo *addrs=NULL;

    memset(&hints, 0, sizeof(hints));
    /* IPv6 is not supported; asking for A only also skips the AAAA lookup. */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str,7,"%i",port);

    const int status = getaddrinfo(hostname, port_str, &hints, &addrs);
    if (status != 0)
    {
    	log_error("%s:%s -> %s\n", hostname,port_str, gai_strerror(status));
        return false;
    }

    int sfd = -1;
    for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
    {
        sfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sfd == -1)
        {
        	log_error("Socks Error : Could not create socket");
            continue;
        }

        if (net_mono_ms() >= deadline)
        {
            close(sfd);
            sfd = -1;
            break;
        }

        if (net_connect_one(sfd, addr->ai_addr, addr->ai_addrlen, deadline))
        {
            *sockfd = sfd;
            freeaddrinfo(addrs);
            return true;
        }

        close(sfd);
        sfd = -1;
    }

    freeaddrinfo(addrs);
    return false;
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
