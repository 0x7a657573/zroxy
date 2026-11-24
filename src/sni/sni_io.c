/*
 * Copyright (c) 2020-2026 zeus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

/* Socket and reactor wrappers used by the SNI event loop. */

#include "sni_internal.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <zroxy/net.h>

bool sni_set_nb_cloexec(int fd)
{
	return net_set_nonblock_cloexec(fd);
}

ssize_t sni_io_read(int fd, void *buf, size_t len)
{
#ifdef SNI_TEST_HOOKS
	int limit;
	if (sni_take_fault(SNI_FAULT_EINTR_READ))
	{
		errno = EINTR;
		return -1;
	}
	limit = sni_read_limit();
	if (limit > 0 && len > (size_t)limit)
		len = (size_t)limit;
#endif
	return read(fd, buf, len);
}

ssize_t sni_io_write(int fd, const void *buf, size_t len)
{
#ifdef SNI_TEST_HOOKS
	int limit;
	if (sni_take_fault(SNI_FAULT_EAGAIN_WRITE))
	{
		errno = EAGAIN;
		return -1;
	}
	if (sni_take_fault(SNI_FAULT_EINTR_WRITE))
	{
		errno = EINTR;
		return -1;
	}
	limit = sni_write_limit();
	if (limit > 0 && len > (size_t)limit)
		len = (size_t)limit;
#endif
#if defined(MSG_NOSIGNAL)
	return send(fd, buf, len, MSG_NOSIGNAL);
#else
	return write(fd, buf, len);
#endif
}

int sni_io_accept(int fd, struct sockaddr_storage *peer)
{
	socklen_t len = (socklen_t)sizeof(*peer);

#ifdef SNI_TEST_HOOKS
	if (sni_take_fault(SNI_FAULT_FAIL_ACCEPT))
	{
		errno = EMFILE;
		return -1;
	}
#endif
	return accept(fd, (struct sockaddr *)peer, &len);
}

int sni_io_connect(int fd, const struct sockaddr *sa, socklen_t len)
{
#ifdef SNI_TEST_HOOKS
	if (sni_take_fault(SNI_FAULT_EINTR_CONNECT))
	{
		errno = EINTR;
		return -1;
	}
#endif
	return connect(fd, sa, len);
}

bool sni_react_add(sni_engine *e, int fd, uint32_t ev, sni_tag *tag)
{
	return reactor_add(&e->re, fd, ev, tag);
}

bool sni_react_mod(sni_engine *e, int fd, uint32_t ev, sni_tag *tag)
{
	return reactor_mod(&e->re, fd, ev, tag);
}

void sni_react_del(sni_engine *e, int fd)
{
	reactor_del(&e->re, fd);
}

int sni_react_wait(sni_engine *e, sni_ready *out, int max, int timeout_ms)
{
	reactor_event evs[64];
	int n;
	int i;
	if (max > 64)
		max = 64;
	sni_note_wait();
#ifdef SNI_TEST_HOOKS
	if (sni_take_fault(SNI_FAULT_EINTR_WAIT))
	{
		errno = EINTR;
		return -1;
	}
	if (sni_take_fault(SNI_FAULT_FAIL_WAIT))
	{
		errno = EBADF;
		return -1;
	}
#endif
	n = reactor_wait(&e->re, evs, max, timeout_ms);
	if (n < 0)
		return -1;
	for (i = 0; i < n; i++)
	{
		sni_tag *tag = (sni_tag *)evs[i].tag;
		out[i].tag = tag;
		/* epoll reports no fd; the tag holds the fd it is armed with. */
		out[i].fd = evs[i].fd >= 0 ? evs[i].fd : (tag ? tag->fd : -1);
		out[i].ev = evs[i].ev;
	}
	return n;
}

bool sni_watch(sni_engine *e, int fd, uint32_t ev, uint32_t *slot, sni_tag *tag)
{
	if (fd < 0)
	{
		*slot = 0;
		return true;
	}
	if (ev == *slot)
		return true;
	if (tag)
		tag->fd = fd;
	if (ev == 0)
	{
		sni_react_del(e, fd);
		*slot = 0;
		return true;
	}
	if (*slot == 0)
	{
		if (!sni_react_add(e, fd, ev, tag))
			return false;
	}
	else if (!sni_react_mod(e, fd, ev, tag))
	{
		return false;
	}
	*slot = ev;
	return true;
}

void sni_drop_watched(sni_engine *e, int *fd, uint32_t *slot, sni_tag *tag)
{
	if (*fd < 0)
	{
		if (tag)
			tag->fd = -1;
		return;
	}
	if (*slot != 0)
	{
		sni_react_del(e, *fd);
		*slot = 0;
	}
	close(*fd);
	*fd = -1;
	if (tag)
		tag->fd = -1;
}

int sni_read_some(int fd, uint8_t *buf, uint32_t cap, uint32_t *len)
{
	size_t space;
	ssize_t n;
	if (*len >= cap)
		return 0;
	space = (size_t)(cap - *len);
	do
	{
		n = sni_io_read(fd, buf + *len, space);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return 0;
		}
		return -1;
	}
	if (n == 0)
		return -2;
	if ((size_t)n > space)
		return -1;
	*len += (uint32_t)n;
	return 1;
}

int sni_write_some(int fd, const uint8_t *buf, uint32_t len, uint32_t *off, uint32_t *counter)
{
	while (*off < len)
	{
		size_t space = (size_t)(len - *off);
		ssize_t n;
		do
		{
			n = sni_io_write(fd, buf + *off, space);
		} while (n < 0 && errno == EINTR);
		if (n < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				sni_note_eagain();
				return 0;
			}
			return -1;
		}
		if (n == 0 || (size_t)n > space)
			return -1;
		*off += (uint32_t)n;
		if (counter)
			*counter += (uint32_t)n;
	}
	return 1;
}

int sni_shut_write(int fd)
{
	int rc;
	do
	{
		rc = shutdown(fd, SHUT_WR);
	} while (rc < 0 && errno == EINTR);
	return rc;
}
