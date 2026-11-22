#define _GNU_SOURCE

#include "reactor.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/epoll.h>
#endif

#define REACTOR_BATCH 64

#if defined(POLLRDHUP)
#define REACTOR_POLL_IN (POLLIN | POLLRDHUP)
#else
#define REACTOR_POLL_IN POLLIN
#endif

#if defined(__linux__)
static uint32_t to_epoll(uint32_t ev)
{
	uint32_t out = 0;
	if (ev & RE_IN)
		out |= (uint32_t)(EPOLLIN | EPOLLRDHUP);
	if (ev & RE_OUT)
		out |= (uint32_t)EPOLLOUT;
	return out;
}

static uint32_t from_epoll(uint32_t ev)
{
	uint32_t out = 0;
	if ((ev & (uint32_t)EPOLLIN) != 0)
		out |= RE_IN;
	if ((ev & (uint32_t)EPOLLOUT) != 0)
		out |= RE_OUT;
	if ((ev & (uint32_t)EPOLLERR) != 0)
		out |= RE_ERR;
	if ((ev & (uint32_t)(EPOLLHUP | EPOLLRDHUP)) != 0)
		out |= RE_HUP;
	return out;
}
#endif

static short to_poll_ev(uint32_t ev)
{
	short out = 0;
	if (ev & RE_IN)
		out = (short)(out | REACTOR_POLL_IN);
	if (ev & RE_OUT)
		out = (short)(out | POLLOUT);
	return out;
}

static uint32_t from_poll_ev(short rev)
{
	uint32_t out = 0;
	if ((rev & POLLIN) != 0)
		out |= RE_IN;
	if ((rev & POLLOUT) != 0)
		out |= RE_OUT;
	if ((rev & POLLERR) != 0)
		out |= RE_ERR;
	if ((rev & POLLHUP) != 0)
		out |= RE_HUP;
	if ((rev & POLLNVAL) != 0)
		out |= RE_ERR;
#ifdef POLLRDHUP
	if ((rev & POLLRDHUP) != 0)
		out |= RE_HUP;
#endif
	return out;
}

static int poll_index(const reactor *r, int fd)
{
	int i;
	for (i = 0; i < r->n; i++)
	{
		if (r->pfds[i].fd == fd)
			return i;
	}
	return -1;
}

bool reactor_open(reactor *r, int capacity, bool force_poll)
{
	memset(r, 0, sizeof(*r));
	r->epfd = -1;
#if defined(__linux__)
	if (!force_poll)
	{
		r->epfd = epoll_create1(EPOLL_CLOEXEC);
		return r->epfd >= 0;
	}
#else
	(void)force_poll;
#endif
	if (capacity <= 0)
		return false;
	r->cap = capacity;
	r->pfds = (struct pollfd *)calloc((size_t)capacity, sizeof(*r->pfds));
	r->tags = (void **)calloc((size_t)capacity, sizeof(*r->tags));
	if (!r->pfds || !r->tags)
	{
		reactor_close(r);
		return false;
	}
	return true;
}

void reactor_close(reactor *r)
{
	if (r->epfd >= 0)
		close(r->epfd);
	r->epfd = -1;
	free(r->pfds);
	free(r->tags);
	r->pfds = NULL;
	r->tags = NULL;
	r->n = 0;
	r->cap = 0;
	r->cursor = 0;
}

bool reactor_add(reactor *r, int fd, uint32_t ev, void *tag)
{
#if defined(__linux__)
	if (r->epfd >= 0)
	{
		struct epoll_event ee;
		memset(&ee, 0, sizeof(ee));
		ee.events = to_epoll(ev);
		ee.data.ptr = tag;
		return epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ee) == 0;
	}
#endif
	if (r->n >= r->cap)
		return false;
	r->pfds[r->n].fd = fd;
	r->pfds[r->n].events = to_poll_ev(ev);
	r->pfds[r->n].revents = 0;
	r->tags[r->n] = tag;
	r->n++;
	return true;
}

bool reactor_mod(reactor *r, int fd, uint32_t ev, void *tag)
{
	int i;
#if defined(__linux__)
	if (r->epfd >= 0)
	{
		struct epoll_event ee;
		memset(&ee, 0, sizeof(ee));
		ee.events = to_epoll(ev);
		ee.data.ptr = tag;
		return epoll_ctl(r->epfd, EPOLL_CTL_MOD, fd, &ee) == 0;
	}
#endif
	i = poll_index(r, fd);
	if (i < 0)
		return false;
	r->pfds[i].events = to_poll_ev(ev);
	r->tags[i] = tag;
	return true;
}

void reactor_del(reactor *r, int fd)
{
	int i;
#if defined(__linux__)
	if (r->epfd >= 0)
	{
		struct epoll_event ee;
		memset(&ee, 0, sizeof(ee));
		epoll_ctl(r->epfd, EPOLL_CTL_DEL, fd, &ee);
		return;
	}
#endif
	i = poll_index(r, fd);
	if (i < 0)
		return;
	r->n--;
	if (i != r->n)
	{
		r->pfds[i] = r->pfds[r->n];
		r->tags[i] = r->tags[r->n];
	}
}

int reactor_wait(reactor *r, reactor_event *out, int max, int timeout_ms)
{
	int n;
	int seen = 0;
	int produced = 0;
	int start;
#if defined(__linux__)
	if (r->epfd >= 0)
	{
		struct epoll_event evs[REACTOR_BATCH];
		int cap = max;
		int i;
		if (cap > REACTOR_BATCH)
			cap = REACTOR_BATCH;
		n = epoll_wait(r->epfd, evs, cap, timeout_ms);
		if (n < 0)
			return -1;
		for (i = 0; i < n; i++)
		{
			out[i].tag = evs[i].data.ptr;
			out[i].fd = -1;
			out[i].ev = from_epoll(evs[i].events);
		}
		return n;
	}
#endif
	n = poll(r->pfds, (nfds_t)r->n, timeout_ms);
	if (n < 0)
		return -1;
	if (r->n <= 0)
		return 0;
	/*
	 * Start one slot further on each call so a busy low slot cannot starve
	 * the others when more than max descriptors are ready.
	 */
	start = r->cursor;
	if (start >= r->n)
		start = 0;
	while (seen < r->n && produced < max)
	{
		int i = start + seen;
		if (i >= r->n)
			i -= r->n;
		if (r->pfds[i].revents != 0)
		{
			out[produced].tag = r->tags[i];
			out[produced].fd = r->pfds[i].fd;
			out[produced].ev = from_poll_ev(r->pfds[i].revents);
			produced++;
		}
		seen++;
	}
	r->cursor = start + 1;
	if (r->cursor >= r->n)
		r->cursor = 0;
	return produced;
}
