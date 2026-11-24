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
#ifndef ZROXY_CORE_REACTOR_H
#define ZROXY_CORE_REACTOR_H

/*
 * Private readiness reactor shared by the SNI and DNS event loops.
 *
 * Linux uses epoll unless force_poll is set; every other platform uses
 * poll(2). Interest is level-triggered. A reactor is used from one thread.
 * Callers delete an fd (reactor_del) before closing it.
 */

#include <stdbool.h>
#include <stdint.h>

#include <poll.h>

enum
{
	RE_IN = 1,
	RE_OUT = 2,
	RE_ERR = 4,
	RE_HUP = 8
};

typedef struct reactor_event
{
	void *tag;
	/* The registered fd with the poll backend, -1 with epoll. */
	int fd;
	uint32_t ev;
} reactor_event;

typedef struct reactor
{
	int epfd;
	struct pollfd *pfds;
	void **tags;
	int n;
	int cap;
	int cursor;
} reactor;

/* capacity bounds the number of registered fds with the poll backend. */
bool reactor_open(reactor *r, int capacity, bool force_poll);
void reactor_close(reactor *r);
bool reactor_add(reactor *r, int fd, uint32_t ev, void *tag);
bool reactor_mod(reactor *r, int fd, uint32_t ev, void *tag);
void reactor_del(reactor *r, int fd);
/* Returns the number of events stored, or -1 with errno set. */
int reactor_wait(reactor *r, reactor_event *out, int max, int timeout_ms);

#endif
