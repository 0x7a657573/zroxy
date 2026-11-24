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
/*
 * monitor.h
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#ifndef MONITOR_H_
#define MONITOR_H_
#include <stdbool.h>
#include <stdint.h>

/*
 * Appends the members of a top-level report object as `"Key" : value` pairs
 * separated by ",\n", with no trailing separator. The monitor adds the braces.
 */
typedef bool (*mon_section_fn)(void *ctx, char **ptr, char *end);

typedef struct mon mon_t;

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec);
/* Adds a top-level object written by fn. ctx must outlive the monitor. */
bool monitor_add_section(mon_t *self, const char *name, mon_section_fn fn, void *ctx);
/*
 * Stops accepting, joins the monitor thread, closes every client, the listener
 * and pipe, then frees the sections, token and monitor itself. After it
 * returns, nothing reads the sections' contexts any more. Call it while the
 * sections' contexts are still valid.
 */
void monitor_stop(mon_t *self);

#ifdef MON_TEST_HOOKS
#include <stddef.h>
#include <stdint.h>
/* -1 while the request line is incomplete, else 0 or the HTTP status to send. */
int monitor_test_classify(const uint8_t *buf, size_t len);
bool monitor_test_headers_done(const uint8_t *buf, size_t len);
bool monitor_test_authorized(const uint8_t *buf, size_t len, const char *token);
#endif

#endif /* MONITOR_H_ */
