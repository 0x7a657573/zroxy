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
#ifndef NET_IO_H_
#define NET_IO_H_

#include <stdint.h>

/* Raise sub-second timeouts to 1s and cap the result at 86400s. */
int net_timeout_ms(int timeout_sec);
int64_t net_mono_ms(void);

#endif /* NET_IO_H_ */
