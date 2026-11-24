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
 * priv.h - give up root after the sockets are bound.
 */

#ifndef ZROXY_PRIV_H_
#define ZROXY_PRIV_H_
#include <stdbool.h>
#include <sys/types.h>

/*
 * Switch to uid/gid for good: clear the supplementary groups, setgid,
 * setuid, then check that every thread of the process runs as that
 * identity and that root cannot be regained. Returns false on any
 * failure; the caller must not carry on as a half-dropped process.
 */
bool priv_drop(uid_t uid, gid_t gid);

/*
 * Linux: set no_new_privs. After a drop (`dropped`) also make the process
 * non-dumpable, so a same-uid process can not ptrace it or read its
 * /proc/PID/fd and memory, and it leaves no core file. The kernel already
 * does that on a uid change, but fs.suid_dumpable can undo it. Without a
 * drop the process stays dumpable, which keeps /proc/PID/fd usable for the
 * operator and the test harness. A no-op elsewhere.
 */
void priv_harden(bool dropped);

#endif /* ZROXY_PRIV_H_ */
