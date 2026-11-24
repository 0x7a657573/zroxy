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
/* Shared by the args sources; not a public header. */
#ifndef ARGS_INTERNAL_H_
#define ARGS_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

#include <zroxy/args.h>

#define ARGS_MAX_IDENT 255
#define ARGS_MAX_TOKEN 256

void args_free_secret(char *s);
bool args_socks_spec_has_pass(const char *spec);
bool args_dns_route_has_pass(char *value);
void args_note_cli_secret(int key, char *arg);
void args_warn_secret_mode(const struct stat *st, const char *path, const char *what);
bool args_load_secret_files(zroxy_t *ptr);
void args_reset_secret_tracking(void);
char *args_ltrim(char *s);
char *args_trim(char *s);
char *args_find_dns_via(char *str);
int args_apply_option(int key, char *arg, void *userprm);

#endif /* ARGS_INTERNAL_H_ */
