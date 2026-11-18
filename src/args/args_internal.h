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
char *args_find_dns_via(char *str);

#endif /* ARGS_INTERNAL_H_ */
