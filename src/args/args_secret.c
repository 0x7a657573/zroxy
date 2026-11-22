/* Secret command-line tracking and secret-file handling for the args parser. */
#include <zroxy/args.h>
#include "args_internal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <zroxy/log.h>

/* Secret option values on the command line, wiped by args_scrub_argv. */
#define ARGS_MAX_ARGV_SECRETS 16
static struct
{
	char *ptr;
	size_t len;
} argv_secrets[ARGS_MAX_ARGV_SECRETS];
static size_t argv_secret_count;

void args_reset_secret_tracking(void)
{
	argv_secret_count = 0;
}

void args_free_secret(char *s)
{
	if (s)
		zroxy_wipe(s, strlen(s));
	free(s);
}

/* True when a SOCKS spec carries a password: a ':' before the first '@'. */
bool args_socks_spec_has_pass(const char *spec)
{
	const char *at = spec ? strchr(spec, '@') : NULL;
	const char *colon;
	if (!at)
		return false;
	colon = memchr(spec, ':', (size_t)(at - spec));
	return colon != NULL;
}

/* True when a DNS= / -u value has a "via" SOCKS spec that carries a password. */
bool args_dns_route_has_pass(char *value)
{
	char *via = args_find_dns_via(value);
	return via && args_socks_spec_has_pass(args_ltrim(via + 3));
}

/*
 * A secret given on the command line is visible to every local user in
 * /proc/PID/cmdline until args_scrub_argv runs. Warn and remember where
 * the bytes are; the string is not touched here because tests and other
 * callers may pass read-only arguments.
 */
void args_note_cli_secret(int key, char *arg)
{
	if (!arg || arg[0] == '\0')
		return;
	if (key == 'u' ? !args_dns_route_has_pass(arg) : (key != 'k' && !args_socks_spec_has_pass(arg)))
		return;
	if (key == 'k')
		log_warn("monitor token on the command line is visible to other local users; use MONITORTOKENFILE (--monitortokenfile)");
	else if (key == 's')
		log_warn("SOCKS password on the command line is visible to other local users; use SOCKSPASSFILE (--sockspassfile)");
	else
		log_warn("DNS SOCKS password on the command line is visible to other local users; use DSOCKSPASSFILE (--dsockspassfile)");
	if (argv_secret_count < ARGS_MAX_ARGV_SECRETS)
	{
		argv_secrets[argv_secret_count].ptr = arg;
		argv_secrets[argv_secret_count].len = strlen(arg);
		argv_secret_count++;
	}
}

/*
 * Best effort: overwrite the secret option values that args_init saw on
 * the command line, so /proc/PID/cmdline and ps stop showing them. Call it
 * from main with the real argv, after args_init. Everything the parser
 * keeps was copied already. A SOCKS spec is cleared whole, host included.
 */
void args_scrub_argv(void)
{
	for (size_t i = 0; i < argv_secret_count; i++)
		zroxy_wipe(argv_secrets[i].ptr, argv_secrets[i].len);
	argv_secret_count = 0;
}

/* Warn about loose permissions on an open file that holds a secret. */
void args_warn_secret_mode(const struct stat *st, const char *path, const char *what)
{
	if (st->st_mode & 077)
		log_warn("%s %s is accessible by group or others (mode %04o); chmod 600 it", what, path, (unsigned)(st->st_mode & 07777));
}

/*
 * Read the first line of a secret file: trailing CR/LF stripped, never
 * empty, at most maxlen bytes. The permission check uses the open
 * descriptor. Returns a malloc'd string or NULL (error already logged).
 */
static char *read_secret_file(const char *path, size_t maxlen, const char *what)
{
	char buf[ARGS_MAX_TOKEN + 3];
	size_t cap = maxlen + 2;
	size_t n = 0;
	size_t len;
	struct stat st;
	char *out = NULL;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);

	if (fd < 0)
	{
		log_error("cannot open %s file %s", what, path);
		return NULL;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
	{
		log_error("%s file %s is not a regular file", what, path);
		goto done;
	}
	if (st.st_mode & S_IWOTH)
	{
		log_error("%s file %s is world-writable (mode %04o); refusing it", what, path, (unsigned)(st.st_mode & 07777));
		goto done;
	}
	args_warn_secret_mode(&st, path, what);
	while (n < cap)
	{
		ssize_t r = read(fd, buf + n, cap - n);
		if (r < 0)
		{
			if (errno == EINTR)
				continue;
			log_error("cannot read %s file %s", what, path);
			goto done;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	len = n;
	for (size_t i = 0; i < n; i++)
	{
		if (buf[i] == '\n')
		{
			len = i;
			break;
		}
	}
	while (len > 0 && buf[len - 1] == '\r')
		len--;
	if (len == 0)
	{
		log_error("%s file %s is empty", what, path);
		goto done;
	}
	if (len > maxlen || memchr(buf, '\0', len))
	{
		log_error("%s file %s has an invalid or too long first line (max %zu)", what, path, maxlen);
		goto done;
	}
	out = malloc(len + 1);
	if (out)
	{
		memcpy(out, buf, len);
		out[len] = '\0';
	}
done:
	zroxy_wipe(buf, sizeof(buf));
	close(fd);
	return out;
}

static bool load_socks_pass_file(sockshost_t *socks, char **path, const char *what)
{
	bool ok = false;
	if (!*path)
		return true;
	if (!socks)
		log_error("%s file is set but there is no matching SOCKS server", what);
	else if (!socks->user)
		log_error("%s file needs a user in the SOCKS spec (USER@HOST[:PORT])", what);
	else if (socks->pass)
		log_error("%s is set both inline and as a file; use one", what);
	else
	{
		socks->pass = read_secret_file(*path, ARGS_MAX_IDENT, what);
		ok = socks->pass != NULL;
	}
	free(*path);
	*path = NULL;
	return ok;
}

bool args_load_secret_files(zroxy_t *ptr)
{
	bool ok = true;
	if (!load_socks_pass_file(ptr->socks, &ptr->socks_pass_file, "SOCKS password"))
		ok = false;
	if (!load_socks_pass_file(ptr->dnsserver ? ptr->dnsserver->socks : NULL, &ptr->dsocks_pass_file, "DNS SOCKS password"))
		ok = false;
	if (ptr->monitor_token_file)
	{
		if (ptr->monitor_token)
		{
			log_error("monitor token is set both inline and as a file; use one");
			ok = false;
		}
		else
		{
			ptr->monitor_token = read_secret_file(ptr->monitor_token_file, ARGS_MAX_TOKEN, "monitor token");
			if (!ptr->monitor_token)
				ok = false;
		}
		free(ptr->monitor_token_file);
		ptr->monitor_token_file = NULL;
	}
	return ok;
}
