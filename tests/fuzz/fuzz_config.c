/*
 * The config-file parser (src/args.c) and the whitelist parser and matcher
 * (src/filter/filter.c), fed the same input as a file.
 *
 * The input is written to a memfd and opened by its /proc path, which is how
 * both parsers take their input. Inputs that name the "config" key (it loads
 * another file, and a file that names itself recurses without bound) or the
 * "help" key (it prints usage and calls exit) are skipped.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <zroxy/args.h>
#include <zroxy/config.h>
#include <zroxy/filter.h>

#include "fuzz_common.h"

#define MAX_FILE (64u * 1024u)
#define MAX_LINES 64u

bool args_parse_config(zroxy_t *ptr, char *str);	/* not in args.h */

/* Occurrences of word in s, ignoring ASCII case. */
static size_t count_icase(const uint8_t *s, size_t n, const char *word)
{
	size_t wl = strlen(word);
	size_t count = 0;
	size_t i;
	size_t j;

	for (i = 0; i + wl <= n; i++)
	{
		for (j = 0; j < wl && tolower(s[i + j]) == (unsigned char)word[j]; j++)
			;
		if (j == wl)
			count++;
	}
	return count;
}

/* Write data to a memfd and give back its path. -1 on failure. */
static int make_file(const uint8_t *data, size_t size, char *path, size_t cap)
{
	int fd = memfd_create("zroxy-fuzz", MFD_CLOEXEC);
	size_t done = 0;

	if (fd < 0)
		return -1;
	while (done < size)
	{
		ssize_t n = write(fd, data + done, size - done);
		if (n <= 0)
		{
			close(fd);
			return -1;
		}
		done += (size_t)n;
	}
	snprintf(path, cap, "/proc/self/fd/%d", fd);
	return fd;
}

static void free_settings(zroxy_t *cfg)
{
	args_free_ports(cfg);
	args_free_dns(cfg);
	args_free_socks(cfg);
	args_free_monitor_token(cfg);
	free(cfg->monitorPort);
	free(cfg->run_user);
	free(cfg->run_group);
	free(cfg->WhitePath);
	free(cfg->monitor_token_file);
	free(cfg->socks_pass_file);
	free(cfg->dsocks_pass_file);
	memset(cfg, 0, sizeof(*cfg));
}

static void fuzz_args(const char *path)
{
	zroxy_t cfg;
	char arg[64];

	memset(&cfg, 0, sizeof(cfg));
	snprintf(arg, sizeof(arg), "%s", path);
	(void)args_parse_config(&cfg, arg);
	free_settings(&cfg);
}

/* Match every line of the file, and its last line, against the list. */
static void match_lines(filter_t *f, const uint8_t *data, size_t size)
{
	size_t start = 0;
	size_t lines = 0;
	size_t i;

	for (i = 0; i <= size && lines < MAX_LINES; i++)
	{
		if (i == size || data[i] == '\n')
		{
			size_t n = i - start;
			char *name = malloc(n + 1);
			if (!name)
				abort();
			memcpy(name, data + start, n);
			name[n] = '\0';
			(void)filter_match(f, name);
			free(name);
			start = i + 1;
			lines++;
		}
	}
	(void)filter_match(f, "example.com");
	(void)filter_match(f, "a.b.c.example.org.");
	(void)filter_match(f, "");
}

static void fuzz_whitelist(const char *path, const uint8_t *data, size_t size)
{
	filter_t *f = filter_test_open(path);

	if (!f)
		return;
	match_lines(f, data, size);
	filter_reload(f);
	match_lines(f, data, size);
	filter_free(f);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char path[64];
	uint8_t *in;
	int fd;

	fuzz_init_once();
	if (size > MAX_FILE)
		size = MAX_FILE;
	if (count_icase(data, size, "config") || count_icase(data, size, "help"))
		return 0;
	in = fuzz_dup(data, size);
	fd = make_file(in, size, path, sizeof(path));
	if (fd < 0)
		abort();
	fuzz_args(path);
	fuzz_whitelist(path, in, size);
	close(fd);
	free(in);
	return 0;
}
