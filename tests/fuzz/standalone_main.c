/*
 * Replays files through LLVMFuzzerTestOneInput, for builds without libFuzzer.
 *
 *   fuzz_<name>_replay PATH...
 *
 * A PATH is a file or a directory of files (not searched recursively). The
 * exit status is 1 when a PATH cannot be read, 0 otherwise; a crash or a
 * sanitizer report ends the process as usual.
 */
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define REPLAY_MAX_SIZE (1u << 20)

static int run_file(const char *path)
{
	struct stat st;
	uint8_t *buf;
	size_t got = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size < 0 || (uint64_t)st.st_size > REPLAY_MAX_SIZE)
	{
		fprintf(stderr, "cannot use %s\n", path);
		if (fd >= 0)
			close(fd);
		return 1;
	}
	buf = malloc(st.st_size ? (size_t)st.st_size : 1);
	if (!buf)
		abort();
	while (got < (size_t)st.st_size)
	{
		ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	close(fd);
	LLVMFuzzerTestOneInput(buf, got);
	free(buf);
	return 0;
}

int main(int argc, char **argv)
{
	int failed = 0;
	unsigned count = 0;
	int i;

	for (i = 1; i < argc; i++)
	{
		struct stat st;
		if (stat(argv[i], &st) != 0)
		{
			fprintf(stderr, "cannot stat %s\n", argv[i]);
			failed = 1;
		}
		else if (S_ISDIR(st.st_mode))
		{
			DIR *dir = opendir(argv[i]);
			struct dirent *ent;
			if (!dir)
			{
				failed = 1;
				continue;
			}
			while ((ent = readdir(dir)) != NULL)
			{
				char path[4096];
				if (ent->d_name[0] == '.')
					continue;
				if (snprintf(path, sizeof(path), "%s/%s", argv[i], ent->d_name) >= (int)sizeof(path))
					continue;
				failed |= run_file(path);
				count++;
			}
			closedir(dir);
		}
		else
		{
			failed |= run_file(argv[i]);
			count++;
		}
	}
	printf("replayed %u input(s)\n", count);
	if (count == 0)
		failed = 1;
	return failed;
}
