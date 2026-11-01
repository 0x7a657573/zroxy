/*
 * priv.c - drop root after startup.
 *
 * zroxy starts its listener, DNS, monitor and resolver threads before it
 * can give up root, because they are what binds the ports. That is only
 * safe when setuid() and friends change every thread, not just the
 * caller. They do on both libcs we build against: glibc (2.3.4 and
 * later) and musl run the call in all threads through a signal broadcast
 * (the "setxid" and "synccall" mechanisms) so the POSIX process-wide
 * semantics hold, and the raw Linux syscall alone would be per-thread.
 * Rather than trust that, priv_drop reads the credentials of every task
 * back from /proc/self/task and fails when one still differs.
 */
#define _GNU_SOURCE
#include <zroxy/priv.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zroxy/log.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifdef __linux__
/* True when the "Uid:" or "Gid:" line of a status file is all `want`. */
static bool status_ids_match(const char *text, const char *key, unsigned long want)
{
	const char *p = strstr(text, key);
	int i;

	if (!p)
		return false;
	p += strlen(key);
	for (i = 0; i < 4; i++)	/* real, effective, saved, filesystem */
	{
		char *tail = NULL;
		unsigned long v = strtoul(p, &tail, 10);
		if (tail == p || v != want)
			return false;
		p = tail;
	}
	return true;
}

static bool task_ids_match(const char *tid, uid_t uid, gid_t gid)
{
	char path[64];
	char text[2048];
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "/proc/self/task/%s/status", tid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return true;	/* the thread ended since readdir */
	n = read(fd, text, sizeof(text) - 1);
	close(fd);
	if (n <= 0)
		return true;
	text[n] = '\0';
	return status_ids_match(text, "\nUid:", (unsigned long)uid) &&
		status_ids_match(text, "\nGid:", (unsigned long)gid);
}

/* Every thread must have taken the change. Linux only; best effort if /proc is absent. */
static bool all_threads_dropped(uid_t uid, gid_t gid)
{
	struct dirent *entry;
	DIR *dp = opendir("/proc/self/task");
	bool ok = true;

	if (!dp)
	{
		log_warn("can not check the other threads' credentials: %s", strerror(errno));
		return true;
	}
	while ((entry = readdir(dp)) != NULL)
	{
		if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
			continue;
		if (!task_ids_match(entry->d_name, uid, gid))
		{
			log_error("thread %s did not drop privileges", entry->d_name);
			ok = false;
			break;
		}
	}
	closedir(dp);
	return ok;
}
#endif

bool priv_drop(uid_t uid, gid_t gid)
{
	if (setgroups(0, NULL) != 0)
	{
		log_error("setgroups failed: %s", strerror(errno));
		return false;
	}
	if (setgid(gid) != 0)
	{
		log_error("setgid(%lu) failed: %s", (unsigned long)gid, strerror(errno));
		return false;
	}
	if (setuid(uid) != 0)
	{
		log_error("setuid(%lu) failed: %s", (unsigned long)uid, strerror(errno));
		return false;
	}

	if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid ||
		getgroups(0, NULL) != 0)
	{
		log_error("privilege drop did not take effect");
		return false;
	}
	/* a non-root identity must not be able to come back */
	if (uid != 0 && (setuid(0) == 0 || seteuid(0) == 0))
	{
		log_error("privileges can still be regained after the drop");
		return false;
	}
	if (gid != 0 && setgid(0) == 0)
	{
		log_error("group privileges can still be regained after the drop");
		return false;
	}
#ifdef __linux__
	if (!all_threads_dropped(uid, gid))
		return false;
#endif
	return true;
}

void priv_harden(bool dropped)
{
#ifdef __linux__
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		log_warn("PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
	if (dropped && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
		log_warn("PR_SET_DUMPABLE failed: %s", strerror(errno));
#else
	(void)dropped;
#endif
}
