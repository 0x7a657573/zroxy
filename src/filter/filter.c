/*
 * filter.c
 *
 *  Created on: Mar 8, 2020
 *      Author: zeus
 */
#include <zroxy/filter.h>
#include <zroxy/log.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef __linux__
#include <sys/inotify.h>
#elif __FreeBSD__
#include <sys/types.h>
#include <sys/event.h>
#include <fcntl.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

/* Open-addressing string set. cap is a power of two, at most half full. */
typedef struct
{
	char   **slot;
	size_t cap;
}strset_t;

struct filter_set
{
	strset_t exact;		/* "example.com" */
	strset_t suffix;	/* ".example.com" from "*.example.com" */
	char   **pattern;	/* everything else with '*' or '?' */
	size_t pattern_count;
	size_t total;
};

static uint64_t fnv1a(const char *s)
{
	uint64_t h = 1469598103934665603ULL;
	while (*s)
	{
		h ^= (unsigned char)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}

static bool strset_init(strset_t *set, size_t count)
{
	size_t cap = 8;
	while (cap < count * 2)
		cap <<= 1;
	set->slot = calloc(cap, sizeof(*set->slot));
	set->cap = set->slot ? cap : 0;
	return set->slot != NULL;
}

/* Takes ownership of key; frees it if already present. */
static void strset_add(strset_t *set, char *key)
{
	size_t i = (size_t)fnv1a(key) & (set->cap - 1);
	while (set->slot[i])
	{
		if (strcmp(set->slot[i], key) == 0)
		{
			free(key);
			return;
		}
		i = (i + 1) & (set->cap - 1);
	}
	set->slot[i] = key;
}

static bool strset_has(const strset_t *set, const char *key)
{
	size_t i;
	if (set->cap == 0)
		return false;
	i = (size_t)fnv1a(key) & (set->cap - 1);
	while (set->slot[i])
	{
		if (strcmp(set->slot[i], key) == 0)
			return true;
		i = (i + 1) & (set->cap - 1);
	}
	return false;
}

static void strset_free(strset_t *set)
{
	size_t i;
	for (i = 0; i < set->cap; i++)
		free(set->slot[i]);
	free(set->slot);
	set->slot = NULL;
	set->cap = 0;
}

static void set_free(filter_set_t *set)
{
	size_t i;
	if (!set)
		return;
	strset_free(&set->exact);
	strset_free(&set->suffix);
	for (i = 0; i < set->pattern_count; i++)
		free(set->pattern[i]);
	free(set->pattern);
	free(set);
}

/*
 * Lower-case, drop surrounding whitespace and one trailing dot.
 * Returns false for an over-long entry; *out is "" for a line to skip.
 */
static bool normalize_entry(const char *in, char *out, size_t out_cap)
{
	size_t n;
	size_t i;

	while (*in && isspace((unsigned char)*in))
		in++;
	n = strlen(in);
	while (n > 0 && isspace((unsigned char)in[n - 1]))
		n--;
	if (n == 0 || in[0] == '#')
	{
		out[0] = '\0';
		return true;
	}
	if (n > 1 && in[n - 1] == '.')
		n--;
	if (n >= out_cap)
		return false;
	for (i = 0; i < n; i++)
		out[i] = (char)tolower((unsigned char)in[i]);
	out[n] = '\0';
	return true;
}

/* "*.example.com" with no other wildcard -> ".example.com" */
static bool is_suffix_pattern(const char *e)
{
	return e[0] == '*' && e[1] == '.' && e[2] != '\0' && strpbrk(e + 1, "*?") == NULL;
}

/* entries are already normalized and non-empty */
static filter_set_t *set_build(char **entries, size_t count)
{
	filter_set_t *set = calloc(1, sizeof(*set));
	size_t i;
	size_t nexact = 0, nsuffix = 0, npattern = 0;

	if (!set)
		return NULL;
	for (i = 0; i < count; i++)
	{
		if (is_suffix_pattern(entries[i]))
			nsuffix++;
		else if (strpbrk(entries[i], "*?"))
			npattern++;
		else
			nexact++;
	}
	if (!strset_init(&set->exact, nexact) || !strset_init(&set->suffix, nsuffix) ||
		(npattern && !(set->pattern = calloc(npattern, sizeof(*set->pattern)))))
	{
		set_free(set);
		return NULL;
	}
	for (i = 0; i < count; i++)
	{
		char *e = entries[i];
		entries[i] = NULL; /* ownership moves into the set */
		if (is_suffix_pattern(e))
		{
			memmove(e, e + 1, strlen(e)); /* keep the leading '.' */
			strset_add(&set->suffix, e);
		}
		else if (strpbrk(e, "*?"))
			set->pattern[set->pattern_count++] = e;
		else
			strset_add(&set->exact, e);
	}
	set->total = count;
	return set;
}

typedef struct
{
	char   **item;
	size_t count;
	size_t cap;
}entry_list_t;

static void entry_list_free(entry_list_t *l)
{
	size_t i;
	for (i = 0; i < l->count; i++)
		free(l->item[i]);
	free(l->item);
	memset(l, 0, sizeof(*l));
}

/* Normalize and append one raw entry. false on error. */
static bool entry_list_add(entry_list_t *l, const char *raw)
{
	char norm[ZROXY_MAX_HOSTNAME];
	char *copy;

	if (!normalize_entry(raw, norm, sizeof(norm)))
	{
		log_error("whitelist entry too long");
		return false;
	}
	if (norm[0] == '\0')
		return true;
	if (l->count == l->cap)
	{
		size_t cap = l->cap ? l->cap * 2 : 64;
		char **item = realloc(l->item, cap * sizeof(*item));
		if (!item)
			return false;
		l->item = item;
		l->cap = cap;
	}
	copy = strdup(norm);
	if (!copy)
		return false;
	l->item[l->count++] = copy;
	return true;
}

static filter_set_t *set_load_file(const char *path)
{
	FILE *fp = fopen(path, "r"); // read only
	entry_list_t list = {0};
	filter_set_t *set = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	bool ok = true;

	if (!fp)
	{
		log_error("can not open whitelist file %s", path);
		return NULL;
	}
	while ((read = getline(&line, &len, fp)) != -1)
	{
		if (read > ZROXY_MAX_CONFIG_LINE || !entry_list_add(&list, line))
		{
			if (read > ZROXY_MAX_CONFIG_LINE)
				log_error("whitelist entry too long");
			ok = false;
			break;
		}
	}
	free(line);
	fclose(fp);
	if (ok)
		set = set_build(list.item, list.count);
	entry_list_free(&list);
	return set;
}

static filter_t *filter_alloc(filter_set_t *set, const char *path)
{
	filter_t *self = calloc(1, sizeof(*self));
	if (!self)
		return NULL;
	if (path && !(self->filepath = strdup(path)))
	{
		free(self);
		return NULL;
	}
	if (pthread_rwlock_init(&self->lock, NULL) != 0)
	{
		log_error("filter lock init has failed");
		free(self->filepath);
		free(self);
		return NULL;
	}
	self->set = set;
	return self;
}

void filter_reload(filter_t *self)
{
	filter_set_t *fresh;
	filter_set_t *old;

	if(!self || !self->filepath)
		return;

	log_info("reloading whitelist %s", self->filepath);
	fresh = set_load_file(self->filepath);
	if (!fresh)
	{
		log_error("Reload filter failed; keeping previous list");
		return;
	}

	pthread_rwlock_wrlock(&self->lock);
	old = self->set;
	self->set = fresh;
	pthread_rwlock_unlock(&self->lock);

	/* no reader can still hold old: the write lock waited for them */
	set_free(old);
	log_info("Reload filter: %zu valid host loaded", fresh->total);
}

#ifdef __linux__
/*
 * Watch the parent directory, not the file. Editors and config tools often
 * save by writing a temp file and renaming it over the original, which
 * replaces the inode and silently kills a watch on the file itself.
 * IN_CLOSE_WRITE also avoids reloading a half-written file.
 */
static void *filter_watch_thread(void *vargp)
{
	filter_t *self = (filter_t *)vargp;
	int wd, fd;
	char dir[4096];
	const char *base;
	const char *slash = strrchr(self->filepath, '/');

	if (slash)
	{
		size_t dlen = (size_t)(slash - self->filepath);
		if (dlen == 0)
			dlen = 1; /* file in "/" */
		if (dlen >= sizeof(dir))
		{
			log_error("whitelist path too long to watch");
			return NULL;
		}
		memcpy(dir, self->filepath, dlen);
		dir[dlen] = '\0';
		base = slash + 1;
	}
	else
	{
		memcpy(dir, ".", 2);
		base = self->filepath;
	}

	fd = inotify_init1(IN_CLOEXEC);
	if ( fd < 0 )
	{
		log_error("Couldn't initialize inotify");
		return NULL;
	}

	wd = inotify_add_watch(fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO);
	if (wd == -1)
	{
		log_error("Couldn't add watch to %s",dir);
		close(fd);
		return NULL;
	}
	log_info("watching %s for changes",self->filepath);

	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	ssize_t len;
	while(1)
	{
		len = read(fd, buf, sizeof(buf));
		if (len < 0)
		{
			if (errno == EINTR)
				continue;
			log_error("filter watcher crash");
			break;
		}
		if (len == 0)
			break;

		bool changed = false;
		char *ptr = buf;
		char *buf_end = buf + len;
		while (ptr + sizeof(struct inotify_event) <= buf_end)
		{
			size_t evsz;
			event = (const struct inotify_event *) ptr;
			if ((size_t)event->len > (size_t)(buf_end - ptr) - sizeof(*event))
				break;
			evsz = sizeof(*event) + (size_t)event->len;
			if (event->len > 0 && strcmp(event->name, base) == 0 &&
				(event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)))
				changed = true;
			if (event->mask & IN_IGNORED)
			{
				log_error("whitelist directory watch removed");
				close(fd);
				return NULL;
			}
			ptr += evsz;
		}
		if (changed)
		{
			log_info( "file %s was modified", self->filepath);
			filter_reload(self);
		}
	}

	close(fd);
	return NULL;
}
#elif __FreeBSD__
#ifdef NOTE_CLOSE_WRITE
#define FILTER_NOTE_CHANGE	(NOTE_CLOSE_WRITE | NOTE_ATTRIB)
#else
#define FILTER_NOTE_CHANGE	(NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB)
#endif

/* open the whitelist and register it; the old registration goes with close(fd) */
static int filter_watch_open(int kq, const char *filename)
{
	struct kevent change;
	int fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return -1;
	EV_SET(&change, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
		FILTER_NOTE_CHANGE | NOTE_DELETE | NOTE_RENAME, 0, NULL);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1)
	{
		close(fd);
		return -1;
	}
	return fd;
}

static void *filter_watch_thread(void *vargp)
{
	filter_t *self = (filter_t *)vargp;
	const char *filename = self->filepath; // The file to monitor
	int kq = kqueue(); // Create a new kernel event queue

	if (kq == -1)
	{
		log_error("Couldn't initialize kqueue");
		return NULL;
	}

	int fd = filter_watch_open(kq, filename);
	if (fd == -1)
	{
		log_error("Couldn't add open %s",filename);
		close(kq);
		return NULL;
	}

	log_info("Watching for changes to %s...", filename);

	while (1)
	{
		struct kevent event;
		int nev = kevent(kq, NULL, 0, &event, 1, NULL); // Wait for events

		if (nev == -1)
		{
			if (errno == EINTR)
				continue;
			log_error("kevent event error");
			break;
		}
		if (nev == 0)
			continue;

		if (event.fflags & (NOTE_DELETE | NOTE_RENAME))
		{
			/* replaced by rename or delete+create: follow the new file */
			int tries;
			close(fd);
			fd = -1;
			for (tries = 0; tries < 50 && fd == -1; tries++)
			{
				usleep(100000);
				fd = filter_watch_open(kq, filename);
			}
			if (fd == -1)
			{
				log_error("whitelist %s is gone; stop watching", filename);
				break;
			}
			log_info( "file %s was replaced", self->filepath);
			filter_reload(self);
			continue;
		}
		if (event.fflags & FILTER_NOTE_CHANGE)
		{
			log_info( "file %s was modified", self->filepath);
			filter_reload(self);
		}
	}

	// Cleanup
	if (fd != -1)
		close(fd);
	close(kq);
	return NULL;
}
#endif

filter_t *filter_init(char *filename)
{
	filter_set_t *set = set_load_file(filename);
	filter_t *self;
	pthread_t thread_id;

	if (!set)
		return NULL;
	self = filter_alloc(set, filename);
	if (!self)
	{
		set_free(set);
		return NULL;
	}
	log_info("load %zu valid host", set->total);

	/*create file watcher*/
	if (pthread_create(&thread_id, NULL, filter_watch_thread, (void*)self) == 0)
		pthread_detach(thread_id);
	else
		log_error("whitelist watcher thread failed");
	return self;
}

filter_t *filter_from_list(const char *const *entries, size_t count)
{
	entry_list_t list = {0};
	filter_set_t *set;
	filter_t *self;
	size_t i;

	for (i = 0; i < count; i++)
	{
		if (!entry_list_add(&list, entries[i]))
		{
			entry_list_free(&list);
			return NULL;
		}
	}
	set = set_build(list.item, list.count);
	entry_list_free(&list);
	if (!set)
		return NULL;
	self = filter_alloc(set, NULL);
	if (!self)
		set_free(set);
	return self;
}

void filter_free(filter_t *self)
{
	if(!self)
		return;
	set_free(self->set);
	free(self->filepath);
	pthread_rwlock_destroy(&self->lock);
	free(self);
}

/*
this function chack str2 match pattern in str1
'*' matches any run of characters (dots included), '?' exactly one.
str1 = apple, str2 = app* -return-> true
str1 = apple, str2 = *ple -return-> true
str1 = apple, str2 = *plex -return-> false
*/
static bool match(const char *str1, const char *str2)
{
   int i = 0;
   int j = 0;
   int star = -1;
   int mark = 0;

   while (str1[i] != '\0')
   {
      if (str2[j] == '*')
      {
         star = j++;
         mark = i;
      }
      else if (str2[j] != '\0' && (str1[i] == str2[j] || str2[j] == '?'))
      {
         i++;
         j++;
      }
      else if (star != -1)
      {
         j = star + 1;
         i = ++mark;
      }
      else
      {
         return false;
      }
   }

   while (str2[j] == '*')
   {
      j++;
   }

   return str2[j] == '\0';
}

static bool set_match(const filter_set_t *set, const char *host)
{
	const char *dot;
	size_t i;

	if (strset_has(&set->exact, host))
		return true;
	for (dot = strchr(host, '.'); dot; dot = strchr(dot + 1, '.'))
	{
		if (strset_has(&set->suffix, dot))
			return true;
	}
	for (i = 0; i < set->pattern_count; i++)
	{
		if (match(host, set->pattern[i]))
			return true;
	}
	return false;
}

bool filter_match(filter_t *self,const char *host)
{
	char norm[ZROXY_MAX_HOSTNAME];
	size_t n;
	size_t i;
	bool res;

	if (!self || !host)
		return false;
	n = strlen(host);
	if (n > 1 && host[n - 1] == '.')
		n--;
	if (n >= sizeof(norm))
		return false;
	for (i = 0; i < n; i++)
		norm[i] = (char)tolower((unsigned char)host[i]);
	norm[n] = '\0';

	pthread_rwlock_rdlock(&self->lock);
	res = set_match(self->set, norm);
	pthread_rwlock_unlock(&self->lock);
	return res;
}

size_t filter_count(filter_t *self)
{
	size_t n;
	if (!self)
		return 0;
	pthread_rwlock_rdlock(&self->lock);
	n = self->set->total;
	pthread_rwlock_unlock(&self->lock);
	return n;
}
