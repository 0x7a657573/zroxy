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
#ifdef __linux__
#include <sys/inotify.h>
#elif __FreeBSD__
#include <sys/types.h>
#include <sys/event.h>
#include <fcntl.h>
#include <unistd.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

void filter_Remove(filter_t *self);
void filter_Remove_Itemlist(item_t *ptr);

static bool filter_store_line(char *dst, size_t dstsz, char *line, ssize_t read)
{
	size_t n;
	if (read < 0 || (size_t)read >= _MaxHostName_ || (size_t)read >= dstsz)
		return false;
	n = (size_t)read;
	if (n > 0 && line[n - 1] == '\n')
	{
		line[--n] = '\0';
	}
	if (n > 0 && line[n - 1] == '\r')
	{
		line[--n] = '\0';
	}
	if (n >= dstsz)
		return false;
	memcpy(dst, line, n + 1);
	return true;
}

void filter_Reload(filter_t *self)
{
	if(!self)
		return;

	log_info("Try Reload Filters");

	FILE *FilterFile  = fopen(self->filepath, "r"); // read only
	if(FilterFile==NULL)
	{
		log_error("Can not Open Filter File");
		return;
	}

	/*load domain from file to new list*/
	item_t *NewList = NULL;
	item_t *Pvitem = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int num = 0;
	bool failed = false;
	while ((read = getline(&line, &len, FilterFile)) != -1)
	{
		if (read > _MaxConfigLine_)
		{
			log_error("Filter Item Len Bigest Buffer");
			failed = true;
			break;
		}

	    NewList = malloc(sizeof(item_t));
	    if(NewList==NULL)
	    {
	    	filter_Remove_Itemlist(Pvitem);
	    	Pvitem = NULL;
	    	failed = true;
	    	break;
	    }

	    memset(NewList,0,sizeof(item_t));

	    if (!filter_store_line(NewList->Rec, sizeof(NewList->Rec), line, read))
	    {
	    	log_error("Filter Item Len Bigest Buffer");
	    	free(NewList);
	    	filter_Remove_Itemlist(Pvitem);
	    	Pvitem = NULL;
	    	failed = true;
	    	break;
	    }

	    NewList->Next = Pvitem;
	    Pvitem = NewList;
	    num++;
	}

	/*free getline buffer*/
	free(line);
	fclose(FilterFile);

	if (failed)
	{
		log_error("Reload filter failed; keeping previous list");
		return;
	}

	/*replace new list with old one*/
	pthread_mutex_lock(&self->Lock);
	item_t *ptr = self->item;
	self->item = NewList;
	pthread_mutex_unlock(&self->Lock);

	/*remove old entry entry*/
	filter_Remove_Itemlist(ptr);
	log_info("Reload filter: %i valid host loaded",num);
}

#ifdef __linux__
/*
 * Watch the parent directory, not the file. Editors and config tools often
 * save by writing a temp file and renaming it over the original, which
 * replaces the inode and silently kills a watch on the file itself.
 * IN_CLOSE_WRITE also avoids reloading a half-written file.
 */
void *filter_Handlefilewatcher(void *vargp)
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
	log_info("Watching::%s",self->filepath);

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
			filter_Reload(self);
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

void *filter_Handlefilewatcher(void *vargp)
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
			filter_Reload(self);
			continue;
		}
		if (event.fflags & FILTER_NOTE_CHANGE)
		{
			log_info( "file %s was modified", self->filepath);
			filter_Reload(self);
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
	filter_t *self = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *FilterFile  = fopen(filename, "r"); // read only

	if(FilterFile==NULL)
	{
		log_error("Can not Open Filter File");
		return self;
	}

	self = malloc(sizeof(filter_t));
	if (!self)
	{
		free(line);
		fclose(FilterFile);
		return NULL;
	}
	memset(self,0,sizeof(filter_t));
	if(pthread_mutex_init(&self->Lock, NULL) != 0)
	{
	    log_error("filter mutex init has failed");
	    free(self);
	    free(line);
	    fclose(FilterFile);
	    return NULL;
	}

	self->filepath = malloc(strlen(filename)+1);
	if(!self->filepath)
	{
		log_error("filter filename malloc error");
		pthread_mutex_destroy(&self->Lock);
		free(self);
		free(line);
		fclose(FilterFile);
		return NULL;
	}
	memcpy(self->filepath, filename, strlen(filename) + 1);

	item_t *Pvitem = NULL;
	int num = 0;
	while ((read = getline(&line, &len, FilterFile)) != -1)
	{
		if(read > _MaxConfigLine_)
		{
			log_error("Filter Item Len Bigest Buffer");
			filter_Remove(self);
			self = NULL;
			break;
		}

	    self->item = malloc(sizeof(item_t));
	    if(self->item==NULL)
	    {
	    	filter_Remove(self);
	    	self = NULL;
	    	break;
	    }

	    memset(self->item,0,sizeof(item_t));

	    if (!filter_store_line(self->item->Rec, sizeof(self->item->Rec), line, read))
	    {
	    	log_error("Filter Item Len Bigest Buffer");
	    	free(self->item);
	    	self->item = Pvitem;
	    	filter_Remove(self);
	    	self = NULL;
	    	break;
	    }

	    self->item->Next = Pvitem;
	    Pvitem = self->item;
	    num++;
	}

	log_info("load %i valid host",num);

	free(line);
	fclose(FilterFile);

	/*create file watcher*/
	if(self)
	{
		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, filter_Handlefilewatcher, (void*)self) == 0)
			pthread_detach(thread_id);
		else
			log_error("whitelist watcher thread failed");
	}

	return self;
}

void filter_Remove_Itemlist(item_t *ptr)
{
	while(ptr)
	{
		item_t *next = ptr->Next;
		free(ptr);
		ptr = next;
	}
}

void filter_Remove(filter_t *self)
{
	if(!self)
		return;

	filter_Remove_Itemlist(self->item);
	free(self->filepath);
	pthread_mutex_destroy(&self->Lock);
	free(self);
}

/*
this function chack str2 match pattern in str1 (ASCII case-insensitive, RFC 4343)
str1 = apple, str2 = app* -return-> true
str1 = apple, str2 = *ple -return-> true
str1 = apple, str2 = *plex -return-> false
*/
bool match(char *str1, char *str2) 
{
   int i = 0;
   int j = 0;
   int star = -1;
   int match = 0;

   while (str1[i] != '\0' && str2[j] != '\0') 
   {
      if (str2[j] == '*') 
	  {
         star = j++;
         match = i;
      } 
	  else if (tolower((unsigned char)str1[i]) == tolower((unsigned char)str2[j]) || str2[j] == '?')
	  {
         i++;
         j++;
      }
	  else if (star != -1) 
	  {
         j = star + 1;
         i = ++match;
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

bool filter_IsWhite(filter_t *self,char *host)
{
	bool res = false;
	pthread_mutex_lock(&self->Lock);

	item_t *ptr = self->item;
	while(ptr)
	{
		item_t *next = ptr->Next;
		if(match(host,ptr->Rec))
		{
			res = true;
			break;
		}
		ptr = next;
	}

	pthread_mutex_unlock(&self->Lock);
	return res;
}
