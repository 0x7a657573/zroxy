/*
 * filter.c
 *
 *  Created on: Mar 8, 2020
 *      Author: zeus
 */
#include "filter.h"
#include <log/log.h>
#include <string.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>

void filter_Remove(filter_t *self);

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

	pthread_mutex_lock(&self->Lock);

	/*remove all entry*/
	item_t *ptr = self->item;
	while(ptr)
	{
		item_t *next = ptr->Next;
		free(ptr);
		ptr = next;
	}

	/*read and load filter from file*/
	size_t len = 0;
	char *line = NULL;
	item_t *Pvitem = NULL;
	int num = 0;
	ssize_t read;
	while ((read = getline(&line, &len, FilterFile)) != -1)
	{
		if(read>=_MaxHostName_)
		{
			log_error("Filter Item Len Bigest Buffer");
			break;
		}

	    self->item = malloc(sizeof(item_t));
	    if(self->item==NULL)
	    {
	    	log_error("we don't have enough memory for loading filter");
	    	break;
	    }

	    memset(self->item,0,sizeof(item_t));

	    char *pos;	/*remove new line*/
	    if ((pos=strchr(line, '\n')) != NULL)
	        *pos = '\0';

	    strcpy(self->item->Rec,line);

	    self->item->Next = Pvitem;
	    Pvitem = self->item;
	    num++;
	}

	free(line);
	log_info("Reload filter: %i valid host loaded",num);
	
	pthread_mutex_unlock(&self->Lock);
}

void *filter_Handlefilewatcher(void *vargp)
{
	filter_t *self = (filter_t *)vargp;
	int wd, fd;
	fd = inotify_init();
    if ( fd < 0 ) 
	{
        log_error("Couldn't initialize inotify");
		return false;
    }

	wd = inotify_add_watch(fd, self->filepath, IN_MODIFY); 
    if (wd == -1) 
	{
        log_error("Couldn't add watch to %s\n",self->filepath);
		return false;
    }
	else 
	{
        log_info("Watching::%s\n",self->filepath);
    }
	
	char buf[4096];
	const struct inotify_event *event;
    ssize_t len;
	while(1)
	{
		len = read(fd, buf, sizeof(buf));
        if (len < 0) 
		{
            log_error("filter watcher crash");
            break;
        }

		for (char *ptr = buf; ptr < buf + len;
            ptr += sizeof(struct inotify_event) + event->len)
		{
			event = (const struct inotify_event *) ptr;
			if ( event->mask & IN_MODIFY) 
			{
				log_info( "file %s was modified", self->filepath);
				filter_Reload(self);
			}
		}
	}

	pthread_exit(0);
}


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
	memset(self,0,sizeof(filter_t));
	if(pthread_mutex_init(&self->Lock, NULL) != 0)
	{
	    log_error("filter mutex init has failed");
	    exit(0);
	}

	self->filepath = malloc(strlen(filename)+1);
	if(!self->filepath)
	{
		log_error("filter filename malloc error");
	    exit(0);
	}
	bzero(self->filepath,strlen(filename)+1);
	strcpy(self->filepath,filename);

	item_t *Pvitem = NULL;
	int num = 0;
	while ((read = getline(&line, &len, FilterFile)) != -1)
	{
		if(read>=_MaxHostName_)
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

	    char *pos;	/*remove new line*/
	    if ((pos=strchr(line, '\n')) != NULL)
	        *pos = '\0';

	    strcpy(self->item->Rec,line);

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
		pthread_create(&thread_id, NULL, filter_Handlefilewatcher, (void*)self);
	}
	
	return self;
}


void filter_Remove(filter_t *self)
{
	if(!self)
		return;

	item_t *ptr = self->item;
	while(ptr)
	{
		item_t *next = ptr->Next;
		free(ptr);
		ptr = next;
	}

	free(self->filepath);
	free(self);
}

bool filter_IsWhite(filter_t *self,char *host)
{
	bool res = false;
	pthread_mutex_lock(&self->Lock);

	item_t *ptr = self->item;
	while(ptr)
	{
		item_t *next = ptr->Next;
		if(strstr(host,ptr->Rec))
		{
			res = true;
			break;
		}
		ptr = next;
	}

	pthread_mutex_unlock(&self->Lock);
	return res;
}
