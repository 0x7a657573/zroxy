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


void filter_Remove(filter_t *self);

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
	    log_error("statistics mutex init has failed");
	    exit(0);
	}

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
	return self;
}


void filter_Remove(filter_t *self)
{
	if(!self)
		return ;
	item_t *ptr = self->item;
	while(ptr)
	{
		item_t *next = ptr->Next;
		free(ptr);
		ptr = next;
	}
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
