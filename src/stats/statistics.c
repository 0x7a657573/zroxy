/*
 * statistics.c
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#include <zroxy/statistics.h>
#include <zroxy/log.h>
#include <stdlib.h>
#include <string.h>


void stats_init(statistics_t **self,char *name)
{
	*self = malloc(sizeof(statistics_t));
	if (!*self)
	{
		log_error("statistics allocation failed");
		exit(1);
	}
	memset(*self,0,sizeof(statistics_t));
	if(pthread_mutex_init(&(*self)->Lock, NULL) != 0)
	{
	    log_error("statistics mutex init has failed");
	    exit(1);
	}
	if (!name || strlen(name) >= sizeof((*self)->name))
	{
		log_error("statistics name rejected");
		exit(1);
	}
	memcpy((*self)->name, name, strlen(name) + 1);
	time ( &(*self)->stat.StartTime );
	(*self)->next = NULL;
}


void stats_close_connection(statistics_t *self,uint32_t rx,uint32_t tx)
{
	pthread_mutex_lock(&self->Lock);
	self->stat.TotalRx += rx;
	self->stat.TotalTx += tx;
	if (self->stat.ActiveConnection > 0)
		self->stat.ActiveConnection--;
	self->stat.TotalConnection++;
	pthread_mutex_unlock(&self->Lock);
}


void stats_open_connection(statistics_t *self)
{
	pthread_mutex_lock(&self->Lock);
	self->stat.ActiveConnection++;
	if(self->stat.ActiveConnection>self->stat.MaxConnection)
		self->stat.MaxConnection = self->stat.ActiveConnection;
	pthread_mutex_unlock(&self->Lock);
}

void stats_get(statistics_t *self,stat_t *st)
{
	pthread_mutex_lock(&self->Lock);
	*st =  self->stat;
	pthread_mutex_unlock(&self->Lock);
}

