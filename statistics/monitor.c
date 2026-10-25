/*
 * monitor.c
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "monitor.h"
#include <log.h>
#include "net.h"
#include <inttypes.h>
#include <version.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/select.h>
#include "net_io.h"

#define MON_MAX_WORKERS 32

static pthread_mutex_t mon_worker_mu = PTHREAD_MUTEX_INITIALIZER;
static int mon_workers = 0;

static bool mon_worker_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&mon_worker_mu);
	if (mon_workers < MON_MAX_WORKERS)
	{
		mon_workers++;
		ok = true;
	}
	pthread_mutex_unlock(&mon_worker_mu);
	return ok;
}

static void mon_worker_release(void)
{
	pthread_mutex_lock(&mon_worker_mu);
	if (mon_workers > 0)
		mon_workers--;
	pthread_mutex_unlock(&mon_worker_mu);
}

static bool http_headers_done(const uint8_t *buf, size_t len)
{
	size_t i;
	if (len < 4)
		return false;
	for (i = 0; i + 3 < len; i++)
	{
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		    buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return true;
	}
	return false;
}

void *Monitor_HandleConnection(void *vargp);
void Conv_Time(time_t Up,UpTime_t *tm);
char *Print_humanSize(char *ptr,uint64_t bytes);
int count_open_files(void);
void read_memory_usage(void);

mon_t *monitor_Init(uint16_t *Port)
{
	int sockfd;

	if(net_ListenIp4(htonl(INADDR_ANY), *Port,&sockfd)==false)
	{
		log_error("monitor can not listen on Port %i",*Port);
		return NULL;
	}

	log_info("monitor listen on %d",*Port);
	mon_t	*mon = calloc(1, sizeof(mon_t));
	if (!mon)
	{
		close(sockfd);
		return NULL;
	}
	if (pthread_mutex_init(&mon->state_lock, NULL) != 0)
	{
		close(sockfd);
		free(mon);
		return NULL;
	}
	mon->state = NULL;
	mon->fd = sockfd;
	mon->Port = *Port;

	pthread_t thread_id;
	if (pthread_create(&thread_id, NULL, Monitor_HandleConnection, (void*)mon) != 0)
	{
		close(sockfd);
		pthread_mutex_destroy(&mon->state_lock);
		free(mon);
		return NULL;
	}
	pthread_detach(thread_id);

	return mon;
}

statistics_t *monitor_AddNewStat(mon_t *self,char *name)
{
	statistics_t *stat;
	statistics_t *created;
	if (!self)
		return NULL;
	pthread_mutex_lock(&self->state_lock);
	stat = self->state;
	state_init(&self->state,name);		/*create statistics var*/
	self->state->next = stat;
	created = self->state;
	pthread_mutex_unlock(&self->state_lock);
	return created;
}

void *Minitor_HandelConnection(void *arg);
void Monitor_HandelClient(int fd,uint8_t *data,int len,mon_t *owner);
void *Monitor_HandleConnection(void *vargp)
{
	mon_t *mon = (mon_t*)vargp;
	int sockfd = mon->fd;	  /* listening socket descriptor */

	log_info("Monitor thread start on socket %i Port %d",sockfd,mon->Port);
	monclient_t *client;
	while(1)
	{
		client = (monclient_t *)calloc(1, sizeof(monclient_t));
		if (!client)
			continue;
		client->owner = mon;
		client->addr_len = sizeof(client->cli);
		client->connid = accept(sockfd, (struct sockaddr*)&client->cli, &client->addr_len);
		if (client->connid < 0)
		{
			if (errno != EINTR)
				log_error("server accept failed");
			free(client);
			continue;
		}

		if (client->connid >= FD_SETSIZE || !mon_worker_acquire())
		{
			close(client->connid);
			free(client);
			continue;
		}

		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, Minitor_HandelConnection, (void*)client) != 0)
		{
			mon_worker_release();
			close(client->connid);
			free(client);
			continue;
		}
		pthread_detach(thread_id);
	}
}

void *Minitor_HandelConnection(void *arg)
{
	if (!arg) pthread_exit(0);
	monclient_t *client = (monclient_t*)arg;
	uint8_t buffer[0x4000]; /*16Kb memory tmp*/
	uint32_t Windex = 0;

	fd_set rfds;
	struct timeval tv;
	while(1)
	{
		if (client->connid < 0 || client->connid >= FD_SETSIZE)
			break;

		FD_ZERO(&rfds);
		tv.tv_sec = 30;
		tv.tv_usec = 0;
		FD_SET(client->connid,&rfds);

		if (select(client->connid + 1, &rfds, NULL, NULL, &tv) < 0)	/*wait for socket data ready*/
		{
			if (errno == EINTR)
				continue;
			log_error("Err in select");
			break;
		}

		if(!FD_ISSET( client->connid, &rfds ))
		{
			log_trace("TimeOut tid:%i",client->connid);
			break;
		}

		int newData = read(client->connid, &buffer[Windex], sizeof(buffer) - Windex);/* read length of message */
		if (newData < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (newData <= 0)
		{
			log_trace("client %i disconnect %i",client->connid,newData);
			break;
		}
		if ((uint32_t)newData > sizeof(buffer) - Windex)
			break;
		Windex += (uint32_t)newData;

		if (http_headers_done(buffer, Windex))
		{
			Monitor_HandelClient(client->connid, buffer, (int)Windex, client->owner);
			break;
		}
		if (Windex >= sizeof(buffer))
			break;
	}

	log_trace("Monitor tid:%i Prosess",client->connid);
	if (client->connid >= 0)
		close(client->connid);
	mon_worker_release();
	free(client);
	return NULL;
}

static bool mon_append(char **ptr, char *end, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t left;
	if (*ptr >= end)
		return false;
	left = (size_t)(end - *ptr);
	va_start(ap, fmt);
	n = vsnprintf(*ptr, left, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
	return true;
}

void Monitor_HandelClient(int fd,uint8_t *data,int len,mon_t *owner)
{
	char message[2048];
	char *ptr = message;
	char *end = message + sizeof(message);
	statistics_t *stat = NULL;
	(void)data;
	(void)len;

	if (!owner)
		return;
	pthread_mutex_lock(&owner->state_lock);
	stat = owner->state;
	pthread_mutex_unlock(&owner->state_lock);

	memset(message, 0, sizeof(message));
	if (!mon_append(&ptr, end, "{\n\"ZroxyVersion\" : \"%s\",\n", version) ||
	    !mon_append(&ptr, end, "\"CountOfOpenFile\" : %i,\n", count_open_files()))
		return;
	
	// return;
	// read_memory_usage();

	statistics_t *sta = stat;
	while(sta)
	{
		/*incoming data and possess it*/
		stat_t stdata;
		state_get(sta,&stdata);	/*get static data*/
		time_t CurrentTime;
		time ( &CurrentTime );
		time_t LiveTime = CurrentTime - stdata.StartTime;

		if (!mon_append(&ptr, end, "\"%s\" : {\n", sta->name) ||
		    !mon_append(&ptr, end, "\"UpTime\" : %lu ,\n", LiveTime) ||
		    !mon_append(&ptr, end, "\"MaxConnection\" : %i ,\n", stdata.MaxConnection) ||
		    !mon_append(&ptr, end, "\"ActiveConnection\" : %i ,\n", stdata.ActiveConnection) ||
		    !mon_append(&ptr, end, "\"TotalConnection\" : %i ,\n", stdata.TotalConnection) ||
		    !mon_append(&ptr, end, "\"TotalRx\" : %lu ,\n", stdata.TotalRx) ||
		    !mon_append(&ptr, end, "\"TotalTx\" : %lu", stdata.TotalTx) ||
		    !mon_append(&ptr, end, "\n},\n"))
			return;

		sta = (statistics_t*)sta->next;
	}

	if (ptr - message < 2)
		return;
	memcpy(ptr - 2, "\n}", 3);

	{
		char httpMessage[8000];
		int body_len = (int)(ptr - message);
		int slen;
		if (body_len < 0)
			return;
		slen = snprintf(httpMessage, sizeof(httpMessage),
			"HTTP/1.1 200 OK\nContent-Type: application/json; charset=UTF-8\nContent-Length: %i\nConnection: Closed\n\n%s",
			body_len, message);
		if (slen < 0 || (size_t)slen >= sizeof(httpMessage))
			return;
		net_write_all(fd, httpMessage, (size_t)slen);
	}
}



void Conv_Time(time_t Up,UpTime_t *tm)
{
#define OneDaySec	(3600*24)

	tm->tm_yday = Up/OneDaySec;
	time_t Rtime = Up%OneDaySec;
	tm->tm_hour = Rtime/3600;
	Rtime = Rtime%3600;
	tm->tm_min = Rtime/60;
	tm->tm_sec = Rtime%60;
}

char *Print_humanSize(char *ptr,uint64_t bytes)
{
	char *suffix[] = {"B", "KB", "MB", "GB", "TB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if (bytes >= 1024)
	{
		for (i = 0; (bytes / 1024) > 0 && i<length-1; i++, bytes /= 1024)
			dblBytes = bytes / 1024.0;
	}

	ptr += sprintf(ptr, "%.02lf %s", dblBytes, suffix[i]);
	return ptr;
}


int count_open_files(void)
{
    struct dirent *entry;
    int count = 0;

	DIR *dp = NULL;
#ifdef __linux__
    dp = opendir("/proc/self/fd");
#elif __FreeBSD__
    dp = opendir("/dev/fd/");
#endif

    if (dp == NULL) 
	{
        perror("opendir");
        return -1;
    }

    // The number of files in the directory '/proc/self/fd'
    while ((entry = readdir(dp)) != NULL) 
	{
        count++;
    }

    closedir(dp);
    
	// because "." and ".." are also in the directory, we need to reduce by 2
    return count - 2;
}

void read_memory_usage(void) 
{
    FILE *status_file;

    status_file = fopen("/proc/self/status", "r");
    if (!status_file) 
	{
        perror("fopen");
        return;
    }

	char line[256];
    while (fgets(line, sizeof(line), status_file)) 
	{
        if (strncmp(line, "VmRSS:", 6) == 0 || strncmp(line, "VmSize:", 7) == 0) 
		{
            printf("%s", line);
        }
		//printf("%s", line);
    }

    fclose(status_file);
}