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
	mon_t	*mon = malloc(sizeof(mon_t));
	mon->state = NULL;
	//state_init(&mon->state);		/*create statistics var*/
	mon->fd = sockfd;
	mon->Port = *Port;

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, Monitor_HandleConnection, (void*)mon);
	//pthread_join(thread_id, NULL);

	return mon;
}

statistics_t *monitor_AddNewStat(mon_t *self,char *name)
{
	statistics_t *stat = self->state;
	state_init(&self->state,name);		/*create statistics var*/
	self->state->next = stat;
	return self->state;
}

void *Minitor_HandelConnection(void *arg);
void Monitor_HandelClient(int fd,uint8_t *data,int len,statistics_t *sta);
void *Monitor_HandleConnection(void *vargp)
{
	mon_t *mon = (mon_t*)vargp;
	int sockfd = mon->fd;	  /* listening socket descriptor */

	log_info("Monitor thread start on socket %i Port %d",sockfd,mon->Port);
	monclient_t *client;
	while(1)
	{
		client = (monclient_t *)malloc(sizeof(monclient_t));
		client->connid = accept(sockfd, (struct sockaddr*)&client->cli, &client->addr_len);
		client->state = mon->state;
		if (client->connid < 0)
		{
			free(client);
			log_error("server accept failed");
			continue;
		}

		pthread_t thread_id;
		pthread_create(&thread_id, NULL, Minitor_HandelConnection, (void*)client);
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
		FD_ZERO(&rfds);
		tv.tv_sec = 30;
		tv.tv_usec = 0;
		FD_SET(client->connid,&rfds);

		if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) < 0)	/*wait for socket data ready*/
		{
			log_error("Err in select");
			break;
		}

		if(!FD_ISSET( client->connid, &rfds ))
		{
			log_trace("TimeOut tid:%i",client->connid);
			break;
		}

		int newData = read(client->connid, &buffer[Windex], sizeof(buffer) - Windex);/* read length of message */
		if (newData <= 0)
		{
			log_trace("client %i disconnect %i",client->connid,newData);
			break;
		}
		Windex+=newData;

		Monitor_HandelClient(client->connid,buffer,Windex,client->state);
		break;
	}

	log_trace("Monitor tid:%i Prosess",client->connid);
	close(client->connid);
	free(client);
	pthread_exit(0);
	return NULL;
}

void Monitor_HandelClient(int fd,uint8_t *data,int len,statistics_t *stat)
{
	char message[2048] = {0};
	char *ptr = message;

	ptr += sprintf(ptr,"{\n\"ZroxyVersion\" : \"%s\",\n",version);
	ptr += sprintf(ptr,"\"CountOfOpenFile\" : %i,\n",count_open_files());
	
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

		ptr += sprintf(ptr,"\"%s\" : {\n",sta->name);
		ptr += sprintf(ptr,"\"UpTime\" : %lu ,\n",LiveTime);
		ptr += sprintf(ptr,"\"MaxConnection\" : %i ,\n",stdata.MaxConnection);
		ptr += sprintf(ptr,"\"ActiveConnection\" : %i ,\n",stdata.ActiveConnection);
		ptr += sprintf(ptr,"\"TotalConnection\" : %i ,\n",stdata.TotalConnection);
		ptr += sprintf(ptr,"\"TotalRx\" : %lu ,\n",stdata.TotalRx);
		ptr += sprintf(ptr,"\"TotalTx\" : %lu",stdata.TotalTx);
		ptr += sprintf(ptr,"\n},\n");

		sta = (statistics_t*)sta->next;
	}

	ptr += sprintf(ptr-2,"\n}");

	char httpMessage[8000];
	int slen = sprintf(httpMessage,"HTTP/1.1 200 OK\nContent-Type: application/json; charset=UTF-8\nContent-Length: %i\nConnection: Closed\n\n%s",(int)(ptr-message),message);
	write(fd,httpMessage,slen);	/*echo*/
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
    DIR *dp = opendir("/proc/self/fd");
    
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

    // باز کردن فایل
    status_file = fopen("/proc/self/status", "r");
    if (!status_file) 
	{
        perror("fopen");
        return;
    }

	char line[256];
    // خواندن هر خط از فایل و پیدا کردن VmRSS و VmSize
    while (fgets(line, sizeof(line), status_file)) 
	{
        if (strncmp(line, "VmRSS:", 6) == 0 || strncmp(line, "VmSize:", 7) == 0) 
		{
            printf("%s", line);  // چاپ مقدار حافظه مصرف شده
        }
		//printf("%s", line);
    }

    fclose(status_file);
}