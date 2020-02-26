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
#include "log/log.h"
#include "net/net.h"
#include <inttypes.h>

void *Monitor_HandleConnection(void *vargp);

statistics_t *monitor_Init(uint16_t *Port)
{
	int sockfd;

	if(net_ListenIp4(htonl(INADDR_ANY), *Port,&sockfd)==false)
	{
		log_error("monitor can not listen on Port %i",*Port);
		return NULL;
	}

	log_info("monitor listen on %d",*Port);
	mon_t	*mon = malloc(sizeof(mon_t));
	state_init(&mon->state);		/*create statistics var*/
	mon->fd = sockfd;

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, Monitor_HandleConnection, (void*)mon);
	//pthread_join(thread_id, NULL);


	return mon->state;
}

void Monitor_HandelClient(int fd,uint8_t *data,int len,statistics_t *sta);
void *Monitor_HandleConnection(void *vargp)
{
	mon_t *mon = (mon_t*)vargp;
	int listener = mon->fd;	/* listening socket descriptor */


	struct sockaddr_in clientaddr;	/* client address */
	fd_set master;		/* master file descriptor list */
	fd_set read_fds;	/* temp file descriptor list for select() */
	int fdmax;			/* maximum file descriptor number */
	int newfd;			/* newly accept()ed socket descriptor */
	uint8_t buf[8192];		/* buffer for client data */

	/* clear the master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);


	FD_SET(listener, &master);	/* add the listener to the master set */
	/* keep track of the biggest file descriptor */
	fdmax = listener; /* so far, it's this one*/

	while(1)
	{
		read_fds = master;	/* copy it */
		if(select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1)
		{
		    log_error("monitor select() error O_o !");
		    exit(1);
		}

		/*run through the existing connections looking for data to be read*/
		for(int i = 0; i <= fdmax; i++)
		{
			if(FD_ISSET(i, &read_fds))
			{
				if(i == listener) /*it's need handle new connections */
				{
					socklen_t addrlen = sizeof(clientaddr);
					if((newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) == -1)
					{
						log_error("monitor accept() error X_x !");
					}
					else
					{
						FD_SET(newfd, &master); /* add to master set */
						if(newfd > fdmax)		/* keep track of the maximum */
						{
						    fdmax = newfd;
						}
						log_info("monitor: New connection from %s on socket %d", inet_ntoa(clientaddr.sin_addr), newfd);
					}
				}
				else	/* handle data from a client */
				{
					uint32_t nbytes;
					if((nbytes = read(i, buf, sizeof(buf))) <= 0)
					{
						if(nbytes == 0)	/* got error or connection closed by client */
						{
							/* connection closed */
							log_info("monitor: close socket %d", i);
						}
						else
						{
							log_error("monitor: recv() error lol!");
						}

						close(i);	/* close it... */
						FD_CLR(i, &master);	/* remove from master set */
					}
					else	/* we got some data from a client*/
					{
						Monitor_HandelClient(i,buf,nbytes,mon->state);
						//close(i);	/* close it... */
						//FD_CLR(i, &master);	/* remove from master set */
					}
				}
			}
		}
	}
}


void Monitor_HandelClient(int fd,uint8_t *data,int len,statistics_t *sta)
{
	/*incoming data and possess it*/
	stat_t stdata;
	state_get(sta,&stdata);	/*get static data*/

	char message[2048] = {0};
	char *ptr = message;

	ptr += sprintf(ptr,"Max Connection : %i</br>",stdata.MaxConnection);
	ptr += sprintf(ptr,"Active Connection : %i</br>",stdata.ActiveConnection);
	ptr += sprintf(ptr,"Total Connection : %i</br>",stdata.TotalConnection);
	ptr += sprintf(ptr,"Total Rx : %" PRIu64 "</br>",stdata.TotalRx);
	ptr += sprintf(ptr,"Total Tx : %" PRIu64 "</br>",stdata.TotalTx);


	char httpMessage[8000];
	int slen = sprintf(httpMessage,"HTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\nContent-Length: %i\n\n%s",(int)(ptr-message),message);
	write(fd,httpMessage,slen);	/*echo*/
}
