/*
 * SniProxy.c
 *
 *  Created on: Jan 28, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>	/* http://www.csc.villanova.edu/~mdamian/threads/posixthreads.html */
#include "sniproxy.h"
#include <log.h>
#include <string.h>
#include "sniclient.h"
#include "net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

void *SniProxy_HandleIncomingConnection(void *vargp);

bool SniProxy_Start(SniServer_t *Sni)
{
	int sockfd;

	in_addr_t host_ip = inet_addr(Sni->Port.bindip);
	if(net_ListenIp4(host_ip, Sni->Port.local_port,&sockfd)==false)
	{
		log_error("can not listen on Port %s:%i",Sni->Port.bindip,Sni->Port.local_port);
		return false;
	}

	log_info("socket listen on %s:%d",Sni->Port.bindip,Sni->Port.local_port);

	pthread_t thread_id;
	server_t *ptr = malloc(sizeof(server_t));
	if (!ptr)
	{
		close(sockfd);
		return false;
	}
	ptr->SniConfig = *Sni;
	ptr->sockfd = sockfd;
	if (pthread_create(&thread_id, NULL, SniProxy_HandleIncomingConnection, (void*)ptr) != 0)
	{
		close(sockfd);
		free(ptr);
		return false;
	}
	pthread_detach(thread_id);

	return true;
}



void *SniProxy_HandleIncomingConnection(void *vargp)
{
	server_t *soc = ((server_t*)vargp);

	int sockfd = soc->sockfd;
	SniServer_t sniconf = soc->SniConfig;
	free(soc);

	//log_info("thread start on socket %i Port %d",sockfd,sniconf.Port);
	sniclient_t *client;
	while(1)
	{
		client = (sniclient_t *)calloc(1, sizeof(sniclient_t));
		if (!client)
		{
			log_error("malloc failed for sniclient_t");
			continue;
		}
		client->SniConfig = sniconf;
		client->addr_len = sizeof(client->cli);
		client->connid = accept(sockfd, (struct sockaddr*)&client->cli, &client->addr_len);
		if (client->connid < 0)
		{
			if (errno != EINTR)
				log_error("server accept() %i: %s",errno,strerror(errno));
			free(client);
			continue;
		}

		if (client->connid >= FD_SETSIZE || !sni_worker_acquire())
		{
			log_error("refusing SNI connection");
			close(client->connid);
			free(client);
			continue;
		}

		if(sniconf.sta)
			state_IncConnection(sniconf.sta);

		//log_info("incoming connection %i",client->connid);
		pthread_t thread_id;
		if(pthread_create(&thread_id, NULL, SniClientHandler, (void*)client) != 0)
		{
			log_error("can not create thread for new client");
			if (sniconf.sta)
				state_abandon(sniconf.sta);
			sni_worker_release();
			close(client->connid);
			free(client);
			continue;
		}
		pthread_detach(thread_id);
	}
}
