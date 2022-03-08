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
#include "log/log.h"
#include <string.h>
#include "sniclient.h"
#include "net.h"
#include <arpa/inet.h>

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
	ptr->SniConfig = *Sni;
	ptr->sockfd = sockfd;
	pthread_create(&thread_id, NULL, SniProxy_HandleIncomingConnection, (void*)ptr);
	//pthread_join(thread_id, NULL);

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
		client = (sniclient_t *)malloc(sizeof(sniclient_t));
		client->SniConfig = sniconf;
		client->connid = accept(sockfd, (struct sockaddr*)&client->cli, &client->addr_len);
		if (client->connid < 0)
		{
			free(client);
			log_error("server accept failed");
			continue;
		}

		if(sniconf.sta)
			state_IncConnection(sniconf.sta);

		//log_info("incoming connection %i",client->connid);
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, SniClientHandler, (void*)client);
		pthread_detach(thread_id);
	}
}
