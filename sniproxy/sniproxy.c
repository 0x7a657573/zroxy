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
#include <errno.h>
#include <ev.h>

static void sni_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void sni_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

void *SniProxy_HandleIncomingConnection(void *vargp);

bool SniProxy_Start(struct ev_loop *eloop,SniServer_t *Sni)
{
	int sockfd;
	in_addr_t host_ip = inet_addr(Sni->Port.bindip);
	if(net_ListenIp4(host_ip, Sni->Port.local_port,&sockfd)==false)
	{
		log_error("can not listen on Port %s:%i",Sni->Port.bindip,Sni->Port.local_port);
		return false;
	}

	log_info("socket listen on %s:%d",Sni->Port.bindip,Sni->Port.local_port);

	
	server_t *ptr = malloc(sizeof(server_t));
	bzero(ptr,sizeof(server_t));

	ptr->sni_config = *Sni;

	// Initialize and start a watcher to accepts client requests
	ev_io_init(&ptr->evio, sni_accept_cb, sockfd, EV_READ);
	ev_io_start(eloop, &ptr->evio);

	return true;
}

static inline void close_server_client(struct ev_loop *loop,server_t *ptr)
{
	SniServer_t *config = &ptr->sni_config;
	sni_link_t	*sni_data = &ptr->sni_data;
	sni_ctx_t *user = &ptr->user;
	sni_ctx_t *server = &ptr->server;
	
	log_info("end Host 0x%X: txrx(%i/%i)",(uintptr_t)ptr,user->total_rx,server->total_rx);
	if(sni_data->is_sni_mark)
	{
		log_info("SNI end Host 0x%X:{ %s } txrx(%i/%i)",(uintptr_t)ptr,sni_data->hostname,user->total_rx,server->total_rx);

		/*Update statistics*/
		if(config->sta)
			state_RxTxClose(config->sta,server->total_rx,user->total_rx);
	}

	// close origin socket
	if(server->cLink)
	{
		int socket = server->evio.fd;
		//log_info("server side close socket %d",socket);
		// Stop and free watchet if client socket is closing
		ev_io_stop(loop,&server->evio);
		close(socket);
	}
	
	if(user->cLink)
	{
		int socket = user->evio.fd;
		//log_info("user side close socket %d",socket);
		// Stop and free watchet if client socket is closing
		ev_io_stop(loop,&user->evio);
		close(socket);
	}

	bzero(ptr,sizeof(server_t));
	free(ptr);
}

/* Accept client requests */
static void sni_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	server_t *ptr = (server_t*)watcher;

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	
	server_t *w_client = (server_t*) malloc (sizeof(server_t));
	bzero(w_client,sizeof(server_t));

	/*copy server data*/
	w_client->sni_config =  ptr->sni_config;
	w_client->evio	=	ptr->evio;
	

	if(EV_ERROR & revents)
	{
		log_error("got invalid event");
		return;
	}

	// Accept client request
	int client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_sd < 0)
	{
		log_error("accept error");
		return;
	}

	SniServer_t *config = &ptr->sni_config;
	state_IncConnection(config->sta);
	// Initialize and start watcher to read client requests
	w_client->user.cLink = w_client;	/*copy ptr of connection info*/
	ev_io_init(&w_client->user.evio, sni_read_cb, client_sd, EV_READ);
	ev_io_start(loop, &w_client->user.evio);
}

static void sni_origin_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	sni_ctx_t *xptr = (sni_ctx_t*)watcher;
	server_t *ptr = (server_t*)xptr->cLink;

	char buffer[SNI_BUFFER_SIZE];
	ssize_t read;
	
	if(EV_ERROR & revents)
	{
		log_error("got invalid event");
		return;
	}

	// Receive message from server socket
	read = recv(watcher->fd, buffer, SNI_BUFFER_SIZE, 0);

	if(read < 0)
	{
		log_error("read error from socket(%d)",read);
		close_server_client(loop,ptr);
		return;
	}

	if(read == 0)
	{
		// Stop and free watchet if client socket is closing
		close_server_client(loop,ptr);
		return;
	}
	xptr->total_rx += read;
	sni_ctx_t *user = &ptr->user;
	// Send message bach to the origin server
	if(send(user->evio.fd, buffer, read, 0)!=read)
	{
		log_error("Can not write to socket.....");
		close_server_client(loop,ptr);
	}
	
}

static void sni_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	sni_ctx_t *xptr = (sni_ctx_t*)watcher;
	server_t *ptr = (server_t*)xptr->cLink;

	char buffer[SNI_BUFFER_SIZE];
	ssize_t read;

	if(EV_ERROR & revents)
	{
		log_error("got invalid event");
		return;
	}

	// Receive message from client socket
	read = recv(watcher->fd, buffer, SNI_BUFFER_SIZE, 0);

	if(read < 0)
	{
		log_error("read error from socket(%d)",read);
		close_server_client(loop,ptr);
		return;
	}

	if(read == 0)
	{
		close_server_client(loop,ptr);
		return;
	}
	xptr->total_rx += read;

	sni_link_t *client = &ptr->sni_data;
	SniServer_t *config = &ptr->sni_config;
	/*is found sni ?*/
	if(client->is_sni_mark!=true)
	{	
		/*check buffer overflow*/
		if(read+client->w_index >= MAX_SNI_PACKET)
		{
			log_error("sni packet Buffer OverFlow!");
			close_server_client(loop,ptr);
			return;
		}

		//copy data to buffer
		memcpy(&client->sni_packet[client->w_index],buffer,read);
		client->w_index += read;

		if(net_GetHost(client->sni_packet,client->w_index,client->hostname,_MaxHostName_))
		{
			/*Check host validate*/
			if(config->wlist && filter_IsWhite(config->wlist,client->hostname)==false)
			{
				log_info("SNI filter Host { %s }",client->hostname);
				close_server_client(loop,ptr);
				return;
			}

			if(isTrueIpAddress(client->hostname))
			{
				log_info("SNI we can't support IP address");
				close_server_client(loop,ptr);
				return;
			}

			log_info("SNI start Host 0x%X:{ %s }",(uintptr_t)ptr,client->hostname);
			client->is_sni_mark = true;

			sockshost_t *socks = config->Socks;
			lport_t 	xport = config->Port;
			int socket = 0;
			if(socks)	/*Set Connect to socks*/
			{
				if(!socks5_connect(&socket,socks,client->hostname,xport.remote_port,false))
				{
					close_server_client(loop,ptr);
					return;
				}
			}
			else	/*connect directly*/
			{
				if(!net_connect(&socket,client->hostname,xport.remote_port))
				{
					close_server_client(loop,ptr);
					return;
				}
			}
			
			sni_ctx_t *server = &ptr->server;
			server->cLink = ptr;
			// Initialize and start watcher to read client requests
			ev_io_init(&server->evio, sni_origin_read_cb, socket, EV_READ);
			ev_io_start(loop, &server->evio);

			/*Send sni packet to origin server*/
			if(send(socket,client->sni_packet,client->w_index,0)!=client->w_index)
			{
				close_server_client(loop,ptr);
				return;
			}
			return;
		}
		else
		{
			log_error("SNI NotFound @0x%X buffer len %d",(uintptr_t)ptr,client->w_index);
		}
	}

	sni_ctx_t *server = &ptr->server;
	// Send message bach to the origin server
	if(send(server->evio.fd, buffer, read, 0)!=read)
	{
		log_error("Can not write to socket...");
		close_server_client(loop,ptr);
	}
}