/*
 * SniClient.c
 *
 *  Created on: Jan 29, 2020
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
#include <socks.h>
#include "net.h"
#include <stdint.h>
#include "net_io.h"
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

#define SNI_MAX_WORKERS 1024

static pthread_mutex_t sni_worker_mu = PTHREAD_MUTEX_INITIALIZER;
static int sni_workers = 0;

bool sni_worker_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&sni_worker_mu);
	if (sni_workers < SNI_MAX_WORKERS)
	{
		sni_workers++;
		ok = true;
	}
	pthread_mutex_unlock(&sni_worker_mu);
	return ok;
}

void sni_worker_release(void)
{
	pthread_mutex_lock(&sni_worker_mu);
	if (sni_workers > 0)
		sni_workers--;
	pthread_mutex_unlock(&sni_worker_mu);
}

void *SniClientHandler(void *arg)
{
	if (!arg) pthread_exit(0);
	sniclient_t *client = (sniclient_t*)arg;
	sockshost_t *socks = client->SniConfig.Socks;
	lport_t 	xport = client->SniConfig.Port;
	int			timeout = client->SniConfig.snitimeout;
	int			io_ms = net_timeout_ms(timeout);
	int64_t		hello_deadline = net_mono_ms() + io_ms;

	//log_info("client thread %i",client->connid);
	uint8_t buffer[0x2000]; /*8Kb memory tmp*/
	uint32_t Windex = 0;
	char HostName[_MaxHostName_] = {0};
	uint32_t TotalRx = 0;
	uint32_t TotalTx = 0;
	fd_set rfds;
	struct timeval tv;
	while(1)
	{
		int64_t now;
		int64_t remain_ms;

		if (client->connid < 0 || client->connid >= FD_SETSIZE)
			break;

		now = net_mono_ms();
		if (now < 0 || now >= hello_deadline)
		{
			log_trace("TimeOut tid:%i",client->connid);
			break;
		}
		remain_ms = hello_deadline - now;
		if (remain_ms > 5000)
			remain_ms = 5000;

		FD_ZERO(&rfds);
		tv.tv_sec = (time_t)(remain_ms / 1000);
		tv.tv_usec = (suseconds_t)((remain_ms % 1000) * 1000);
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
		if(Windex>=sizeof(buffer))
		{
			log_error("Host Buffer OverFlow");
			break;
		}

		if(net_GetHost(buffer,Windex,HostName,_MaxHostName_))
		{
			/*Check host validate*/
			if(client->SniConfig.wlist && filter_IsWhite(client->SniConfig.wlist,HostName)==false)
			{
				log_trace("SNI filter Host { %s }",HostName);
				break;
			}

			if(isTrueIpAddress(HostName))
			{
				log_trace("SNI we can't support IP address");
				break;
			}

			log_trace("SNI start Host { %s } ",HostName);
			int sockssocket = -1;
			if(socks)	/*Set Connect to socks*/
			{
				if(!socks5_connect(&sockssocket,socks,HostName,xport.remote_port,false, timeout))
					break;
			}
			else	/*connect directly*/
			{
				if(!net_connect(&sockssocket,HostName,xport.remote_port, timeout))
					break;
			}


			int n;
			if(!net_write_all_ms(sockssocket,buffer,Windex, io_ms))
			{
				/*try close upstream socket*/
				close(sockssocket);
				break;
			}
			TotalTx += Windex;

			while(1)
			{
				tv.tv_sec  = timeout;
				tv.tv_usec = 0;
				FD_ZERO(&rfds);
				FD_SET(sockssocket,&rfds);
				FD_SET(client->connid,&rfds);
				int max_fd = (sockssocket > client->connid) ? sockssocket : client->connid;
				if (select(max_fd + 1, &rfds, NULL, NULL, &tv) < 0)
				{
					if (errno == EINTR)
						continue;
					log_error("SNI error in select");
					break;
				}

				if( FD_ISSET( sockssocket, &rfds ) )
				{
					/* data coming in */
					if((n=read(sockssocket,buffer,sizeof(buffer)))<0 &&
					   (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
						continue;
					if(n<1) break;
					if(!net_write_all_ms(client->connid,buffer,(size_t)n, io_ms)) break;
					TotalRx += n;
				}
				else if(FD_ISSET( client->connid, &rfds ) )
				{
					/* data going out */
					if((n=read(client->connid,buffer,sizeof(buffer)))<0 &&
					   (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
						continue;
					if(n<1) break;
					if(!net_write_all_ms(sockssocket,buffer,(size_t)n, io_ms)) break;
					TotalTx += n;
				}
				else
				{
					/*timeout wait for read socket*/
					log_trace("SNI timeout Host { %s }",HostName);
					break;
				}
			}
			
			/*try close upstream socket*/
			if (sockssocket >= 0)
				close(sockssocket);
			break;
		}
	}

	log_trace("SNI end Host{ %s } txrx(%i/%i)",HostName,TotalRx,TotalTx);

	if(client->SniConfig.sta)	/*Update statistics*/
	{
		state_RxTxClose(client->SniConfig.sta,TotalRx,TotalTx);
	}

	/* close socket and clean up */
	if (client->connid >= 0)
		close(client->connid);
	sni_worker_release();
	free(client);
	return NULL;
}
