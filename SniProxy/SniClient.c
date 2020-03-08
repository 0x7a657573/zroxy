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
#include "SniProxy.h"
#include "log/log.h"
#include <string.h>
#include "SniClient.h"
#include "socks/socks.h"
#include "net/net.h"
#include <stdint.h>


void *SniClientHandler(void *arg)
{
	if (!arg) pthread_exit(0);
	sniclient_t *client = (sniclient_t*)arg;
	sockshost_t *socks = client->SniConfig.Socks;
	uint16_t 	port = client->SniConfig.Port;

	//log_info("client thread %i",client->connid);
	uint8_t buffer[0x4000]; /*16Kb memory tmp*/
	uint32_t Windex = 0;
	char HostName[_MaxHostName_] = {0};
	uint32_t TotalRx = 0;
	uint32_t TotalTx = 0;
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

			log_info("TimeOut tid:%i",client->connid);
			break;
		}

		int newData = read(client->connid, &buffer[Windex], sizeof(buffer) - Windex);/* read length of message */
		if (newData <= 0)
		{
			log_info("client %i disconnect %i",client->connid,newData);
			break;
		}

		Windex += newData;
		if(Windex>=sizeof(buffer))
		{
			log_error("Host Buffer OverFlow");
			break;
		}

		if(net_GetHost(buffer,Windex,HostName,_MaxHostName_))
		{
			log_info(" Open tid:%i Host %s ",client->connid,HostName);
			if(isTrueIpAddress(HostName))
			{
				log_info("we can't support IP address");
				break;
			}

			int sockssocket = 0;
			if(socks)	/*Set Connect to socks*/
			{
				//log_info("socks host %s:%i",socks->host,socks->port);
				//log_info("host %s:%i",HostName,port);
				if(!socks5_connect(&sockssocket,socks->host,socks->port,HostName,port))
					break;
			}
			else	/*connect directly*/
			{
				if(!net_connect(&sockssocket,HostName,port))
					break;
			}


			FD_ZERO(&rfds);

			int n;
			if(write(sockssocket,buffer,Windex)<Windex) break;
			TotalTx += Windex;

			while(1)
			{
				tv.tv_sec  = 300;
				tv.tv_usec = 0;
				FD_SET(sockssocket,&rfds);
				FD_SET(client->connid,&rfds);
				if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) < 0)
				{
					log_error("Err in select");
					break;
				}

				if( FD_ISSET( sockssocket, &rfds ) )
				{
					/* data coming in */
					if((n=read(sockssocket,buffer,sizeof(buffer)))<1) break;
					if(write(client->connid,buffer,n)<n) break;
					TotalRx += n;
				}
				else if(FD_ISSET( client->connid, &rfds ) )
				{
					/* data going out */
					if((n=read(client->connid,buffer,sizeof(buffer)))<1) break;
					if(write(sockssocket,buffer,n)<n) break;
					TotalTx += n;
				}
				else
				{
					/*timeout wait for read socket*/
					log_info("TimeOut tid:%i Host %s",client->connid,HostName);
					break;
				}
			}

			close(sockssocket);
			break;
		}
	}

	if(client->SniConfig.sta)	/*Update statistics*/
	{
		state_RxTxClose(client->SniConfig.sta,TotalRx,TotalTx);
	}

	log_info("Close tid:%i Host %s Tx:%i Rx:%i",client->connid,HostName,TotalRx,TotalTx);
	/* close socket and clean up */
	close(client->connid);
	free(client);
	pthread_exit(0);
}
