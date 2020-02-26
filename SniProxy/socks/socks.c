/*
 * socks.c
 *
 *  Created on: Feb 1, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>	/* http://www.csc.villanova.edu/~mdamian/threads/posixthreads.html */
#include "log/log.h"
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "socks.h"

bool socks5_connect(int *sockfd,const char *socks5_host, int socks5_port, const char *host, int port)
{

	 if((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	 {
	     log_error("Socks Error : Could not create socket");
	     return false;
	 }

	 struct sockaddr_in serv_addr;
	 serv_addr.sin_family = AF_INET;
	 serv_addr.sin_port = htons(socks5_port);
	 //serv_addr.sin_addr.s_addr = inet_addr(socks5_host);

	 if(inet_pton(AF_INET, socks5_host, &serv_addr.sin_addr)<=0)
	 {
		 log_error("inet_pton error occured");
	     return false;
	 }

	 if(connect(*sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	 {
		log_error("Socks Error : Connect Failed");
	    return false;
	 }

	 uint8_t Tempbuf[300] = {0};
    // SOCKS5 CLIENT HELLO
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+
	 Tempbuf[0] = 0x05;
	 Tempbuf[1] = 0x01;
	 Tempbuf[2] = 0x00;
	 write(*sockfd,Tempbuf,3);	/*Write Hello*/

    // SOCKS5 SERVER HELLO
    // +-----+--------+
    // | VER | METHOD |
    // +-----+--------+
    // |  1  |   1    |
    // +-----+--------+
	 uint8_t SocksVer = 0;
	 if(read(*sockfd,&SocksVer,sizeof(uint8_t))<=0)
	 {
		 log_error("Error Read Socks Ver");
		 close(*sockfd);
		 return false;
	 }

	 if(SocksVer!=5)
	 {
		 log_error("We can not support ver %d",SocksVer);
		 close(*sockfd);
		 return false;
	 }

	 uint8_t SocksMethod;
	 if(read(*sockfd,&SocksMethod,sizeof(uint8_t))<=0)
	 {
		 log_error("Error Read Socks Ver");
		 close(*sockfd);
	 	 return false;
	 }

	 if(SocksMethod!=0)
	 {
		 log_error("We can not support Method %d",SocksMethod);
		 close(*sockfd);
		 return false;
	 }

	 // SOCKS5 CLIENT REQUEST
	 // +-----+-----+-------+------+----------+----------+
	 // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	 // +-----+-----+-------+------+----------+----------+
	 // |  1  |  1  | X'00' |  1   | Variable |    2     |
	 // +-----+-----+-------+------+----------+----------+
	 Tempbuf[0] = 0x05;  // VER 5
	 Tempbuf[1] = 0x01;  // CONNECT
	 Tempbuf[2] = 0x00;
	 Tempbuf[3] = 0x03;  // Domain name
	 Tempbuf[4] = (uint8_t)strlen(host);
	 memcpy(Tempbuf + 5, host, Tempbuf[4]);
	 *(uint16_t *)(Tempbuf + 5 + Tempbuf[4]) = htons(port);
	 write(*sockfd,Tempbuf,5 + Tempbuf[4] + 2);

    // SOCKS5 SERVER REPLY
    // +-----+-----+-------+------+----------+----------+
    // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +-----+-----+-------+------+----------+----------+
    // |  1  |  1  | X'00' |  1   | Variable |    2     |
    // +-----+-----+-------+------+----------+----------+
	 SocksReplayHeader_t Replay;
	 if(read(*sockfd,&Replay,sizeof(SocksReplayHeader_t))<=0)
	 {
		 log_error("Error Read Replay");
		 close(*sockfd);
	 	 return false;
	 }

	 if(Replay.ver!=5)
	 {
		log_error("Error Socks Ver");
		close(*sockfd);
		return false;
	 }

	 if(Replay.rep!=0)
	 {
		log_error("Error Success Command");
		close(*sockfd);
		return false;
	 }

	 if(Replay.atyp == 0x01)	// IPv4 address
	 {
		 if(read(*sockfd,Tempbuf,4)<=0)
		 {
		 	 log_error("Error Read Replay");
		 	 close(*sockfd);
		 	 return false;
		 }
	 }
	 else if (Replay.atyp == 0x03)	// Domain name
	 {
		 uint8_t len;
		 if(read(*sockfd,&len,sizeof(uint8_t))<=0)
		 {
		  	 log_error("Error Read Replay");
		  	 close(*sockfd);
		  	 return false;
		 }

		 if(read(*sockfd,&Tempbuf,len)<=0)
		 {
		  	 log_error("Error Read Replay");
		  	 close(*sockfd);
		  	 return false;
		 }
	 }
	 else if (Replay.atyp == 0x04)	// IPv6 address
	 {
		 if(read(*sockfd,&Tempbuf,16)<=0)
		 {
		   	 log_error("Error Read Replay");
		   	 close(*sockfd);
		   	 return false;
		 }
	 }
	 else
	 {
		 log_error("unsupported address type");
		 close(*sockfd);
		 return false;
	 }

	 if(read(*sockfd,&Tempbuf,sizeof(uint16_t))<=0)	/*Read Port*/
	 {
	   	 log_error("Error Read Replay");
	   	  close(*sockfd);
	   	 return false;
	 }

	 return true;
}
