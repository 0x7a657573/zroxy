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
#include "log.h"
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "socks.h"
#include "net.h"
#include "net_io.h"


bool socks5_connect(int *sockfd,sockshost_t *socks, const char *host, int port,bool keepalive)
{
	uint16_t socks5_port = socks->port;
	char *socks5_host = socks->host;
	
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(socks5_port);
	//serv_addr.sin_addr.s_addr = inet_addr(socks5_host);

	/*if host is domain need resolve domain*/
	bool status = net_connect(sockfd,socks5_host, socks5_port);
	if (!status)
	{
		log_error("Socks Error: Connect to %s Failed", socks5_host);
		return false;
	}

	if(keepalive)
    {
        net_enable_keepalive(*sockfd);
    }

	#define MAX_TEMPBUF_SIZE 300
	uint8_t Tempbuf[MAX_TEMPBUF_SIZE] = {0};
    // SOCKS5 CLIENT HELLO
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+
	if(!net_write_all(*sockfd,"\x05\x02\x00\x02",4))	/*Write Hello*/
	{
		log_error("[!] Error writing SOCKS hello to %s", socks5_host);
		close(*sockfd);
		return false;
	}

    // SOCKS5 SERVER HELLO
    // +-----+--------+
    // | VER | METHOD |
    // +-----+--------+
    // |  1  |   1    |
    // +-----+--------+
	uint8_t SocksVer = 0;
	if(!net_read_exact(*sockfd,&SocksVer,sizeof(uint8_t)))
	{
		log_error("[!] Error reading SOCKS version from %s", socks5_host);
		close(*sockfd);
		return false;
	}

	 if(SocksVer!=5)
	 {
		 log_error("[!] We can not support ver %d",SocksVer);
		 close(*sockfd);
		 return false;
	 }

	 uint8_t SocksMethod;
	if(!net_read_exact(*sockfd,&SocksMethod,sizeof(uint8_t)))
	{
		log_error("[!] Error reading SOCKS method from %s", socks5_host);
		close(*sockfd);
		return false;
	}

	 if(!(SocksMethod==0 || SocksMethod==2))
	 {
		 log_error("[!] We can not support Method %d",SocksMethod);
		 close(*sockfd);
		 return false;
	 }
	

	if(SocksMethod==2)
	{
		/*Authentication With Socks,
		*
		* From RFC1929:
		* Once the SOCKS V5 server has started, and the client has selected the
		* Username/Password Authentication protocol, the Username/Password
		* subnegotiation begins.  This begins with the client producing a
		* Username/Password request:
		*
		* +----+------+----------+------+----------+
		* |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		* +----+------+----------+------+----------+
		* | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		* +----+------+----------+------+----------+
		*
		* The VER field contains the current version of the subnegotiation,
		* which is X'01'
		*/
		uint8_t uLen = strlen(socks->user);
		uint8_t pLen = strlen(socks->pass);
		char temp[512+4] = {0};
		int packet_len = snprintf(temp, sizeof(temp), "\x01%c%s%c%s", uLen, socks->user, pLen, socks->pass);
		if (packet_len < 0 || packet_len >= sizeof(temp)) {
			log_error("[!] Error formatting authentication packet for %s", socks5_host);
			close(*sockfd);
			return false;
		}
		
		if(!net_write_all(*sockfd,temp,(size_t)packet_len)) /*write UserPass*/
		{
			log_error("[!] Error writing SOCKS authentication packet to %s", socks5_host);
			close(*sockfd);
			return false;
		}

		SocksAuthenticationReplay_t SocksAuth;
		if(!net_read_exact(*sockfd,&SocksAuth,sizeof(SocksAuthenticationReplay_t)))
		{
			log_error("[!] Error reading SOCKS authentication response from %s", socks5_host);
			close(*sockfd);
			return false;
		}

		if(SocksAuth.status!=0)
		{
			log_error("[!] Error Socks Authentication:%02X",SocksAuth.status);
			close(*sockfd);
	 		return false;
		}
	}

	 /*check domain or ip*/
	 in_addr_t host_ip = inet_addr(host);
	 bool is_domain = (host_ip == INADDR_NONE && strcmp(host, "255.255.255.255") != 0);

	 // SOCKS5 CLIENT REQUEST
	 // +-----+-----+-------+------+----------+----------+
	 // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	 // +-----+-----+-------+------+----------+----------+
	 // |  1  |  1  | X'00' |  1   | Variable |    2     |
	 // +-----+-----+-------+------+----------+----------+
	 Tempbuf[0] = 0x05;  // VER 5
	 Tempbuf[1] = 0x01;  // CONNECT
	 Tempbuf[2] = 0x00;

	 uint16_t datalen = 10;
	 if (is_domain)
	 {
		/*if host is domain*/
		Tempbuf[3] = 0x03;  // Domain name
		size_t domain_len = strlen(host);
		if (domain_len > 255 || domain_len > MAX_TEMPBUF_SIZE - 7) { // 7 = 1 (VER) + 1 (CMD) + 1 (RSV) + 1 (ATYP) + 2 (PORT)
			log_error("[!] Domain name too long for buffer in %s", socks5_host);
			close(*sockfd);
			return false;
		}
		Tempbuf[4] = (uint8_t)domain_len;
		memcpy(Tempbuf + 5, host, domain_len);				    /*copy host*/
		*(uint16_t *)(Tempbuf + 5 + domain_len) = htons(port); /*copy port*/
		datalen = 5 + domain_len + 2;
	 }
	 else
	 {
		/*if host is ip*/
		Tempbuf[3] = 0x01;	/*IP V4 address*/
		memcpy(Tempbuf + 4, &host_ip, 4);		   /*copy ip*/
		*(uint16_t *)(Tempbuf + 8) = htons(port); /*copy port*/
	 }

	 if(!net_write_all(*sockfd,Tempbuf,datalen))
	 {
		log_error("[!] Error writing SOCKS connect request to %s", socks5_host);
		close(*sockfd);
		return false;
	 }

    // SOCKS5 SERVER REPLY
    // +-----+-----+-------+------+----------+----------+
    // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +-----+-----+-------+------+----------+----------+
    // |  1  |  1  | X'00' |  1   | Variable |    2     |
    // +-----+-----+-------+------+----------+----------+
	 SocksReplayHeader_t Replay;
	if(!net_read_exact(*sockfd,&Replay,sizeof(SocksReplayHeader_t)))
	{
		log_error("[!] Error reading SOCKS5 server reply from %s", socks5_host);
		close(*sockfd);
		return false;
	}

	 if(Replay.ver!=5)
	 {
		log_error("[!] Error Socks Ver");
		close(*sockfd);
		return false;
	 }

	 if(Replay.rep!=0)
	 {
		log_error("[!] Error Success Command: %d",Replay.rep);
		close(*sockfd);
		return false;
	 }

	 if(Replay.atyp == 0x01)	// IPv4 address
	 {
		if(!net_read_exact(*sockfd,Tempbuf,4))
		{
			log_error("[!] Error reading IPv4 address from %s", socks5_host);
			close(*sockfd);
			return false;
		}
	 }
	 else if (Replay.atyp == 0x03)	// Domain name
	 {
		 uint8_t len;
		if(!net_read_exact(*sockfd,&len,sizeof(uint8_t)))
		{
			log_error("[!] Error reading domain name length from %s", socks5_host);
			close(*sockfd);
			return false;
		}

		if(!net_read_exact(*sockfd,&Tempbuf,len))
		{
			log_error("[!] Error reading domain name from %s", socks5_host);
			close(*sockfd);
			return false;
		}
	 }
	 else if (Replay.atyp == 0x04)	// IPv6 address
	 {
		if(!net_read_exact(*sockfd,&Tempbuf,16))
		{
			log_error("[!] Error reading IPv6 address from %s", socks5_host);
			close(*sockfd);
			return false;
		}
	 }
	 else
	 {
		 log_error("[!] unsupported address type");
		 close(*sockfd);
		 return false;
	 }

	if(!net_read_exact(*sockfd,&Tempbuf,sizeof(uint16_t)))	/*Read Port*/
	{
		log_error("[!] Error reading port from %s", socks5_host);
		close(*sockfd);
		return false;
	}

	 return true;
}
