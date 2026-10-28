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
#include <zroxy/log.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <zroxy/socks.h>
#include <zroxy/net.h>
#include <zroxy/net_io.h>

#define MAX_TEMPBUF_SIZE 300
#define SOCKS_MAX_IDENT 255

static void socks5_close(int *sockfd)
{
	if (sockfd && *sockfd >= 0)
	{
		close(*sockfd);
		*sockfd = -1;
	}
}

static bool socks5_write_port(uint8_t *dst, int port)
{
	uint16_t be;
	if (port < 0 || port > 65535)
		return false;
	be = htons((uint16_t)port);
	memcpy(dst, &be, sizeof(be));
	return true;
}

bool socks5_connect(int *sockfd,sockshost_t *socks, const char *host, int port,bool keepalive, int timeout_sec)
{
	int io_ms;
	uint16_t socks5_port;
	char *socks5_host;
	uint8_t Tempbuf[MAX_TEMPBUF_SIZE];
	uint8_t SocksVer = 0;
	uint8_t SocksMethod = 0;
	bool status;
	in_addr_t host_ip = 0;
	bool is_domain;
	uint16_t datalen = 10;
	SocksReplayHeader_t Replay;

	if (!sockfd || !socks || !socks->host || !host || host[0] == '\0')
		return false;

	*sockfd = -1;
	io_ms = net_timeout_ms(timeout_sec);
	socks5_port = socks->port;
	socks5_host = socks->host;
	memset(Tempbuf, 0, sizeof(Tempbuf));

	/*if host is domain need resolve domain*/
	status = net_connect(sockfd,socks5_host, socks5_port, timeout_sec);
	if (!status)
	{
		log_error("Socks Error: Connect to %s Failed", socks5_host);
		socks5_close(sockfd);
		return false;
	}

	if(keepalive)
    {
        net_enable_keepalive(*sockfd);
    }

    // SOCKS5 CLIENT HELLO
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+
	if(!net_write_all_ms(*sockfd,"\x05\x02\x00\x02",4, io_ms))	/*Write Hello*/
	{
		log_error("[!] Error writing SOCKS hello to %s", socks5_host);
		socks5_close(sockfd);
		return false;
	}

    // SOCKS5 SERVER HELLO
    // +-----+--------+
    // | VER | METHOD |
    // +-----+--------+
    // |  1  |   1    |
    // +-----+--------+
	if(!net_read_exact_ms(*sockfd,&SocksVer,sizeof(uint8_t), io_ms))
	{
		log_error("[!] Error reading SOCKS version from %s", socks5_host);
		socks5_close(sockfd);
		return false;
	}

	 if(SocksVer!=5)
	 {
		 log_error("[!] We can not support ver %d",SocksVer);
		 socks5_close(sockfd);
		 return false;
	 }

	if(!net_read_exact_ms(*sockfd,&SocksMethod,sizeof(uint8_t), io_ms))
	{
		log_error("[!] Error reading SOCKS method from %s", socks5_host);
		socks5_close(sockfd);
		return false;
	}

	 if(!(SocksMethod==0 || SocksMethod==2))
	 {
		 log_error("[!] We can not support Method %d",SocksMethod);
		 socks5_close(sockfd);
		 return false;
	 }


	if(SocksMethod==2)
	{
		size_t uLen;
		size_t pLen;
		uint8_t auth[1 + 1 + SOCKS_MAX_IDENT + 1 + SOCKS_MAX_IDENT];
		size_t packet_len;
		SocksAuthenticationReplay_t SocksAuth;

		if (!socks->user || !socks->pass)
		{
			log_error("[!] SOCKS username/password required");
			socks5_close(sockfd);
			return false;
		}
		uLen = strlen(socks->user);
		pLen = strlen(socks->pass);
		if (uLen == 0 || uLen > SOCKS_MAX_IDENT || pLen > SOCKS_MAX_IDENT)
		{
			log_error("[!] SOCKS username/password length rejected");
			socks5_close(sockfd);
			return false;
		}

		/* VER | ULEN | UNAME | PLEN | PASSWD */
		auth[0] = 0x01;
		auth[1] = (uint8_t)uLen;
		memcpy(auth + 2, socks->user, uLen);
		auth[2 + uLen] = (uint8_t)pLen;
		if (pLen > 0)
			memcpy(auth + 3 + uLen, socks->pass, pLen);
		packet_len = 3 + uLen + pLen;

		if(!net_write_all_ms(*sockfd, auth, packet_len, io_ms)) /*write UserPass*/
		{
			log_error("[!] Error writing SOCKS authentication packet to %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}

		if(!net_read_exact_ms(*sockfd,&SocksAuth,sizeof(SocksAuthenticationReplay_t), io_ms))
		{
			log_error("[!] Error reading SOCKS authentication response from %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}

		if(SocksAuth.status!=0)
		{
			log_error("[!] Error Socks Authentication:%02X",SocksAuth.status);
			socks5_close(sockfd);
	 		return false;
		}
	}

	 /*check domain or ip*/
	 is_domain = !net_is_ip_literal(host);

	 // SOCKS5 CLIENT REQUEST
	 // +-----+-----+-------+------+----------+----------+
	 // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	 // +-----+-----+-------+------+----------+----------+
	 // |  1  |  1  | X'00' |  1   | Variable |    2     |
	 // +-----+-----+-------+------+----------+----------+
	 Tempbuf[0] = 0x05;  // VER 5
	 Tempbuf[1] = 0x01;  // CONNECT
	 Tempbuf[2] = 0x00;

	 if (is_domain)
	 {
		size_t domain_len = strlen(host);
		if (domain_len == 0 || domain_len > 255 || domain_len > MAX_TEMPBUF_SIZE - 7)
		{
			log_error("[!] Domain name too long for buffer in %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}
		Tempbuf[3] = 0x03;  // Domain name
		Tempbuf[4] = (uint8_t)domain_len;
		memcpy(Tempbuf + 5, host, domain_len);
		if (!socks5_write_port(Tempbuf + 5 + domain_len, port))
		{
			socks5_close(sockfd);
			return false;
		}
		datalen = (uint16_t)(5 + domain_len + 2);
	 }
	 else
	 {
		if (inet_pton(AF_INET, host, &host_ip) != 1)
		{
			socks5_close(sockfd);
			return false;
		}
		Tempbuf[3] = 0x01;	/*IP V4 address*/
		memcpy(Tempbuf + 4, &host_ip, 4);
		if (!socks5_write_port(Tempbuf + 8, port))
		{
			socks5_close(sockfd);
			return false;
		}
	 }

	 if(!net_write_all_ms(*sockfd,Tempbuf,datalen, io_ms))
	 {
		log_error("[!] Error writing SOCKS connect request to %s", socks5_host);
		socks5_close(sockfd);
		return false;
	 }

    // SOCKS5 SERVER REPLY
    // +-----+-----+-------+------+----------+----------+
    // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +-----+-----+-------+------+----------+----------+
    // |  1  |  1  | X'00' |  1   | Variable |    2     |
    // +-----+-----+-------+------+----------+----------+
	if(!net_read_exact_ms(*sockfd,&Replay,sizeof(SocksReplayHeader_t), io_ms))
	{
		log_error("[!] Error reading SOCKS5 server reply from %s", socks5_host);
		socks5_close(sockfd);
		return false;
	}

	 if(Replay.ver!=5)
	 {
		log_error("[!] Error Socks Ver");
		socks5_close(sockfd);
		return false;
	 }

	 if(Replay.rep!=0)
	 {
		log_error("[!] Error Success Command: %d",Replay.rep);
		socks5_close(sockfd);
		return false;
	 }

	 if(Replay.atyp == 0x01)	// IPv4 address
	 {
		if(!net_read_exact_ms(*sockfd,Tempbuf,4, io_ms))
		{
			log_error("[!] Error reading IPv4 address from %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}
	 }
	 else if (Replay.atyp == 0x03)	// Domain name
	 {
		 uint8_t len;
		if(!net_read_exact_ms(*sockfd,&len,sizeof(uint8_t), io_ms))
		{
			log_error("[!] Error reading domain name length from %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}

		/* len is one byte, and Tempbuf is larger than 255. */
		if (!net_read_exact_ms(*sockfd, Tempbuf, len, io_ms))
		{
			log_error("[!] Error reading domain name from %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}
	 }
	 else if (Replay.atyp == 0x04)	// IPv6 address
	 {
		if(!net_read_exact_ms(*sockfd,Tempbuf,16, io_ms))
		{
			log_error("[!] Error reading IPv6 address from %s", socks5_host);
			socks5_close(sockfd);
			return false;
		}
	 }
	 else
	 {
		 log_error("[!] unsupported address type");
		 socks5_close(sockfd);
		 return false;
	 }

	if(!net_read_exact_ms(*sockfd,Tempbuf,sizeof(uint16_t), io_ms))	/*Read Port*/
	{
		log_error("[!] Error reading port from %s", socks5_host);
		socks5_close(sockfd);
		return false;
	}

	 return true;
}
