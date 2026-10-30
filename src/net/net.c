/*
 * net.c
 *
 *  Created on: Feb 9, 2020
 *      Author: zeus
 */
#include <stdbool.h>
#include <stdint.h>
#include <zroxy/log.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <zroxy/net.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <zroxy/net_io.h>

static void *net_memmem(const void *haystack_start, size_t haystack_len,
        		const void *needle_start, size_t needle_len);

bool net_set_nonblock_cloexec(int fd)
{
    int flags;
    int fdflags;

    if (fd < 0)
        return false;
    flags = fcntl(fd, F_GETFL, 0);
    fdflags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fdflags < 0)
        return false;
    if ((flags & O_NONBLOCK) == 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return false;
    if ((fdflags & FD_CLOEXEC) == 0 && fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) != 0)
        return false;
    return true;
}

bool net_enable_keepalive(int sock) 
{
    int yes = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) != 0)
        return false;

    int idle = 1;
    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int)) != 0)
        return false;

    int interval = 1;
    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) != 0)
        return false;

    int maxpkt = 10;
    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int)) != 0)
        return false;

    return true;
}

static bool net_connect_one(int sfd, const struct sockaddr *addr, socklen_t len, int64_t deadline_ms)
{
    int flags;
    int rc;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags < 0)
        return false;
    if (fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0)
        return false;

    do
    {
        rc = connect(sfd, addr, len);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0 && errno != EINPROGRESS && errno != EALREADY)
    {
        fcntl(sfd, F_SETFL, flags);
        return false;
    }

    if (rc < 0)
    {
        int err = 0;
        socklen_t elen = sizeof(err);
        if (!net_wait_fd(sfd, POLLOUT, deadline_ms) ||
            getsockopt(sfd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 ||
            err != 0)
        {
            fcntl(sfd, F_SETFL, flags);
            return false;
        }
    }

    if (fcntl(sfd, F_SETFL, flags) < 0)
        return false;
    return true;
}

bool net_connect(int *sockfd,const char *hostname, uint16_t port, int timeout_sec)
{
    int64_t deadline;
    int64_t now;

    *sockfd = -1;
    now = net_mono_ms();
    if (now < 0)
        return false;
    deadline = now + net_timeout_ms(timeout_sec);

    /*check Hostname is IP or Domain*/
    if(net_is_ip_literal(hostname))
	{
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sfd < 0)
	    {
	        log_error("Socks Error : Could not create socket");
	        return false;
	    }

        struct sockaddr_in serv_addr;
	    serv_addr.sin_family = AF_INET;
	    serv_addr.sin_port = htons(port);

        if(inet_pton(AF_INET, hostname, &serv_addr.sin_addr)<=0)
		{
			log_error("inet_pton error occured");
            close(sfd);
			return false;
		}

		if(!net_connect_one(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr), deadline))
		{
			log_error("net_connect Error : Connect Failed");
            close(sfd);
			return false;
		}

        *sockfd = sfd;
        return true;
	}

    char port_str[8] = {0};
    struct addrinfo hints;
    struct addrinfo *addrs=NULL;

    memset(&hints, 0, sizeof(hints));
    /* IPv6 is not supported; asking for A only also skips the AAAA lookup. */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str,7,"%i",port);

    const int status = getaddrinfo(hostname, port_str, &hints, &addrs);
    if (status != 0)
    {
    	log_error("%s:%s -> %s\n", hostname,port_str, gai_strerror(status));
        return false;
    }

    int sfd = -1;
    for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
    {
        sfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sfd == -1)
        {
        	log_error("Socks Error : Could not create socket");
            continue;
        }

        if (net_mono_ms() >= deadline)
        {
            close(sfd);
            sfd = -1;
            break;
        }

        if (net_connect_one(sfd, addr->ai_addr, addr->ai_addrlen, deadline))
        {
            *sockfd = sfd;
            freeaddrinfo(addrs);
            return true;
        }

        close(sfd);
        sfd = -1;
    }

    freeaddrinfo(addrs);
    return false;
}

bool net_listen_ipv4(in_addr_t addr, uint16_t Port,int *sockfd)
{

	struct  sockaddr_in servaddr;

	/*
	 * 	╔═══════════╦══════════════════════════╗
		║           ║       Socket Type        ║
		║ Address   ╟────────────┬─────────────╢
		║ Family    ║ SOCK_DGRAM │ SOCK_STREAM ║
		╠═══════════╬════════════╪═════════════╣
		║ IPX/SPX   ║ SPX        │ IPX         ║
		║ NetBIOS   ║ NetBIOS    │ n/a         ║
		║ IPv4      ║ UDP        │ TCP         ║
		║ AppleTalk ║ DDP        │ ADSP        ║
		║ IPv6      ║ UDP        │ TCP         ║
		║ IrDA      ║ IrLMP      │ IrTTP       ║
		║ Bluetooth ║ ?          │ RFCOMM      ║
		╚═══════════╩════════════╧═════════════╝
	 */
	// socket create and verification
	*sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*sockfd == -1)
	{
	  log_error("socket creation on port %d failed.",Port);
	  return false;
	}
	memset(&servaddr, 0, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = addr;//htonl(INADDR_ANY);
	servaddr.sin_port = htons(Port);

	int opt = 1;
	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))<0)
	{
		close(*sockfd);
		log_error("socket setopt failed");
		return false;
	}

	// Binding newly created socket to given IP and verification
	if ((bind(*sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) < 0)
	{
		close(*sockfd);
		log_error("socket bind failed");
		return false;
	}

	// Now server is ready to listen and verification
	if ((listen(*sockfd, 10)) != 0)
	{
	   log_error("Listen failed on port %d",Port);
	   close(*sockfd);
	   *sockfd = -1;
	   return false;
	}

	return true;
}

bool net_get_host(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName)
{
	if(net_get_http_host(buf,len,HostName,MaxHostName)==true)
	{
		return true;
	}
	if(net_get_https_host(buf,len,HostName,MaxHostName)==true)
	{
		return true;
	}
	return false;
}

static bool tls_need(size_t pos, size_t n, size_t limit)
{
	if (n > limit || pos > limit - n)
		return false;
	return true;
}

bool net_get_https_host(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName)
{
    /* 1   TLS_HANDSHAKE_CONTENT_TYPE
     * 1   TLS major version
     * 1   TLS minor version
     * 2   TLS Record length
     * --------------
     * 1   Handshake type
     * 3   Length
     * 2   Version
     * 32  Random
     * 1   Session ID length
     * ?   Session ID
     * 2   Cipher Suites length
     * ?   Cipher Suites
     * 1   Compression Methods length
     * ?   Compression Methods
     * 2   Extensions length
     * ---------------
     * 2   Extension type (0x0000 for server_name)
     * 2   Extension data length
     * ---------------
     * 2   server_name list length
     * 1   server_name type (0)
     * 2   server_name length
     * ?   server_name
     */
    const size_t TLS_HEADER_LEN = 5;
    const size_t FIXED_LENGTH_RECORDS = 38;
    const uint8_t TLS_HANDSHAKE_CONTENT_TYPE = 0x16;
    const uint8_t TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    const uint8_t *data = buf;
    size_t pos = 0;
    size_t length = len;
    size_t record_len;
    size_t record_end;
    size_t extensions_end;

    if (!buf || !HostName || MaxHostName == 0)
        return false;
    HostName[0] = '\0';

    if (length < TLS_HEADER_LEN + FIXED_LENGTH_RECORDS)
    {
    	log_error("Get HTTPS Host: not enough data");
        return false;
    }

    if ((data[0] & 0x80) && (data[2] == 1))
    {
    	log_error("SSL 2.0, does not support SNI");
        return false;
    }
    if (data[0] != TLS_HANDSHAKE_CONTENT_TYPE)
    {
        return false;
    }
    if (data[1] < 3)
    {
    	log_error("TLS major version < 3, does not support SNI");
        return false;
    }

    record_len = ((size_t)data[3] << 8) + data[4];
    if (record_len < FIXED_LENGTH_RECORDS || record_len > length - TLS_HEADER_LEN)
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    record_end = TLS_HEADER_LEN + record_len;
    if (data[TLS_HEADER_LEN] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
    	log_error("HTTPS Host: invalid handshake type");
        return false;
    }
    pos = TLS_HEADER_LEN + FIXED_LENGTH_RECORDS;

    if (!tls_need(pos, 1, record_end))
    	return false;
    if (!tls_need(pos + 1, data[pos], record_end))
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    pos += 1u + data[pos];

    if (!tls_need(pos, 2, record_end))
    	return false;
    {
    	size_t suite_len = ((size_t)data[pos] << 8) + data[pos + 1];
    	if ((suite_len % 2u) != 0 || !tls_need(pos + 2, suite_len, record_end))
    	{
    		log_error("Get HTTPS Host: not enough data");
    		return false;
    	}
    	pos += 2u + suite_len;
    }

    if (!tls_need(pos, 1, record_end) || !tls_need(pos + 1, data[pos], record_end))
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    pos += 1u + data[pos];

    if (!tls_need(pos, 2, record_end))
       return false;
    {
    	size_t ext_total = ((size_t)data[pos] << 8) + data[pos + 1];
    	pos += 2;
    	if (!tls_need(pos, ext_total, record_end))
    		return false;
    	extensions_end = pos + ext_total;
    }

    while (pos + 4 <= extensions_end)
    {
       size_t ext_data_len;
       size_t ext_end;
       if (!tls_need(pos, 4, extensions_end))
    	   return false;
       ext_data_len = ((size_t)data[pos + 2] << 8) + data[pos + 3];
       if (!tls_need(pos + 4, ext_data_len, extensions_end))
       {
    	   log_error("Get HTTPS Host: not enough data");
    	   return false;
       }
       ext_end = pos + 4 + ext_data_len;
       if (data[pos] == 0 && data[pos + 1] == 0)
       {
          size_t name_pos;
          size_t list_len;
          size_t server_name_len;
          pos += 4;
          if (!tls_need(pos, 5, ext_end))
          {
        	 log_error("server_name list header");
             return false;
          }
          list_len = ((size_t)data[pos] << 8) + data[pos + 1];
          if (list_len < 3 || pos + 2 + list_len != ext_end)
        	  return false;
          if (data[pos + 2] != 0)
        	  return false;
          server_name_len = ((size_t)data[pos + 3] << 8) + data[pos + 4];
          if (server_name_len + 3 != list_len)
        	  return false;
          name_pos = pos + 5;
          if (!tls_need(name_pos, server_name_len, ext_end))
          {
          	log_error("Get HTTPS Host: not enough data");
          	return false;
          }
          if (server_name_len == 0 || server_name_len + 1 > MaxHostName)
              return false;

          memcpy(HostName, data + name_pos, server_name_len);
          HostName[server_name_len] = '\0';
          return true;
        }
        if (ext_end <= pos)
        	return false;
        pos = ext_end;
    }
    log_error("buffer more than one record, SNI still not found");
    return false;
}

bool net_get_http_host(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName)
{
    const uint8_t *data = buf;
    const uint8_t *end;
    const uint8_t *pos;
    const uint8_t *end_pos;
    size_t host_len;

    if (!buf || !HostName || MaxHostName == 0)
        return false;
    HostName[0] = '\0';
    end = data + len;

    pos = (const uint8_t *)net_memmem(buf, len, "\r\nHost:", 7);
    if (pos == NULL || pos < data || pos > end)
        return false;

    if ((size_t)(end - pos) < 7)
        return false;
    pos += 7;
    while (pos < end && *pos == ' ')
        pos++;
    if (pos >= end)
        return false;

    end_pos = (const uint8_t *)net_memmem(pos, (size_t)(end - pos), "\r\n", 2);
    if (end_pos == NULL || end_pos < pos || end_pos > end)
        return false;

    host_len = (size_t)(end_pos - pos);
    if (host_len == 0)
    {
        log_error("invalid Host in request");
        return false;
    }
    if (host_len + 1 > MaxHostName)
        return false;

    memcpy(HostName, pos, host_len);
    HostName[host_len] = '\0';
    return true;
}

static void *net_memmem(const void *haystack_start, size_t haystack_len,
        		const void *needle_start, size_t needle_len)
{
    /* Abstract memory is considered to be an array of 'unsigned char' values,
	   not an array of 'char' values.  See ISO C 99 section 6.2.6.1.  */
	const unsigned char *haystack = (const unsigned char *) haystack_start;
	const unsigned char *needle = (const unsigned char *) needle_start;


	/* The first occurrence of the empty string is deemed to occur at
	   the beginning of the string.  */
	if (needle_len == 0)
		return (void *) haystack;

	/* Sanity check, otherwise the loop might search through the whole memory.  */
	if (haystack_len < needle_len)
	    return NULL;

	const unsigned char *Startptr = (const unsigned char *)haystack_start;
	while(haystack_len)
	{
		haystack = memchr(haystack, *needle, haystack_len);
		if (!haystack || (needle_len == 1))
			return (void *) haystack;
		haystack_len -= (size_t)(haystack - Startptr);

		if (haystack_len < needle_len)
				return NULL;
		if (memcmp (haystack, needle, needle_len) == 0)
				return (void *) haystack;
		haystack++;
		haystack_len--;
		Startptr = haystack;
	}
	return NULL;
}

bool net_is_ip_literal(const char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

