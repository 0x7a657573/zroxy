/*
 *
 */
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <zroxy/log.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <zroxy/net.h>
#include <arpa/inet.h>
#include <fcntl.h>

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

bool net_set_nodelay(int fd)
{
	int one = 1;

	return fd >= 0 && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
	                          &one, sizeof(one)) == 0;
}

bool net_listen_ipv4(in_addr_t addr, uint16_t port, int *sockfd)
{

	struct sockaddr_in servaddr;

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
		log_error("socket creation on port %d failed.", port);
		return false;
	}
	memset(&servaddr, 0, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = addr; //htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	int opt = 1;
	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
	{
		close(*sockfd);
		log_error("socket setopt failed");
		return false;
	}

	// Binding newly created socket to given IP and verification
	if ((bind(*sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) < 0)
	{
		close(*sockfd);
		log_error("socket bind failed");
		return false;
	}

	/*
	 * An SNI listener holds up to 1024 connections and browsers open them in
	 * bursts. A short queue drops SYNs while the event loop is busy, and the
	 * client waits about a second to retry. The kernel caps this value at
	 * net.core.somaxconn.
	 */
	if ((listen(*sockfd, SOMAXCONN)) != 0)
	{
		log_error("Listen failed on port %d", port);
		close(*sockfd);
		*sockfd = -1;
		return false;
	}

	return true;
}

bool net_get_host(uint8_t *buf, uint32_t len, char *HostName, uint16_t MaxHostName)
{
	if (net_get_http_host(buf, len, HostName, MaxHostName) == true)
	{
		return true;
	}
	if (net_get_https_host(buf, len, HostName, MaxHostName) == true)
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

bool net_get_https_host(uint8_t *buf, uint32_t len, char *HostName, uint16_t MaxHostName)
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

static const uint8_t *net_find_host_header(const uint8_t *data, size_t len)
{
	static const char needle[] = "\r\nhost:";
	const size_t n = sizeof(needle) - 1;
	size_t i;
	size_t j;

	if (len < n)
		return NULL;
	for (i = 0; i + n <= len; i++)
	{
		for (j = 0; j < n; j++)
		{
			if (tolower(data[i + j]) != needle[j])
				break;
		}
		if (j == n)
			return data + i;
	}
	return NULL;
}

bool net_get_http_host(uint8_t *buf, uint32_t len, char *HostName, uint16_t MaxHostName)
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

	/* Header names are case-insensitive (RFC 9110 section 5.1). */
	pos = net_find_host_header(data, len);
	if (pos == NULL || pos < data || pos > end)
		return false;

	if ((size_t)(end - pos) < 7)
		return false;
	pos += 7;
	while (pos < end && (*pos == ' ' || *pos == '\t'))
		pos++;
	if (pos >= end)
		return false;

	end_pos = (const uint8_t *)net_memmem(pos, (size_t)(end - pos), "\r\n", 2);
	if (end_pos == NULL || end_pos < pos || end_pos > end)
		return false;

	while (end_pos > pos && (end_pos[-1] == ' ' || end_pos[-1] == '\t'))
		end_pos--;

	/* The remote port comes from the listener, so drop a ":port" suffix. */
	if (pos < end_pos && *pos != '[')
	{
		const uint8_t *colon = end_pos;
		while (colon > pos && colon[-1] >= '0' && colon[-1] <= '9')
			colon--;
		if (colon - 1 > pos && colon < end_pos && colon[-1] == ':')
			end_pos = colon - 1;
	}

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
	const unsigned char *haystack = (const unsigned char *)haystack_start;
	const unsigned char *needle = (const unsigned char *)needle_start;

	/* The first occurrence of the empty string is deemed to occur at
	   the beginning of the string.  */
	if (needle_len == 0)
		return (void *)haystack;

	/* Sanity check, otherwise the loop might search through the whole memory.  */
	if (haystack_len < needle_len)
		return NULL;

	const unsigned char *Startptr = (const unsigned char *)haystack_start;
	while (haystack_len)
	{
		haystack = memchr(haystack, *needle, haystack_len);
		if (!haystack || (needle_len == 1))
			return (void *)haystack;
		haystack_len -= (size_t)(haystack - Startptr);

		if (haystack_len < needle_len)
			return NULL;
		if (memcmp(haystack, needle, needle_len) == 0)
			return (void *)haystack;
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
