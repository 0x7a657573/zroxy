#include "resolver_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

/* Hostname normalization, numeric address handling, and destination policy. */

int resolver_copy_numeric(const char *host, uint16_t port, resolver_addr *out, size_t *count)
{
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	memset(&in, 0, sizeof(in));
	memset(&in6, 0, sizeof(in6));
	if (inet_pton(AF_INET, host, &in.sin_addr) == 1) {
		in.sin_family = AF_INET;
		in.sin_port = htons(port);
		memset(out, 0, sizeof(*out));
		memcpy(&out->address, &in, sizeof(in));
		out->length = (socklen_t)sizeof(in);
		*count = 1;
		return 1;
	}
	if (inet_pton(AF_INET6, host, &in6.sin6_addr) == 1) {
		in6.sin6_family = AF_INET6;
		in6.sin6_port = htons(port);
		memset(out, 0, sizeof(*out));
		memcpy(&out->address, &in6, sizeof(in6));
		out->length = (socklen_t)sizeof(in6);
		*count = 1;
		return 1;
	}
	return 0;
}

void resolver_apply_port_one(resolver_addr *addr, uint16_t port)
{
	struct sockaddr *sa = (struct sockaddr *)&addr->address;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		in->sin_port = htons(port);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
		in6->sin6_port = htons(port);
	}
}

bool resolver_normalize(const char *in, char *out, size_t out_cap)
{
	size_t n = 0;
	size_t i;
	size_t label = 0;
	if (!in || !out || out_cap < 2)
		return false;
	while (in[n] != '\0') {
		if (n >= (size_t)RESOLVER_HOST_MAX + 1u)
			return false;
		n++;
	}
	if (n == 0 || n > (size_t)RESOLVER_HOST_MAX + 1u)
		return false;
	if (in[n - 1] == '.') {
		n--;
		if (n == 0 || n > (size_t)RESOLVER_HOST_MAX)
			return false;
	}
	if (n > (size_t)RESOLVER_HOST_MAX || n + 1 > out_cap)
		return false;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)in[i];
		char prev;
		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c - 'A' + 'a');
		if (c == '.') {
			if (label == 0 || label > 63)
				return false;
			prev = (i == 0) ? '\0' : out[i - 1];
			if (prev == '-')
				return false;
			out[i] = '.';
			label = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
			return false;
		if (c == '-' && label == 0)
			return false;
		out[i] = (char)c;
		label++;
	}
	if (label == 0 || label > 63)
		return false;
	if (out[n - 1] == '-')
		return false;
	out[n] = '\0';
	return true;
}

static int v4_private(uint32_t host)
{
	if ((host >> 24) == 10)
		return 1;
	if ((host & 0xfff00000u) == 0xac100000u)
		return 1;
	if ((host & 0xffff0000u) == 0xc0a80000u)
		return 1;
	if ((host & 0xffc00000u) == 0x64400000u)
		return 1;
	return 0;
}

static int v4_rejected(uint32_t host, uint16_t port, unsigned flags)
{
	int i;
	int self = 0;
	int loopback = (host >> 24) == 127;
	if ((host >> 24) == 0 || host == 0xffffffffu)
		return 1;
	if ((host & 0xffff0000u) == 0xa9fe0000u)
		return 1;
	if ((host & 0xf0000000u) == 0xe0000000u)
		return 1;
	if ((host & 0xf0000000u) == 0xf0000000u)
		return 1;
	if (loopback && !(flags & RESOLVER_POLICY_ALLOW_LOOPBACK))
		return 1;
	if ((flags & RESOLVER_POLICY_DENY_PRIVATE) && v4_private(host))
		return 1;
	for (i = 0; i < RESOLVER_BIND_MAX; i++) {
		sni_bind_rec *b = &g_resolver_pool->binds[i];
		uint32_t bip;
		if (!b->used)
			continue;
		bip = ntohl(b->ip.s_addr);
		if (b->port == port && (b->wildcard || bip == host))
			self = 1;
		if (b->port == port && loopback && (bip >> 24) == 127)
			self = 1;
	}
	return self;
}

static int v6_rejected(const struct in6_addr *ip, uint16_t port, unsigned flags)
{
	int i;
	static const uint8_t nat64[12] = { 0x00, 0x64, 0xff, 0x9b };
	static const uint8_t zero12[12] = { 0 };
	if (IN6_IS_ADDR_UNSPECIFIED(ip) || IN6_IS_ADDR_MULTICAST(ip) ||
	    IN6_IS_ADDR_LINKLOCAL(ip) || IN6_IS_ADDR_SITELOCAL(ip))
		return 1;
	if (IN6_IS_ADDR_LOOPBACK(ip)) {
		if (!(flags & RESOLVER_POLICY_ALLOW_LOOPBACK))
			return 1;
		for (i = 0; i < RESOLVER_BIND_MAX; i++) {
			if (g_resolver_pool->binds[i].used && g_resolver_pool->binds[i].port == port)
				return 1;
		}
		return 0;
	}
	/* IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::/96) embed an IPv4 address. */
	if (memcmp(ip->s6_addr, zero12, 12) == 0 || memcmp(ip->s6_addr, nat64, 12) == 0) {
		uint32_t host;
		memcpy(&host, &ip->s6_addr[12], 4);
		return v4_rejected(ntohl(host), port, flags);
	}
	if ((flags & RESOLVER_POLICY_DENY_PRIVATE) && (ip->s6_addr[0] & 0xfe) == 0xfc)
		return 1;
	return 0;
}

static int normalize_mapped(resolver_addr *addr)
{
	struct sockaddr *sa = (struct sockaddr *)&addr->address;
	if (sa->sa_family != AF_INET6)
		return 0;
	{
		struct sockaddr_in6 in6;
		memcpy(&in6, &addr->address, sizeof(in6));
		if (!IN6_IS_ADDR_V4MAPPED(&in6.sin6_addr))
			return 0;
		{
			struct sockaddr_in in;
			memset(&in, 0, sizeof(in));
			in.sin_family = AF_INET;
			in.sin_port = in6.sin6_port;
			memcpy(&in.sin_addr, &in6.sin6_addr.s6_addr[12], 4);
			memset(addr, 0, sizeof(*addr));
			memcpy(&addr->address, &in, sizeof(in));
			addr->length = (socklen_t)sizeof(in);
		}
	}
	return 1;
}

size_t resolver_policy_keep(resolver_addr *addrs, size_t count, unsigned flags)
{
	size_t i;
	size_t kept = 0;
	if (!addrs)
		return 0;
	if (!g_resolver_pool && !resolver_start())
		return 0;
	pthread_mutex_lock(&g_resolver_pool->mu);
	for (i = 0; i < count; i++) {
		struct sockaddr *sa;
		int drop = 0;
		normalize_mapped(&addrs[i]);
		sa = (struct sockaddr *)&addrs[i].address;
		if (sa->sa_family == AF_INET) {
			struct sockaddr_in in;
			uint32_t host;
			uint16_t port;
			memcpy(&in, &addrs[i].address, sizeof(in));
			host = ntohl(in.sin_addr.s_addr);
			port = ntohs(in.sin_port);
			drop = v4_rejected(host, port, flags);
		} else if (sa->sa_family == AF_INET6) {
			struct sockaddr_in6 in6;
			memcpy(&in6, &addrs[i].address, sizeof(in6));
			drop = v6_rejected(&in6.sin6_addr, ntohs(in6.sin6_port), flags);
		} else {
			drop = 1;
		}
		if (!drop) {
			if (kept != i)
				addrs[kept] = addrs[i];
			kept++;
		}
	}
	pthread_mutex_unlock(&g_resolver_pool->mu);
	return kept;
}

