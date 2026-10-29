#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/dnsacl.h>

static const char *skip_space(const char *p)
{
	while (*p && isspace((unsigned char)*p))
		p++;
	return p;
}

static const char *trim_end(const char *begin, const char *end)
{
	while (end > begin && isspace((unsigned char)end[-1]))
		end--;
	return end;
}

bool dns_acl_parse(const char *spec, dns_cidr_t *out, size_t cap, size_t *count)
{
	const char *p;
	size_t used = 0;

	if (count)
		*count = 0;
	if (!spec || !out || !count || cap == 0)
		return false;
	p = spec;
	for (;;)
	{
		const char *begin = skip_space(p);
		const char *comma = strchr(begin, ',');
		const char *end = comma ? comma : begin + strlen(begin);
		char *slash;
		char token[64];
		char address[INET_ADDRSTRLEN];
		char *prefix_end;
		unsigned long prefix;
		struct in_addr parsed;
		size_t len;

		end = trim_end(begin, end);
		if (end == begin || (size_t)(end - begin) >= sizeof(token) || used >= cap)
			return false;
		len = (size_t)(end - begin);
		memcpy(token, begin, len);
		token[len] = '\0';
		slash = strchr(token, '/');
		if (!slash || strchr(slash + 1, '/'))
			return false;
		*slash = '\0';
		if (strlen(token) == 0 || strlen(slash + 1) == 0 ||
			strlen(token) >= sizeof(address))
			return false;
		memcpy(address, token, strlen(token) + 1);
		if (inet_pton(AF_INET, address, &parsed) != 1)
			return false;
		for (prefix_end = slash + 1; *prefix_end; prefix_end++)
			if (!isdigit((unsigned char)*prefix_end))
				return false;
		errno = 0;
		prefix = strtoul(slash + 1, &prefix_end, 10);
		if (errno != 0 || *prefix_end != '\0' || prefix > 32)
			return false;
		out[used].mask = prefix == 0 ? 0u : UINT32_MAX << (32u - (uint32_t)prefix);
		out[used].net = ntohl(parsed.s_addr) & out[used].mask;
		used++;
		if (!comma)
			break;
		p = comma + 1;
		if (*skip_space(p) == '\0')
			return false;
	}
	*count = used;
	return used > 0;
}

bool dns_acl_allows(const dns_cidr_t *acl, size_t n, uint32_t ip_host_order)
{
	size_t i;
	if (!acl)
		return false;
	for (i = 0; i < n; i++)
		if ((ip_host_order & acl[i].mask) == acl[i].net)
			return true;
	return false;
}
