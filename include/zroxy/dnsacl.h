#ifndef ZROXY_DNSACL_H
#define ZROXY_DNSACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
	uint32_t net;
	uint32_t mask;
} dns_cidr_t;

bool dns_acl_parse(const char *spec, dns_cidr_t *out, size_t cap, size_t *count);
bool dns_acl_allows(const dns_cidr_t *acl, size_t n, uint32_t ip_host_order);

#endif
