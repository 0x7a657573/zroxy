#ifndef ZROXY_ACL_H
#define ZROXY_ACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
	uint32_t net;
	uint32_t mask;
} zroxy_cidr_t;

bool acl_parse(const char *spec, zroxy_cidr_t *out, size_t cap, size_t *count);
bool acl_allows(const zroxy_cidr_t *acl, size_t n, uint32_t ip_host_order);

#endif
