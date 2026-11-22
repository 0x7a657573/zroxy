/* Option value parsers and the dispatcher for the args module. */
#include <zroxy/args.h>
#include <zroxy/dnscache.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <zroxy/log.h>
#include <ctype.h>
#include <limits.h>
#include <zroxy/config.h>
#include <zroxy/acl.h>
#include "args_internal.h"

static bool parse_uint(const char *str, unsigned long maxv, unsigned long *out)
{
	unsigned long value = 0;
	const char *s = str;
	if (!s || *s == '\0' || !out)
		return false;
	while (*s)
	{
		if (!isdigit((unsigned char)*s))
			return false;
		if (value > maxv / 10ul ||
		    (value == maxv / 10ul && (unsigned long)(*s - '0') > maxv % 10ul))
			return false;
		value = value * 10ul + (unsigned long)(*s - '0');
		s++;
	}
	*out = value;
	return true;
}

static bool parse_u16(const char *str, uint16_t *out, uint16_t minv, uint16_t maxv)
{
	unsigned long value;
	if (!parse_uint(str, maxv, &value) || value < minv)
		return false;
	*out = (uint16_t)value;
	return true;
}

static bool parse_u32_in(const char *str, int minv, int maxv, uint32_t *out)
{
	unsigned long value;
	if (!parse_uint(str, (unsigned long)maxv, &value) || value < (unsigned long)minv)
		return false;
	*out = (uint32_t)value;
	return true;
}

static bool copy_bounded(char *dst, size_t dstsz, const char *src)
{
	size_t n;
	if (!dst || !src || dstsz == 0)
		return false;
	n = strlen(src);
	if (n >= dstsz)
		return false;
	memcpy(dst, src, n + 1);
	return true;
}

static char *dup_bounded(const char *src, size_t max_len)
{
	size_t n;
	char *out;
	if (!src)
		return NULL;
	n = strlen(src);
	if (n == 0 || n > max_len)
		return NULL;
	out = malloc(n + 1);
	if (!out)
		return NULL;
	memcpy(out, src, n + 1);
	return out;
}

static void free_sockshost(sockshost_t *socks)
{
	if (!socks)
		return;
	free(socks->host);
	free(socks->user);
	args_free_secret(socks->pass);
	free(socks);
}

static bool parse_ports(zroxy_t *ptr,char *str);
static bool parse_socks(zroxy_t *ptr,char *str);
static bool parse_monitor(zroxy_t *ptr,char *str);
static bool parse_monitor_token(zroxy_t *ptr,char *str);
static bool parse_secret_path(char **slot,char *str);
static bool parse_monitor_timeout(zroxy_t *ptr,char *str);
static bool parse_whitelist(zroxy_t *ptr,char *str);
static bool parse_dns_server(zroxy_t *ptr,char *str);
static bool parse_dns_upstream(zroxy_t *ptr,char *str);
static bool parse_dns_socks(zroxy_t *ptr,char *str);
static bool parse_sni_ip(zroxy_t *ptr,char *str);
static bool parse_dns_timeout(zroxy_t *ptr,char *str);
static bool parse_dns_cache(zroxy_t *ptr,char *str);
static bool parse_dns_ttl(zroxy_t *ptr,char *str);
static bool parse_dns_acl(zroxy_t *ptr,char *str);
static bool parse_dns_rate(zroxy_t *ptr,char *str);
static bool parse_dns_connections(zroxy_t *ptr,char *str);
static bool parse_log_level(zroxy_t *ptr,char *str);
static bool parse_sni_timeout(zroxy_t *ptr,char *str);
static bool parse_sni_idle_timeout(zroxy_t *ptr,char *str);
static bool parse_sni_max_conn(zroxy_t *ptr,char *str);
static bool parse_sni_acl(zroxy_t *ptr,char *str);
static bool parse_bool(char *str, bool *out);
static bool validate_ip(char *ip);

static bool validate_ip(char *ip)
{
	unsigned int a, b, c, d;
	char tail = '\0';
	const char *p;
	if (ip == NULL || ip[0] == '\0')
		return false;

	/* Do not accept trailing junk or empty octets. */
	if (sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4)
		return false;
	if (a > 255 || b > 255 || c > 255 || d > 255)
		return false;

	p = ip;
	for (;;)
	{
		const char *dot;
		size_t n;
		if (*p == '\0' || !isdigit((unsigned char)*p))
			return false;
		dot = strchr(p, '.');
		n = dot ? (size_t)(dot - p) : strlen(p);
		if (n == 0 || n > 3)
			return false;
		if (!dot)
			break;
		p = dot + 1;
	}
	return true;
}

static dnshost_t *dns_config(zroxy_t *ptr)
{
	if (!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)calloc(1, sizeof(dnshost_t));
		if (!ptr->dnsserver)
			return NULL;
		ptr->dnsserver->Local.port = 53;
		ptr->dnsserver->timeout = 5;
		ptr->dnsserver->cache_entries = DNSCACHE_ENTRIES;
		ptr->dnsserver->local_ttl = DNS_LOCAL_TTL_DEFAULT;
		ptr->dnsserver->upstream_connections = DNS_UPSTREAM_CONNECTIONS_DEFAULT;
		memcpy(ptr->dnsserver->Local.ip, "127.0.0.1", sizeof("127.0.0.1"));
	}
	return ptr->dnsserver;
}

int args_apply_option(int key, char *arg, void *userprm)
{
	zroxy_t *setting = (zroxy_t*)userprm;

	/*remove space form arg*/
	if(arg)
		while(*arg==' ') arg++;
	if (key != 'h' && (!arg || arg[0] == '\0'))
		return -1;

    switch (key)
    {
		case 'c': if (!args_parse_config(setting,arg)) return -1; break;
		case 'p': if (!parse_ports(setting,arg)) return -1; break;
		case 's': if (!parse_socks(setting,arg)) return -1; break;
		case 'm': if (!parse_monitor(setting,arg)) return -1; break;
		case 'k': if (!parse_monitor_token(setting,arg)) return -1; break;
		case 'K': if (!parse_secret_path(&setting->monitor_token_file,arg)) return -1; break;
		case 'S': if (!parse_secret_path(&setting->socks_pass_file,arg)) return -1; break;
		case 'X': if (!parse_secret_path(&setting->dsocks_pass_file,arg)) return -1; break;
		case 'a': if (!parse_monitor_timeout(setting,arg)) return -1; break;
		case 'w': if (!parse_whitelist(setting,arg)) return -1; break;
		case 'd': if (!parse_dns_server(setting,arg)) return -1; break;
		case 'u': if (!parse_dns_upstream(setting,arg)) return -1; break;
		case 'x': if (!parse_dns_socks(setting,arg)) return -1; break;
		case 'i': if (!parse_sni_ip(setting,arg)) return -1; break;
		case 't': if (!parse_dns_timeout(setting,arg)) return -1; break;
		case 'e': if (!parse_dns_cache(setting,arg)) return -1; break;
		case 'r': if (!parse_dns_ttl(setting,arg)) return -1; break;
		case 'A': if (!parse_dns_acl(setting,arg)) return -1; break;
		case 'R': if (!parse_dns_rate(setting,arg)) return -1; break;
		case 'C': if (!parse_dns_connections(setting,arg)) return -1; break;
		case 'l': if (!parse_log_level(setting,arg)) return -1; break;
		case 'o': if (!parse_sni_timeout(setting,arg)) return -1; break;
		case 'L': if (!parse_bool(arg, &setting->allow_loopback)) return -1; break;
		case 'P': if (!parse_bool(arg, &setting->deny_private)) return -1; break;
		case 'U': if (!parse_secret_path(&setting->run_user,arg)) return -1; break;
		case 'G': if (!parse_secret_path(&setting->run_group,arg)) return -1; break;
		case 'O': if (!parse_bool(arg, &setting->open_proxy)) return -1; break;
		case 'I': if (!parse_sni_idle_timeout(setting,arg)) return -1; break;
		case 'n': if (!parse_sni_max_conn(setting,arg)) return -1; break;
		case 'N': if (!parse_sni_acl(setting,arg)) return -1; break;
		case 'h': args_print_usage(); exit(0);
		default: return -1;
    }
    return 0;
}

static bool parse_whitelist(zroxy_t *ptr,char *str)
{
	char *path;
	path = dup_bounded(str, ZROXY_MAX_CONFIG_VALUE);
	if (!path)
		return false;
	free(ptr->WhitePath);
	ptr->WhitePath = path;
	return true;
}

static bool parse_monitor(zroxy_t *ptr,char *str)
{
	char *colon;
	char *port_str = str;
	char bind[ZROXY_MAX_IP_TEXT];
	uint16_t port;

	if (!copy_bounded(bind, sizeof(bind), "127.0.0.1"))
		return false;
	colon = strrchr(str, ':');
	if (colon)
	{
		*colon = '\0';
		port_str = colon + 1;
		if (!validate_ip(str) || !copy_bounded(bind, sizeof(bind), str))
		{
			log_error("invalid monitor bind address");
			return false;
		}
	}
	if (!parse_u16(port_str, &port, 1, 65535))
		return false;
	ptr->monitor_port = port;
	memcpy(ptr->monitor_bind, bind, sizeof(bind));
	return true;
}

static bool parse_monitor_token(zroxy_t *ptr,char *str)
{
	char *token = dup_bounded(str, ARGS_MAX_TOKEN);
	if (!token)
		return false;
	args_free_secret(ptr->monitor_token);
	ptr->monitor_token = token;
	return true;
}

static bool parse_secret_path(char **slot,char *str)
{
	char *path = dup_bounded(str, ZROXY_MAX_CONFIG_VALUE);
	if (!path)
		return false;
	free(*slot);
	*slot = path;
	return true;
}

static bool parse_monitor_timeout(zroxy_t *ptr,char *str)
{
	uint32_t timeout;
	if (!parse_u32_in(str, 1, 60, &timeout))
		return false;
	ptr->monitor_header_timeout = (int)timeout;
	return true;
}

static bool parse_dns_timeout(zroxy_t *ptr,char *str)
{
	dnshost_t *dns = dns_config(ptr);
	return dns && parse_u32_in(str, 0, 86400, &dns->timeout);
}

static bool parse_dns_cache(zroxy_t *ptr,char *str)
{
	dnshost_t *dns = dns_config(ptr);
	return dns && parse_u32_in(str, 0, 65536, &dns->cache_entries);
}

static bool parse_dns_ttl(zroxy_t *ptr,char *str)
{
	dnshost_t *dns = dns_config(ptr);
	return dns && parse_u32_in(str, 1, 86400, &dns->local_ttl);
}

static bool parse_dns_acl(zroxy_t *ptr,char *str)
{
	zroxy_cidr_t parsed[32];
	zroxy_cidr_t *copy;
	size_t count = 0;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !acl_parse(str, parsed, sizeof(parsed) / sizeof(parsed[0]), &count))
		return false;
	copy = malloc(count * sizeof(*copy));
	if (!copy)
		return false;
	memcpy(copy, parsed, count * sizeof(*copy));
	free(dns->acl);
	dns->acl = copy;
	dns->acl_count = count;
	dns->acl_set = true;
	return true;
}

static bool parse_dns_rate(zroxy_t *ptr,char *str)
{
	dnshost_t *dns = dns_config(ptr);
	return dns && parse_u32_in(str, 0, 100000, &dns->rate_qps);
}

static bool parse_dns_connections(zroxy_t *ptr,char *str)
{
	uint32_t count;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !parse_u32_in(str, 1, DNS_UPSTREAM_CONNECTIONS_DEFAULT, &count))
		return false;
	dns->upstream_connections = (uint16_t)count;
	return true;
}

static bool parse_dns_server(zroxy_t *ptr,char *str)
{
	char *endname;
	uint16_t port = 53;
	dnshost_t *dns = dns_config(ptr);

	if (!dns)
		return false;
	dns->Local.port = 53;

	endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		if (!parse_u16(endname, &port, 0, 65535))
			return false;
		dns->Local.port = port;
	}
	if (!validate_ip(str) || !copy_bounded(dns->Local.ip, sizeof(dns->Local.ip), str))
	{
		log_error("invalid local DNS address");
		return false;
	}
	dns->listen_set = true;
	return true;
}

static bool parse_sni_ip(zroxy_t *ptr,char *str)
{
	unsigned int si[4];
	char tail = '\0';
	uint8_t *sni_ip;
	dnshost_t *dns;

	dns = dns_config(ptr);
	if (!dns)
		return false;

	if (sscanf(str, "%u.%u.%u.%u%c", &si[0], &si[1], &si[2], &si[3], &tail) != 4)
		return false;
	if (si[0] > 255 || si[1] > 255 || si[2] > 255 || si[3] > 255)
		return false;

	sni_ip = dns->sni_ip;
	sni_ip[0] = (uint8_t)si[0];
	sni_ip[1] = (uint8_t)si[1];
	sni_ip[2] = (uint8_t)si[2];
	sni_ip[3] = (uint8_t)si[3];
	return true;
}

/*
 * "HOST[:PORT] via SPEC": the start of the "via" word after the upstream,
 * or NULL. "via" is a whole whitespace-separated word, so it cannot be cut
 * out of a host name.
 */
char *args_find_dns_via(char *str)
{
	char *p = str;
	while (*p && !isspace((unsigned char)*p))
		p++;
	while (*p && isspace((unsigned char)*p))
		p++;
	if (strncmp(p, "via", 3) == 0 && (p[3] == '\0' || isspace((unsigned char)p[3])))
		return p;
	return NULL;
}

static bool str_equal_null(const char *a, const char *b)
{
	if (!a || !b)
		return a == b;
	return strcmp(a, b) == 0;
}

/* The same upstream reached the same way. */
static bool dns_route_same(const dns_route_t *a, const dns_route_t *b)
{
	if (strcasecmp(a->upstream.ip, b->upstream.ip) != 0 ||
	    a->upstream.port != b->upstream.port || a->direct != b->direct)
		return false;
	if (!a->socks || !b->socks)
		return a->socks == b->socks;
	return strcasecmp(a->socks->host, b->socks->host) == 0 &&
		a->socks->port == b->socks->port &&
		str_equal_null(a->socks->user, b->socks->user) &&
		str_equal_null(a->socks->pass, b->socks->pass);
}

static bool fill_sockshost(sockshost_t *socks, char *str);

/*
 * One DNS= / -u value is one route: HOST[:PORT] [via SOCKS-SPEC|direct].
 * It is parsed completely and appended only when valid.
 */
static bool parse_dns_upstream(zroxy_t *ptr,char *str)
{
	char *endname;
	char *via;
	char *end;
	uint16_t port = 53;
	dns_route_t route;
	dnshost_t *dns = dns_config(ptr);

	if (!dns)
		return false;
	memset(&route, 0, sizeof(route));

			via = args_find_dns_via(str);
	end = str;
	while (*end && !isspace((unsigned char)*end))
		end++;
	if (*end)
	{
		/* anything after the host must be the via clause */
		char *rest = end;
		*end = '\0';
		while (isspace((unsigned char)*++rest)) ;
		if (*rest && !via)
		{
			log_error("DNS upstream: unexpected text after the host (use \"HOST[:PORT] via SPEC\")");
			return false;
		}
	}
	if (via)
	{
		char *spec = args_trim(via + 3);
		if (spec[0] == '\0')
		{
			log_error("DNS upstream: \"via\" needs a SOCKS5 spec or \"direct\"");
			return false;
		}
		if (strcasecmp(spec, "direct") == 0)
			route.direct = true;
		else
		{
			route.socks = (sockshost_t*)calloc(1, sizeof(sockshost_t));
			if (!route.socks)
				return false;
			if (!fill_sockshost(route.socks, spec))
			{
				free_sockshost(route.socks);
				return false;
			}
		}
	}

	endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		if (!parse_u16(endname, &port, 1, 65535))
			goto fail;
	}
	if (!copy_bounded(route.upstream.ip, sizeof(route.upstream.ip), str))
		goto fail;
	route.upstream.port = port;

	for (unsigned i = 0; i < dns->route_count; i++)
	{
		if (dns_route_same(&route, &dns->routes[i]))
		{
			log_error("DNS upstream %s:%u is already defined", route.upstream.ip,
			    (unsigned)route.upstream.port);
			goto fail;
		}
	}
	if (dns->route_count >= DNS_ROUTES_MAX)
	{
		log_error("too many DNS upstreams (at most %d)", DNS_ROUTES_MAX);
		goto fail;
	}
	dns->routes[dns->route_count++] = route;
	return true;

fail:
	free_sockshost(route.socks);
	return false;
}

static bool fill_sockshost(sockshost_t *socks, char *str)
{
	char *at;
	char *hostpart = str;
	char *user = NULL;
	char *pass = NULL;
	char *host;
	uint16_t port = 1080;
	char *endname;

	at = strchr(str, '@');
	if (at)
	{
		*at++ = 0;
		hostpart = at;
		endname = strchr(str, ':');
		if (endname)
		{
			*endname++ = 0;
			user = dup_bounded(str, ARGS_MAX_IDENT);
			if (endname[0] == '\0')
			{
				pass = calloc(1, 1);
			}
			else
			{
				pass = dup_bounded(endname, ARGS_MAX_IDENT);
			}
			if (!user || !pass)
			{
				free(user);
				args_free_secret(pass);
				return false;
			}
		}
		else
		{
			user = dup_bounded(str, ARGS_MAX_IDENT);
			if (!user)
				return false;
		}
	}

	endname = strchr(hostpart, ':');
	if (endname)
	{
		*endname++ = 0;
		if (!parse_u16(endname, &port, 1, 65535))
		{
			free(user);
			args_free_secret(pass);
			return false;
		}
	}
	host = dup_bounded(hostpart, ZROXY_MAX_DNS_HOST);
	if (!host)
	{
		free(user);
		args_free_secret(pass);
		return false;
	}

	socks->user = user;
	socks->pass = pass;
	socks->host = host;
	socks->port = port;
	return true;
}

static bool parse_socks(zroxy_t *ptr,char *str)
{
	sockshost_t *socks = (sockshost_t*)calloc(1, sizeof(sockshost_t));
	if (!socks)
		return false;
	if (!fill_sockshost(socks, str))
	{
		free_sockshost(socks);
		return false;
	}
	free_sockshost(ptr->socks);
	ptr->socks = socks;
	return true;
}

/* IPv4 text that validate_ip accepted, as a host-order number. */
static uint32_t ip_value(const char *ip)
{
	unsigned int a = 0, b = 0, c = 0, d = 0;

	(void)sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
	return (a << 24) | (b << 16) | (c << 8) | d;
}

/*
 * True when binding port would fail because other listens on the same local
 * port: the same address, or either one is the wildcard. Port 0 asks for any
 * free port, so two of them never collide.
 */
static bool listener_conflict(const lport_t *port,const lport_t *other)
{
	uint32_t a = ip_value(port->bindip);
	uint32_t b = ip_value(other->bindip);

	if (port->local_port == 0 || port->local_port != other->local_port)
		return false;
	return a == b || a == 0 || b == 0;
}

static void free_port_list(lport_t *p)
{
	while (p)
	{
		lport_t *next = (lport_t*)p->next;
		free(p);
		p = next;
	}
}

/*
 * Parse a comma list of listeners and append it to ptr->ports, after the ones
 * from earlier PORT lines or -p options. All or nothing: the entries go into a
 * list of their own first, so a bad entry leaves ptr->ports as it was.
 */
static bool parse_ports(zroxy_t *ptr,char *str)
{
	lport_t *head = NULL;
	lport_t *tail = NULL;
	lport_t *last;
	lport_t *port = NULL;

	do{
		port = (lport_t*)calloc(1, sizeof(lport_t));
		char *xptr = str;
		char *Iptr;
		char *Pptr;
		uint16_t local_port;
		uint16_t remote_port;

		if (!port)
			goto fail;
		str = strchr(str,',');
		if(str)
		{
			*str++=0;
		}

		/*check for ip*/
		Iptr = strchr(xptr,':');
		if(Iptr)
		{
			*Iptr++=0;
			if (!validate_ip(xptr) ||
			    !copy_bounded(port->bindip, sizeof(port->bindip), xptr))
			{
				log_error("invalid listener address");
				goto fail;
			}
			xptr = Iptr;
		}
		else if (!copy_bounded(port->bindip, sizeof(port->bindip), "0.0.0.0"))
			goto fail;

		Pptr = strchr(xptr,'@');
		if(Pptr)
		{
			*Pptr++=0;
			if (!parse_u16(xptr, &local_port, 0, 65535) ||
			    !parse_u16(Pptr, &remote_port, 0, 65535))
				goto fail;
		}
		else
		{
			if (!parse_u16(xptr, &local_port, 0, 65535))
				goto fail;
			remote_port = local_port;
		}

		port->local_port = local_port;
		port->remote_port = remote_port;

		/*against the earlier lines and the entries of this one*/
		for (last = ptr->ports; last; last = (lport_t*)last->next)
			if (listener_conflict(port, last))
				break;
		for (lport_t *p = head; !last && p; p = (lport_t*)p->next)
			if (listener_conflict(port, p))
				last = p;
		if (last)
		{
			log_error("listener %s:%u is already defined", port->bindip,
			    (unsigned)port->local_port);
			goto fail;
		}

		if (tail)
			tail->next = port;
		else
			head = port;
		tail = port;

	}while( str!=NULL );

	if (ptr->ports)
	{
		for (last = ptr->ports; last->next; last = (lport_t*)last->next)
			;
		last->next = head;
	}
	else
		ptr->ports = head;
	return true;

fail:
	free(port);
	free_port_list(head);
	return false;
}

void args_free_ports(zroxy_t *ptr)
{
	free_port_list(ptr->ports);
	ptr->ports = NULL;
}

void args_free_sacl(zroxy_t *ptr)
{
	free(ptr->sacl);
	ptr->sacl = NULL;
	ptr->sacl_count = 0;
}

void args_free_socks(zroxy_t *ptr)
{
	free_sockshost(ptr->socks);
	ptr->socks = NULL;
}

void args_free_monitor_token(zroxy_t *ptr)
{
	args_free_secret(ptr->monitor_token);
	ptr->monitor_token = NULL;
}

void args_free_dns(zroxy_t *ptr)
{
	if(ptr->dnsserver)
	{
		if(ptr->dnsserver->Socks)
		{
			free_sockshost(ptr->dnsserver->Socks);
		}
		for (unsigned i = 0; i < ptr->dnsserver->route_count; i++)
			free_sockshost(ptr->dnsserver->routes[i].socks);
		free(ptr->dnsserver->acl);
		free(ptr->dnsserver);
		ptr->dnsserver = NULL;
	}
}

static bool parse_dns_socks(zroxy_t *ptr,char *str)
{
	sockshost_t *socks;
	dnshost_t *dns = dns_config(ptr);
	if (!dns)
		return false;
	socks = (sockshost_t*)calloc(1, sizeof(sockshost_t));
	if (!socks)
		return false;
	if (!fill_sockshost(socks, str))
	{
		free_sockshost(socks);
		return false;
	}
	free_sockshost(dns->Socks);
	dns->Socks = socks;
	return true;
}

static bool parse_log_level(zroxy_t *ptr,char *str)
{
	uint32_t log_level;
	(void)ptr;
	if (!parse_u32_in(str, 0, 5, &log_level))
		return false;
	log_set_level((int)log_level);
	return true;
}

static bool parse_sni_timeout(zroxy_t *ptr,char *str)
{
	uint32_t timeout;
	if (!parse_u32_in(str, 0, 86400, &timeout))
		return false;
	ptr->snitimeout = (int)timeout;
	return true;
}

static bool parse_sni_idle_timeout(zroxy_t *ptr,char *str)
{
	uint32_t timeout;
	if (!parse_u32_in(str, 1, 86400, &timeout))
		return false;
	ptr->sniidletimeout = (int)timeout;
	return true;
}

static bool parse_sni_acl(zroxy_t *ptr,char *str)
{
	zroxy_cidr_t parsed[32];
	zroxy_cidr_t *copy;
	size_t count = 0;
	if (!acl_parse(str, parsed, sizeof(parsed) / sizeof(parsed[0]), &count))
		return false;
	copy = malloc(count * sizeof(*copy));
	if (!copy)
		return false;
	memcpy(copy, parsed, count * sizeof(*copy));
	free(ptr->sacl);
	ptr->sacl = copy;
	ptr->sacl_count = count;
	return true;
}

static bool parse_sni_max_conn(zroxy_t *ptr,char *str)
{
	uint32_t count;
	if (!parse_u32_in(str, 1, SNI_CONN_LIMIT_MAX, &count))
		return false;
	ptr->snimaxconn = (int)count;
	return true;
}

static bool parse_bool(char *str, bool *out)
{
	if (!strcasecmp(str, "yes") || !strcasecmp(str, "on") || !strcasecmp(str, "true") || !strcmp(str, "1"))
		*out = true;
	else if (!strcasecmp(str, "no") || !strcasecmp(str, "off") || !strcasecmp(str, "false") || !strcmp(str, "0"))
		*out = false;
	else
		return false;
	return true;
}

