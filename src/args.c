/*
 * args.c
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */
#include <zroxy/args.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zroxy/version.h>
#include <stdbool.h>
//#include <argp.h>
#include <zroxy/log.h>
#include <netdb.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define ARGS_MAX_IDENT 255

static bool parse_u16(const char *str, uint16_t *out, uint16_t minv, uint16_t maxv)
{
	unsigned long value = 0;
	const char *s = str;
	if (!s || *s == '\0')
		return false;
	while (*s)
	{
		if (!isdigit((unsigned char)*s))
			return false;
		value = value * 10ul + (unsigned long)(*s - '0');
		if (value > 65535ul)
			return false;
		s++;
	}
	if (value < minv || value > maxv)
		return false;
	*out = (uint16_t)value;
	return true;
}

static bool parse_i32_range(const char *str, int *out, int minv, int maxv)
{
	unsigned long value = 0;
	const char *s = str;
	if (!s || *s == '\0' || !out)
		return false;
	while (*s)
	{
		if (!isdigit((unsigned char)*s))
			return false;
		value = value * 10ul + (unsigned long)(*s - '0');
		if (value > (unsigned long)INT_MAX)
			return false;
		s++;
	}
	if ((int)value < minv || (int)value > maxv)
		return false;
	*out = (int)value;
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
	free(socks->pass);
	free(socks);
}

static const char doc[] = "SNI proxy with optional SOCKS5 upstream, DNS proxy, and HTTP monitor.";
static int parse_opt(int key, char *arg, void *userprm);

static bool parse_ports(zroxy_t *ptr,char *str);
static bool parse_socks(zroxy_t *ptr,char *str);
static bool parse_monitor(zroxy_t *ptr,char *str);
static bool parse_monitor_token(zroxy_t *ptr,char *str);
static bool parse_monitor_timeout(zroxy_t *ptr,char *str);
static bool parse_whitelist(zroxy_t *ptr,char *str);
static bool parse_dns_server(zroxy_t *ptr,char *str);
static bool parse_dns_upstream(zroxy_t *ptr,char *str);
static bool parse_dns_socks(zroxy_t *ptr,char *str);
bool args_parse_config(zroxy_t *ptr,char *str);
static bool parse_sni_ip(zroxy_t *ptr,char *str);
static bool parse_dns_timeout(zroxy_t *ptr,char *str);
static bool parse_dns_cache(zroxy_t *ptr,char *str);
static bool parse_dns_ttl(zroxy_t *ptr,char *str);
static bool parse_dns_acl(zroxy_t *ptr,char *str);
static bool parse_dns_rate(zroxy_t *ptr,char *str);
static bool parse_log_level(zroxy_t *ptr,char *str);
static bool parse_sni_timeout(zroxy_t *ptr,char *str);

static dnshost_t *dns_config(zroxy_t *ptr)
{
	if (!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)calloc(1, sizeof(dnshost_t));
		if (!ptr->dnsserver)
			return NULL;
		ptr->dnsserver->Local.port = 53;
		ptr->dnsserver->timeout = 5;
		ptr->dnsserver->cache_entries = 2048;
		ptr->dnsserver->local_ttl = 300;
		memcpy(ptr->dnsserver->Local.ip, "127.0.0.1", sizeof("127.0.0.1"));
	}
	return ptr->dnsserver;
}

typedef struct 
{
	const char *name;
	char 		key;
	const char  *arg;
	int			require;
	const char *doc;
	int			section;
}arg_option;

enum
{
	OPTION_SECTION_GENERAL,
	OPTION_SECTION_SNI,
	OPTION_SECTION_DNS,
	OPTION_SECTION_MONITOR
};


static arg_option options[] =
{
	{ "config", 'c', "PATH", required_argument, "load configuration from PATH", OPTION_SECTION_GENERAL },
	{ "log", 'l', "0..5", required_argument, "set log level (0=trace, 5=fatal)", OPTION_SECTION_GENERAL },
	{ "help", 'h', "", no_argument, "show this help and exit", OPTION_SECTION_GENERAL },

	{ "port", 'p', "SPEC", required_argument, "SNI listener(s): [BIND-IP:]PORT[@REMOTE-PORT][,...]", OPTION_SECTION_SNI },
	{ "socks", 's', "SPEC", required_argument, "SOCKS5 upstream: [USER:PASSWORD@]HOST[:PORT]", OPTION_SECTION_SNI },
	{ "snitimeout", 'o', "SECONDS", required_argument, "SNI socket timeout (default: 30)", OPTION_SECTION_SNI },
	{ "white", 'w', "PATH", required_argument, "whitelist host names from PATH", OPTION_SECTION_SNI },

	{ "ldns", 'd', "BIND-IP[:PORT]", required_argument, "enable the local DNS listener (UDP and TCP)", OPTION_SECTION_DNS },
	{ "dns", 'u', "HOST[:PORT]", required_argument, "set the upstream DNS server (default port: 53)", OPTION_SECTION_DNS },
	{ "dsocks", 'x', "SPEC", required_argument, "SOCKS5 for DNS: [USER:PASSWORD@]HOST[:PORT]", OPTION_SECTION_DNS },
	{ "dtimeout", 't', "SECONDS", required_argument, "DNS upstream timeout (default: 5)", OPTION_SECTION_DNS },
	{ "snip", 'i', "IPv4", required_argument, "synthetic address for whitelisted DNS names", OPTION_SECTION_DNS },
	{ "dcache", 'e', "ENTRIES", required_argument, "DNS answer cache size, 0 disables (default: 2048)", OPTION_SECTION_DNS },
	{ "dttl", 'r', "SECONDS", required_argument, "TTL of synthetic DNS answers (default: 300)", OPTION_SECTION_DNS },
	{ "dacl", 'A', "CIDR[,CIDR...]", required_argument, "IPv4 networks allowed to query DNS", OPTION_SECTION_DNS },
	{ "drate", 'R', "QPS", required_argument, "per-source DNS query rate, 0 disables (default: 0)", OPTION_SECTION_DNS },

	{ "monitor", 'm', "[BIND-IP:]PORT", required_argument, "enable the HTTP monitor (default bind: 127.0.0.1)", OPTION_SECTION_MONITOR },
	{ "monitortoken", 'k', "TOKEN", required_argument, "require Bearer TOKEN for the monitor", OPTION_SECTION_MONITOR },
	{ "monitortimeout", 'a', "SECONDS", required_argument, "incomplete-header timeout, 1..60 (default: 5)", OPTION_SECTION_MONITOR },

	{ 0 }
};

static void print_option(const arg_option *option)
{
	printf("  -%c, --%-16s %-16s %s\n",
		option->key,
		option->name,
		option->arg,
		option->doc);
}

static void print_option_section(int section, const char *title)
{
	int arg_number = (int)(sizeof(options) / sizeof(arg_option));

	printf("%s:\n", title);
	for (int i = 0; i < arg_number - 1; i++)
	{
		if (options[i].section == section)
			print_option(&options[i]);
	}
}

void args_print_usage(void)
{
	printf("Usage: zroxy [OPTIONS]\n");
	printf("       zroxy --help\n\n");
	printf("zroxy v%s\n%s\n\n", version, doc);

	print_option_section(OPTION_SECTION_GENERAL, "General options");
	printf("\n");
	print_option_section(OPTION_SECTION_SNI, "SNI proxy options");
	printf("\n");
	print_option_section(OPTION_SECTION_DNS, "DNS proxy options");
	printf("\n");
	print_option_section(OPTION_SECTION_MONITOR, "Monitor options");

	printf("\nExamples:\n");
	printf("  zroxy -c ./zroxy.conf\n");
	printf("  zroxy -p 127.0.0.1:8443@443 -s 127.0.0.1:9050\n");
	printf("  zroxy -d 127.0.0.1:5353 -u 1.1.1.1 -i 192.0.2.10\n");

	printf("\nNotes:\n");
	printf("  With no options, zroxy loads ./zroxy.conf.\n");
	printf("  A configured service must start successfully; unconfigured services are skipped.\n");
}

bool args_init(zroxy_t *pgp,int argc, const char **argv)
{
	pgp->snitimeout = 30;
	pgp->monitor_header_timeout = 5;
	pgp->monitor_bind[0] = '\0';
	pgp->monitor_token = NULL;
	pgp->ports = NULL;
	pgp->socks = NULL;
	pgp->monitorPort = NULL;
	pgp->WhitePath = NULL;
	pgp->dnsserver = NULL;
	/*ran without parameter*/
	if(argc==1) 
	{
		return args_parse_config(pgp,DEF_CONFIG_PATH);
	}

	/*map arg_option to option*/
	int arg_number = sizeof(options)/sizeof(arg_option);
	struct option x_options[arg_number];
	bzero(x_options,sizeof(x_options));
	for(int i=0;i<arg_number;i++)
	{
		x_options[i].name = options[i].name;
		x_options[i].val = options[i].key;
		x_options[i].has_arg = options[i].require;
		x_options[i].flag = NULL;
	}	

	//make opt string
	char optstring[128] = {0};
	uint32_t index = 0;
	for(struct option *op=x_options;op->name!=NULL;op++)
	{
		optstring[index++]=(char)op->val;
		if(op->has_arg==required_argument)
			optstring[index++]=':';
		else if(op->has_arg==optional_argument)
			optstring[index++]=';';

		/*check Overflow*/
		if(index>=sizeof(optstring)-1)
			break;
	}	

	int option_index = 0;
	while(1)
	{
		int key = getopt_long(argc, (char **)argv, optstring, x_options, &option_index);
		if (key == -1)
            break;
		
		if(parse_opt(key, optarg, pgp)!=0)
		{
			log_error("error invalid option or value");
			return false;
		}
	}

    return true;
}

bool args_validate(zroxy_t *ptr)
{
	bool sni_ip_zero;

	if (!ptr || !ptr->dnsserver)
		return true;
	if (!ptr->dnsserver->listen_set)
	{
		log_error("DNS, SNIP, DSOCKS, DTIMEOUT and DACL need LDNS; add \"LDNS = 127.0.0.1:53\" for the previous behaviour");
		return false;
	}
	if (ptr->dnsserver->Remote.ip[0] == '\0')
	{
		log_error("LDNS needs an upstream DNS (DNS = HOST[:PORT])");
		return false;
	}
	sni_ip_zero = ptr->dnsserver->sni_ip[0] == 0 &&
		ptr->dnsserver->sni_ip[1] == 0 &&
		ptr->dnsserver->sni_ip[2] == 0 &&
		ptr->dnsserver->sni_ip[3] == 0;
	if (ptr->WhitePath && sni_ip_zero)
		log_info("whitelisted names will resolve to 0.0.0.0");
	return true;
}

static int parse_opt(int key, char *arg, void *userprm)
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
		case 'l': if (!parse_log_level(setting,arg)) return -1; break;
		case 'o': if (!parse_sni_timeout(setting,arg)) return -1; break;
		case 'h': args_print_usage(); exit(0);
		default: return -1;
    }
    return 0;
}

static char *ltrim(char *s)
{
    while(*s && isspace((unsigned char)*s)) s++;
    return s;
}

static char *rtrim(char *s)
{
    size_t n = strlen(s);
    while(n > 0 && isspace((unsigned char)s[n - 1]))
        n--;
    s[n] = '\0';
    return s;
}

static char *trim(char *s)
{
    return rtrim(ltrim(s)); 
}

static char* to_lower(char* s) 
{
  for(char *p=s; *p; p++) *p=(char)tolower((unsigned char)*p);
  return s;
}

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

static int config_find_key(char *key)
{
	for(arg_option *ptr=options;ptr->name!=NULL;ptr++)
	{
		if(strcmp(ptr->name,key)==0)
			return ptr->key;
	}
	return -1;
}

static bool config_key_chars(const char *key)
{
	const char *p;
	if (!key || key[0] == '\0')
		return false;
	for (p = key; *p; p++)
	{
		unsigned char c = (unsigned char)*p;
		if (!(isalpha(c) || c == '_' || c == ' '))
			return false;
	}
	return true;
}

bool args_parse_config(zroxy_t *ptr,char *str)
{
	FILE *ConfigFile;
	bool ret_status = true;
	size_t len = 0;
	char *line = NULL;
	ssize_t read;

	if (!str)
		return false;
	while(*str==' ') str++; /*remove space*/
	if (*str == '\0')
		return false;
	ConfigFile  = fopen(str, "r"); // read only
	if(ConfigFile==NULL)
	{
		log_error("config file not found");
		return false;
	}

	/*read and load config from file*/
	while ((read = getline(&line, &len, ConfigFile)) != -1)
	{
		char *eq;
		char *fix_key;
		char *fix_val;
		int ckey;

		if (read < 0 || (size_t)read > ZROXY_MAX_CONFIG_LINE)
		{
			log_error("config line too long");
			ret_status = false;
			break;
		}
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		fix_key = to_lower(trim(line));
		fix_val = trim(eq + 1);
		if (!config_key_chars(fix_key))
			continue;

		if (fix_val[0] == '\0' || strlen(fix_val) > ZROXY_MAX_CONFIG_VALUE)
		{
			log_error("error invalid value in config for key %s", fix_key);
			ret_status = false;
			break;
		}

		ckey = config_find_key(fix_key);
		if(ckey<0)
		{
			log_error("error invalid key in config: %s",fix_key);
			ret_status = false;
			break;
		}

		if(parse_opt(ckey, fix_val, ptr)!=0)
		{
			log_error("error invalid value in config for key %s", fix_key);
			ret_status = false;
			break;
		}
	}

	free(line);
	fclose(ConfigFile);
	return ret_status;
}

static bool parse_whitelist(zroxy_t *ptr,char *str)
{
	char *path;
	while(*str==' ') str++; /*remove space before path*/
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
	uint16_t *slot;

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
	slot = (uint16_t*)malloc(sizeof(uint16_t));
	if (!slot)
		return false;
	*slot = port;
	free(ptr->monitorPort);
	ptr->monitorPort = slot;
	memcpy(ptr->monitor_bind, bind, sizeof(bind));
	return true;
}

static bool parse_monitor_token(zroxy_t *ptr,char *str)
{
	char *token = dup_bounded(str, 256);
	if (!token)
		return false;
	free(ptr->monitor_token);
	ptr->monitor_token = token;
	return true;
}

static bool parse_monitor_timeout(zroxy_t *ptr,char *str)
{
	int timeout;
	if (!parse_i32_range(str, &timeout, 1, 60))
		return false;
	ptr->monitor_header_timeout = timeout;
	return true;
}

static bool parse_dns_timeout(zroxy_t *ptr,char *str)
{
	int timeout;
	dnshost_t *dns = dns_config(ptr);
	if (!dns)
		return false;
	if (!parse_i32_range(str, &timeout, 0, 86400))
		return false;
	dns->timeout = (uint32_t)timeout;
	return true;
}

static bool parse_dns_cache(zroxy_t *ptr,char *str)
{
	int entries;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !parse_i32_range(str, &entries, 0, 65536))
		return false;
	dns->cache_entries = (uint32_t)entries;
	return true;
}

static bool parse_dns_ttl(zroxy_t *ptr,char *str)
{
	int ttl;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !parse_i32_range(str, &ttl, 1, 86400))
		return false;
	dns->local_ttl = (uint32_t)ttl;
	return true;
}

static bool parse_dns_acl(zroxy_t *ptr,char *str)
{
	dns_cidr_t parsed[32];
	dns_cidr_t *copy;
	size_t count = 0;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !dns_acl_parse(str, parsed, sizeof(parsed) / sizeof(parsed[0]), &count))
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
	int qps;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !parse_i32_range(str, &qps, 0, 100000))
		return false;
	dns->rate_qps = (uint32_t)qps;
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

	while(*str==' ')
		str++;

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

static bool parse_dns_upstream(zroxy_t *ptr,char *str)
{
	char *endname;
	uint16_t port = 53;
	dnshost_t *dns = dns_config(ptr);

	if (!dns)
		return false;

	endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		if (!parse_u16(endname, &port, 1, 65535))
			return false;
	}
	if (!copy_bounded(dns->Remote.ip, sizeof(dns->Remote.ip), str))
		return false;
	dns->Remote.port = port;
	return true;
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
				free(pass);
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
			free(pass);
			return false;
		}
	}
	host = dup_bounded(hostpart, ZROXY_MAX_DNS_HOST);
	if (!host)
	{
		free(user);
		free(pass);
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

static bool parse_ports(zroxy_t *ptr,char *str)
{
	lport_t *perv = NULL;
	do{
		lport_t *port = (lport_t*)calloc(1, sizeof(lport_t));
		char *xptr = str;
		char *Iptr;
		char *Pptr;
		uint16_t local_port;
		uint16_t remote_port;

		if (!port)
			return false;
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
			if (strlen(xptr) >= sizeof(port->bindip) || !validate_ip(xptr) ||
			    !copy_bounded(port->bindip, sizeof(port->bindip), xptr))
			{
				log_error("invalid listener address");
				free(port);
				return false;
			}
			xptr = Iptr;
		}
		else if (!copy_bounded(port->bindip, sizeof(port->bindip), "0.0.0.0"))
		{
			free(port);
			return false;
		}

		Pptr = strchr(xptr,'@');
		if(Pptr)
		{
			*Pptr++=0;
			if (!parse_u16(xptr, &local_port, 0, 65535) ||
			    !parse_u16(Pptr, &remote_port, 0, 65535))
			{
				free(port);
				return false;
			}
		}
		else
		{
			if (!parse_u16(xptr, &local_port, 0, 65535))
			{
				free(port);
				return false;
			}
			remote_port = local_port;
		}

		port->local_port = local_port;
		port->remote_port = remote_port;
		port->next = perv;
		perv = port;
		ptr->ports = port;

	}while( str!=NULL );
	return true;
}

void args_free_ports(zroxy_t *ptr)
{
	lport_t *p=ptr->ports;
	while(p)
	{
		lport_t *next = p->next;
		free(p);
		p=next;
	}
	ptr->ports = NULL;
}

void args_free_dns(zroxy_t *ptr)
{
	if(ptr->dnsserver)
	{
		if(ptr->dnsserver->Socks)
		{
			free(ptr->dnsserver->Socks->host);
			free(ptr->dnsserver->Socks->user);
			free(ptr->dnsserver->Socks->pass);
			free(ptr->dnsserver->Socks);
		}
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
	int log_level;
	(void)ptr;
	if (!parse_i32_range(str, &log_level, 0, 5))
		return false;
	log_set_level(log_level);
	return true;
}

static bool parse_sni_timeout(zroxy_t *ptr,char *str)
{
	int timeout;
	if (!parse_i32_range(str, &timeout, 0, 86400))
		return false;
	ptr->snitimeout = timeout;
	return true;
}
