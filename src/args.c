/*
 * args.c
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */
#include "args.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "version.h"
#include <stdbool.h>
//#include <argp.h>
#include <log.h>
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

static char doc[] = "zroxy v"version "\n\tsimple sni and dns proxy.";
static int parse_opt(int key, char *arg, void *userprm);

bool Parse_Ports(zroxy_t *ptr,char *str);
bool Parse_Socks(zroxy_t *ptr,char *str);
bool Parse_Monit(zroxy_t *ptr,char *str);
bool Parse_monitor_token(zroxy_t *ptr,char *str);
bool Parse_monitor_timeout(zroxy_t *ptr,char *str);
bool Parse_whitelist(zroxy_t *ptr,char *str);
bool Parse_DNSServer(zroxy_t *ptr,char *str);
bool Parse_DnsUpstream(zroxy_t *ptr,char *str);
bool Parse_DnsSocks(zroxy_t *ptr,char *str);
bool Parse_config(zroxy_t *ptr,char *str);
bool Parse_Snip(zroxy_t *ptr,char *str);
bool Parse_DNStimeout(zroxy_t *ptr,char *str);
bool Parse_loglevel(zroxy_t *ptr,char *str);
bool Parse_snitimeout(zroxy_t *ptr,char *str);

typedef struct 
{
	const char *name;
	char 		key;
	const char  *arg;
	int			require;
	const char *doc;
}arg_option;


static arg_option options[] =
{
	{ "config", 'c' , "path to config" , required_argument, "path to config. -c /etc/zroxy.conf"},
    { "port", 'p', "sni port", required_argument, "sni port that listens.\n\t\t\t\t\t\t<bind ip>:<local port>@<remote port>\n\t\t\t\t\t\t -p 127.0.0.1:8080@80,4433@433,853..."},
	{ "socks", 's', "socks proxy", required_argument, "set proxy for up stream. -s 127.0.0.1:9050"},
	{ "monitor", 'm', "monitor port", required_argument, "monitor port that listens. -m 1234 or -m 127.0.0.1:1234"},
	{ "monitortoken", 'k', "monitor token", required_argument, "bearer token for the monitor. -k secret"},
	{ "monitortimeout", 'a', "monitor header timeout", required_argument, "incomplete header timeout in sec. -a 5"},
	{ "snitimeout", 'o', "set sni timeout", required_argument, "set sni timeout in sec. -o 30"},
	{ "white", 'w' , "white list" , required_argument, "white list for host -w /etc/whitelist.txt"},
	{ "ldns", 'd' , "local DNS server" , required_argument, "dns server that listens. -d 0.0.0.0:53"},
	{ "dns", 'u' , "upstream DNS providers" , required_argument, "upstream DNS providers. -u 8.8.8.8"},
	{ "dsocks", 'x' , "DNS upstream socks" , required_argument, "DNS upstream socks. -x 127.0.0.1:9050"},
	{ "dtimeout", 't' , "DNS timeout in sec" , required_argument, "DNS upstream timeout. -t 5"},
	{ "snip", 'i' , "SNI IP for DNS server" , required_argument, "SNI IP for DNS server. -i 127.0.0.1"},
	{ "log", 'l' , "set log level" , required_argument, "set log level between 0 to 5. -l 2"},
	{ "help", 'h' , "Give this help list" , no_argument, ""},
    { 0 }
};

void print_usage(void)
{
	
	printf("\r\nUsage: zroxy [OPTION...]\r\n");
	printf("\t%s\r\n\r\n",doc);

	int arg_number = sizeof(options)/sizeof(arg_option);
	for(int i=0;i<arg_number-1;i++)
	{
		printf("\t-%c, '%s'\t%s\t\t%s\r\n",
			options[i].key,
			options[i].name,
			options[i].arg,
			options[i].doc
		);
	}
	printf("\r\n");
}

bool arg_Init(zroxy_t *pgp,int argc, const char **argv)
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
		return Parse_config(pgp,DEF_CONFIG_PATH);
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
		optstring[index++]=op->val;
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
		case 'c': if (!Parse_config(setting,arg)) return -1; break;
		case 'p': if (!Parse_Ports(setting,arg)) return -1; break;
		case 's': if (!Parse_Socks(setting,arg)) return -1; break;
		case 'm': if (!Parse_Monit(setting,arg)) return -1; break;
		case 'k': if (!Parse_monitor_token(setting,arg)) return -1; break;
		case 'a': if (!Parse_monitor_timeout(setting,arg)) return -1; break;
		case 'w': if (!Parse_whitelist(setting,arg)) return -1; break;
		case 'd': if (!Parse_DNSServer(setting,arg)) return -1; break;
		case 'u': if (!Parse_DnsUpstream(setting,arg)) return -1; break;
		case 'x': if (!Parse_DnsSocks(setting,arg)) return -1; break;
		case 'i': if (!Parse_Snip(setting,arg)) return -1; break;
		case 't': if (!Parse_DNStimeout(setting,arg)) return -1; break;
		case 'l': if (!Parse_loglevel(setting,arg)) return -1; break;
		case 'o': if (!Parse_snitimeout(setting,arg)) return -1; break;
		case 'h': print_usage(); exit(0);
		default: return -1;
    }
    return 0;
}

char *ltrim(char *s)
{
    while(*s && isspace((unsigned char)*s)) s++;
    return s;
}

char *rtrim(char *s)
{
    size_t n = strlen(s);
    while(n > 0 && isspace((unsigned char)s[n - 1]))
        n--;
    s[n] = '\0';
    return s;
}

char *trim(char *s)
{
    return rtrim(ltrim(s)); 
}

char* toLower(char* s) 
{
  for(char *p=s; *p; p++) *p=(char)tolower((unsigned char)*p);
  return s;
}

bool validate_ip(char *ip)
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

int config_find_key(char *key)
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

bool Parse_config(zroxy_t *ptr,char *str)
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

		if (read < 0 || (size_t)read > _MaxConfigLine_)
		{
			log_error("config line too long");
			ret_status = false;
			break;
		}
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		fix_key = toLower(trim(line));
		fix_val = trim(eq + 1);
		if (!config_key_chars(fix_key))
			continue;

		if (fix_val[0] == '\0' || strlen(fix_val) > _MaxConfigValue_)
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

bool Parse_whitelist(zroxy_t *ptr,char *str)
{
	char *path;
	while(*str==' ') str++; /*remove space before path*/
	path = dup_bounded(str, _MaxConfigValue_);
	if (!path)
		return false;
	free(ptr->WhitePath);
	ptr->WhitePath = path;
	return true;
}

bool Parse_Monit(zroxy_t *ptr,char *str)
{
	char *colon;
	char *port_str = str;
	char bind[_MaxIPAddress_];
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

bool Parse_monitor_token(zroxy_t *ptr,char *str)
{
	char *token = dup_bounded(str, 256);
	if (!token)
		return false;
	free(ptr->monitor_token);
	ptr->monitor_token = token;
	return true;
}

bool Parse_monitor_timeout(zroxy_t *ptr,char *str)
{
	int timeout;
	if (!parse_i32_range(str, &timeout, 1, 60))
		return false;
	ptr->monitor_header_timeout = timeout;
	return true;
}

bool Parse_DNStimeout(zroxy_t *ptr,char *str)
{
	int timeout;
	if(!ptr->dnsserver)
	{
		log_error("before set dns timeout enable dns server!");
		return false;
	}
	if (!parse_i32_range(str, &timeout, 0, 86400))
		return false;
	ptr->dnsserver->timeout = (uint32_t)timeout;
	return true;
}

bool Parse_DNSServer(zroxy_t *ptr,char *str)
{
	char *endname;
	uint16_t port = 53;

	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)calloc(1, sizeof(dnshost_t));
		if (!ptr->dnsserver)
			return false;
	}

	ptr->dnsserver->Local.port	= 53;
	ptr->dnsserver->timeout		= 5;
	memset(ptr->dnsserver->Local.ip, 0, sizeof(ptr->dnsserver->Local.ip));
	memcpy(ptr->dnsserver->Local.ip, "127.0.0.1", sizeof("127.0.0.1"));

	endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		if (!parse_u16(endname, &port, 0, 65535))
			return false;
		ptr->dnsserver->Local.port = port;
	}
	if (!validate_ip(str) || !copy_bounded(ptr->dnsserver->Local.ip, sizeof(ptr->dnsserver->Local.ip), str))
	{
		log_error("invalid local DNS address");
		return false;
	}
	return true;
}

bool Parse_Snip(zroxy_t *ptr,char *str)
{
	unsigned int si[4];
	char tail = '\0';
	uint8_t *sni_ip;

	while(*str==' ')
		str++;

	/*check dns config is exisit*/
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)calloc(1, sizeof(dnshost_t));
		if (!ptr->dnsserver)
			return false;
		ptr->dnsserver->Local.port = 53;
		memcpy(ptr->dnsserver->Local.ip, "127.0.0.1", sizeof("127.0.0.1"));
	}

	if (sscanf(str, "%u.%u.%u.%u%c", &si[0], &si[1], &si[2], &si[3], &tail) != 4)
		return false;
	if (si[0] > 255 || si[1] > 255 || si[2] > 255 || si[3] > 255)
		return false;

	sni_ip = ptr->dnsserver->sni_ip;
	sni_ip[0] = (uint8_t)si[0];
	sni_ip[1] = (uint8_t)si[1];
	sni_ip[2] = (uint8_t)si[2];
	sni_ip[3] = (uint8_t)si[3];
	return true;
}

bool Parse_DnsUpstream(zroxy_t *ptr,char *str)
{
	char *endname;
	uint16_t port = 53;

	/*check dns config is exisit*/
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)calloc(1, sizeof(dnshost_t));
		if (!ptr->dnsserver)
			return false;
		ptr->dnsserver->Local.port = 53;
		memcpy(ptr->dnsserver->Local.ip, "127.0.0.1", sizeof("127.0.0.1"));
	}

	endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		if (!parse_u16(endname, &port, 1, 65535))
			return false;
	}
	if (!copy_bounded(ptr->dnsserver->Remote.ip, sizeof(ptr->dnsserver->Remote.ip), str))
		return false;
	ptr->dnsserver->Remote.port = port;
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
	host = dup_bounded(hostpart, _MaxDNSHost_);
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

bool Parse_Socks(zroxy_t *ptr,char *str)
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

bool Parse_Ports(zroxy_t *ptr,char *str)
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

void Free_PortList(zroxy_t *ptr)
{
	lport_t *p=ptr->ports;
	while(p)
	{
		lport_t *next = p->next;
		free(p);
		p=next;
	}
}

void Free_DnsServer(zroxy_t *ptr)
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
		free(ptr->dnsserver);
	}
}

bool Parse_DnsSocks(zroxy_t *ptr,char *str)
{
	sockshost_t *socks;
	if (!ptr->dnsserver)
	{
		log_error("DNS SOCKS set before DNS server");
		return false;
	}
	socks = (sockshost_t*)calloc(1, sizeof(sockshost_t));
	if (!socks)
		return false;
	if (!fill_sockshost(socks, str))
	{
		free_sockshost(socks);
		return false;
	}
	free_sockshost(ptr->dnsserver->Socks);
	ptr->dnsserver->Socks = socks;
	return true;
}

bool Parse_loglevel(zroxy_t *ptr,char *str)
{
	int log_level;
	(void)ptr;
	if (!parse_i32_range(str, &log_level, 0, 5))
		return false;
	log_set_level(log_level);
	return true;
}

bool Parse_snitimeout(zroxy_t *ptr,char *str)
{
	int timeout;
	if (!parse_i32_range(str, &timeout, 0, 86400))
		return false;
	ptr->snitimeout = timeout;
	return true;
}
