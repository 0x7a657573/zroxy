/*
 * args.c
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */
#include <zroxy/args.h>
#include <zroxy/dnscache.h>
#include <string.h>
#include <strings.h>
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <zroxy/config.h>

#define ARGS_MAX_IDENT 255
#define ARGS_MAX_TOKEN 256

/* Secret option values on the command line, wiped by args_scrub_argv. */
#define ARGS_MAX_ARGV_SECRETS 16
static struct { char *ptr; size_t len; } argv_secrets[ARGS_MAX_ARGV_SECRETS];
static size_t argv_secret_count;

static void free_secret(char *s)
{
	if (s)
		zroxy_wipe(s, strlen(s));
	free(s);
}

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
	free_secret(socks->pass);
	free(socks);
}

static const char doc[] = "SNI proxy with optional SOCKS5 upstream, DNS proxy, and HTTP monitor.";
static int parse_opt(int key, char *arg, void *userprm);

static bool parse_ports(zroxy_t *ptr,char *str);
static bool parse_socks(zroxy_t *ptr,char *str);
static bool parse_monitor(zroxy_t *ptr,char *str);
static bool parse_monitor_token(zroxy_t *ptr,char *str);
static bool parse_secret_path(char **slot,char *str);
static bool parse_monitor_timeout(zroxy_t *ptr,char *str);
static bool parse_whitelist(zroxy_t *ptr,char *str);
static bool parse_dns_server(zroxy_t *ptr,char *str);
static bool parse_dns_upstream(zroxy_t *ptr,char *str);
static char *find_dns_via(char *str);
static char *ltrim(char *s);
static bool parse_dns_socks(zroxy_t *ptr,char *str);
bool args_parse_config(zroxy_t *ptr,char *str);
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
static bool parse_bool(char *str, bool *out);

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
	{ "user", 'U', "NAME", required_argument, "after binding the ports, run as NAME (needs root at start)", OPTION_SECTION_GENERAL },
	{ "group", 'G', "NAME", required_argument, "group to run as with USER (default: the user's primary group)", OPTION_SECTION_GENERAL },

	{ "port", 'p', "SPEC", required_argument, "SNI listener(s): [BIND-IP:]PORT[@REMOTE-PORT][,...]; repeat to add more", OPTION_SECTION_SNI },
	{ "socks", 's', "SPEC", required_argument, "SOCKS5 upstream: [USER:PASSWORD@]HOST[:PORT]", OPTION_SECTION_SNI },
	{ "sockspassfile", 'S', "PATH", required_argument, "read the SOCKS5 password from the first line of PATH (spec: USER@HOST[:PORT])", OPTION_SECTION_SNI },
	{ "snitimeout", 'o', "SECONDS", required_argument, "SNI socket timeout (default: 30)", OPTION_SECTION_SNI },
	{ "sniidletimeout", 'I', "SECONDS", required_argument, "close a relay idle this long, 1..86400 (default: 300)", OPTION_SECTION_SNI },
	{ "allowloopback", 'L', "yes|no", required_argument, "let client-supplied names reach loopback upstreams (default: no)", OPTION_SECTION_SNI },
	{ "denyprivate", 'P', "yes|no", required_argument, "refuse client-supplied names that resolve to private addresses (default: no)", OPTION_SECTION_SNI },
	{ "white", 'w', "PATH", required_argument, "whitelist host names from PATH", OPTION_SECTION_SNI },
	{ "openproxy", 'O', "yes|no", required_argument, "allow SNI listeners to forward every host name when no whitelist is set (default: no)", OPTION_SECTION_SNI },

	{ "ldns", 'd', "BIND-IP[:PORT]", required_argument, "enable the local DNS listener (UDP and TCP)", OPTION_SECTION_DNS },
	{ "dns", 'u', "SPEC", required_argument, "upstream DNS route: HOST[:PORT] [via SOCKS-SPEC|direct] (default port: 53); repeat for up to 4 routes", OPTION_SECTION_DNS },
	{ "dsocks", 'x', "SPEC", required_argument, "SOCKS5 for DNS routes without via/direct: [USER:PASSWORD@]HOST[:PORT]", OPTION_SECTION_DNS },
	{ "dsockspassfile", 'X', "PATH", required_argument, "read the DNS SOCKS5 password from the first line of PATH", OPTION_SECTION_DNS },
	{ "dtimeout", 't', "SECONDS", required_argument, "DNS upstream timeout (default: 5)", OPTION_SECTION_DNS },
	{ "snip", 'i', "IPv4", required_argument, "synthetic address for whitelisted DNS names", OPTION_SECTION_DNS },
	{ "dcache", 'e', "ENTRIES", required_argument, "DNS answer cache size, 0 disables (default: 2048)", OPTION_SECTION_DNS },
	{ "dttl", 'r', "SECONDS", required_argument, "TTL of synthetic DNS answers (default: 300)", OPTION_SECTION_DNS },
	{ "dacl", 'A', "CIDR[,CIDR...]", required_argument, "IPv4 networks allowed to query DNS", OPTION_SECTION_DNS },
	{ "drate", 'R', "QPS", required_argument, "per-source DNS query rate, 0 disables (default: 0)", OPTION_SECTION_DNS },
	{ "dnsconnections", 'C', "COUNT", required_argument, "maximum concurrent DNS upstream TCP connections, 1..96 (default: 96)", OPTION_SECTION_DNS },

	{ "monitor", 'm', "[BIND-IP:]PORT", required_argument, "enable the HTTP monitor (default bind: 127.0.0.1)", OPTION_SECTION_MONITOR },
	{ "monitortoken", 'k', "TOKEN", required_argument, "require Bearer TOKEN for the monitor", OPTION_SECTION_MONITOR },
	{ "monitortokenfile", 'K', "PATH", required_argument, "read the monitor Bearer token from the first line of PATH", OPTION_SECTION_MONITOR },
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

/* True when a SOCKS spec carries a password: a ':' before the first '@'. */
static bool socks_spec_has_pass(const char *spec)
{
	const char *at = spec ? strchr(spec, '@') : NULL;
	const char *colon;
	if (!at)
		return false;
	colon = memchr(spec, ':', (size_t)(at - spec));
	return colon != NULL;
}

/* True when a DNS= / -u value has a "via" SOCKS spec that carries a password. */
static bool dns_route_has_pass(char *value)
{
	char *via = find_dns_via(value);
	return via && socks_spec_has_pass(ltrim(via + 3));
}

/*
 * A secret given on the command line is visible to every local user in
 * /proc/PID/cmdline until args_scrub_argv runs. Warn and remember where
 * the bytes are; the string is not touched here because tests and other
 * callers may pass read-only arguments.
 */
static void note_cli_secret(int key, char *arg)
{
	if (!arg || arg[0] == '\0')
		return;
	if (key == 'u' ? !dns_route_has_pass(arg) :
	    (key != 'k' && !socks_spec_has_pass(arg)))
		return;
	if (key == 'k')
		log_warn("monitor token on the command line is visible to other local users; use MONITORTOKENFILE (--monitortokenfile)");
	else if (key == 's')
		log_warn("SOCKS password on the command line is visible to other local users; use SOCKSPASSFILE (--sockspassfile)");
	else
		log_warn("DNS SOCKS password on the command line is visible to other local users; use DSOCKSPASSFILE (--dsockspassfile)");
	if (argv_secret_count < ARGS_MAX_ARGV_SECRETS)
	{
		argv_secrets[argv_secret_count].ptr = arg;
		argv_secrets[argv_secret_count].len = strlen(arg);
		argv_secret_count++;
	}
}

/*
 * Best effort: overwrite the secret option values that args_init saw on
 * the command line, so /proc/PID/cmdline and ps stop showing them. Call it
 * from main with the real argv, after args_init. Everything the parser
 * keeps was copied already. A SOCKS spec is cleared whole, host included.
 */
void args_scrub_argv(void)
{
	for (size_t i = 0; i < argv_secret_count; i++)
		zroxy_wipe(argv_secrets[i].ptr, argv_secrets[i].len);
	argv_secret_count = 0;
}

/* Warn about loose permissions on an open file that holds a secret. */
static void warn_secret_mode(const struct stat *st, const char *path, const char *what)
{
	if (st->st_mode & 077)
		log_warn("%s %s is accessible by group or others (mode %04o); chmod 600 it", what, path, (unsigned)(st->st_mode & 07777));
}

/*
 * Read the first line of a secret file: trailing CR/LF stripped, never
 * empty, at most maxlen bytes. The permission check uses the open
 * descriptor. Returns a malloc'd string or NULL (error already logged).
 */
static char *read_secret_file(const char *path, size_t maxlen, const char *what)
{
	char buf[ARGS_MAX_TOKEN + 3];
	size_t cap = maxlen + 2;
	size_t n = 0;
	size_t len;
	struct stat st;
	char *out = NULL;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);

	if (fd < 0)
	{
		log_error("cannot open %s file %s", what, path);
		return NULL;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
	{
		log_error("%s file %s is not a regular file", what, path);
		goto done;
	}
	if (st.st_mode & S_IWOTH)
	{
		log_error("%s file %s is world-writable (mode %04o); refusing it", what, path, (unsigned)(st.st_mode & 07777));
		goto done;
	}
	warn_secret_mode(&st, path, what);
	while (n < cap)
	{
		ssize_t r = read(fd, buf + n, cap - n);
		if (r < 0)
		{
			if (errno == EINTR)
				continue;
			log_error("cannot read %s file %s", what, path);
			goto done;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	len = n;
	for (size_t i = 0; i < n; i++)
	{
		if (buf[i] == '\n')
		{
			len = i;
			break;
		}
	}
	while (len > 0 && buf[len - 1] == '\r')
		len--;
	if (len == 0)
	{
		log_error("%s file %s is empty", what, path);
		goto done;
	}
	if (len > maxlen || memchr(buf, '\0', len))
	{
		log_error("%s file %s has an invalid or too long first line (max %zu)", what, path, maxlen);
		goto done;
	}
	out = malloc(len + 1);
	if (out)
	{
		memcpy(out, buf, len);
		out[len] = '\0';
	}
done:
	zroxy_wipe(buf, sizeof(buf));
	close(fd);
	return out;
}

static bool load_socks_pass_file(sockshost_t *socks, char **path, const char *what)
{
	bool ok = false;
	if (!*path)
		return true;
	if (!socks)
		log_error("%s file is set but there is no matching SOCKS server", what);
	else if (!socks->user)
		log_error("%s file needs a user in the SOCKS spec (USER@HOST[:PORT])", what);
	else if (socks->pass)
		log_error("%s is set both inline and as a file; use one", what);
	else
	{
		socks->pass = read_secret_file(*path, ARGS_MAX_IDENT, what);
		ok = socks->pass != NULL;
	}
	free(*path);
	*path = NULL;
	return ok;
}

static bool load_secret_files(zroxy_t *ptr)
{
	bool ok = true;
	if (!load_socks_pass_file(ptr->socks, &ptr->socks_pass_file, "SOCKS password"))
		ok = false;
	if (!load_socks_pass_file(ptr->dnsserver ? ptr->dnsserver->Socks : NULL, &ptr->dsocks_pass_file, "DNS SOCKS password"))
		ok = false;
	if (ptr->monitor_token_file)
	{
		if (ptr->monitor_token)
		{
			log_error("monitor token is set both inline and as a file; use one");
			ok = false;
		}
		else
		{
			ptr->monitor_token = read_secret_file(ptr->monitor_token_file, ARGS_MAX_TOKEN, "monitor token");
			if (!ptr->monitor_token)
				ok = false;
		}
		free(ptr->monitor_token_file);
		ptr->monitor_token_file = NULL;
	}
	return ok;
}

/*
 * The config files being read, outermost first: a file that names itself or
 * an ancestor, or a chain deeper than ARGS_MAX_CONFIG_DEPTH, would recurse
 * until the stack ran out. Files are told apart by device and inode of the
 * descriptor that was opened, so a symlink or another path to the same file
 * is caught too. Parsing is single threaded and finishes before any worker
 * starts.
 */
#define ARGS_MAX_CONFIG_DEPTH 8

static struct
{
	dev_t dev;
	ino_t ino;
} config_chain[ARGS_MAX_CONFIG_DEPTH];
static unsigned config_depth;

bool args_init(zroxy_t *pgp,int argc, const char **argv)
{
	pgp->snitimeout = 30;
	pgp->sniidletimeout = 300;
	pgp->allow_loopback = false;
	pgp->deny_private = false;
	pgp->open_proxy = false;
	pgp->run_user = NULL;
	pgp->run_group = NULL;
	pgp->drop_priv = false;
	pgp->drop_uid = 0;
	pgp->drop_gid = 0;
	pgp->monitor_header_timeout = 5;
	pgp->monitor_bind[0] = '\0';
	argv_secret_count = 0;
	config_depth = 0;
	pgp->monitor_token = NULL;
	pgp->monitor_token_file = NULL;
	pgp->socks_pass_file = NULL;
	pgp->dsocks_pass_file = NULL;
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

		if (key == 's' || key == 'x' || key == 'k' || key == 'u')
			note_cli_secret(key, optarg);
		if(parse_opt(key, optarg, pgp)!=0)
		{
			log_error("error invalid option or value");
			return false;
		}
	}

    return true;
}

/*
 * Look the run-as user and group up now, before any thread exists, so
 * NSS is never entered from a threaded process and a bad name stops
 * startup. Nothing changes here; main drops privileges once the sockets
 * are bound.
 */
static bool resolve_run_identity(zroxy_t *ptr)
{
	struct passwd pw;
	struct passwd *res = NULL;
	char buf[4096];
	uid_t uid;
	gid_t gid;
	int rc;

	ptr->drop_priv = false;
	if (!ptr->run_user)
	{
		if (ptr->run_group)
		{
			log_error("GROUP needs USER");
			return false;
		}
		if (geteuid() == 0)
			log_warn("running as root; set USER (--user) to drop privileges after the ports are bound");
		return true;
	}

	rc = getpwnam_r(ptr->run_user, &pw, buf, sizeof(buf), &res);
	if (rc != 0 || !res)
	{
		log_error("USER %s: %s", ptr->run_user, rc != 0 ? strerror(rc) : "no such user");
		return false;
	}
	uid = res->pw_uid;
	gid = res->pw_gid;
	if (ptr->run_group)
	{
		struct group gr;
		struct group *gres = NULL;
		char gbuf[4096];

		rc = getgrnam_r(ptr->run_group, &gr, gbuf, sizeof(gbuf), &gres);
		if (rc != 0 || !gres)
		{
			log_error("GROUP %s: %s", ptr->run_group, rc != 0 ? strerror(rc) : "no such group");
			return false;
		}
		gid = gres->gr_gid;
	}

	if (geteuid() != 0)
	{
		/* only root can change identity; the same one is a harmless no-op */
		if (uid != geteuid() || (ptr->run_group && gid != getegid()))
		{
			log_error("USER %s needs zroxy to start as root, but it runs as uid %lu",
				ptr->run_user, (unsigned long)geteuid());
			return false;
		}
		return true;
	}
	if (uid == 0)
	{
		log_warn("USER %s is root; privileges are not dropped", ptr->run_user);
		return true;
	}
	ptr->drop_priv = true;
	ptr->drop_uid = uid;
	ptr->drop_gid = gid;
	return true;
}

bool args_validate(zroxy_t *ptr)
{
	bool sni_ip_zero;

	if (!ptr)
		return true;
	if (!load_secret_files(ptr))
		return false;
	if (!resolve_run_identity(ptr))
		return false;
	if (ptr->ports && !ptr->WhitePath)
	{
		if (!ptr->open_proxy)
		{
			log_error("SNI listeners without a whitelist would forward every host name; set a whitelist (WHITE = PATH) or OPENPROXY = yes");
			return false;
		}
		log_warn("OPENPROXY is on and no whitelist is set: every host name is forwarded");
	}
	if (!ptr->dnsserver)
		return true;
	if (!ptr->dnsserver->listen_set)
	{
		log_error("DNS, SNIP, DSOCKS, DTIMEOUT and DACL need LDNS; add \"LDNS = 127.0.0.1:53\" for the previous behaviour");
		return false;
	}
	if (ptr->dnsserver->route_count == 0)
	{
		log_error("LDNS needs an upstream DNS (DNS = HOST[:PORT])");
		return false;
	}
	sni_ip_zero = ptr->dnsserver->sni_ip[0] == 0 &&
		ptr->dnsserver->sni_ip[1] == 0 &&
		ptr->dnsserver->sni_ip[2] == 0 &&
		ptr->dnsserver->sni_ip[3] == 0;
	if (ptr->WhitePath && sni_ip_zero)
		log_warn("whitelisted names will resolve to 0.0.0.0");
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
	struct stat st;
	int cfd;
	unsigned i;
	bool ret_status = true;
	bool secret_seen = false;
	size_t len = 0;
	char *line = NULL;
	ssize_t read;

	if (!str)
		return false;
	while(*str==' ') str++; /*remove space*/
	if (*str == '\0')
		return false;
	cfd = open(str, O_RDONLY | O_CLOEXEC);
	ConfigFile = cfd >= 0 ? fdopen(cfd, "r") : NULL;
	if(ConfigFile==NULL)
	{
		if (cfd >= 0)
			close(cfd);
		log_error("config file not found");
		return false;
	}
	if (fstat(cfd, &st) != 0)
	{
		log_error("config file not readable");
		fclose(ConfigFile);
		return false;
	}
	if (config_depth >= ARGS_MAX_CONFIG_DEPTH)
	{
		log_error("config files nested more than %d deep", ARGS_MAX_CONFIG_DEPTH);
		fclose(ConfigFile);
		return false;
	}
	for (i = 0; i < config_depth; i++)
	{
		if (config_chain[i].dev == st.st_dev && config_chain[i].ino == st.st_ino)
		{
			log_error("config file includes itself: %s", str);
			fclose(ConfigFile);
			return false;
		}
	}
	config_chain[config_depth].dev = st.st_dev;
	config_chain[config_depth].ino = st.st_ino;
	config_depth++;

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

		if (!secret_seen && (ckey == 'k' ||
		    ((ckey == 's' || ckey == 'x') && socks_spec_has_pass(fix_val)) ||
		    (ckey == 'u' && dns_route_has_pass(fix_val))))
		{
			secret_seen = true;
			if (fstat(cfd, &st) == 0)
				warn_secret_mode(&st, str, "config file with a secret:");
		}

		if(parse_opt(ckey, fix_val, ptr)!=0)
		{
			log_error("error invalid value in config for key %s", fix_key);
			ret_status = false;
			break;
		}
	}

	if (line)
		zroxy_wipe(line, len);
	free(line);
	fclose(ConfigFile);
	config_depth--;
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
	char *token = dup_bounded(str, ARGS_MAX_TOKEN);
	if (!token)
		return false;
	free_secret(ptr->monitor_token);
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

static bool parse_dns_connections(zroxy_t *ptr,char *str)
{
	int count;
	dnshost_t *dns = dns_config(ptr);
	if (!dns || !parse_i32_range(str, &count, 1, DNS_UPSTREAM_CONNECTIONS_DEFAULT))
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

/*
 * "HOST[:PORT] via SPEC": the start of the "via" word after the upstream,
 * or NULL. "via" is a whole whitespace-separated word, so it cannot be cut
 * out of a host name.
 */
static char *find_dns_via(char *str)
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

	via = find_dns_via(str);
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
		char *spec = trim(via + 3);
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
				free_secret(pass);
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
			free_secret(pass);
			return false;
		}
	}
	host = dup_bounded(hostpart, ZROXY_MAX_DNS_HOST);
	if (!host)
	{
		free(user);
		free_secret(pass);
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

	do{
		lport_t *port = (lport_t*)calloc(1, sizeof(lport_t));
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
			if (strlen(xptr) >= sizeof(port->bindip) || !validate_ip(xptr) ||
			    !copy_bounded(port->bindip, sizeof(port->bindip), xptr))
			{
				log_error("invalid listener address");
				free(port);
				goto fail;
			}
			xptr = Iptr;
		}
		else if (!copy_bounded(port->bindip, sizeof(port->bindip), "0.0.0.0"))
		{
			free(port);
			goto fail;
		}

		Pptr = strchr(xptr,'@');
		if(Pptr)
		{
			*Pptr++=0;
			if (!parse_u16(xptr, &local_port, 0, 65535) ||
			    !parse_u16(Pptr, &remote_port, 0, 65535))
			{
				free(port);
				goto fail;
			}
		}
		else
		{
			if (!parse_u16(xptr, &local_port, 0, 65535))
			{
				free(port);
				goto fail;
			}
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
			free(port);
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
	free_port_list(head);
	return false;
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

void args_free_socks(zroxy_t *ptr)
{
	free_sockshost(ptr->socks);
	ptr->socks = NULL;
}

void args_free_monitor_token(zroxy_t *ptr)
{
	free_secret(ptr->monitor_token);
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

static bool parse_sni_idle_timeout(zroxy_t *ptr,char *str)
{
	int timeout;
	if (!parse_i32_range(str, &timeout, 1, 86400))
		return false;
	ptr->sniidletimeout = timeout;
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
