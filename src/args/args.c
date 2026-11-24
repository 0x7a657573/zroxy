/*
 * args.c
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */
#include <zroxy/args.h>
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <zroxy/config.h>
#include "args_internal.h"

static const char doc[] = "SNI proxy with optional SOCKS5 upstream, DNS proxy, and HTTP monitor.";

void args_free(zroxy_t *ptr)
{
	args_free_ports(ptr);
	args_free_dns(ptr);
	args_free_socks(ptr);
	args_free_sacl(ptr);
	args_free_monitor_token(ptr);
	free(ptr->whitelist_path);
	ptr->whitelist_path = NULL;
	free(ptr->monitor_token_file);
	ptr->monitor_token_file = NULL;
	free(ptr->socks_pass_file);
	ptr->socks_pass_file = NULL;
	free(ptr->dsocks_pass_file);
	ptr->dsocks_pass_file = NULL;
	free(ptr->run_user);
	ptr->run_user = NULL;
	free(ptr->run_group);
	ptr->run_group = NULL;
}

typedef struct
{
	const char *name;
	char key;
	const char *arg;
	int require;
	const char *doc;
	int section;
} arg_option;

enum
{
	OPTION_SECTION_GENERAL,
	OPTION_SECTION_SNI,
	OPTION_SECTION_DNS,
	OPTION_SECTION_MONITOR
};

static arg_option options[] =
        {
                {"config", 'c', "PATH", required_argument, "load configuration from PATH", OPTION_SECTION_GENERAL},
                {"log", 'l', "0..5", required_argument, "set log level (0=trace, 5=fatal)", OPTION_SECTION_GENERAL},
                {"help", 'h', "", no_argument, "show this help and exit", OPTION_SECTION_GENERAL},
                {"user", 'U', "NAME", required_argument, "after binding the ports, run as NAME (needs root at start)", OPTION_SECTION_GENERAL},
                {"group", 'G', "NAME", required_argument, "group to run as with USER (default: the user's primary group)", OPTION_SECTION_GENERAL},

                {"port", 'p', "SPEC", required_argument, "SNI listener(s): [BIND-IP:]PORT[@REMOTE-PORT][,...]; repeat to add more", OPTION_SECTION_SNI},
                {"socks", 's', "SPEC", required_argument, "SOCKS5 upstream: [USER:PASSWORD@]HOST[:PORT]", OPTION_SECTION_SNI},
                {"sockspassfile", 'S', "PATH", required_argument, "read the SOCKS5 password from the first line of PATH (spec: USER@HOST[:PORT])", OPTION_SECTION_SNI},
                {"snitimeout", 'o', "SECONDS", required_argument, "SNI socket timeout (default: 30)", OPTION_SECTION_SNI},
                {"sniidletimeout", 'I', "SECONDS", required_argument, "close a relay idle this long, 1..86400 (default: 300)", OPTION_SECTION_SNI},
                {"snimaxconn", 'n', "COUNT", required_argument, "maximum concurrent SNI connections, 1..65535 (default: 1024)", OPTION_SECTION_SNI},
                {"sacl", 'N', "CIDR[,CIDR...]", required_argument, "IPv4 networks allowed to use the SNI listeners (default: all)", OPTION_SECTION_SNI},
                {"allowloopback", 'L', "yes|no", required_argument, "let client-supplied names reach loopback upstreams (default: no)", OPTION_SECTION_SNI},
                {"denyprivate", 'P', "yes|no", required_argument, "refuse client-supplied names that resolve to private addresses (default: no)", OPTION_SECTION_SNI},
                {"white", 'w', "PATH", required_argument, "whitelist host names from PATH", OPTION_SECTION_SNI},
                {"openproxy", 'O', "yes|no", required_argument, "allow SNI listeners to forward every host name when no whitelist is set (default: no)", OPTION_SECTION_SNI},

                {"ldns", 'd', "BIND-IP[:PORT]", required_argument, "enable the local DNS listener (UDP and TCP)", OPTION_SECTION_DNS},
                {"dns", 'u', "SPEC", required_argument, "upstream DNS route: HOST[:PORT] [via SOCKS-SPEC|direct] (default port: 53); repeat for up to 4 routes", OPTION_SECTION_DNS},
                {"dsocks", 'x', "SPEC", required_argument, "SOCKS5 for DNS routes without via/direct: [USER:PASSWORD@]HOST[:PORT]", OPTION_SECTION_DNS},
                {"dsockspassfile", 'X', "PATH", required_argument, "read the DNS SOCKS5 password from the first line of PATH", OPTION_SECTION_DNS},
                {"dtimeout", 't', "SECONDS", required_argument, "DNS upstream timeout (default: 5)", OPTION_SECTION_DNS},
                {"snip", 'i', "IPv4", required_argument, "synthetic address for whitelisted DNS names", OPTION_SECTION_DNS},
                {"dcache", 'e', "ENTRIES", required_argument, "DNS answer cache size, 0 disables (default: 2048)", OPTION_SECTION_DNS},
                {"dttl", 'r', "SECONDS", required_argument, "TTL of synthetic DNS answers (default: 300)", OPTION_SECTION_DNS},
                {"dacl", 'A', "CIDR[,CIDR...]", required_argument, "IPv4 networks allowed to query DNS", OPTION_SECTION_DNS},
                {"drate", 'R', "QPS", required_argument, "per-source DNS query rate, 0 disables (default: 0)", OPTION_SECTION_DNS},
                {"dnsconnections", 'C', "COUNT", required_argument, "maximum concurrent DNS upstream TCP connections, 1..96 (default: 96)", OPTION_SECTION_DNS},

                {"monitor", 'm', "[BIND-IP:]PORT", required_argument, "enable the HTTP monitor (default bind: 127.0.0.1)", OPTION_SECTION_MONITOR},
                {"monitortoken", 'k', "TOKEN", required_argument, "require Bearer TOKEN for the monitor", OPTION_SECTION_MONITOR},
                {"monitortokenfile", 'K', "PATH", required_argument, "read the monitor Bearer token from the first line of PATH", OPTION_SECTION_MONITOR},
                {"monitortimeout", 'a', "SECONDS", required_argument, "incomplete-header timeout, 1..60 (default: 5)", OPTION_SECTION_MONITOR},

                {0}};

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

bool args_init(zroxy_t *pgp, int argc, const char **argv)
{
	pgp->snitimeout = 30;
	pgp->sniidletimeout = 300;
	pgp->snimaxconn = SNI_CONN_LIMIT_DEFAULT;
	pgp->sacl = NULL;
	pgp->sacl_count = 0;
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
	args_reset_secret_tracking();
	config_depth = 0;
	pgp->monitor_token = NULL;
	pgp->monitor_token_file = NULL;
	pgp->socks_pass_file = NULL;
	pgp->dsocks_pass_file = NULL;
	pgp->ports = NULL;
	pgp->socks = NULL;
	pgp->monitor_port = 0;
	pgp->whitelist_path = NULL;
	pgp->dnsserver = NULL;
	/*ran without parameter*/
	if (argc == 1)
	{
		return args_parse_config(pgp, DEF_CONFIG_PATH);
	}

	/*map arg_option to option*/
	int arg_number = sizeof(options) / sizeof(arg_option);
	struct option x_options[arg_number];
	bzero(x_options, sizeof(x_options));
	for (int i = 0; i < arg_number; i++)
	{
		x_options[i].name = options[i].name;
		x_options[i].val = options[i].key;
		x_options[i].has_arg = options[i].require;
		x_options[i].flag = NULL;
	}

	//make opt string
	char optstring[128] = {0};
	uint32_t index = 0;
	for (struct option *op = x_options; op->name != NULL; op++)
	{
		optstring[index++] = (char)op->val;
		if (op->has_arg == required_argument)
			optstring[index++] = ':';
		else if (op->has_arg == optional_argument)
			optstring[index++] = ';';

		/*check Overflow*/
		if (index >= sizeof(optstring) - 1)
			break;
	}

	int option_index = 0;
	while (1)
	{
		int key = getopt_long(argc, (char **)argv, optstring, x_options, &option_index);
		if (key == -1)
			break;

		if (key == 's' || key == 'x' || key == 'k' || key == 'u')
			args_note_cli_secret(key, optarg);
		if (args_apply_option(key, optarg, pgp) != 0)
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
	if (!args_load_secret_files(ptr))
		return false;
	if (!resolve_run_identity(ptr))
		return false;
	if (ptr->ports && !ptr->whitelist_path)
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
	if (ptr->whitelist_path && sni_ip_zero)
		log_warn("whitelisted names will resolve to 0.0.0.0");
	return true;
}

char *args_ltrim(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	return s;
}

static char *rtrim(char *s)
{
	size_t n = strlen(s);
	while (n > 0 && isspace((unsigned char)s[n - 1]))
		n--;
	s[n] = '\0';
	return s;
}

char *args_trim(char *s)
{
	return rtrim(args_ltrim(s));
}

static char *to_lower(char *s)
{
	for (char *p = s; *p; p++)
		*p = (char)tolower((unsigned char)*p);
	return s;
}

static int config_find_key(char *key)
{
	for (arg_option *ptr = options; ptr->name != NULL; ptr++)
	{
		if (strcmp(ptr->name, key) == 0)
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

bool args_parse_config(zroxy_t *ptr, char *str)
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
	while (*str == ' ')
		str++; /*remove space*/
	if (*str == '\0')
		return false;
	cfd = open(str, O_RDONLY | O_CLOEXEC);
	ConfigFile = cfd >= 0 ? fdopen(cfd, "r") : NULL;
	if (ConfigFile == NULL)
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
		fix_key = to_lower(args_trim(line));
		fix_val = args_trim(eq + 1);
		if (!config_key_chars(fix_key))
			continue;

		if (fix_val[0] == '\0' || strlen(fix_val) > ZROXY_MAX_CONFIG_VALUE)
		{
			log_error("error invalid value in config for key %s", fix_key);
			ret_status = false;
			break;
		}

		ckey = config_find_key(fix_key);
		if (ckey < 0)
		{
			log_error("error invalid key in config: %s", fix_key);
			ret_status = false;
			break;
		}

		if (!secret_seen && (ckey == 'k' ||
		                            ((ckey == 's' || ckey == 'x') && args_socks_spec_has_pass(fix_val)) ||
		                            (ckey == 'u' && args_dns_route_has_pass(fix_val))))
		{
			secret_seen = true;
			if (fstat(cfd, &st) == 0)
				args_warn_secret_mode(&st, str, "config file with a secret:");
		}

		if (args_apply_option(ckey, fix_val, ptr) != 0)
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
