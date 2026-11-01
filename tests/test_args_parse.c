#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <zroxy/args.h>
#include <zroxy/log.h>

bool args_parse_config(zroxy_t *ptr, char *str);

extern int optind;

static int failures = 0;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void expect_u16(uint16_t actual, uint16_t expected, const char *name)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL: %s expected %u, got %u\n", name, expected, actual);
        failures++;
    }
}

static void expect_int(int actual, int expected, const char *name)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL: %s expected %d, got %d\n", name, expected, actual);
        failures++;
    }
}

static void expect_string(const char *actual, const char *expected, const char *name)
{
    if (actual == NULL || strcmp(actual, expected) != 0)
    {
        fprintf(stderr, "FAIL: %s expected '%s', got '%s'\n",
                name, expected, actual ? actual : "(null)");
        failures++;
    }
}

static void free_settings(zroxy_t *cfg)
{
    args_free_ports(cfg);
    args_free_dns(cfg);
    if (cfg->socks)
    {
        free(cfg->socks->host);
        free(cfg->socks->user);
        free(cfg->socks->pass);
        free(cfg->socks);
    }
    free(cfg->monitorPort);
    free(cfg->monitor_token);
    free(cfg->run_user);
    free(cfg->run_group);
    free(cfg->WhitePath);
    free(cfg->monitor_token_file);
    free(cfg->socks_pass_file);
    free(cfg->dsocks_pass_file);
    memset(cfg, 0, sizeof(*cfg));
}

static void reset_getopt(void)
{
    optind = 1;
}

static void test_cli_listener_with_bind_and_remote(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-p";
    char arg2[] = "127.0.0.1:8080@80";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "args_init listener bind/remote");
    expect_true(cfg.ports != NULL, "listener bind/remote has one port");
    if (cfg.ports)
    {
        expect_string(cfg.ports->bindip, "127.0.0.1", "listener bind ip");
        expect_u16(cfg.ports->local_port, 8080, "listener local port");
        expect_u16(cfg.ports->remote_port, 80, "listener remote port");
    }

    free_settings(&cfg);
}

static void test_cli_listener_defaults(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-p";
    char arg2[] = "4433";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "args_init listener defaults");
    expect_true(cfg.ports != NULL, "listener defaults has one port");
    if (cfg.ports)
    {
        expect_string(cfg.ports->bindip, "0.0.0.0", "listener default bind ip");
        expect_u16(cfg.ports->local_port, 4433, "listener default local port");
        expect_u16(cfg.ports->remote_port, 4433, "listener default remote port");
    }

    free_settings(&cfg);
}

static void test_cli_socks_case_preserved(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-s";
    char arg2[] = "UserName:PassWord@ProxyHost.Example:1081";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "args_init socks");
    expect_true(cfg.socks != NULL, "socks parsed");
    if (cfg.socks)
    {
        expect_string(cfg.socks->user, "UserName", "socks user case preserved");
        expect_string(cfg.socks->pass, "PassWord", "socks pass case preserved");
        expect_string(cfg.socks->host, "ProxyHost.Example", "socks host case preserved");
        expect_u16(cfg.socks->port, 1081, "socks port");
    }

    free_settings(&cfg);
}

static void test_cli_monitor_and_sni_timeout(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-m";
    char arg2[] = "8123";
    char arg3[] = "-o";
    char arg4[] = "45";
    const char *argv[] = {arg0, arg1, arg2, arg3, arg4};

    reset_getopt();
    expect_true(args_init(&cfg, 5, argv), "args_init monitor + snitimeout");
    expect_true(cfg.monitorPort != NULL, "monitor port parsed");
    if (cfg.monitorPort)
    {
        expect_u16(*cfg.monitorPort, 8123, "monitor port value");
    }
    expect_string(cfg.monitor_bind, "127.0.0.1", "bare monitor port binds localhost");
    expect_int(cfg.monitor_header_timeout, 5, "default monitor header timeout");
    expect_int(cfg.snitimeout, 45, "sni timeout value");
    expect_int(cfg.sniidletimeout, 300, "default sni idle timeout");

    free_settings(&cfg);
}

static void test_cli_monitor_bind_and_token(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char m[] = "-m";
    char bind[] = "10.1.2.3:8123";
    char k[] = "-k";
    char tok[] = "secret";
    char a[] = "-a";
    char to[] = "7";
    char bad_to[] = "0";
    char bad_hi[] = "61";
    const char *argv[] = {arg0, m, bind, k, tok, a, to};
    const char *bad_argv[] = {arg0, a, bad_to};
    const char *hi_argv[] = {arg0, a, bad_hi};

    reset_getopt();
    expect_true(args_init(&cfg, 7, argv), "args_init monitor bind token timeout");
    expect_true(cfg.monitorPort != NULL, "explicit monitor port parsed");
    if (cfg.monitorPort)
        expect_u16(*cfg.monitorPort, 8123, "explicit monitor port");
    expect_string(cfg.monitor_bind, "10.1.2.3", "explicit monitor bind");
    expect_string(cfg.monitor_token, "secret", "monitor token");
    expect_int(cfg.monitor_header_timeout, 7, "monitor header timeout");
    free_settings(&cfg);

    reset_getopt();
    expect_true(!args_init(&cfg, 3, bad_argv), "reject monitor timeout 0");
    free_settings(&cfg);

    reset_getopt();
    expect_true(!args_init(&cfg, 3, hi_argv), "reject monitor timeout 61");
    free_settings(&cfg);
}

static void write_all_or_fail(int fd, const char *data)
{
    size_t left = strlen(data);
    while (left > 0)
    {
        ssize_t n = write(fd, data, left);
        if (n < 0)
        {
            fprintf(stderr, "FAIL: write temp config failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        data += n;
        left -= (size_t)n;
    }
}

static void test_config_value_case_preserved(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data =
        "SOCKS = UserName:PassWord@ProxyHost.Example:1081\n"
        "WHITE = /TMP/WhiteList.TXT\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);

    expect_true(args_parse_config(&cfg, template_path), "args_parse_config value case preserved");
    expect_true(cfg.socks != NULL, "config socks parsed");
    if (cfg.socks)
    {
        expect_string(cfg.socks->user, "UserName", "config socks user preserved");
        expect_string(cfg.socks->pass, "PassWord", "config socks pass preserved");
        expect_string(cfg.socks->host, "ProxyHost.Example", "config socks host preserved");
        expect_u16(cfg.socks->port, 1081, "config socks port");
    }
    expect_string(cfg.WhitePath, "/TMP/WhiteList.TXT", "config white path preserved");

    unlink(template_path);
    free_settings(&cfg);
}

static void test_config_port_key_case_insensitive(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data = "PORT = 127.0.0.1:8080@80\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);

    expect_true(args_parse_config(&cfg, template_path), "args_parse_config uppercase PORT key");
    expect_true(cfg.ports != NULL, "config port parsed");
    if (cfg.ports)
    {
        expect_string(cfg.ports->bindip, "127.0.0.1", "config port bind ip");
        expect_u16(cfg.ports->local_port, 8080, "config port local");
        expect_u16(cfg.ports->remote_port, 80, "config port remote");
    }

    unlink(template_path);
    free_settings(&cfg);
}

static void test_cli_socks_no_auth_cleanup_safe(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-s";
    char arg2[] = "127.0.0.1:9050";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "args_init socks no auth");
    expect_true(cfg.socks != NULL, "socks no auth allocated");
    if (cfg.socks)
    {
        expect_string(cfg.socks->host, "127.0.0.1", "socks no auth host");
        expect_u16(cfg.socks->port, 9050, "socks no auth port");
        expect_true(cfg.socks->user == NULL, "socks no auth user is NULL");
        expect_true(cfg.socks->pass == NULL, "socks no auth pass is NULL");
    }

    free_settings(&cfg);
}

static void test_cli_socks_user_no_pass_cleanup_safe(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-s";
    char arg2[] = "myuser@127.0.0.1:9050";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "args_init socks user no pass");
    expect_true(cfg.socks != NULL, "socks user no pass allocated");
    if (cfg.socks)
    {
        expect_string(cfg.socks->user, "myuser", "socks user no pass user");
        expect_true(cfg.socks->pass == NULL, "socks user no pass is NULL");
        expect_string(cfg.socks->host, "127.0.0.1", "socks user no pass host");
    }

    free_settings(&cfg);
}

static void test_config_dns_only_cleanup_safe(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data =
        "LDNS = 127.0.0.1:5353\n"
        "DNS = 8.8.8.8\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);

    expect_true(args_parse_config(&cfg, template_path), "args_parse_config dns only");
    expect_true(cfg.dnsserver != NULL, "config dnsserver allocated");
    if (cfg.dnsserver)
    {
        expect_true(cfg.dnsserver->Socks == NULL, "dns only Socks is NULL");
        expect_true(cfg.dnsserver->whitelist == NULL, "dns only whitelist is NULL");
    }

    unlink(template_path);
    free_settings(&cfg);
}

static void test_config_dns_with_dsocks_no_auth_cleanup_safe(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data =
        "LDNS = 127.0.0.1:5353\n"
        "DNS = 8.8.8.8\n"
        "DSOCKS = 127.0.0.1:9050\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);

    expect_true(args_parse_config(&cfg, template_path), "args_parse_config dns with dsocks no auth");
    expect_true(cfg.dnsserver != NULL, "config dnsserver allocated");
    if (cfg.dnsserver)
    {
        expect_true(cfg.dnsserver->Socks != NULL, "dns dsocks allocated");
        if (cfg.dnsserver->Socks)
        {
            expect_string(cfg.dnsserver->Socks->host, "127.0.0.1", "dns dsocks host");
            expect_u16(cfg.dnsserver->Socks->port, 9050, "dns dsocks port");
            expect_true(cfg.dnsserver->Socks->user == NULL, "dns dsocks user is NULL");
            expect_true(cfg.dnsserver->Socks->pass == NULL, "dns dsocks pass is NULL");
        }
        expect_true(cfg.dnsserver->whitelist == NULL, "dns dsocks whitelist is NULL");
    }

    unlink(template_path);
    free_settings(&cfg);
}

static void test_config_dns_with_snip_cleanup_safe(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data =
        "LDNS = 127.0.0.1:5353\n"
        "DNS = 8.8.8.8\n"
        "SNIP = 127.0.0.1\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);

    expect_true(args_parse_config(&cfg, template_path), "args_parse_config dns with snip");
    expect_true(cfg.dnsserver != NULL, "config dnsserver allocated");
    if (cfg.dnsserver)
    {
        expect_true(cfg.dnsserver->Socks == NULL, "dns with snip Socks is NULL");
        expect_true(cfg.dnsserver->whitelist == NULL, "dns with snip whitelist is NULL");
    }

    unlink(template_path);
    free_settings(&cfg);
}

static void test_cli_rejects_overlong_bind_and_bad_port(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-p";
    char arg2[] = "this-name-is-not-an-ipv4-address:8080@80";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(!args_init(&cfg, 3, argv), "reject overlong listener token");
    free_settings(&cfg);

    {
        char bad0[] = "zroxy";
        char bad1[] = "-p";
        char bad2[] = "127.0.0.1:80abc@80";
        const char *bad_argv[] = {bad0, bad1, bad2};
        reset_getopt();
        expect_true(!args_init(&cfg, 3, bad_argv), "reject non-numeric listener port");
        free_settings(&cfg);
    }
}

static void test_cli_accepts_long_dns_hostname(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-u";
    char arg2[] = "long.dns.example.test";
    const char *argv[] = {arg0, arg1, arg2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "args_init long DNS hostname");
    expect_true(cfg.dnsserver != NULL, "long DNS hostname allocated");
    if (cfg.dnsserver)
        expect_string(cfg.dnsserver->Remote.ip, "long.dns.example.test", "long DNS hostname stored");
    free_settings(&cfg);
}

static void test_dns_option_order_and_last_listener_wins(void)
{
    zroxy_t cfg = {0};
    char arg0[] = "zroxy";
    char arg1[] = "-t";
    char arg2[] = "2";
    char arg3[] = "-d";
    char arg4[] = "127.0.0.1:5353";
    char arg5[] = "-u";
    char arg6[] = "1.1.1.1";
    const char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6};

    reset_getopt();
    expect_true(args_init(&cfg, 7, argv), "DNS options are order independent");
    expect_true(cfg.dnsserver != NULL, "DNS config exists after ordered options");
    if (cfg.dnsserver)
    {
        expect_int((int)cfg.dnsserver->timeout, 2, "DNS timeout survives LDNS");
        expect_string(cfg.dnsserver->Remote.ip, "1.1.1.1", "DNS upstream after LDNS");
    }
    free_settings(&cfg);

    {
        zroxy_t last = {0};
        char a0[] = "zroxy";
        char a1[] = "-d";
        char a2[] = "127.0.0.1:5353";
        char a3[] = "-d";
        char a4[] = "127.0.0.1:5454";
        const char *last_argv[] = {a0, a1, a2, a3, a4};
        reset_getopt();
        expect_true(args_init(&last, 5, last_argv), "repeated LDNS parses");
        if (last.dnsserver)
            expect_u16(last.dnsserver->Local.port, 5454, "last LDNS wins");
        free_settings(&last);
    }
}

static void test_repeated_ldns_resets_default_port(void)
{
	zroxy_t cfg = {0};
	char a0[] = "zroxy";
	char a1[] = "-t";
	char a2[] = "2";
	char a3[] = "-d";
	char a4[] = "127.0.0.1:5353";
	char a5[] = "-d";
	char a6[] = "127.0.0.1";
	const char *argv[] = {a0, a1, a2, a3, a4, a5, a6};

	reset_getopt();
	expect_true(args_init(&cfg, 7, argv), "LDNS without port resets previous port");
	if (cfg.dnsserver)
	{
		expect_u16(cfg.dnsserver->Local.port, 53, "LDNS default port replaces previous port");
		expect_string(cfg.dnsserver->Local.ip, "127.0.0.1", "LDNS default-port address");
		expect_int((int)cfg.dnsserver->timeout, 2, "LDNS replacement preserves timeout");
	}
	free_settings(&cfg);

	{
		zroxy_t next = {0};
		char b0[] = "zroxy";
		char b1[] = "-d";
		char b2[] = "127.0.0.1";
		char b3[] = "-d";
		char b4[] = "127.0.0.2:5300";
		const char *next_argv[] = {b0, b1, b2, b3, b4};
		reset_getopt();
		expect_true(args_init(&next, 5, next_argv), "LDNS with port replaces default port");
		if (next.dnsserver)
		{
			expect_u16(next.dnsserver->Local.port, 5300, "LDNS explicit replacement port");
			expect_string(next.dnsserver->Local.ip, "127.0.0.2", "LDNS explicit replacement address");
		}
		free_settings(&next);
	}
}

static void test_config_dns_timeout_before_listener(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data =
        "DTIMEOUT = 2\n"
        "LDNS = 127.0.0.1:5353\n"
        "DNS = 1.1.1.1\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }
    write_all_or_fail(fd, config_data);
    close(fd);
    expect_true(args_parse_config(&cfg, template_path), "config timeout before LDNS parses");
    if (cfg.dnsserver)
        expect_int((int)cfg.dnsserver->timeout, 2, "config timeout survives LDNS");
    unlink(template_path);
    free_settings(&cfg);
}

static void test_dns_validation(void)
{
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-u";
        char a2[] = "1.1.1.1";
        const char *argv[] = {a0, a1, a2};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "upstream-only parser accepts");
        expect_true(!args_validate(&cfg), "upstream-only validation rejects");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-i";
        char a2[] = "192.0.2.10";
        const char *argv[] = {a0, a1, a2};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "SNIP-only parser accepts");
        expect_true(!args_validate(&cfg), "SNIP-only validation rejects");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-d";
        char a2[] = "127.0.0.1:5353";
        const char *argv[] = {a0, a1, a2};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "LDNS-only parser accepts");
        expect_true(!args_validate(&cfg), "LDNS without upstream rejects");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-d";
        char a2[] = "127.0.0.1:5353";
        char a3[] = "-u";
        char a4[] = "1.1.1.1";
        const char *argv[] = {a0, a1, a2, a3, a4};
        reset_getopt();
        expect_true(args_init(&cfg, 5, argv), "LDNS with upstream parses");
        expect_true(args_validate(&cfg), "LDNS with upstream validates");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        expect_true(args_validate(&cfg), "no DNS options validate");
        free_settings(&cfg);
    }
}

static void test_dns_connection_limit(void)
{
    zroxy_t cfg = {0};
    char a0[] = "zroxy";
    char a1[] = "-C";
    char a2[] = "48";
    const char *argv[] = {a0, a1, a2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "DNS connection limit parses");
    if (cfg.dnsserver)
        expect_u16(cfg.dnsserver->upstream_connections, 48, "DNS connection limit value");
    free_settings(&cfg);

    {
        zroxy_t invalid = {0};
        char b0[] = "zroxy";
        char b1[] = "--dnsconnections";
        char b2[] = "97";
        const char *bad_argv[] = {b0, b1, b2};
        reset_getopt();
        expect_true(!args_init(&invalid, 3, bad_argv), "DNS connection limit above maximum rejects");
        free_settings(&invalid);
    }
}

static void test_sni_idle_timeout(void)
{
    zroxy_t cfg = {0};
    char a0[] = "zroxy";
    char a1[] = "-I";
    char a2[] = "900";
    const char *argv[] = {a0, a1, a2};

    reset_getopt();
    expect_true(args_init(&cfg, 3, argv), "SNI idle timeout parses");
    expect_int(cfg.sniidletimeout, 900, "SNI idle timeout value");
    expect_int(cfg.snitimeout, 30, "SNI idle timeout leaves snitimeout alone");
    free_settings(&cfg);

    {
        zroxy_t invalid = {0};
        char b0[] = "zroxy";
        char b1[] = "--sniidletimeout";
        char b2[] = "0";
        const char *bad_argv[] = {b0, b1, b2};
        reset_getopt();
        expect_true(!args_init(&invalid, 3, bad_argv), "SNI idle timeout 0 rejects");
        free_settings(&invalid);
    }

    {
        zroxy_t file_cfg = {0};
        char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
        int fd = mkstemp(template_path);
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        write_all_or_fail(fd, "SNIIDLETIMEOUT = 120\n");
        close(fd);
        expect_true(args_parse_config(&file_cfg, template_path), "config SNIIDLETIMEOUT parses");
        expect_int(file_cfg.sniidletimeout, 120, "config SNIIDLETIMEOUT value");
        unlink(template_path);
        free_settings(&file_cfg);
    }
}

static void test_destination_policy_options(void)
{
    zroxy_t cfg = {0};
    char a0[] = "zroxy";
    char a1[] = "--allowloopback";
    char a2[] = "yes";
    char a3[] = "-P";
    char a4[] = "on";
    const char *argv[] = {a0, a1, a2, a3, a4};

    reset_getopt();
    expect_true(args_init(&cfg, 5, argv), "destination policy options parse");
    expect_true(cfg.allow_loopback, "allowloopback yes");
    expect_true(cfg.deny_private, "denyprivate on");
    free_settings(&cfg);

    {
        zroxy_t d = {0};
        char b1[] = "-l";
        char b2[] = "2";
        const char *dargv[] = {a0, b1, b2};
        reset_getopt();
        expect_true(args_init(&d, 3, dargv), "defaults parse");
        expect_true(!d.allow_loopback, "allowloopback defaults off");
        expect_true(!d.deny_private, "denyprivate defaults off");
        free_settings(&d);
    }

    {
        zroxy_t bad = {0};
        char b1[] = "--denyprivate";
        char b2[] = "maybe";
        const char *bad_argv[] = {a0, b1, b2};
        reset_getopt();
        expect_true(!args_init(&bad, 3, bad_argv), "denyprivate rejects a non-boolean");
        free_settings(&bad);
    }

    {
        zroxy_t file_cfg = {0};
        char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
        int fd = mkstemp(template_path);
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        write_all_or_fail(fd, "ALLOWLOOPBACK = true\nDENYPRIVATE = no\n");
        close(fd);
        expect_true(args_parse_config(&file_cfg, template_path), "config destination policy parses");
        expect_true(file_cfg.allow_loopback, "config ALLOWLOOPBACK value");
        expect_true(!file_cfg.deny_private, "config DENYPRIVATE value");
        unlink(template_path);
        free_settings(&file_cfg);
    }
}

static void test_open_proxy_option(void)
{
    char a0[] = "zroxy";
    char p1[] = "-p";

    {
        zroxy_t cfg = {0};
        char p2[] = "127.0.0.1:8443@443";
        const char *argv[] = {a0, p1, p2};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "listener without whitelist parses");
        expect_true(!cfg.open_proxy, "openproxy defaults off");
        expect_true(!args_validate(&cfg), "listener without whitelist or openproxy rejects");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char o1[] = "--openproxy";
        char o2[] = "yes";
        char p2[] = "127.0.0.1:8443@443";
        const char *argv[] = {a0, p1, p2, o1, o2};
        reset_getopt();
        expect_true(args_init(&cfg, 5, argv), "openproxy yes parses");
        expect_true(cfg.open_proxy, "openproxy yes sets the flag");
        expect_true(args_validate(&cfg), "listener with openproxy validates");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char o1[] = "-O";
        char o2[] = "off";
        char w1[] = "-w";
        char w2[] = "/tmp/zroxy-no-such-whitelist";
        char p2[] = "127.0.0.1:8443@443";
        const char *argv[] = {a0, p1, p2, o1, o2, w1, w2};
        reset_getopt();
        expect_true(args_init(&cfg, 7, argv), "whitelist with openproxy off parses");
        expect_true(!cfg.open_proxy, "openproxy off clears the flag");
        expect_true(args_validate(&cfg), "listener with whitelist validates");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char o1[] = "-O";
        char o2[] = "yes";
        char w1[] = "-w";
        char w2[] = "/tmp/zroxy-no-such-whitelist";
        char p2[] = "127.0.0.1:8443@443";
        const char *argv[] = {a0, p1, p2, o1, o2, w1, w2};
        reset_getopt();
        expect_true(args_init(&cfg, 7, argv), "whitelist with openproxy yes parses");
        expect_true(cfg.WhitePath != NULL, "whitelist stays configured with openproxy");
        expect_true(args_validate(&cfg), "whitelist with openproxy validates");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char d1[] = "-d";
        char d2[] = "127.0.0.1:5353";
        char u1[] = "-u";
        char u2[] = "1.1.1.1";
        const char *argv[] = {a0, d1, d2, u1, u2};
        reset_getopt();
        expect_true(args_init(&cfg, 5, argv), "DNS-only parses");
        expect_true(args_validate(&cfg), "DNS-only needs no whitelist or openproxy");
        free_settings(&cfg);
    }
    {
        zroxy_t bad = {0};
        char o1[] = "--openproxy";
        char o2[] = "maybe";
        const char *argv[] = {a0, o1, o2};
        reset_getopt();
        expect_true(!args_init(&bad, 3, argv), "openproxy rejects a non-boolean");
        free_settings(&bad);
    }
    {
        zroxy_t file_cfg = {0};
        char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
        int fd = mkstemp(template_path);
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        write_all_or_fail(fd, "PORT = 127.0.0.1:8443@443\nOPENPROXY = true\n");
        close(fd);
        expect_true(args_parse_config(&file_cfg, template_path), "config OPENPROXY parses");
        expect_true(file_cfg.open_proxy, "config OPENPROXY value");
        expect_true(args_validate(&file_cfg), "config listener with OPENPROXY validates");
        unlink(template_path);
        free_settings(&file_cfg);
    }
    {
        zroxy_t file_cfg = {0};
        char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
        int fd = mkstemp(template_path);
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        write_all_or_fail(fd, "PORT = 127.0.0.1:8443@443\n");
        close(fd);
        expect_true(args_parse_config(&file_cfg, template_path), "config listener only parses");
        expect_true(!args_validate(&file_cfg), "config listener without whitelist rejects");
        unlink(template_path);
        free_settings(&file_cfg);
    }
}

static void test_dns_cache_and_ttl_ranges(void)
{
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-e";
        char a2[] = "0";
        char a3[] = "-r";
        char a4[] = "86400";
        const char *argv[] = {a0, a1, a2, a3, a4};
        reset_getopt();
        expect_true(args_init(&cfg, 5, argv), "cache and TTL lower/upper ranges parse");
        if (cfg.dnsserver)
        {
            expect_int((int)cfg.dnsserver->cache_entries, 0, "zero cache disables cache");
            expect_int((int)cfg.dnsserver->local_ttl, 86400, "maximum synthetic TTL parses");
        }
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-e";
        char a2[] = "65536";
        const char *argv[] = {a0, a1, a2};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "maximum cache size parses");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char a0[] = "zroxy";
        char a1[] = "-e";
        char a2[] = "65537";
        const char *argv[] = {a0, a1, a2};
        reset_getopt();
        expect_true(!args_init(&cfg, 3, argv), "cache size above maximum rejects");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
        int fd = mkstemp(template_path);
        const char *data = "DCACHE = 65536\nDTTL = 1\n";
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        write_all_or_fail(fd, data);
        close(fd);
        expect_true(args_parse_config(&cfg, template_path), "cache and TTL config ranges parse");
        unlink(template_path);
        free_settings(&cfg);
    }
}

static void test_config_rejects_blank_value(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data = "PORT =\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);
    expect_true(!args_parse_config(&cfg, template_path), "reject blank config value");
    unlink(template_path);
    free_settings(&cfg);
}

static void test_config_minimal_cleanup_safe(void)
{
    zroxy_t cfg = {0};
    char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
    int fd = mkstemp(template_path);
    const char *config_data = "PORT = 8080\n";

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }

    write_all_or_fail(fd, config_data);
    close(fd);

    expect_true(args_parse_config(&cfg, template_path), "args_parse_config minimal");
    expect_true(cfg.ports != NULL, "config port parsed");
    expect_true(cfg.socks == NULL, "minimal socks is NULL");
    expect_true(cfg.dnsserver == NULL, "minimal dnsserver is NULL");
    expect_true(cfg.WhitePath == NULL, "minimal WhitePath is NULL");
    expect_true(cfg.monitorPort == NULL, "minimal monitorPort is NULL");

    unlink(template_path);
    free_settings(&cfg);
}

/* Write content to a temp file; path (a mkstemp template) gets the name. */
static bool write_conf(char *path, const char *data)
{
    int fd = mkstemp(path);

    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return false;
    }
    write_all_or_fail(fd, data);
    close(fd);
    return true;
}

static void expect_port(const lport_t *p, const char *ip, uint16_t local,
                        uint16_t remote, const char *name)
{
    expect_true(p != NULL, name);
    if (p)
    {
        expect_string(p->bindip, ip, name);
        expect_u16(p->local_port, local, name);
        expect_u16(p->remote_port, remote, name);
    }
}

static size_t count_ports(const zroxy_t *cfg)
{
    size_t n = 0;
    const lport_t *p;

    for (p = cfg->ports; p; p = p->next)
        n++;
    return n;
}

static void test_repeated_port_lines_append(void)
{
    zroxy_t cfg = {0};
    char path[] = "/tmp/zroxy_args_test_XXXXXX";
    const lport_t *p;

    if (!write_conf(path, "PORT = 127.0.0.1:8080@80\nPORT = 127.0.0.1:8443@443,9000\n"))
        return;
    expect_true(args_parse_config(&cfg, path), "two PORT lines parse");
    expect_int((int)count_ports(&cfg), 3, "two PORT lines give three listeners");
    p = cfg.ports;
    expect_port(p, "127.0.0.1", 8080, 80, "first PORT line first");
    p = p ? p->next : NULL;
    expect_port(p, "127.0.0.1", 8443, 443, "second PORT line, first entry");
    p = p ? p->next : NULL;
    expect_port(p, "0.0.0.0", 9000, 9000, "second PORT line, second entry");
    unlink(path);
    free_settings(&cfg);
}

static void test_repeated_cli_port_appends(void)
{
    zroxy_t cfg = {0};
    char a0[] = "zroxy", a1[] = "-p", a2[] = "127.0.0.1:8080@80";
    char a3[] = "--port", a4[] = "127.0.0.2:8080@81";
    const char *argv[] = {a0, a1, a2, a3, a4};

    reset_getopt();
    expect_true(args_init(&cfg, 5, argv), "two -p parse");
    expect_int((int)count_ports(&cfg), 2, "two -p give two listeners");
    expect_port(cfg.ports, "127.0.0.1", 8080, 80, "first -p first");
    if (cfg.ports)
        expect_port(cfg.ports->next, "127.0.0.2", 8080, 81, "second -p second");
    free_settings(&cfg);
}

static void test_config_and_cli_ports_append(void)
{
    zroxy_t cfg = {0};
    char path[] = "/tmp/zroxy_args_test_XXXXXX";
    char a0[] = "zroxy", a1[] = "-c", a3[] = "-p", a4[] = "127.0.0.1:9090";
    const char *argv[] = {a0, a1, path, a3, a4};

    if (!write_conf(path, "PORT = 127.0.0.1:8080\n"))
        return;
    reset_getopt();
    expect_true(args_init(&cfg, 5, argv), "config and -p parse");
    expect_int((int)count_ports(&cfg), 2, "config and -p give two listeners");
    expect_port(cfg.ports, "127.0.0.1", 8080, 8080, "config listener first");
    if (cfg.ports)
        expect_port(cfg.ports->next, "127.0.0.1", 9090, 9090, "-p listener after it");
    unlink(path);
    free_settings(&cfg);
}

static bool one_port_arg(zroxy_t *cfg, const char *spec)
{
    char a0[] = "zroxy", a1[] = "-p";
    char arg[128];
    const char *argv[] = {a0, a1, arg};

    snprintf(arg, sizeof(arg), "%s", spec);
    reset_getopt();
    return args_init(cfg, 3, argv);
}

static void test_duplicate_listener_rejected(void)
{
    const char *dups[] = {
        "127.0.0.1:8080,127.0.0.1:8080@81",    /* same call */
        "127.0.0.1:8080,127.000.000.001:8080", /* same address, other spelling */
        "8080,127.0.0.1:8080",                 /* wildcard first */
        "127.0.0.1:8080,8080",                 /* wildcard second */
    };
    zroxy_t cfg = {0};
    char path[] = "/tmp/zroxy_args_test_XXXXXX";
    size_t i;

    for (i = 0; i < sizeof(dups) / sizeof(dups[0]); i++)
    {
        memset(&cfg, 0, sizeof(cfg));
        expect_true(!one_port_arg(&cfg, dups[i]), dups[i]);
        free_settings(&cfg);
    }

    /* across two PORT lines */
    memset(&cfg, 0, sizeof(cfg));
    if (!write_conf(path, "PORT = 127.0.0.1:8080\nPORT = 0.0.0.0:8080\n"))
        return;
    expect_true(!args_parse_config(&cfg, path), "wildcard after specific across lines");
    unlink(path);
    free_settings(&cfg);

    memset(&cfg, 0, sizeof(cfg));
    expect_true(one_port_arg(&cfg, "127.0.0.1:8080,127.0.0.2:8080,127.0.0.1:8081,0,0"),
                "other ip, other port and port 0 are not duplicates");
    expect_int((int)count_ports(&cfg), 5, "five distinct listeners kept");
    free_settings(&cfg);
}

static void test_port_failure_keeps_earlier_list(void)
{
    zroxy_t cfg = {0};
    char path[] = "/tmp/zroxy_args_test_XXXXXX";

    /* a bad entry after good ones in the second line */
    if (!write_conf(path, "PORT = 127.0.0.1:8080\nPORT = 127.0.0.1:8081,127.0.0.1:8082,bogus\n"))
        return;
    expect_true(!args_parse_config(&cfg, path), "bad entry in comma list fails");
    expect_int((int)count_ports(&cfg), 1, "nothing of the failed list was added");
    expect_port(cfg.ports, "127.0.0.1", 8080, 8080, "earlier listener kept");
    unlink(path);
    free_settings(&cfg);

    /* a duplicate at the end of the second line */
    memset(&cfg, 0, sizeof(cfg));
    strcpy(path, "/tmp/zroxy_args_test_XXXXXX");
    if (!write_conf(path, "PORT = 127.0.0.1:8080\nPORT = 127.0.0.1:8081,127.0.0.1:8080\n"))
        return;
    expect_true(!args_parse_config(&cfg, path), "duplicate at the end of a list fails");
    expect_int((int)count_ports(&cfg), 1, "list intact after a rejected duplicate");
    unlink(path);
    free_settings(&cfg);
}

/*
 * Make count files dir/f0 .. dir/f(count-1) in a fresh temp directory. File
 * i names file i+1 with the config key; the last one holds a listener, or
 * names file last_to when that is not negative.
 */
static bool make_chain(char *dir, int count, int last_to)
{
    char path[PATH_MAX];
    int i;

    if (!mkdtemp(dir))
    {
        fprintf(stderr, "FAIL: mkdtemp failed: %s\n", strerror(errno));
        failures++;
        return false;
    }
    for (i = 0; i < count; i++)
    {
        char data[PATH_MAX + 32];
        int fd;

        snprintf(path, sizeof(path), "%s/f%d", dir, i);
        if (i + 1 < count)
            snprintf(data, sizeof(data), "config = %s/f%d\n", dir, i + 1);
        else if (last_to >= 0)
            snprintf(data, sizeof(data), "config = %s/f%d\n", dir, last_to);
        else
            snprintf(data, sizeof(data), "PORT = 127.0.0.1:8080\n");
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: open %s failed: %s\n", path, strerror(errno));
            failures++;
            return false;
        }
        write_all_or_fail(fd, data);
        close(fd);
    }
    return true;
}

static void drop_chain(const char *dir, int count)
{
    char path[PATH_MAX];
    int i;

    for (i = 0; i < count; i++)
    {
        snprintf(path, sizeof(path), "%s/f%d", dir, i);
        unlink(path);
    }
    rmdir(dir);
}

/* Parse dir/f0; true when it was accepted. */
static bool parse_chain(const char *dir, zroxy_t *cfg)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/f0", dir);
    return args_parse_config(cfg, path);
}

static void test_config_includes_itself(void)
{
    zroxy_t cfg = {0};
    char dir[] = "/tmp/zroxy_args_dir_XXXXXX";

    if (!make_chain(dir, 1, 0))
        return;
    expect_true(!parse_chain(dir, &cfg), "config naming itself is rejected");
    free_settings(&cfg);
    drop_chain(dir, 1);
}

static void test_config_include_cycle(void)
{
    zroxy_t cfg = {0};
    char dir[] = "/tmp/zroxy_args_dir_XXXXXX";
    char link[PATH_MAX];

    if (!make_chain(dir, 2, 0))
        return;
    expect_true(!parse_chain(dir, &cfg), "A -> B -> A is rejected");
    free_settings(&cfg);

    /* the same file by another name is the same file */
    snprintf(link, sizeof(link), "%s/alias", dir);
    if (symlink("f0", link) == 0)
    {
        char path[PATH_MAX];
        int fd;

        snprintf(path, sizeof(path), "%s/f1", dir);
        fd = open(path, O_WRONLY | O_TRUNC);
        if (fd >= 0)
        {
            char data[PATH_MAX + 32];

            snprintf(data, sizeof(data), "config = %s\n", link);
            write_all_or_fail(fd, data);
            close(fd);
            memset(&cfg, 0, sizeof(cfg));
            expect_true(!parse_chain(dir, &cfg), "cycle through a symlink is rejected");
            free_settings(&cfg);
        }
        unlink(link);
    }
    drop_chain(dir, 2);
}

static void test_config_include_depth(void)
{
    zroxy_t cfg = {0};
    char ok[] = "/tmp/zroxy_args_dir_XXXXXX";
    char deep[] = "/tmp/zroxy_args_dir_XXXXXX";
    char good[] = "/tmp/zroxy_args_test_XXXXXX";
    const int limit = 8;

    if (!make_chain(ok, limit, -1))
        return;
    expect_true(parse_chain(ok, &cfg), "a chain at the depth limit is accepted");
    expect_int((int)count_ports(&cfg), 1, "the last file of the chain was read");
    free_settings(&cfg);

    if (make_chain(deep, limit + 1, -1))
    {
        expect_true(!parse_chain(deep, &cfg), "a chain over the depth limit is rejected");
        free_settings(&cfg);
    }

    /* nothing is left over from the rejected chain */
    expect_true(parse_chain(ok, &cfg), "the chain at the limit still works after a rejection");
    free_settings(&cfg);
    if (write_conf(good, "PORT = 127.0.0.1:8081\n"))
    {
        char a0[] = "zroxy", a1[] = "-c";
        const char *argv[] = {a0, a1, good};

        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "args_init with a valid config after a rejection");
        expect_int((int)count_ports(&cfg), 1, "valid config read after a rejection");
        unlink(good);
        free_settings(&cfg);
    }
    drop_chain(ok, limit);
    drop_chain(deep, limit + 1);
}

static void test_config_include_twice_in_a_row(void)
{
    zroxy_t cfg = {0};
    char inner[] = "/tmp/zroxy_args_test_XXXXXX";
    char outer[] = "/tmp/zroxy_args_test_XXXXXX";
    char data[PATH_MAX + 64];

    /* the same file included twice, one after the other, is not a cycle */
    if (!write_conf(inner, "SNITIMEOUT = 40\n"))
        return;
    snprintf(data, sizeof(data), "config = %s\nconfig = %s\n", inner, inner);
    if (write_conf(outer, data))
    {
        expect_true(args_parse_config(&cfg, outer), "the same file included twice in a row");
        expect_int((int)cfg.snitimeout, 40, "included value was read");
        unlink(outer);
    }
    unlink(inner);
    free_settings(&cfg);
}

/* Write content to a fresh temp file with the given mode; path gets the name. */
static void make_secret_file(char *path, const void *data, size_t n, mode_t mode)
{
    int fd = mkstemp(path);
    if (fd < 0)
    {
        fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
        failures++;
        return;
    }
    if (n > 0 && write(fd, data, n) != (ssize_t)n)
    {
        fprintf(stderr, "FAIL: secret file write failed\n");
        failures++;
    }
    fchmod(fd, mode);
    close(fd);
}

/* Parse "zroxy OPT VALUE [OPT VALUE]" then validate; returns validate's result. */
static bool init_validate(zroxy_t *cfg, const char *o1, const char *v1, const char *o2, const char *v2)
{
    char a0[] = "zroxy";
    char b1[64], b2[512], b3[64], b4[512];
    const char *argv[5];
    int argc = 0;
    argv[argc++] = a0;
    snprintf(b1, sizeof(b1), "%s", o1);
    snprintf(b2, sizeof(b2), "%s", v1);
    argv[argc++] = b1;
    argv[argc++] = b2;
    if (o2)
    {
        snprintf(b3, sizeof(b3), "%s", o2);
        snprintf(b4, sizeof(b4), "%s", v2);
        argv[argc++] = b3;
        argv[argc++] = b4;
    }
    reset_getopt();
    if (!args_init(cfg, argc, argv))
        return false;
    return args_validate(cfg);
}

static void test_monitor_token_file(void)
{
    char path[] = "/tmp/zroxy_secret_XXXXXX";
    zroxy_t cfg = {0};

    make_secret_file(path, "s3cret-token\r\n", 14, 0600);
    expect_true(init_validate(&cfg, "--monitortokenfile", path, "-m", "8123"), "token file validates");
    expect_string(cfg.monitor_token, "s3cret-token", "token file CR LF stripped");
    expect_true(cfg.monitor_token_file == NULL, "token file path released");
    free_settings(&cfg);

    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-K", path, "-k", "inline"), "token inline and file rejected");
    free_settings(&cfg);
    unlink(path);

    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-K", "/tmp/zroxy-no-such-secret", "-m", "8123"), "missing token file rejected");
    free_settings(&cfg);
}

static void test_secret_file_contents(void)
{
    char path[] = "/tmp/zroxy_secret_XXXXXX";
    char longbuf[400];
    zroxy_t cfg = {0};

    make_secret_file(path, "first\nsecond\n", 13, 0600);
    expect_true(init_validate(&cfg, "-K", path, "-m", "8123"), "only the first line is used");
    expect_string(cfg.monitor_token, "first", "first line value");
    free_settings(&cfg);
    unlink(path);

    strcpy(path, "/tmp/zroxy_secret_XXXXXX");
    make_secret_file(path, "", 0, 0600);
    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-K", path, "-m", "8123"), "empty token file rejected");
    free_settings(&cfg);
    unlink(path);

    strcpy(path, "/tmp/zroxy_secret_XXXXXX");
    make_secret_file(path, "\r\nlater\n", 8, 0600);
    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-K", path, "-m", "8123"), "blank first line rejected");
    free_settings(&cfg);
    unlink(path);

    memset(longbuf, 'a', 257);
    longbuf[257] = '\n';
    strcpy(path, "/tmp/zroxy_secret_XXXXXX");
    make_secret_file(path, longbuf, 258, 0600);
    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-K", path, "-m", "8123"), "257 byte token rejected");
    free_settings(&cfg);
    unlink(path);

    longbuf[256] = '\n';
    strcpy(path, "/tmp/zroxy_secret_XXXXXX");
    make_secret_file(path, longbuf, 257, 0600);
    memset(&cfg, 0, sizeof(cfg));
    expect_true(init_validate(&cfg, "-K", path, "-m", "8123"), "256 byte token accepted");
    free_settings(&cfg);
    unlink(path);
}

static void test_secret_file_permissions(void)
{
    char path[] = "/tmp/zroxy_secret_XXXXXX";
    char dirpath[] = "/tmp/zroxy_secret_dir_XXXXXX";
    zroxy_t cfg = {0};

    make_secret_file(path, "tok\n", 4, 0666);
    expect_true(!init_validate(&cfg, "-K", path, "-m", "8123"), "world-writable secret file refused");
    free_settings(&cfg);
    chmod(path, 0644);
    memset(&cfg, 0, sizeof(cfg));
    expect_true(init_validate(&cfg, "-K", path, "-m", "8123"), "world-readable secret file only warns");
    free_settings(&cfg);
    chmod(path, 0620);
    memset(&cfg, 0, sizeof(cfg));
    expect_true(init_validate(&cfg, "-K", path, "-m", "8123"), "group-writable secret file only warns");
    free_settings(&cfg);
    unlink(path);

    if (mkdtemp(dirpath))
    {
        memset(&cfg, 0, sizeof(cfg));
        expect_true(!init_validate(&cfg, "-K", dirpath, "-m", "8123"), "directory as secret file refused");
        free_settings(&cfg);
        rmdir(dirpath);
    }
}

static void test_socks_pass_file(void)
{
    char path[] = "/tmp/zroxy_secret_XXXXXX";
    zroxy_t cfg = {0};

    make_secret_file(path, "p@ss:word\n", 10, 0600);
    expect_true(init_validate(&cfg, "--sockspassfile", path, "-s", "alice@127.0.0.1:1081"), "socks pass file validates");
    expect_true(cfg.socks != NULL, "socks parsed with pass file");
    if (cfg.socks)
    {
        expect_string(cfg.socks->user, "alice", "socks user with pass file");
        expect_string(cfg.socks->pass, "p@ss:word", "socks pass loaded from file");
    }
    free_settings(&cfg);

    /* option order must not matter */
    memset(&cfg, 0, sizeof(cfg));
    expect_true(init_validate(&cfg, "-s", "alice@127.0.0.1", "-S", path), "socks pass file after the spec");
    free_settings(&cfg);

    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-S", path, "-s", "alice:inline@127.0.0.1"), "socks inline and file rejected");
    free_settings(&cfg);

    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-S", path, "-s", "127.0.0.1:1080"), "socks pass file without a user rejected");
    free_settings(&cfg);

    memset(&cfg, 0, sizeof(cfg));
    expect_true(!init_validate(&cfg, "-S", path, "-m", "8123"), "socks pass file without socks rejected");
    free_settings(&cfg);

    memset(&cfg, 0, sizeof(cfg));
    /* validate fails on the missing LDNS, after the secret files are loaded */
    init_validate(&cfg, "-X", path, "-x", "bob@127.0.0.1");
    expect_true(cfg.dnsserver && cfg.dnsserver->Socks, "dns socks parsed with pass file");
    if (cfg.dnsserver && cfg.dnsserver->Socks)
        expect_string(cfg.dnsserver->Socks->pass, "p@ss:word", "dns socks pass loaded from file");
    free_settings(&cfg);
    unlink(path);

    {
        char longbuf[300];
        memset(longbuf, 'b', 256);
        longbuf[256] = '\n';
        strcpy(path, "/tmp/zroxy_secret_XXXXXX");
        make_secret_file(path, longbuf, 257, 0600);
        memset(&cfg, 0, sizeof(cfg));
        expect_true(!init_validate(&cfg, "-S", path, "-s", "alice@127.0.0.1"), "256 byte socks password rejected");
        free_settings(&cfg);
        unlink(path);
    }
}

static void test_config_secret_files(void)
{
    char secret[] = "/tmp/zroxy_secret_XXXXXX";
    char conf[] = "/tmp/zroxy_secret_conf_XXXXXX";
    char text[512];
    zroxy_t cfg = {0};

    make_secret_file(secret, "tok123\n", 7, 0600);
    snprintf(text, sizeof(text), "MONITOR = 8123\nMONITORTOKENFILE = %s\nSOCKS = u@127.0.0.1\nSOCKSPASSFILE = %s\n", secret, secret);
    make_secret_file(conf, text, strlen(text), 0644);
    expect_true(args_parse_config(&cfg, conf), "config with secret files parses");
    expect_true(args_validate(&cfg), "config with secret files validates");
    expect_string(cfg.monitor_token, "tok123", "config token file value");
    if (cfg.socks)
        expect_string(cfg.socks->pass, "tok123", "config socks pass file value");
    free_settings(&cfg);
    unlink(conf);
    unlink(secret);
}

static void test_argv_scrub(void)
{
    zroxy_t cfg = {0};
    char a0[] = "zroxy";
    char a1[] = "-k";
    char a2[] = "topsecret";
    char a3[] = "-s";
    char a4[] = "u:hunter2@127.0.0.1:1080";
    char a5[] = "-d";
    char a6[] = "127.0.0.1:5353";
    const char *argv[] = {a0, a1, a2, a3, a4, a5, a6};

    reset_getopt();
    expect_true(args_init(&cfg, 7, argv), "args_init with inline secrets");
    args_scrub_argv();
    expect_true(a2[0] == '\0' && a2[4] == '\0', "inline token wiped from argv");
    expect_true(a4[0] == '\0' && a4[3] == '\0' && a4[8] == '\0', "inline socks spec wiped from argv");
    expect_string(a6, "127.0.0.1", "other arguments untouched");
    expect_string(cfg.monitor_token, "topsecret", "token survives the argv wipe");
    if (cfg.socks)
        expect_string(cfg.socks->pass, "hunter2", "socks pass survives the argv wipe");
    free_settings(&cfg);
}

static void test_run_identity(void)
{
    struct passwd *me = getpwuid(geteuid());
    struct group *mygrp = getgrgid(getegid());
    char a0[] = "zroxy";
    char u1[] = "--user";
    char g1[] = "--group";

    expect_true(me != NULL, "current user is known");
    if (!me)
        return;
    {
        zroxy_t cfg = {0};
        const char *argv[] = {a0, u1, me->pw_name};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "--user parses");
        expect_true(cfg.run_user && strcmp(cfg.run_user, me->pw_name) == 0, "--user is stored");
        expect_true(args_validate(&cfg), "the current user validates");
        expect_true(!cfg.drop_priv, "the current user needs no privilege drop");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char short_opt[] = "-U";
        const char *argv[] = {a0, short_opt, me->pw_name};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "-U parses");
        expect_true(cfg.run_user != NULL, "-U is stored");
        free_settings(&cfg);
    }
    if (mygrp)
    {
        zroxy_t cfg = {0};
        const char *argv[] = {a0, u1, me->pw_name, g1, mygrp->gr_name};
        reset_getopt();
        expect_true(args_init(&cfg, 5, argv), "--user with --group parses");
        expect_true(cfg.run_group && strcmp(cfg.run_group, mygrp->gr_name) == 0, "--group is stored");
        expect_true(args_validate(&cfg), "the current user and group validate");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char name[] = "zroxy-no-such-user";
        const char *argv[] = {a0, u1, name};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "an unknown user still parses");
        expect_true(!args_validate(&cfg), "an unknown user is rejected");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        char name[] = "zroxy-no-such-group";
        const char *argv[] = {a0, u1, me->pw_name, g1, name};
        reset_getopt();
        expect_true(args_init(&cfg, 5, argv), "an unknown group still parses");
        expect_true(!args_validate(&cfg), "an unknown group is rejected");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        const char *argv[] = {a0, g1, "root"};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "--group alone parses");
        expect_true(!args_validate(&cfg), "--group without --user is rejected");
        free_settings(&cfg);
    }
    if (geteuid() != 0)
    {
        zroxy_t cfg = {0};
        char root[] = "root";
        const char *argv[] = {a0, u1, root};
        reset_getopt();
        expect_true(args_init(&cfg, 3, argv), "--user root parses");
        expect_true(!args_validate(&cfg), "a non-root process cannot switch to another user");
        free_settings(&cfg);
    }
    {
        zroxy_t cfg = {0};
        zroxy_t cfg2 = {0};
        char template_path[] = "/tmp/zroxy_args_test_XXXXXX";
        int fd = mkstemp(template_path);
        char text[256];
        if (fd < 0)
        {
            fprintf(stderr, "FAIL: mkstemp failed: %s\n", strerror(errno));
            failures++;
            return;
        }
        snprintf(text, sizeof(text), "USER = %s\n", me->pw_name);
        write_all_or_fail(fd, text);
        close(fd);
        expect_true(args_parse_config(&cfg, template_path), "config USER parses");
        expect_true(cfg.run_user && strcmp(cfg.run_user, me->pw_name) == 0, "config USER value");
        expect_true(args_validate(&cfg), "config USER validates");
        free_settings(&cfg);

        fd = open(template_path, O_WRONLY | O_TRUNC);
        write_all_or_fail(fd, "USER = zroxy-no-such-user\nGROUP = zroxy-no-such-group\n");
        close(fd);
        expect_true(args_parse_config(&cfg2, template_path), "config USER and GROUP parse");
        expect_true(cfg2.run_group != NULL, "config GROUP value");
        expect_true(!args_validate(&cfg2), "config with an unknown user is rejected");
        unlink(template_path);
        free_settings(&cfg2);
    }
}

int main(void)
{
    log_set_quiet(1);

    test_cli_listener_with_bind_and_remote();
    test_cli_listener_defaults();
    test_cli_socks_case_preserved();
    test_cli_monitor_and_sni_timeout();
    test_cli_monitor_bind_and_token();
    test_destination_policy_options();
    test_open_proxy_option();
    test_config_value_case_preserved();
    test_config_port_key_case_insensitive();
    test_cli_socks_no_auth_cleanup_safe();
    test_cli_socks_user_no_pass_cleanup_safe();
    test_config_dns_only_cleanup_safe();
    test_config_dns_with_dsocks_no_auth_cleanup_safe();
    test_config_dns_with_snip_cleanup_safe();
    test_cli_rejects_overlong_bind_and_bad_port();
    test_cli_accepts_long_dns_hostname();
    test_dns_option_order_and_last_listener_wins();
    test_repeated_ldns_resets_default_port();
    test_config_dns_timeout_before_listener();
    test_dns_validation();
    test_dns_connection_limit();
    test_sni_idle_timeout();
    test_dns_cache_and_ttl_ranges();
    test_config_rejects_blank_value();
    test_config_minimal_cleanup_safe();
    test_repeated_port_lines_append();
    test_repeated_cli_port_appends();
    test_config_and_cli_ports_append();
    test_duplicate_listener_rejected();
    test_port_failure_keeps_earlier_list();
    test_config_includes_itself();
    test_config_include_cycle();
    test_config_include_depth();
    test_config_include_twice_in_a_row();
    test_monitor_token_file();
    test_secret_file_contents();
    test_secret_file_permissions();
    test_socks_pass_file();
    test_config_secret_files();
    test_argv_scrub();
    test_run_identity();

    return failures == 0 ? 0 : 1;
}
