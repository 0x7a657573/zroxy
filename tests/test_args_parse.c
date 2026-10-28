#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zroxy/args.h>
#include <zroxy/log.h>

bool Parse_config(zroxy_t *ptr, char *str);

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
    Free_PortList(cfg);
    Free_DnsServer(cfg);
    if (cfg->socks)
    {
        free(cfg->socks->host);
        free(cfg->socks->user);
        free(cfg->socks->pass);
        free(cfg->socks);
    }
    free(cfg->monitorPort);
    free(cfg->monitor_token);
    free(cfg->WhitePath);
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
    expect_true(arg_Init(&cfg, 3, argv), "arg_Init listener bind/remote");
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
    expect_true(arg_Init(&cfg, 3, argv), "arg_Init listener defaults");
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
    expect_true(arg_Init(&cfg, 3, argv), "arg_Init socks");
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
    expect_true(arg_Init(&cfg, 5, argv), "arg_Init monitor + snitimeout");
    expect_true(cfg.monitorPort != NULL, "monitor port parsed");
    if (cfg.monitorPort)
    {
        expect_u16(*cfg.monitorPort, 8123, "monitor port value");
    }
    expect_string(cfg.monitor_bind, "127.0.0.1", "bare monitor port binds localhost");
    expect_int(cfg.monitor_header_timeout, 5, "default monitor header timeout");
    expect_int(cfg.snitimeout, 45, "sni timeout value");

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
    expect_true(arg_Init(&cfg, 7, argv), "arg_Init monitor bind token timeout");
    expect_true(cfg.monitorPort != NULL, "explicit monitor port parsed");
    if (cfg.monitorPort)
        expect_u16(*cfg.monitorPort, 8123, "explicit monitor port");
    expect_string(cfg.monitor_bind, "10.1.2.3", "explicit monitor bind");
    expect_string(cfg.monitor_token, "secret", "monitor token");
    expect_int(cfg.monitor_header_timeout, 7, "monitor header timeout");
    free_settings(&cfg);

    reset_getopt();
    expect_true(!arg_Init(&cfg, 3, bad_argv), "reject monitor timeout 0");
    free_settings(&cfg);

    reset_getopt();
    expect_true(!arg_Init(&cfg, 3, hi_argv), "reject monitor timeout 61");
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

    expect_true(Parse_config(&cfg, template_path), "Parse_config value case preserved");
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

    expect_true(Parse_config(&cfg, template_path), "Parse_config uppercase PORT key");
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
    expect_true(arg_Init(&cfg, 3, argv), "arg_Init socks no auth");
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
    expect_true(arg_Init(&cfg, 3, argv), "arg_Init socks user no pass");
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

    expect_true(Parse_config(&cfg, template_path), "Parse_config dns only");
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

    expect_true(Parse_config(&cfg, template_path), "Parse_config dns with dsocks no auth");
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

    expect_true(Parse_config(&cfg, template_path), "Parse_config dns with snip");
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
    expect_true(!arg_Init(&cfg, 3, argv), "reject overlong listener token");
    free_settings(&cfg);

    {
        char bad0[] = "zroxy";
        char bad1[] = "-p";
        char bad2[] = "127.0.0.1:80abc@80";
        const char *bad_argv[] = {bad0, bad1, bad2};
        reset_getopt();
        expect_true(!arg_Init(&cfg, 3, bad_argv), "reject non-numeric listener port");
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
    expect_true(arg_Init(&cfg, 3, argv), "arg_Init long DNS hostname");
    expect_true(cfg.dnsserver != NULL, "long DNS hostname allocated");
    if (cfg.dnsserver)
        expect_string(cfg.dnsserver->Remote.ip, "long.dns.example.test", "long DNS hostname stored");
    free_settings(&cfg);
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
    expect_true(!Parse_config(&cfg, template_path), "reject blank config value");
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

    expect_true(Parse_config(&cfg, template_path), "Parse_config minimal");
    expect_true(cfg.ports != NULL, "config port parsed");
    expect_true(cfg.socks == NULL, "minimal socks is NULL");
    expect_true(cfg.dnsserver == NULL, "minimal dnsserver is NULL");
    expect_true(cfg.WhitePath == NULL, "minimal WhitePath is NULL");
    expect_true(cfg.monitorPort == NULL, "minimal monitorPort is NULL");

    unlink(template_path);
    free_settings(&cfg);
}

int main(void)
{
    log_set_quiet(1);

    test_cli_listener_with_bind_and_remote();
    test_cli_listener_defaults();
    test_cli_socks_case_preserved();
    test_cli_monitor_and_sni_timeout();
    test_cli_monitor_bind_and_token();
    test_config_value_case_preserved();
    test_config_port_key_case_insensitive();
    test_cli_socks_no_auth_cleanup_safe();
    test_cli_socks_user_no_pass_cleanup_safe();
    test_config_dns_only_cleanup_safe();
    test_config_dns_with_dsocks_no_auth_cleanup_safe();
    test_config_dns_with_snip_cleanup_safe();
    test_cli_rejects_overlong_bind_and_bad_port();
    test_cli_accepts_long_dns_hostname();
    test_config_rejects_blank_value();
    test_config_minimal_cleanup_safe();

    return failures == 0 ? 0 : 1;
}
