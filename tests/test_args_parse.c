#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "args.h"
#include "log.h"

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
    expect_int(cfg.snitimeout, 45, "sni timeout value");

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

int main(void)
{
    log_set_quiet(1);

    test_cli_listener_with_bind_and_remote();
    test_cli_listener_defaults();
    test_cli_socks_case_preserved();
    test_cli_monitor_and_sni_timeout();
    test_config_value_case_preserved();
    test_config_port_key_case_insensitive();

    return failures == 0 ? 0 : 1;
}
