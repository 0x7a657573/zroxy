#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <zroxy/config.h>
#include <zroxy/filter.h>
#include <zroxy/log.h>

static int failures = 0;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void expect_false(bool value, const char *name)
{
    if (value)
    {
        fprintf(stderr, "FAIL: %s expected false\n", name);
        failures++;
    }
}

static void test_matching(void)
{
    const char *entries[] = {
        "example.com",
        "*.example.com",
        "*.Mixed.Test",
        "api?.wild*.org",
        "",
        "   # comment line",
        "  spaced.test  ",
        "dotted.test.",
    };
    filter_t *filter = filter_from_list(entries, sizeof(entries) / sizeof(entries[0]));
    expect_true(filter != NULL, "build filter");
    if (!filter)
        return;

    expect_true(filter_count(filter) == 6, "blank and comment lines are skipped");

    expect_true(filter_match(filter, "example.com"), "exact match");
    expect_true(filter_match(filter, "api.example.com"), "wildcard subdomain match");
    expect_true(filter_match(filter, "a.b.example.com"), "wildcard matches deeper labels");
    expect_false(filter_match(filter, "api.example.org"), "wildcard unrelated domain");
    expect_false(filter_match(filter, "badexample.com"), "wildcard does not overmatch suffix");
    expect_false(filter_match(filter, "other.com"), "non-match");

    /* an exact entry must not act as a prefix */
    expect_false(filter_match(filter, "example.com.attacker.net"), "exact entry is not a prefix");
    expect_false(filter_match(filter, "example.community"), "exact entry is not a prefix of a label");
    expect_false(filter_match(filter, "example.co"), "shorter name does not match");

    expect_true(filter_match(filter, "Example.COM"), "exact match ignores case");
    expect_true(filter_match(filter, "API.Example.com"), "wildcard match ignores case");
    expect_false(filter_match(filter, "BadExample.com"), "case folding does not overmatch");
    expect_true(filter_match(filter, "www.mixed.test"), "uppercase pattern matches lowercase host");
    expect_true(filter_match(filter, "example.com."), "trailing dot on the query is ignored");

    expect_true(filter_match(filter, "api1.wild-card.org"), "generic pattern match");
    expect_false(filter_match(filter, "api.wild.org"), "'?' needs exactly one character");
    expect_false(filter_match(filter, "api1.wild.org.evil"), "generic pattern is anchored at the end");

    expect_true(filter_match(filter, "spaced.test"), "entry whitespace is trimmed");
    expect_true(filter_match(filter, "dotted.test"), "entry trailing dot is ignored");

    expect_false(filter_match(filter, ""), "empty host");
    expect_false(filter_match(NULL, "example.com"), "NULL filter");

    filter_free(filter);
}

static void test_reject_long_entry(void)
{
    char longname[ZROXY_MAX_HOSTNAME + 8];
    const char *entries[1] = { longname };
    memset(longname, 'a', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    expect_true(filter_from_list(entries, 1) == NULL, "over-long entry rejects the list");
}

static void test_many_entries(void)
{
    enum { N = 20000 };
    static char names[N][32];
    static const char *entries[N];
    int i;
    filter_t *filter;
    for (i = 0; i < N; i++)
    {
        snprintf(names[i], sizeof(names[i]), "host%d.example.net", i);
        entries[i] = names[i];
    }
    filter = filter_from_list(entries, N);
    expect_true(filter != NULL, "build large filter");
    if (!filter)
        return;
    expect_true(filter_count(filter) == N, "large filter count");
    expect_true(filter_match(filter, "host0.example.net"), "first of many");
    expect_true(filter_match(filter, "host19999.example.net"), "last of many");
    expect_false(filter_match(filter, "host20000.example.net"), "absent from many");
    filter_free(filter);
}

int main(void)
{
    log_set_quiet(1);
    test_matching();
    test_reject_long_entry();
    test_many_entries();
    return failures == 0 ? 0 : 1;
}
