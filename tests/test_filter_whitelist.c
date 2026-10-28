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

int main(void)
{
    log_set_quiet(1);

    item_t exact = {0};
    item_t wildcard = {0};
    item_t other = {0};
    filter_t filter = {0};

    strcpy(exact.Rec, "example.com");
    strcpy(wildcard.Rec, "*.example.com");
    strcpy(other.Rec, "nomatch.local");

    exact.Next = &wildcard;
    wildcard.Next = &other;
    other.Next = NULL;

    filter.item = &exact;
    pthread_mutex_init(&filter.Lock, NULL);

    expect_true(filter_IsWhite(&filter, "example.com"), "exact match");
    expect_true(filter_IsWhite(&filter, "api.example.com"), "wildcard subdomain match");

    expect_false(filter_IsWhite(&filter, "api.example.org"), "wildcard unrelated domain");
    expect_false(filter_IsWhite(&filter, "badexample.com"), "wildcard does not overmatch suffix");
    expect_false(filter_IsWhite(&filter, "other.com"), "non-match");

    expect_true(filter_IsWhite(&filter, "Example.COM"), "exact match ignores case");
    expect_true(filter_IsWhite(&filter, "API.Example.com"), "wildcard match ignores case");
    expect_false(filter_IsWhite(&filter, "BadExample.com"), "case folding does not overmatch");

    strcpy(other.Rec, "*.Mixed.Test");
    expect_true(filter_IsWhite(&filter, "www.mixed.test"), "uppercase pattern matches lowercase host");

    pthread_mutex_destroy(&filter.Lock);

    return failures == 0 ? 0 : 1;
}
