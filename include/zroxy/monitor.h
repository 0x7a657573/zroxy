/*
 *
 */
#ifndef MONITOR_H_
#define MONITOR_H_
#include <stdbool.h>
#include <stdint.h>
#include <zroxy/statistics.h>

/*
 * Appends the members of a top-level report object as `"Key" : value` pairs
 * separated by ",\n", with no trailing separator. The monitor adds the braces.
 */
typedef bool (*mon_section_fn)(void *ctx, char **ptr, char *end);

typedef struct mon mon_t;

mon_t *monitor_init(uint16_t port, const char *bind_ip, const char *token, int header_timeout_sec);
/*
 * Adds a caller-owned statistics object to the report, newest first. The
 * monitor only borrows it: stat must outlive the monitor and is never freed
 * here. Returns false for a NULL argument.
 */
bool monitor_attach_stat(mon_t *self, statistics_t *stat);
/* Adds a top-level object written by fn. ctx must outlive the monitor. */
bool monitor_add_section(mon_t *self, const char *name, mon_section_fn fn, void *ctx);
/*
 * Stops accepting, joins the monitor thread, closes every client, the listener
 * and pipe, then frees the sections, token and monitor itself. The attached
 * statistics objects stay the caller's. After it returns, nothing reads the
 * attached statistics objects or the sections' contexts any more.
 * Call it while the statistics objects and the sections' contexts are still valid.
 */
void monitor_stop(mon_t *self);

#ifdef MON_TEST_HOOKS
#include <stddef.h>
#include <stdint.h>
/* -1 while the request line is incomplete, else 0 or the HTTP status to send. */
int monitor_test_classify(const uint8_t *buf, size_t len);
bool monitor_test_headers_done(const uint8_t *buf, size_t len);
bool monitor_test_authorized(const uint8_t *buf, size_t len, const char *token);
#endif

#endif /* MONITOR_H_ */
