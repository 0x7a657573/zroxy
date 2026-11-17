#ifndef ZROXY_RESOLVER_H_
#define ZROXY_RESOLVER_H_
#include <stdbool.h>

/* Monitor section for the shared hostname resolver pool. */
bool resolver_stats_json(void *ctx, char **ptr, char *end);

#endif /* ZROXY_RESOLVER_H_ */
