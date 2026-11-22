/*
 *
 */

#ifndef DNSSERVER_H_
#define DNSSERVER_H_
#include <stdint.h>
#include <stdbool.h>
#include <zroxy/config.h>
#include <zroxy/socks.h>
#include <zroxy/statistics.h>
#include <sys/socket.h>
#include <zroxy/filter.h>
#include <zroxy/acl.h>
#include <zroxy/settings.h>
#include <zroxy/dnsrate.h>

struct dnsserver;

/* Bind the sockets and start the single event-loop thread. NULL on failure. */
struct dnsserver *dnsserver_start(dnshost_t *config);
/* Stop the event loop, join its thread and free. */
void dnsserver_stop(struct dnsserver *dns);

#endif /* DNSSERVER_H_ */
