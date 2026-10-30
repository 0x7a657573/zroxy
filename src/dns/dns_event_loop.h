#ifndef DNS_EVENT_LOOP_H_
#define DNS_EVENT_LOOP_H_

#include <stdbool.h>
#include <zroxy/dnsproxy.h>

/* The loop owns all DNS sockets until dns_event_loop_stop joins it. */
bool dns_event_loop_start(dnsserver_t *dns);
void dns_event_loop_stop(dnsserver_t *dns);

#endif
