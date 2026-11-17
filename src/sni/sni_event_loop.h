/*
 * SNI data plane.
 *
 * One event-loop thread serves a listener. Accepted clients are connection
 * objects on that loop, not additional threads. The loop is epoll on Linux
 * and poll everywhere else (including a Linux build with SNI_FORCE_POLL).
 *
 * Each connection is a state machine: read the ClientHello or HTTP Host,
 * check the whitelist and reject IP literals, connect upstream directly or
 * through SOCKS5, then relay with fixed buffers. Sockets stay non-blocking.
 * Configuration objects pointed to by SniServer_t stay owned by the caller.
 */
#ifndef SNI_EVENT_LOOP_H_
#define SNI_EVENT_LOOP_H_

#include <stdbool.h>
#include <stdint.h>

#include <netinet/in.h>
#include <zroxy/sniproxy.h>

/* Same bound the previous handler used for the initial client read. */
#define SNI_HELLO_CAP 0x2000u
#define SNI_RELAY_CAP 0x2000u
/* The old handshake select waited at most this long for the next byte. */
#define SNI_HELLO_IDLE_MS 5000

typedef struct sni_listener sni_listener;

/* Joinable listener. Caller must sni_listener_close it. */
bool sni_listener_open(const SniServer_t *cfg, sni_listener **out);
void sni_listener_close(sni_listener *ls);

#ifdef SNI_TEST_HOOKS
/* Single-connection path; compiled only into the SNI_TEST_HOOKS libraries. */
typedef struct
{
	int		 connid;
	struct sockaddr_in cli;
	socklen_t addr_len;
	SniServer_t SniConfig;
} sniclient_t;

/* Thread entry: run one client via sni_connection_run, release its slot, free it. */
void *sni_client_handler(void *arg);

/*
 * Run one already-accepted client to completion on the calling thread.
 * Closes client->connid and stores -1. Does not free client and does not
 * take or release an SNI connection slot. Reports stats_close_connection when
 * SniConfig.sta is set, matching the previous handler.
 */
void sni_connection_run(sniclient_t *client);

typedef struct {
	int read_limit;     /* 0 = full reads, else max bytes per read */
	int write_limit;    /* 0 = full writes, else max bytes per write */
	int eagain_write;   /* forced EAGAIN returns from event-loop writes */
	int eintr_read;
	int eintr_write;
	int eintr_connect;
	int eintr_wait;
	int fail_wait;      /* forced non-EINTR wait failures (loop exits) */
	int fail_allocs;
	int fail_accept;    /* forced EMFILE returns from accept() */
} sni_test_faults;

void sni_test_set_faults(const sni_test_faults *faults);
void sni_test_clear_faults(void);
void sni_test_reset_counters(void);
uint32_t sni_test_client_bytes(void);
uint32_t sni_test_max_pending(void);
uint32_t sni_test_eagain_count(void);
uint32_t sni_test_wait_calls(void);
void sni_test_set_hello_idle_ms(int ms);
uint32_t sni_test_relay_yields(void);
uint32_t sni_test_accept_pauses(void);
void sni_test_set_relay_budget(uint32_t bytes); /* 0 restores the default */
#endif

#endif /* SNI_EVENT_LOOP_H_ */
