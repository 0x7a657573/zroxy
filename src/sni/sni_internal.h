#ifndef ZROXY_SNI_INTERNAL_H
#define ZROXY_SNI_INTERNAL_H

#include "sni_event_loop.h"
#include "reactor.h"
#include "resolver.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef SNI_TEST_HOOKS
enum sni_fault {
	SNI_FAULT_EINTR_READ,
	SNI_FAULT_EAGAIN_WRITE,
	SNI_FAULT_EINTR_WRITE,
	SNI_FAULT_FAIL_ACCEPT,
	SNI_FAULT_EINTR_CONNECT,
	SNI_FAULT_EINTR_WAIT,
	SNI_FAULT_FAIL_WAIT,
	SNI_FAULT_FAIL_ALLOCS
};

int sni_take_fault(enum sni_fault which);
int sni_read_limit(void);
int sni_write_limit(void);
int sni_hello_idle_ms_override(void);
uint32_t sni_relay_budget_override(void);
void sni_note_client_read(uint32_t n);
void sni_note_pending(uint32_t n);
void sni_note_eagain(void);
void sni_note_wait(void);
void sni_note_relay_yield(void);
void sni_note_accept_pause(void);
#else
static inline void sni_note_client_read(uint32_t n) { (void)n; }
static inline void sni_note_pending(uint32_t n) { (void)n; }
static inline void sni_note_eagain(void) { }
static inline void sni_note_wait(void) { }
static inline void sni_note_relay_yield(void) { }
static inline void sni_note_accept_pause(void) { }
#endif

#define SNI_SOCKS_CAP 600u
/* Bytes one relay_pump call may move before yielding to other connections. */
#define SNI_RELAY_BUDGET (256u * 1024u)
#define SNI_ADDR_MAX 16
#define SNI_POLL_MAX 4096
/* How long the listener stays unarmed after accept() runs out of descriptors. */
#define SNI_ACCEPT_PAUSE_MS 100
/* The out-of-descriptors error is logged at most this often per listener. */
#define SNI_ACCEPT_LOG_MS 1000

#ifdef SNI_FORCE_POLL
#define SNI_USE_POLL true
#else
#define SNI_USE_POLL false
#endif

enum {
	SNI_EV_IN = RE_IN,
	SNI_EV_OUT = RE_OUT,
	SNI_EV_ERR = RE_ERR,
	SNI_EV_HUP = RE_HUP,
	/* Keep the fd registered so ERR/HUP are reported. No read or write. */
	SNI_EV_ARMED = 16
};

enum {
	SNI_TAG_CONN = 1,
	SNI_TAG_LISTEN = 2,
	SNI_TAG_WAKE = 3,
	SNI_TAG_SINK = 4
};

enum {
	SNI_ST_HELLO = 0,
	SNI_ST_RESOLVE,
	SNI_ST_CONNECT,
	SNI_ST_SOCKS,
	SNI_ST_RELAY
};

/*
 * Why a connection ended, set at the failure site and counted once by
 * conn_kill. NONE is a normal end (EOF or reset from either side of a relay,
 * listener shutdown) or an internal failure with no counter of its own.
 */
enum {
	SNI_CLOSE_NONE = 0,
	SNI_CLOSE_REFUSED,
	SNI_CLOSE_NO_HOSTNAME,
	SNI_CLOSE_BLOCKED,
	SNI_CLOSE_UNSAFE,
	SNI_CLOSE_RESOLVE,
	SNI_CLOSE_SOCKS,
	SNI_CLOSE_CONNECT,
	SNI_CLOSE_HANDSHAKE_TIMEOUT,
	SNI_CLOSE_IDLE_TIMEOUT,
	SNI_CLOSE_STALL_TIMEOUT,
	SNI_CLOSE_EVICTED,
	SNI_CLOSE_ACL_DENIED,
	SNI_CLOSE_COUNT
};

typedef struct sni_engine sni_engine;
typedef struct sni_conn sni_conn;

typedef struct sni_tag {
	int kind;
	int fd;
	sni_engine *eng;
	sni_conn *conn;
} sni_tag;

typedef struct sni_addr {
	struct sockaddr_storage sa;
	socklen_t len;
} sni_addr;

struct sni_conn {
	sni_conn *next;
	/* FIFO of connections still in HELLO, oldest first (see hello_link). */
	sni_conn *hello_prev;
	sni_conn *hello_next;
	int in_hello_list;
	sni_engine *eng;
	sni_tag client_tag;
	sni_tag up_tag;
	int client_fd;
	int up_fd;
	uint32_t client_interest;
	uint32_t up_interest;
	int state;
	int dead;
	int touched;
	int slot_held;
	int close_stats;
	int settled;
	int client_eof;
	int up_eof;
	int client_shut;
	int up_shut;
	int io_ms;
	int idle_ms;
	int socks_step;
	int naddr;
	int addr_i;
	int resolve_slot;
	uint64_t generation;
	uint64_t pending_req_id;
	int64_t hello_abs;
	int64_t last_hello;
	int64_t resolve_deadline;
	int64_t connect_deadline;
	int64_t deadline;
	int64_t idle_at;
	int64_t c2u_by;
	int64_t u2c_by;
	uint32_t rx;
	uint32_t tx;
	uint32_t hello_len;
	uint32_t c2u_len;
	uint32_t c2u_off;
	uint32_t u2c_len;
	uint32_t u2c_off;
	uint32_t socks_out_off;
	uint32_t socks_in_len;
	char host[ZROXY_MAX_HOSTNAME];
	uint8_t hello[SNI_HELLO_CAP];
	uint8_t c2u[SNI_RELAY_CAP];
	uint8_t u2c[SNI_RELAY_CAP];
	uint8_t socks_in[SNI_SOCKS_CAP];
	socks5_client socks;
	sni_addr addrs[SNI_ADDR_MAX];
	SniServer_t cfg;
};

struct sni_engine {
	reactor re;
	int listen_fd;
	int wake_r;
	int wake_w;
	uint32_t listen_interest;
	int accept_paused;
	int64_t accept_resume_at;
	int64_t accept_log_at;
	uint32_t wake_interest;
	int stop;
	SniServer_t cfg;
	sni_conn *head;
	sni_conn *hello_head;
	sni_conn *hello_tail;
	sni_tag listen_tag;
	sni_tag wake_tag;
	sni_tag sink_tag;
	resolver_sink *sink;
	uint32_t sink_interest;
	uint64_t next_generation;
};

struct sni_listener {
	pthread_t thread;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	sni_engine *eng;
	resolver_sink *sink;
	int ready;
	int ok;
};

typedef struct sni_boot {
	int listen_fd;
	SniServer_t cfg;
	sni_listener *joinable;
} sni_boot;

typedef struct sni_ready {
	sni_tag *tag;
	int fd;
	uint32_t ev;
} sni_ready;

bool sni_set_nb_cloexec(int fd);
ssize_t sni_io_read(int fd, void *buf, size_t len);
ssize_t sni_io_write(int fd, const void *buf, size_t len);
int sni_io_accept(int fd, struct sockaddr_storage *peer);
int sni_io_connect(int fd, const struct sockaddr *sa, socklen_t len);
bool sni_react_add(sni_engine *e, int fd, uint32_t ev, sni_tag *tag);
bool sni_react_mod(sni_engine *e, int fd, uint32_t ev, sni_tag *tag);
void sni_react_del(sni_engine *e, int fd);
int sni_react_wait(sni_engine *e, sni_ready *out, int max, int timeout_ms);
bool sni_watch(sni_engine *e, int fd, uint32_t ev, uint32_t *slot, sni_tag *tag);
void sni_drop_watched(sni_engine *e, int *fd, uint32_t *slot, sni_tag *tag);
int sni_read_some(int fd, uint8_t *buf, uint32_t cap, uint32_t *len);
int sni_write_some(int fd, const uint8_t *buf, uint32_t len, uint32_t *off, uint32_t *counter);
int sni_shut_write(int fd);

void sni_conn_set_state(sni_engine *e, sni_conn *c, int state);
void sni_conn_kill(sni_engine *e, sni_conn *c, int reason);
bool sni_conn_arm(sni_engine *e, sni_conn *c);
void sni_enter_relay(sni_engine *e, sni_conn *c);
void sni_socks_pump(sni_engine *e, sni_conn *c);
void sni_connect_pump(sni_engine *e, sni_conn *c, uint32_t ev);
void sni_begin_upstream(sni_engine *e, sni_conn *c);
void sni_drain_resolve(sni_engine *e);
void sni_relay_pump(sni_engine *e, sni_conn *c);
void sni_count_relayed(void);

#endif
