#ifndef TEST_SUPPORT_H_
#define TEST_SUPPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zroxy/socks.h>

/* Blocking dial of host:port (IPv4 only); true and *sockfd set on success. */
bool net_connect(int *sockfd, const char *hostname, uint16_t port, int timeout_sec);

/* Wait for fd readiness until the absolute monotonic deadline. */
bool net_wait_fd(int fd, int events, int64_t deadline_ms);

/* Write exactly len bytes within timeout_ms. */
bool net_write_all_ms(int fd, const void *buf, size_t len, int timeout_ms);

/* Read exactly len bytes within timeout_ms. */
bool net_read_exact_ms(int fd, void *buf, size_t len, int timeout_ms);

/* Blocking SOCKS5 client: dial the proxy and run the handshake to host:port. */
bool socks5_connect(int *sockfd, sockshost_t *socks, const char *host, int port, int timeout_sec);

#endif /* TEST_SUPPORT_H_ */
