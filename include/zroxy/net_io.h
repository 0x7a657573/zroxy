#ifndef NET_IO_H_
#define NET_IO_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool net_write_all(int fd, const void *buf, size_t len);
bool net_read_exact(int fd, void *buf, size_t len);

/* Raise sub-second timeouts to 1s and cap the result at 86400s. */
int net_timeout_ms(int timeout_sec);
int64_t net_mono_ms(void);
bool net_wait_fd(int fd, int events, int64_t deadline_ms);
bool net_write_all_ms(int fd, const void *buf, size_t len, int timeout_ms);
bool net_read_exact_ms(int fd, void *buf, size_t len, int timeout_ms);

#endif /* NET_IO_H_ */
