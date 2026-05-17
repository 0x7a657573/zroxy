#ifndef NET_IO_H_
#define NET_IO_H_

#include <stdbool.h>
#include <stddef.h>

bool net_write_all(int fd, const void *buf, size_t len);
bool net_read_exact(int fd, void *buf, size_t len);

#endif /* NET_IO_H_ */
