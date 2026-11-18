#ifndef NET_IO_H_
#define NET_IO_H_

#include <stdint.h>

/* Raise sub-second timeouts to 1s and cap the result at 86400s. */
int net_timeout_ms(int timeout_sec);
int64_t net_mono_ms(void);

#endif /* NET_IO_H_ */
