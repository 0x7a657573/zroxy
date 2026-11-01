/*
 * SOCKS5 server replies, parsed by socks5_connect.
 *
 * socks5_connect dials the proxy itself, so the harness stands in for the
 * proxy: a loopback listener whose accepted connection receives the whole
 * input and is then closed. The client reads the method choice, the optional
 * password status and the connect reply from that one byte stream, so every
 * byte of the input lands in a different parse step. The helper thread ends
 * when the peer closes, and the client uses a 1 second socket timeout, so a
 * run cannot hang.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zroxy/net_io.h>
#include <zroxy/socks.h>

#include "fuzz_common.h"

#define MAX_REPLY 4096u

static int listen_fd = -1;
static uint16_t listen_port;

typedef struct
{
	const uint8_t *data;
	size_t size;
} reply_t;

static void *serve(void *arg)
{
	const reply_t *reply = arg;
	struct pollfd pfd = { listen_fd, POLLIN, 0 };
	int fd = poll(&pfd, 1, 2000) == 1 ? accept(listen_fd, NULL, NULL) : -1;

	if (fd >= 0)
	{
		(void)net_write_all_ms(fd, reply->data, reply->size, 1000);
		close(fd);
	}
	return NULL;
}

static bool setup(void)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listen_fd < 0)
		return false;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(listen_fd, 1) != 0 ||
	    getsockname(listen_fd, (struct sockaddr *)&addr, &len) != 0)
		return false;
	listen_port = ntohs(addr.sin_port);
	return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char host[] = "127.0.0.1";
	char user[] = "user";
	char pass[] = "pass";
	sockshost_t socks = { host, 0, user, pass };
	static const char *const targets[] = { "example.com", "192.0.2.1" };
	reply_t reply;
	uint8_t *in;
	size_t i;

	fuzz_init_once();
	if (listen_fd < 0 && !setup())
		abort();
	if (size > MAX_REPLY)
		size = MAX_REPLY;
	socks.port = listen_port;
	in = fuzz_dup(data, size);
	reply.data = in;
	reply.size = size;

	/* Both request forms: a domain name and an IPv4 literal. */
	for (i = 0; i < sizeof(targets) / sizeof(targets[0]); i++)
	{
		pthread_t tid;
		int fd = -1;

		if (pthread_create(&tid, NULL, serve, &reply) != 0)
			abort();
		if (socks5_connect(&fd, &socks, targets[i], 443, false, 1) && fd >= 0)
			close(fd);
		pthread_join(tid, NULL);
	}
	free(in);
	return 0;
}
