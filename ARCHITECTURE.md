# Architecture

zroxy is one process. `src/main.c` parses arguments, ignores `SIGPIPE`, loads an optional whitelist, then starts the monitor, the DNS listener, and one SNI listener per configured port. It then sleeps forever. `Free_DnsServer` sits after that loop and does not run on the normal path. Process exit reclaims the remaining sockets, threads, and config heap.

This is the layout the code uses. It is not a production-readiness statement.

## Modules

| Path | Role |
| --- | --- |
| `src/main.c` | Startup order and the service loop |
| `src/args.c` | CLI and config file. Values are bounded and rejected when they do not fit |
| `network/net.c`, `network/net_io.c` | Listen, connect, hostname extraction, exact read/write |
| `network/socks/socks.c` | SOCKS5 client handshake |
| `sniproxy/sniproxy.c` | Bind one SNI port and start its event-loop thread |
| `sniproxy/sni_event_loop.c` | Non-blocking SNI state machine on epoll (Linux) or poll |
| `sniproxy/sni_resolver.c` | Fixed pool of resolver threads and completion sinks |
| `sniproxy/sniclient.c` | 1024 connection-slot cap, and the single-connection entry used by tests |
| `sniproxy/filter/filter.c` | Whitelist file, reload, and match |
| `dnsproxy/dnsserver.c` | DNS socket lifecycle |
| `dnsproxy/dnsproxy.c` | UDP receive, queue, upstream TCP or SOCKS, worker cap |
| `dnsproxy/dns.c` | DNS decode and bounded encode |
| `fifo/fifo.c` | Fixed-size message queue used by DNS |
| `statistics/statistics.c` | Per-listener counters |
| `statistics/monitor.c` | HTTP JSON status page and its worker cap |
| `log/log.c` | Logging |

`network/net.h` does not include the logger. Protocol parsers take a buffer and a length. They do not assume a NUL terminator on network input.

## Ownership

- `zroxy_t` owns the port list, the SOCKS settings, the DNS config object, the monitor port, bind address, token, and the whitelist path string until `main` frees that path. An enabled monitor, DNS listener, or SNI listener that cannot bind or start its thread makes `main` return 1. A service that was not configured is skipped.
- The DNS server stores the config's SOCKS pointer and whitelist pointer. `localdns_free` closes the UDP socket and frees the DNS queue. It does not free the SOCKS object.
- `socks5_connect` owns the descriptor it creates. Every failure path closes it and stores `-1`.
- Each SNI listener is one event-loop thread. That thread owns the listen socket, the wake pipe, and every accepted connection. A connection object is freed on that thread after both descriptors are removed from the poll set and closed. A descriptor is stored as `-1` after `close`, and it is not closed again. The caller keeps the `SniServer_t` filter, SOCKS, and statistics objects.
- The monitor closes the client descriptor once. If the worker cap is full, or the descriptor is outside `FD_SETSIZE`, the accept loop closes it and does not start a thread. The default listen address is `127.0.0.1`. Header reads stop at 4096 bytes or at one absolute header deadline. A later byte does not move that deadline.
- `fifo_init` destroys its mutex if the buffer allocation fails. `fifo_deinit` frees the buffer and destroys the mutex.
- A failed whitelist reload frees the new list and keeps the list already published. Readers hold the filter mutex for the whole walk.

## Threads and locks

DNS and monitor workers are detached. Their accept side reserves a slot before `pthread_create`, and the worker releases it when it finishes. A release with nothing held does not wrap the counter. The monitor allows 32 workers and DNS allows 128.

SNI does not create a thread per accepted client. `SniProxy_Start` detaches one long-lived event-loop thread per listener. The 1024 figure is a cap on connections alive on those loops, not a thread count. The loop uses epoll on Linux and poll otherwise, including a Linux build that defines `SNI_FORCE_POLL`. It does not call `select` or `FD_SET`. Client and upstream sockets are non-blocking.

Name lookup does not run on the event-loop thread. One process-wide pool has 4 resolver threads and 128 fixed slots. Each listener gets its own completion pipe and a client-slot quota, with 8 slots reserved for the SOCKS hostname and 3 for single-connection runs. A slow lookup cannot stall the other connections on that listener. The configured SOCKS hostname is resolved once at startup and refreshed in the background. A numeric SOCKS address never enters the pool. If the cache has no usable address, a new SOCKS connection fails immediately. Shutdown waits a bounded interval for the workers. If one is still inside `getaddrinfo()`, the threads are detached and the pool stays allocated until process exit; its mutex and slots are not destroyed.

While a connection is resolving or connecting, the client socket stays registered only so a reset or full hangup can close it. Readable data is not requested in those states, so a buffered client byte cannot spin epoll or poll. The hostname is lowercased and one trailing dot is removed before the whitelist check and before `getaddrinfo()`. An address that is loopback on a listener port, an unspecified address, link-local, multicast, or an IPv4-mapped form of those is not dialed. Private ranges are dialed. A wildcard bind (`0.0.0.0`) rejects every loopback and unspecified address, because any of those would be this proxy.

The filter mutex covers the list pointer and whitelist checks. Each statistics object has its own mutex. The monitor's `state_lock` covers the list head. `state_get` takes the statistics mutex and is not called while `state_lock` is held. Filter and statistics locks are not nested.

## Data path

SNI and HTTP host detection only choose the upstream. The initial client bytes stay in an 8KB buffer and are written upstream after the direct or SOCKS5 connect. Each relay direction then uses its own 8KB buffer and stops reading while that buffer still holds data. A clean EOF is forwarded with `shutdown(SHUT_WR)` after the buffer drains, so one direction can finish while the other still carries data. A hard read or write error closes both sides. An IP address in the host field is rejected for SNI. Handshake and relay waits use the configured timeout; the handshake also ends if 5 seconds pass with no new client byte.

DNS answers are synthetic A/AAAA records when the whitelist matches. Other queries are forwarded upstream. `recvfrom` errors, including `EINTR`, do not enqueue a message.

The monitor writes one JSON document for an authorized `GET /` and closes. Other methods and paths are rejected. A configured bearer token is required before the counters are written. Connect, SOCKS handshake, and relay writes use a deadline so a stalled peer releases its monitor or DNS worker. An SNI connection that stops making progress hits the same configured deadline and is closed on the event-loop thread.
