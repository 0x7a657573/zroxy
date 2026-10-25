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
| `sniproxy/sniproxy.c` | Accept loop and the SNI worker cap check |
| `sniproxy/sniclient.c` | One client: read until SNI or HTTP `Host`, connect upstream, copy bytes |
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
- An SNI worker that fails while writing upstream closes that upstream socket and leaves the outer loop, so the later close of the same descriptor is not run. The client descriptor is closed once at the end of the handler.
- The monitor closes the client descriptor once. If the worker cap is full, or the descriptor is outside `FD_SETSIZE`, the accept loop closes it and does not start a thread. The default listen address is `127.0.0.1`. Header reads stop at 4096 bytes or at one absolute header deadline. A later byte does not move that deadline.
- `fifo_init` destroys its mutex if the buffer allocation fails. `fifo_deinit` frees the buffer and destroys the mutex.
- A failed whitelist reload frees the new list and keeps the list already published. Readers hold the filter mutex for the whole walk.

## Threads and locks

Workers are detached. The accept side reserves a slot before `pthread_create` and the worker releases it when it finishes. A release with nothing held does not wrap the counter. SNI allows 1024 workers, the monitor 32, and DNS 128.

The filter mutex covers the list pointer and whitelist checks. Each statistics object has its own mutex. The monitor's `state_lock` covers the list head. `state_get` takes the statistics mutex and is not called while `state_lock` is held. Filter and statistics locks are not nested.

## Data path

SNI and HTTP host detection only choose the upstream. After that, the original bytes are copied in both directions until read returns 0 or a write fails. An IP address in the host field is rejected for SNI.

DNS answers are synthetic A/AAAA records when the whitelist matches. Other queries are forwarded upstream. `recvfrom` errors, including `EINTR`, do not enqueue a message.

The monitor writes one JSON document for an authorized `GET /` and closes. Other methods and paths are rejected. A configured bearer token is required before the counters are written. Connect, SOCKS handshake, and SNI relay writes use a deadline so a stalled peer releases its worker.
