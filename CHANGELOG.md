# Changelog

These notes describe the `1.3.1` release. Nothing here says the result is production-ready.

## Unreleased

### Correctness

- Dropped DNS requests now abandon their statistics state when worker admission or allocation fails.
- Whitelist matching is case-insensitive for DNS names and file entries, as required by RFC 4343.
- Linux and FreeBSD whitelist watchers reload after in-place writes and file replacement.

### Test coverage

- Monitor end-to-end tests read the expected version from `src/version.h`.
- DNS end-to-end tests cover mixed-case whitelist queries and atomic or in-place whitelist saves.

## 1.3.1 - 2026-10-28

### Command-line interface

- Reworked `-h` and `--help` output into grouped General, SNI, DNS, and Monitor sections.
- Documented long-option forms, argument syntax, defaults, examples, and no-argument configuration behavior.
- Added a CTest check for both help entry points and the new output format.

## 1.3.0 - 2026-10-26

### SNI data plane

- An accepted SNI client is no longer a detached pthread. Each listener runs one event-loop thread. Linux uses epoll; other builds, and a Linux build with `SNI_FORCE_POLL`, use poll. Client and upstream sockets stay non-blocking.
- The 1024 limit is still the number of SNI connections that may be open at once. It is not a thread count. The initial read and each relay direction use a fixed 8KB buffer. A clean EOF is forwarded with `shutdown(SHUT_WR)` after that direction's buffer drains.
- `getaddrinfo()` for a non-numeric upstream name runs on a fixed pool of 4 resolver threads and 128 slots. The SNI event loop does not call it. Each listener has its own completion pipe and slot quota. The SOCKS hostname is cached and refreshed off the loop. Loopback results that point at a listener, and `::ffff:127.0.0.1` rewritten to that loopback address, are not dialed.
- The DNS listen socket is bound with `inet_pton` on the configured IPv4 literal. That avoids a glibc resolver allocation that LeakSanitizer reported when a DNS bind failed and the process exited immediately. Listen addresses are still IPv4 literals.

### Verification

- `tests/test_sni_engine.c` covers split HTTP Host and TLS ClientHello reads, partial writes, `EAGAIN`, `EINTR`, SOCKS5 success and failure, connect failure, handshake and idle timeouts, EOF and half-close, an oversized hello, allocation failure, exactly-once statistics, whitelist allow/deny, IP literals, two listeners, 1/10/100/1000 short connections, 1024 held connections, a stalled upstream beside short connections, and repeated connect/close cycles. It also covers resolver results, quota and cancellation, stale completions, SOCKS cache refresh, self-connect rejection, and a resolver worker that does not return before shutdown times out. The same binary is built with `SNI_FORCE_POLL`.
- Plain `ctest --test-dir build` passed 14/14 executed tests, including `sni_e2e`. `test_sni_engine` and `test_sni_engine_poll` also passed under `-fsanitize=address,undefined` (`ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1`, `UBSAN_OPTIONS=halt_on_error=1`) and, separately, under `-fsanitize=thread` (`TSAN_OPTIONS=halt_on_error=1`). `zroxy_benchmark` remains disabled and was not run. `musl-gcc` is not on this host.
- Earlier regression coverage remains: malformed DNS names and compression chains, truncated TLS ClientHello and SNI lengths, malformed SOCKS5 replies, partial `net_read_exact` / `net_write_all`, `EINTR` during read and `recvfrom`, `recvfrom` failure, a missing whitelist, invalid process configuration, monitor input without a finished HTTP header, the SNI connection cap, the monitor worker cap, and `SIGPIPE` on a closed upstream.

### Correctness fix found by those tests

- The monitor `Content-Length` was two bytes shorter than the JSON body (`186` versus `188` on an otherwise valid response). The header now uses the length of the body that is written. The JSON bytes are unchanged.

### Hardening already in the tree

- DNS, TLS SNI, SOCKS5, and config parsers reject truncated or oversized input instead of reading off the end of the buffer.
- A missing whitelist file aborts startup. A bad reload keeps the previous list.
- `SIGPIPE` is ignored. Exact reads and writes retry `EINTR`. A failed `recvfrom` does not enqueue work.
- DNS and monitor accept paths cap detached workers. SNI caps concurrent connections on its event-loop threads.
- SOCKS and DNS close descriptors through helpers that store `-1`, so a later cleanup does not close the same descriptor again.
- Config errors do not log the raw value.

### Not verified

- Inotify reload under a concurrent lookup, a monitor client that stays open until the 30 second header timeout, a live flood of the DNS worker cap, and a musl build.
