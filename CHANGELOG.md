# Changelog

These notes describe the `1.3.1` release. Nothing here says the result is production-ready.

## Unreleased

### Security

- A plain whitelist entry no longer matches longer names that start with it. Before, `example.com` also allowed `example.com.attacker.net` and `example.community`.

### DNS

- A fixed pool of 32 worker threads replaces one detached thread per query. Workers block on the queue's condition variable instead of polling it every 10 ms.
- Each worker keeps its upstream TCP connection (direct or SOCKS5) open between queries. A connection closed by the server is detected before reuse; a failure on a reused connection is retried once on a fresh one.
- Upstream reads and writes use monotonic per-call deadlines instead of `SO_RCVTIMEO`/`SO_SNDTIMEO`.

### SNI data plane

- `--snitimeout 0` now uses the minimum one-second relay idle timeout instead of expiring connections immediately.
- Listener shutdown synchronizes its wakeup with engine teardown, preventing writes to closed or reused descriptors.
- Relay work is bounded per pass by a 256 KiB byte budget; pending I/O remains armed for a later wait.

### Process lifecycle

- `SIGINT` and `SIGTERM` stop the SNI listeners and the DNS service, join their threads, and exit with status 0.
- `SIGHUP` reloads the whitelist.

### Whitelist

- Exact names and `*.suffix` entries are stored in hash sets; other patterns are matched linearly. Lookups take a read lock and no longer scan the whole list.
- Matching is case-insensitive for DNS names and file entries, as required by RFC 4343. A trailing dot is ignored.
- Blank lines and `#` comments are skipped; surrounding whitespace is trimmed.
- Linux and FreeBSD watchers reload after in-place writes and file replacement.

### Code structure

- Public headers live in `include/zroxy/` and are included as `<zroxy/name.h>`. Sources live in `src/<module>/`, each built as one static library.
- Misspelled and inconsistently cased functions were renamed to `module_snake_case` (for example `fifo_incert` → `fifo_push`, `Minitor_HandelConnection` → `monitor_client_thread`, `state_RxTxClose` → `stats_close_connection`). Helpers used by one file are now `static`; unused functions were removed.
- Reserved identifiers (`_MaxHostName_`, `__FILENAME__`, ...) were renamed to `ZROXY_MAX_*` and `LOG_FILENAME`.
- The build enables `-Wshadow -Wconversion`; gcc and clang build the tree without warnings.

### Test coverage

- Monitor end-to-end tests read the expected version from `include/zroxy/version.h`.
- DNS end-to-end tests cover mixed-case whitelist queries, atomic or in-place whitelist saves, and upstream connection reuse including server-side close.
- A new `lifecycle_e2e` test covers `SIGHUP` reload and clean `SIGTERM`/`SIGINT` exit.
- Whitelist unit tests cover the prefix-match regression, comments, whitespace, generic patterns and a 20,000-entry list.

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
