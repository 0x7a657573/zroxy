# Changelog

The version string in `src/version.h` is still `1.2.7`. The notes below are unreleased relative to that string. Nothing here says the result is production-ready.

## Unreleased

### Verification

- Added regression coverage for malformed DNS names and compression chains, truncated TLS ClientHello and SNI lengths, malformed SOCKS5 replies, partial `net_read_exact` / `net_write_all`, `EINTR` during read and `recvfrom`, `recvfrom` failure, a missing whitelist, invalid process configuration, monitor input without a finished HTTP header, the SNI worker cap, the monitor worker cap, and `SIGPIPE` on a closed upstream.
- Built with `-Wall -Wextra -Wno-unused-parameter`, debug symbols, AddressSanitizer, and UndefinedBehaviorSanitizer. The warning rebuild printed no warnings. With leak detection enabled, `ctest` reported 9/9 passed. AddressSanitizer's link-order check was disabled for that run because another shared object is mapped first in this environment. Leak and undefined-behavior detection stayed on.
- `musl-gcc` is not available on this host, so no musl build was run.

### Correctness fix found by those tests

- The monitor `Content-Length` was two bytes shorter than the JSON body (`186` versus `188` on an otherwise valid response). The header now uses the length of the body that is written. The JSON bytes are unchanged.

### Hardening already in the tree

- DNS, TLS SNI, SOCKS5, and config parsers reject truncated or oversized input instead of reading off the end of the buffer.
- A missing whitelist file aborts startup. A bad reload keeps the previous list.
- `SIGPIPE` is ignored. Exact reads and writes retry `EINTR`. A failed `recvfrom` does not enqueue work.
- SNI, DNS, and monitor accept paths cap detached workers.
- SOCKS and DNS close descriptors through helpers that store `-1`, so a later cleanup does not close the same descriptor again.
- Config errors do not log the raw value.

### Not verified

- Inotify reload under a concurrent lookup, a monitor client that stays open until the 30 second header timeout, a live flood of the DNS worker cap, and a musl build.
