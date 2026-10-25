# Security notes

This document describes the controls that are in the tree today and the checks that were actually run. It is not a claim that zroxy is production-ready, audited for deployment, or safe to expose on an untrusted network.

zroxy 1.2.7 is a POSIX C proxy. It forwards TLS by the ClientHello SNI or the HTTP `Host` header, forwards DNS over TCP (directly or through SOCKS5), and can serve an HTTP JSON monitor. It does not terminate TLS and it does not authenticate proxy clients. The monitor authenticates only when a token is configured.

## Trust boundaries

- Listener sockets, DNS datagrams, SOCKS replies, TLS ClientHello bytes, HTTP monitor bytes, the config file, and the whitelist file are untrusted input.
- The monitor binds `127.0.0.1` unless the operator sets an address. Without `MONITORTOKEN`, anyone who can open that socket can read the counters. With a token, the counters require `Authorization: Bearer <token>`.
- A whitelist miss still forwards the DNS query upstream. The whitelist is not a default-deny firewall for every protocol.
- Forwarding copies the original client bytes after the hostname is taken from SNI or `Host`. The proxy does not re-encode that stream.
- Config and SOCKS usernames are process memory. Passwords are not written to the log on the SOCKS handshake path. Config failures log the key, not the value.

## Parser and I/O controls

- DNS decoding walks an explicit cursor. Labels longer than 63 bytes, reserved label types, names that do not fit the hostname buffer, questions past the packet, and compression pointers are rejected. Pointer following stops after 16 jumps. The listener uses a bounded encode into a 512-byte buffer for synthetic answers.
- TLS SNI parsing checks the record length against the buffer, then checks extension and server-name lengths against that record. A name that continues past the record is not accepted. An empty name is rejected.
- SOCKS5 accepts only version 5 and methods `0x00` and `0x02`. Username length must be 1–255. A missing password with method 2 fails. Address types other than IPv4, domain, and IPv6 fail. On failure the socket is closed and the descriptor is set to `-1`.
- The monitor reads at most 4096 header bytes and answers `GET /` only after `\r\n\r\n`. A buffer that fills without that terminator, or a client that stops sending, is closed with no JSON body. The incomplete-header wait defaults to 5 seconds. `Content-Length` is the length of the JSON actually written. Other methods and paths are rejected without counters.
- `net_read_exact` and `net_write_all` retry `EINTR` only. `EAGAIN` / `EWOULDBLOCK` fail the call. `SIGPIPE` is ignored in `main`. A negative `recvfrom` does not enqueue a DNS job.

## Resource limits

- SNI accept stops creating workers at 1024. The monitor stops at 32 and closes the extra accepted socket. DNS query workers stop at 128. The DNS cap is inside `dnsproxy.c` and was not driven by a live flood in this pass.
- A configured whitelist that cannot be opened aborts process startup. A failed whitelist reload keeps the previous list. Invalid ports, addresses, and empty config values are rejected instead of truncated.

## What was run

On this Linux host, with gcc, the tree was built with `-Wall -Wextra -Wno-unused-parameter -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all`. The compiler printed no warnings. `ctest` reported 9/9 passed when AddressSanitizer was allowed to start behind the process preload (`ASAN_OPTIONS=verify_asan_link_order=0`) with `detect_leaks=1` and UBSan `halt_on_error=1`. No AddressSanitizer, LeakSanitizer, or UndefinedBehaviorSanitizer report was produced by that run.

`musl-gcc` is not installed here (`musl-dev` is not installed). No musl build was performed.

## Remaining risk

- A monitor started with no token does not check credentials. Binding it to `0.0.0.0` without a token exposes the counters to every reachable client.
- Startup errors return from `main` without a single cleanup of every config allocation. The missing-whitelist and bad-config process tests exited 1 with no LeakSanitizer text. Other failure orders were not exhaustively instrumented. The long-running loop never reaches `Free_DnsServer`; process exit reclaims that memory.
- `localdns_pull` currently always returns true, so the free after that loop does not run while the detached DNS worker is blocked on the queue. Freeing that queue while the worker is alive would be a use-after-free. That path was not executed.
- The DNS worker cap was reviewed and not load-tested. SNI and monitor caps were.
- Inotify whitelist reload and a musl build were not executed. `getaddrinfo()` for a non-numeric upstream name can still block a worker.
- AddressSanitizer's own link-order check fails in this environment because another shared object is mapped before `libasan`. The passing run disabled that one check. It did not disable leak or undefined-behavior detection.
