# zroxy

`zroxy` is a small C-based TCP proxy that routes connections by the hostname
found in an HTTP `Host` header or a TLS ClientHello SNI extension. It forwards
the original byte stream without terminating TLS, installing certificates, or
performing TLS inspection.

It can connect to upstream servers directly or through a SOCKS5 proxy. An
optional local DNS service can synthesize answers for whitelisted domains and
forward other DNS queries upstream over TCP.

> zroxy is a protocol-aware TCP passthrough proxy. It is not a TLS terminator,
> a general-purpose transparent proxy, or a client-authenticating proxy.

## Contents

- [How it works](#how-it-works)
- [Supported behavior and limitations](#supported-behavior-and-limitations)
- [Related projects](#related-projects)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Monitor endpoint](#monitor-endpoint)
- [DNS forwarding](#dns-forwarding)
- [Build and install](#build-and-install)
- [Tests](#tests)
- [Architecture](#architecture)
- [Security considerations](#security-considerations)
- [OpenWrt](#openwrt)
- [Related documents](#related-documents)

## How it works

For an SNI listener, zroxy:

1. accepts a client TCP connection;
2. reads enough of the initial request to find an HTTP `Host` header or TLS
   ClientHello SNI name;
3. normalizes and checks the hostname;
4. connects to the configured remote port, directly or through SOCKS5; and
5. forwards the original bytes in both directions.

The TLS session remains between the original client and the upstream server.
zroxy does not need a private key, certificate, or cryptographic library, and
it does not decrypt or rewrite the TLS stream.

The hostname in a traditional TLS ClientHello SNI extension is visible to
network observers. Encrypted ClientHello (ECH), a TLS ClientHello without a
usable SNI name, and protocols that do not provide a readable HTTP Host header
cannot be routed by hostname using this mechanism.

## Supported behavior and limitations

### Supported

| Area | Behavior |
| --- | --- |
| Routing | Hostname routing from HTTP `Host` or TLS ClientHello SNI |
| Upstream | Direct TCP connection or SOCKS5 |
| SOCKS5 | Optional username/password authentication (RFC 1929) |
| Listeners | Multiple listeners with independent local and remote ports |
| Whitelist | Host patterns with `*` and `?` matching, plus automatic reload |
| DNS | Local UDP and TCP listener; upstream DNS over TCP, directly or through SOCKS5 |
| Monitor | Local HTTP JSON statistics endpoint with optional Bearer token |
| SNI data plane | Non-blocking event loop per listener; epoll on Linux and poll elsewhere |

### Not provided

- TLS termination, certificate management, or man-in-the-middle inspection;
- SOCKS4 support;
- authentication of clients connecting to SNI listeners;
- general UDP proxying or arbitrary DNS-over-HTTPS/DNS-over-TLS support;
- hostname routing when no usable SNI or HTTP Host value is available;
- a fallback or default upstream for a connection whose hostname cannot be
  extracted;
- a guarantee of production readiness or security audit status.

The proxy accepts private upstream addresses, but rejects unsafe destinations
such as loopback, unspecified, link-local, and multicast results where they
would point back to the listener or an unsuitable local address. See
[`SECURITY.md`](SECURITY.md) for the current security model and known risks.

## Related projects

These projects explore related forms of hostname-aware TCP routing or TLS
passthrough. They are references and alternatives, not dependencies of zroxy.

- [SNI-SSL-Proxy](https://github.com/Intika-Linux-Proxy/SNI-SSL-Proxy) — an SNI
  proxy with HTTP/TLS service support and SOCKS5 upstream support.
- [sniproxy](https://github.com/dlundquist/sniproxy) — an original lightweight
  SNI proxy implementation and an important reference for this design.
- [sniproxy](https://github.com/renaudallard/sniproxy) — a continuation of the
  sniproxy idea with broader protocol coverage.
- [SNIProxy](https://github.com/atenart/sniproxy) — a small Rust-based TLS SNI
  passthrough proxy.
- [sni-proxy](https://github.com/igorhakk/sni-proxy) — a small Go TCP proxy
  that shares a TLS port between services using SNI.
- [sni-router](https://github.com/Ashteeer/sni-router) — a broader SNI routing
  project with TCP/UDP/QUIC and optional TLS termination features.

## Quick start

### 1. Install build tools

On Debian or Ubuntu:

```sh
sudo apt install cmake build-essential git
```

The build uses CMake, a C compiler, and POSIX threads. It has no third-party
runtime library dependency beyond the platform's standard C/POSIX facilities.

### 2. Build

From the repository root:

```sh
cmake -S . -B build
cmake --build build
```

### 3. Create a configuration

Start with the included example:

```sh
cp simple-zroxy.conf zroxy.conf
```

Edit at least the listener and upstream settings. For example:

```ini
PORT = 127.0.0.1:8443@443
SOCKS = 127.0.0.1:9050
SNITIMEOUT = 30
LOG = 2
```

This listens on `127.0.0.1:8443`, extracts the hostname from each incoming
connection, and connects to that hostname on remote port `443` through the
SOCKS5 proxy at `127.0.0.1:9050`.

### 4. Run

```sh
./build/zroxy -c ./zroxy.conf
```

When started without command-line arguments, zroxy loads `zroxy.conf` from the
current working directory. To see the command-line help:

```sh
./build/zroxy -h
```

The current source version is `2.0.0`; the authoritative value is defined in
[`include/zroxy/version.h`](include/zroxy/version.h).

## Configuration

Command-line options and configuration keys control the same settings. Command
line arguments use the short and long forms shown below; configuration files
use the key names in the last column.

| Option | Argument | Description | Config key |
| --- | --- | --- | --- |
| `-c`, `--config` | path | Configuration file; a file may load another with `CONFIG`, up to 8 files deep, and a file that is already being read is an error | `CONFIG` |
| `-p`, `--port` | listeners | SNI listener definitions | `PORT` |
| `-s`, `--socks` | host:port | SOCKS5 for SNI upstreams | `SOCKS` |
| `-S`, `--sockspassfile` | path | Read the SOCKS5 password from the first line of a file; the `SOCKS` spec then has the form `user@host[:port]` | `SOCKSPASSFILE` |
| `-m`, `--monitor` | `[ip:]port` | HTTP monitor listener | `MONITOR` |
| `-k`, `--monitortoken` | token | Bearer token for the monitor | `MONITORTOKEN` |
| `-K`, `--monitortokenfile` | path | Read the Bearer token from the first line of a file (max 256 bytes) | `MONITORTOKENFILE` |
| `-a`, `--monitortimeout` | seconds | Incomplete monitor-header timeout | `MONITORTIMEOUT` |
| `-o`, `--snitimeout` | seconds | SNI handshake, connect, and write-stall timeout | `SNITIMEOUT` |
| `-I`, `--sniidletimeout` | `1..86400` | Close a relay with no traffic after this many seconds (default 300) | `SNIIDLETIMEOUT` |
| `-L`, `--allowloopback` | `yes`/`no` | Let names from clients resolve to loopback (127.0.0.0/8, `::1`) upstreams; default `no`, for tests and local backends only | `ALLOWLOOPBACK` |
| `-P`, `--denyprivate` | `yes`/`no` | Also refuse names that resolve to private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7); default `no` | `DENYPRIVATE` |
| `-w`, `--white` | path | Whitelist file | `WHITE` |
| `-O`, `--openproxy` | `yes`/`no` | Allow SNI listeners to forward every host name when no whitelist is set; default `no`, in which case startup fails if listeners are configured without `WHITE`. Ignored when a whitelist is set. Does not affect DNS-only setups | `OPENPROXY` |
| `-d`, `--ldns` | bind:port | Local DNS listener (UDP and TCP) | `LDNS` |
| `-u`, `--dns` | `host[:port] [via spec\|direct]` | Upstream DNS route; repeat for up to 4 routes, in order (see [DNS forwarding](#dns-forwarding)) | `DNS` |
| `-x`, `--dsocks` | host:port | SOCKS5 for DNS upstream TCP, used by routes without `via` | `DSOCKS` |
| `-X`, `--dsockspassfile` | path | Read the DNS SOCKS5 password from the first line of a file; the `DSOCKS` spec then has the form `user@host[:port]` | `DSOCKSPASSFILE` |
| `-t`, `--dtimeout` | seconds | DNS upstream timeout | `DTIMEOUT` |
| `-i`, `--snip` | IPv4 address | Synthetic address for matching DNS names | `SNIP` |
| `-e`, `--dcache` | `0..65536` | DNS answer cache entries; `0` disables cache; counters are in the monitor | `DCACHE` |
| `-r`, `--dttl` | `1..86400` | TTL of synthetic DNS answers and negative SOA records | `DTTL` |
| `-A`, `--dacl` | `CIDR[,CIDR...]` | IPv4 networks allowed to query the local DNS listener | `DACL` |
| `-R`, `--drate` | `0..100000` | Per-source DNS queries per second; `0` disables | `DRATE` |
| `-C`, `--dnsconnections` | `1..96` | Maximum concurrent nonblocking TCP connections to the DNS upstream | `DNSCONNECTIONS` |
| `-U`, `--user` | name | After the ports are bound, switch to this user (needs a start as root; see [Dropping privileges](#dropping-privileges)) | `USER` |
| `-G`, `--group` | name | Group to switch to with `USER`; default is the user's primary group | `GROUP` |
| `-l`, `--log` | `0..5` | Log level | `LOG` |

### Keeping secrets out of `ps`

A SOCKS password or monitor token given with `-s`, `-x` or `-k` is visible to
every local user in `/proc/PID/cmdline`. zroxy logs a warning, overwrites
those arguments after parsing as a best effort, and prefers the file forms:
`SOCKSPASSFILE`, `DSOCKSPASSFILE` and `MONITORTOKENFILE` read the first line
of a file (trailing CR/LF removed, not empty, at most 255 bytes for a
password and 256 for a token). Setting both the inline value and the file for
the same secret is an error, and a password file needs a user in the spec
(`SOCKS = alice@127.0.0.1:1080`). Secret files must be regular files and are
refused when world-writable; group or world access logs a warning, so use
`chmod 600`. A config file that holds a secret gets the same warning. The
files are read once at startup, and the copies of the secrets in memory are
wiped when freed.

### Dropping privileges

zroxy needs root only to bind ports below 1024. With `USER = zroxy` (and
optionally `GROUP`) it binds every listener as root, reads the configuration,
whitelist and secret files, then clears the supplementary groups, calls
`setgid` and `setuid`, and refuses to continue if any step or the final check
fails. `USER` and `GROUP` are looked up before any thread starts. Starting
as a non-root user with a different `USER` is an error, and so is `GROUP`
without `USER`; running as root without `USER` logs a warning. On Linux the
process also sets `no_new_privs`, and after a drop it is non-dumpable, which
stops core dumps and ptrace by other processes of the same user.

After the drop, the only file zroxy opens again is the whitelist, on `SIGHUP`
and when its directory changes, so the whitelist file and its directory must
be readable by `USER`. Config and secret files are read once and may stay
root-only. For systemd, [`contrib/zroxy.service`](contrib/zroxy.service) is a
hardened sample that avoids root altogether with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`.

`LDNS` is the opt-in switch for the local DNS service. `DNS`, `DSOCKS`,
`DTIMEOUT`, and `SNIP` require `LDNS`; when `LDNS` is set, an upstream `DNS`
must also be provided.

### Configuration-file rules

- Keys are case-insensitive.
- Values are trimmed but otherwise preserved.
- Unknown keys, empty values, invalid values, and overlong lines are rejected.
- A configuration file is required when using `-c`, and `zroxy.conf` is used
  when no options are supplied.
- A configured service that cannot start causes process startup to fail. An
  unconfigured service is skipped.

### Listener syntax

Use one or more comma-separated entries:

```text
<bind-ip>:<local-port>@<remote-port>
```

Examples:

```ini
PORT = 127.0.0.1:8443@443, 127.0.0.1:8080@80
```

The local port is where zroxy accepts connections. The remote port is used for
the selected upstream hostname. The listener address is an IPv4 address.

`PORT` and `-p` can be repeated, in the config file and on the command line;
each one adds its listeners to the ones already defined, in order. A listener
that repeats an earlier bind address and local port, or that binds `0.0.0.0`
on a local port another listener already uses (or the other way round), is an
error at startup, as is a bad entry anywhere in a list. Port `0` asks for any
free port and is never a duplicate.

### SOCKS5 syntax

For `SOCKS` and `DSOCKS`, use either:

```text
<host>:<port>
<user>:<password>@<host>:<port>
```

The first form uses an unauthenticated SOCKS5 connection. The second enables
username/password authentication. Credentials are held in process memory and
are not intended to be placed in publicly readable configuration files.

### Whitelist syntax

The whitelist contains one host name or pattern per line. Blank lines and
lines starting with `#` are ignored, and matching is case-insensitive.

- `example.com` matches exactly that name (not `example.com.evil.net`).
- `*.example.net` matches any name ending in `.example.net`, at any depth.
- Any other `*` (any run of characters) or `?` (one character) pattern is
  matched against the whole name.

A configured whitelist that cannot be opened prevents startup. The file is
reloaded automatically when it is saved (including editors that save by
renaming a temporary file), or on `SIGHUP`. A failed reload keeps the
previously loaded list.

Example:

```text
# streaming
example.com
*.example.net
api-?.example.org
```

### Signals

| Signal | Effect |
| --- | --- |
| `SIGHUP` | Reload the whitelist |
| `SIGINT`, `SIGTERM` | Stop SNI listeners and the DNS service, then exit with status 0 |

## Monitor endpoint

Enable the monitor with `-m` or `MONITOR`. It accepts only `GET /` using
HTTP/1.0 or HTTP/1.1 and returns JSON containing the zroxy version, connection
counters, byte totals, and open-file information.

By default, a bare port binds to loopback:

```ini
MONITOR = 8123
```

To bind explicitly:

```ini
MONITOR = 127.0.0.1:8123
```

Protect a monitor that is reachable by other users or networks:

```ini
MONITORTOKEN = replace-with-a-secret-token
MONITORTIMEOUT = 5
```

Clients must send:

```http
GET / HTTP/1.1
Host: localhost
Authorization: Bearer replace-with-a-secret-token
Connection: close

```

The response is `200 OK` with `Content-Type: application/json`, an exact
`Content-Length`, `Cache-Control: no-store`, and `Connection: close`; header
lines end with CRLF. The JSON report is limited to 16 KiB. If it ever does not
fit, the monitor answers `500 Internal Server Error` with an empty body and
logs the failure once.

The report is one JSON object. `ZroxyVersion` and `CountOfOpenFile` come
first, then the `Process` object, the `Whitelist` object when a whitelist is
configured, the `Resolver` object, then one object per enabled service
(`DNS_Server`, `SNI_Server`). Keys are only ever added; existing keys keep
their names and meaning.

| Key | Meaning |
| --- | --- |
| `ZroxyVersion` | Version string |
| `CountOfOpenFile` | Open file descriptors of the process, not counting the one used to count them |

The `Process` object describes the zroxy process:

| Key | Meaning |
| --- | --- |
| `Pid` | Process id |
| `StartTime` | Unix time at which the monitor started, a few milliseconds after the process |
| `UpTime` | Seconds since `StartTime` |
| `OpenFiles` | Same value as `CountOfOpenFile` |
| `MaxOpenFiles` | Soft `RLIMIT_NOFILE`; `-1` when unlimited |
| `Threads` | Thread count (Linux only; omitted elsewhere) |
| `RssBytes` | Resident set size now (Linux only; omitted elsewhere) |
| `PeakRssBytes` | Peak resident set size: `VmHWM` on Linux, `getrusage` elsewhere |
| `CpuUserMs`, `CpuSystemMs` | User and system CPU time used by the process, in milliseconds |

When a whitelist file is configured (`-w`), the report has a `Whitelist`
object. It is absent otherwise.

| Key | Meaning |
| --- | --- |
| `Entries` | Entries in the list now in use |
| `Reloads` | Successful reloads since start (the initial load is not counted) |
| `ReloadFailures` | Reloads that failed and kept the previous list |
| `LastReload` | Unix time of the last successful reload; `0` if none since start |

The `Resolver` object describes the hostname resolver pool shared by the SNI
and DNS paths:

| Key | Meaning |
| --- | --- |
| `Threads` | Resolver worker threads (4) |
| `Slots` | Request slots (128) |
| `SlotsInUse` | Slots queued, running, or waiting to be collected now |
| `Lookups` | `getaddrinfo` calls made |
| `LookupFailures` | Lookups that returned an error or no address |
| `RingFull` | Results dropped because a listener's completion ring was full |

`SNI_Server` adds the connection cap and counters that say how connections
ended. Each connection is counted once, under the reason it ended; a relay that
ends by EOF or reset from either side is counted under none of them.

| Key | Meaning |
| --- | --- |
| `ConnectionLimit` | Maximum simultaneous connections (1024, shared by all listeners) |
| `Relayed` | Connections that reached the relay: upstream connected, and SOCKS5 done if configured |
| `Refused` | Rejected at accept: the cap was reached or an allocation failed |
| `NoHostname` | No usable SNI or HTTP `Host`: the client left first, malformed or oversized hello, an IP literal |
| `Blocked` | Hostname rejected by the whitelist |
| `UnsafeDestination` | Resolved only to rejected addresses (loopback, link-local, ...; see `ALLOWLOOPBACK` and `DENYPRIVATE`) |
| `ResolveFailures` | Hostname resolution failed |
| `SocksFailures` | SOCKS5 negotiation failed or was refused |
| `ConnectFailures` | The TCP connect (direct or to the SOCKS server) failed |
| `HandshakeTimeouts` | `SNITIMEOUT` expired before the relay started (hello, resolve, connect, SOCKS) |
| `IdleTimeouts` | `SNIIDLETIMEOUT` expired on an established relay |
| `StallTimeouts` | An established relay could not write for `SNITIMEOUT` |

`DNS_Server` and `SNI_Server` each carry `UpTime`, `MaxConnection`,
`ActiveConnection`, `TotalConnection`, `TotalRx`, and `TotalTx`. The DNS
counters are listed in the DNS section.

The monitor reads at most 4096 header bytes. `MONITORTIMEOUT` is one absolute
deadline for completing the header; slow-drip input cannot extend it. Do not
bind the monitor to `0.0.0.0` without a token and appropriate network access
controls.

## DNS forwarding

When `LDNS` is configured, zroxy listens for DNS over UDP and TCP locally.
Whitelisted names receive a synthetic A answer using `SNIP` with a configurable
TTL (`DTTL`, default 300 seconds). IPv6 is not proxied, so every other query type for a whitelisted name (AAAA, HTTPS,
SVCB, ...) gets an empty NOERROR (NODATA) answer with one SOA authority record
using the same TTL for RFC 2308 negative caching, and the client falls back to
IPv4. Other queries are forwarded to the configured `DNS` server over TCP,
directly or via the optional `DSOCKS` SOCKS5 connection. The SNI proxy itself
resolves upstream names to IPv4 only.

DNS settings may appear in any CLI or configuration-file order. The parser keeps
one DNS configuration object and the last `LDNS` value wins.

Each `DNS` line or `-u` option adds one upstream route, up to four, in the
order given (config file first, then the command line, like `PORT`):

- `DNS = HOST[:PORT]` goes through the global `DSOCKS` if one is set,
  otherwise directly.
- `DNS = HOST[:PORT] via [USER:PASSWORD@]HOST[:PORT]` goes through that
  route's own SOCKS5 proxy (default port 1080). Routes are separate lines, so
  a password may contain commas. `DSOCKSPASSFILE` applies only to the global
  `DSOCKS`; give a `via` proxy its password inline.
- `DNS = HOST[:PORT] via direct` connects directly even when `DSOCKS` is set.
  There is no automatic fallback to a direct connection.

A fifth route, an exact duplicate (same server and same way of reaching it),
or an empty or malformed `via` is an error.

With more than one route zroxy fails over. New queries go to the active route,
the first one at start. A query attempt fails on a connect error, a SOCKS
handshake failure, a read or write error, EOF, a reply too short to be DNS, or
when `DTIMEOUT` seconds pass without a complete reply. Any valid reply counts
as success, whatever its rcode. When an attempt on the active route fails, the
next route (wrapping around) becomes active, and the query is tried on a route
it has not used yet as long as its overall deadline, `2 * DTIMEOUT`, allows;
if none is left it gets SERVFAIL. Because the whole path counts, a dead SOCKS
proxy in front of a route moves queries to the next route like a dead server
does. A route whose address is still being resolved is skipped for the
queries that need an answer now.

Failover is sticky: zroxy keeps using a route that works and does not go back
to the first one when it recovers; it moves only when the current route
fails, so a list is a ring, not a priority order. There is never an automatic
fallback to a direct connection: if you want one, write it as a route
(`DNS = HOST via direct`). With a single route a fast error is retried once on
the same server and a timeout is not retried.

Forwarded answers are cached in memory for their TTL, capped at one hour, or
five minutes for NXDOMAIN and NODATA. The cache holds up to `DCACHE` entries
(default 2048); `DCACHE = 0` disables it. Identical queries that arrive while
one is being fetched wait for that fetch instead of going upstream again. A
forwarded query has one deadline of twice `DTIMEOUT`.

A failed upstream exchange is answered with SERVFAIL, and so is a query that
arrives while 2048 requests are already held or response buffers have reached
16 MiB. An upstream reply whose id or question does not match the query is
discarded. A
response larger than the client's UDP size (512 bytes, or its EDNS0 size up to
1232) is answered with TC set, and the client retries over TCP on the same
address and port, where the whole reply is sent. Up to 128 TCP connections are
served at once, each for at most 32 queries and closed after 3 seconds idle.
If the TCP port cannot be bound, zroxy logs it and keeps serving UDP.

The `DNS_Server` monitor object adds `CacheHits`, `CacheMisses`, `CacheShared`,
`CacheEntries`, `CacheEvictions`, `AclDropped`, `RateDropped`, `TcpRefused`,
`TcpActive`, `QueueDropped`, `UpstreamTimeouts`, `UpstreamErrors`,
`ActiveUpstreams` (open upstream TCP connections), `ActiveUpstream` (index of
the active DNS route, 0-based, in configuration order) and `UpstreamSwitches`
(how many times the active route moved). `QueueStaleDropped` and `QueueFull` are still reported for
compatibility but are always 0. These counters are detached before the DNS
service is freed during shutdown.

`DACL` silently drops UDP datagrams and closes TCP connections whose source
address is not in one of the listed IPv4 networks. With no `DACL`, a loopback
listener has no additional restriction; a non-loopback listener allows only
loopback, RFC 1918, and shared-address-space networks. Use `DACL = 0.0.0.0/0`
to explicitly allow every IPv4 source.

`DRATE` applies a per-source-IP token bucket to UDP queries only. Its burst is
twice the configured QPS and its fixed 1024-slot table intentionally shares
capacity when source hashes collide. TCP remains governed by the 128-connection
and 32-query limits. Rate-limited UDP queries are silent and counted as
`RateDropped` in the monitor.

Example:

```ini
WHITE = /etc/zroxy/whitelist.txt
SNIP = 192.0.2.10
LDNS = 127.0.0.1:5353
DNS = 1.1.1.1:53
DSOCKS = 127.0.0.1:9050
DTIMEOUT = 5
```

With more than one route:

```ini
DNS = 1.1.1.1 via 127.0.0.1:9050
DNS = 9.9.9.9 via user:secret@127.0.0.1:9051
DNS = 192.168.1.1 via direct
```

DNS-over-TCP framing uses a two-byte length prefix. Queries are forwarded
upstream over TCP even when the client asked over UDP.

## Build and install

The normal build is:

```sh
cmake -S . -B build
cmake --build build
```

To install the binary under a chosen prefix:

```sh
cmake --install build --prefix /usr/local
```

The project also contains a musl-based static-build workflow. On a Debian-like
Linux system, install the toolchain and configure with:

```sh
sudo apt install musl-tools cmake build-essential
CC='musl-gcc -static -Os' cmake -S . -B build-musl
cmake --build build-musl
```

The static build and platform-specific behavior should be validated with the
toolchain used for the target device. A musl build is not implied by a normal
glibc build.

### Making a release

Bump `include/zroxy/version.h`, add a matching `## <version>` section to
`CHANGELOG.md`, commit, and push. Then tag the commit and push the tag; the tag
has no `v` prefix:

```sh
git tag -a X.Y.Z -m "Release X.Y.Z"
git push origin X.Y.Z
```

The `release` workflow checks the tag against `version.h` and the changelog,
runs the full test suite, builds every architecture, and publishes the GitHub
release using the changelog section as its notes. A tag containing `-` is
published as a prerelease. Running the workflow by hand performs the same
builds without publishing. `scripts/release-build.sh <arch>` reproduces one
build locally (set `ZIG` if `zig` is not on `PATH`) and writes to `dist/`.

The OpenWrt package is not built by this workflow; update its pinned source
as described in the
[OpenWrt release checklist](openwrt/README.md#release-checklist).

## Tests

Tests are local and do not require public Internet access, external DNS, SSH,
Tor, Docker, `curl`, or `dig`.

Configure and build first, then run the default suite:

```sh
ctest --test-dir build --output-on-failure
```

The default suite includes unit, process, and loopback integration tests:

- `help_output`
- `net_host_extract`
- `filter_whitelist`
- `dns_codec`
- `dns_cache`
- `dns_acl`
- `dns_rate`
- `dns_throttle`
- `args_parse`
- `socks_handshake`
- `sni_forwarding`
- `sni_engine`
- `sni_engine_poll`
- `fuzz_corpus_sni_host`, `fuzz_corpus_dns`, `fuzz_corpus_socks`, `fuzz_corpus_monitor_request`, `fuzz_corpus_config` (replay the seed corpora, see Fuzzing)
- `process_limits`
- `sni_e2e`
- `dns_e2e`
- `monitor_e2e`
- `lifecycle_e2e`

Run only integration tests with:

```sh
ctest --test-dir build -L integration --output-on-failure
```

### Fuzzing

`tests/fuzz/` has one harness per parser of untrusted input, each with a
seed corpus in `tests/fuzz/corpus/<name>/`:

| Harness | Covers |
| --- | --- |
| `sni_host` | TLS SNI and HTTP Host extraction, then `sni_resolver_normalize` and the whitelist match |
| `dns` | DNS message decode and encode, error, truncate, cache key, TTL, age and reply-match helpers |
| `socks` | SOCKS5 replies, read by `socks5_connect` from a loopback stand-in server |
| `monitor_request` | monitor request line, end of header and Bearer token checks |
| `config` | config-file parser (`args.c`) and whitelist file parser and matcher |

A normal build (any compiler) replays the corpora as the `fuzz_corpus_*`
tests; a crash or sanitizer report fails the test. To fuzz with libFuzzer,
ASan and UBSan, use clang in a separate build directory:

```sh
CC=clang cmake -S . -B build-fuzz -DZROXY_FUZZ=ON
cmake --build build-fuzz -j
mkdir -p /tmp/fuzz-dns
build-fuzz/tests/fuzz/fuzz_dns -max_total_time=120 /tmp/fuzz-dns tests/fuzz/corpus/dns
```

The first directory receives new inputs, the second is the read-only seed
corpus. A failing input is written to `crash-*` / `leak-*` in the current
directory; replay it with `build-fuzz/tests/fuzz/fuzz_dns crash-FILE`.
The `dns` input is one length byte `N`, then an `N`-byte query and the reply.

### Stress tests

The stress test exercises concurrent, malformed, slow, and overloaded clients:

```sh
python3 tests/stress/zroxy_stress.py \
  --duration 30 \
  --connections 100 \
  --workers 4 \
  --payload-size 4096 \
  --output build/stress-result.json
```

### Benchmarks

Run a local baseline:

```sh
python3 tests/benchmark/zroxy_benchmark.py \
  --connections 1,10,50,100 \
  --payload-size 1024,65536 \
  --duration 10 \
  --output build/benchmark-result.json
```

Compare two results instead of interpreting one machine-dependent measurement:

```sh
python3 tests/benchmark/compare_baseline.py \
  build/baseline.json build/current.json
```

Stress and benchmark tests are registered with CTest but disabled in a plain
`ctest` run. To run them, call the scripts directly:

```sh
ZROXY_BIN="$PWD/build/zroxy" python3 tests/stress/zroxy_stress.py \
  --duration 3 --connections 8 --workers 2 --payload-size 1024 \
  --output build/stress-result.json
ZROXY_BIN="$PWD/build/zroxy" python3 tests/benchmark/dns_benchmark.py \
  --workers 32 --upstream-connections 32 --duration 10 \
  --output build/dns-benchmark-result.json
```

`tests/benchmark/dns_benchmark.py` writes DNS success QPS, p50/p95/p99
latency, thread/fd peaks, and process CPU time to JSON. Compare two runs with
the same upstream delay, worker count, and machine before treating a result as
a performance change.

Socket-based end-to-end results depend on the execution environment. A focused
unit-test pass is not evidence of production capacity, Internet compatibility,
or a security audit.

## Architecture

The process starts the configured monitor, DNS listener, and SNI listeners.
Each SNI listener owns one long-lived event-loop thread. Accepted SNI clients
are connection objects on that loop, not one pthread per client. Linux uses
`epoll`; other supported builds use `poll`.

Current important bounds include:

- up to 1024 concurrent SNI connections;
- fixed 8 KiB buffers for the initial data and each relay direction;
- a process-wide resolver pool with 4 threads and 128 resolver slots;
- up to 32 monitor workers;
- one DNS event-loop thread, with up to 96 reusable non-blocking upstream TCP
  connections (configurable with `--dnsconnections`).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for ownership, locking, resolver,
connection-state, and data-path details.

## Security considerations

zroxy handles untrusted network input. Before exposing it beyond a trusted
loopback or private network, read [`SECURITY.md`](SECURITY.md).

In particular:

- SNI listeners do not authenticate clients.
- The monitor is local by default, but a token is required when it is exposed
  to a broader network.
- The whitelist is not a universal default-deny firewall for every protocol.
- SOCKS credentials are configuration secrets and must be protected accordingly.
- Set `USER` so zroxy does not run as root once its ports are bound.
- The project does not claim production readiness or independent security audit
  status.

## OpenWrt

The repository includes an OpenWrt package Makefile and build notes:

[`openwrt/README.md`](openwrt/README.md)

Cross-compilation must be performed with the toolchain and OpenWrt revision
used by the target firmware. The OpenWrt document is a build guide, not a
claim that every router model has sufficient CPU, memory, or protocol support.

## Related documents

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — current process and data-plane design
- [`SECURITY.md`](SECURITY.md) — security controls, verification, and remaining risk
- [`CHANGELOG.md`](CHANGELOG.md) — release notes and validation history
- [`simple-zroxy.conf`](simple-zroxy.conf) — annotated configuration example
- [`LICENSE`](LICENSE) — project license

## License

See [`LICENSE`](LICENSE).
