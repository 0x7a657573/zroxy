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
| DNS | Local UDP listener; upstream DNS over TCP, directly or through SOCKS5 |
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

The current source version is `1.3.0`; the authoritative value is defined in
[`src/version.h`](src/version.h).

## Configuration

Command-line options and configuration keys control the same settings. Command
line arguments use the short and long forms shown below; configuration files
use the key names in the last column.

| Option | Argument | Description | Config key |
| --- | --- | --- | --- |
| `-c`, `--config` | path | Configuration file | — |
| `-p`, `--port` | listeners | SNI listener definitions | `PORT` |
| `-s`, `--socks` | host:port | SOCKS5 for SNI upstreams | `SOCKS` |
| `-m`, `--monitor` | `[ip:]port` | HTTP monitor listener | `MONITOR` |
| `-k`, `--monitortoken` | token | Bearer token for the monitor | `MONITORTOKEN` |
| `-a`, `--monitortimeout` | seconds | Incomplete monitor-header timeout | `MONITORTIMEOUT` |
| `-o`, `--snitimeout` | seconds | SNI socket timeout | `SNITIMEOUT` |
| `-w`, `--white` | path | Whitelist file | `WHITE` |
| `-d`, `--ldns` | bind:port | Local UDP DNS listener | `LDNS` |
| `-u`, `--dns` | host[:port] | Upstream DNS server | `DNS` |
| `-x`, `--dsocks` | host:port | SOCKS5 for DNS upstream TCP | `DSOCKS` |
| `-t`, `--dtimeout` | seconds | DNS upstream timeout | `DTIMEOUT` |
| `-i`, `--snip` | IPv4 address | Synthetic address for matching DNS names | `SNIP` |
| `-l`, `--log` | `0..5` | Log level | `LOG` |

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

The whitelist contains one host pattern per line. The current matcher supports
`*` and `?` wildcards. A configured whitelist that cannot be opened prevents
startup; a failed later reload keeps the previously loaded list.

Example:

```text
example.com
*.example.net
api-?.example.org
```

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

The monitor reads at most 4096 header bytes. `MONITORTIMEOUT` is one absolute
deadline for completing the header; slow-drip input cannot extend it. Do not
bind the monitor to `0.0.0.0` without a token and appropriate network access
controls.

## DNS forwarding

When `LDNS` is configured, zroxy listens for DNS over UDP locally. Whitelisted
names can receive a synthetic A answer using `SNIP`; a matching AAAA query is
answered with the current zero IPv6 value. Other supported queries are
forwarded to the configured `DNS` server over TCP, directly or via the
optional `DSOCKS` SOCKS5 connection.

Example:

```ini
WHITE = /etc/zroxy/whitelist.txt
SNIP = 192.0.2.10
LDNS = 127.0.0.1:5353
DNS = 1.1.1.1:53
DSOCKS = 127.0.0.1:9050
DTIMEOUT = 5
```

DNS-over-TCP framing uses a two-byte length prefix. DNS is forwarded over TCP
upstream even though clients use the local UDP listener.

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

## Tests

Tests are local and do not require public Internet access, external DNS, SSH,
Tor, Docker, `curl`, or `dig`.

Configure and build first, then run the default suite:

```sh
ctest --test-dir build --output-on-failure
```

The default suite includes unit, process, and loopback integration tests:

- `net_host_extract`
- `filter_whitelist`
- `dns_codec`
- `args_parse`
- `socks_handshake`
- `sni_forwarding`
- `sni_engine`
- `sni_engine_poll`
- `dnsproxy_tcp_io`
- `io_limits`
- `process_limits`
- `sni_e2e`
- `dns_e2e`
- `monitor_e2e`

Run only integration tests with:

```sh
ctest --test-dir build -L integration --output-on-failure
```

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
`ctest` run. To include them:

```sh
ctest --test-dir build -L stress --include-disabled --output-on-failure
ctest --test-dir build -L benchmark --include-disabled --output-on-failure
```

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
- up to 128 DNS workers.

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
