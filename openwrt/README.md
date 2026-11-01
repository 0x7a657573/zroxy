# zroxy on OpenWrt

This package installs the zroxy binary, a procd service, and its UCI
configuration (plus an example native file for the legacy mode below). The service is installed disabled; once enabled, it starts on boot and
is supervised by procd. Its default SNI listener is limited to
`127.0.0.1:8443`, so it is safe to test locally before allowing LAN clients to
connect.

## Build with an OpenWrt SDK

Use an SDK that matches your router's OpenWrt release and target architecture.
Get it from the [OpenWrt downloads](https://downloads.openwrt.org/) for that
release and target, then extract it. OpenWrt 25.12 is the current supported
release; 24.10 is in security maintenance. OpenWrt 21.02 is end of life.

In the commands below, replace `/absolute/path/to/zroxy` with the absolute path
to this repository and add the `src-link` line only once. The feed root is the
**repository root**: its `openwrt/` subdirectory is the package directory.

```sh
cd /path/to/openwrt-sdk
test -e feeds.conf || cp feeds.conf.default feeds.conf
printf '\nsrc-link zroxy /absolute/path/to/zroxy\n' >> feeds.conf
./scripts/feeds update zroxy
./scripts/feeds install -p zroxy zroxy
make defconfig
make package/feeds/zroxy/zroxy/compile V=s
```

The resulting package is under `bin/packages/<architecture>/zroxy/`. OpenWrt
24.10 produces an `.ipk`; OpenWrt 25.12 produces an `.apk`. The recipe pins a
specific source commit and checks its archive SHA-256. It builds the binary
without cross-compiling the test programs.

The feed only supplies the recipe: the source is still downloaded from GitHub
at the pinned commit, so local or unpushed changes are not built. To build a
working tree instead, point the build at it:

```sh
make package/feeds/zroxy/zroxy/{clean,compile} USE_SOURCE_DIR=/absolute/path/to/zroxy V=s
```

Copy the package to the router and install it with the package manager for the
router's release:

```sh
# OpenWrt 24.10
opkg install /tmp/zroxy_*.ipk

# OpenWrt 25.12
apk add --allow-untrusted /tmp/zroxy-*.apk
```

Build and install only packages for the exact release and architecture of your
router. A successful SDK build does not establish that the proxy works on the
target; check startup and a real proxied connection on that router.

## Configure and run

- `/etc/config/zroxy` is the source of truth. It has a `zroxy 'main'` section
  (service control and SNI settings), a `dns 'dns'` section, repeatable
  `route` sections for upstream DNS servers, and a `monitor 'monitor'`
  section. At every start or reload the init script turns it into the native
  zroxy configuration `/var/etc/zroxy/zroxy.conf` (directory `0700`, file
  `0600`, root) and passes that file with `-c`. Only options that are set are
  written, and a disabled `dns` or `monitor` section writes nothing.
  The generated file is rewritten each time: edit UCI, not that file.
- The start fails, with a message in `logread -e zroxy`, if a value contains a
  line break, a boolean is not `0`/`1`/`yes`/`no`, a route has no `server`, or
  more than 4 routes are enabled.
- Secrets are never inline: `socks_pass_file`, `dsocks_pass_file` and
  `token_file` name a `chmod 600` file; zroxy warns about group or world
  access and refuses world-writable files. `socks` and `dsocks` hold at most
  `user@host:port`.
- zroxy starts as root, binds its ports, then drops to the `zroxy` user the
  package creates (`USERID` in the package Makefile). `-U zroxy` is passed
  first, so `user` or `group` in UCI overrides it. The whitelist file and its
  directory must be readable by that user; the generated file and the secret
  files are read before the drop and may stay root-only (`chmod 600`).
- The init script also sets `no_new_privs` and runs zroxy in a procd jail
  (`procd_add_jail zroxy log procfs`) that mounts read-only the generated
  file, the secret files named in it, the whitelist's directory, `/etc/passwd`,
  `/etc/group`, `/etc/hosts` and the resolver files. Set
  `uci set zroxy.main.jail='0'` and reload to run without the jail, for
  example if a name lookup fails inside it. The jail, the user creation and
  the privilege drop under procd have not been tested on a device. If the
  resolver file is replaced rather than rewritten, the jail may keep seeing
  the old one until zroxy restarts.
- `/etc/config/zroxy` is a package conffile and is included in the normal
  configuration backup used by sysupgrade. After a firmware upgrade, confirm
  that the zroxy package is installed for the new release before trying to
  start it.

UCI options and the zroxy keys they write:

| Section | Option | zroxy key |
| --- | --- | --- |
| `main` | `enabled`, `jail` | service control only |
| `main` | `list listen` | `PORT` (one line each) |
| `main` | `white`, `openproxy`, `allowloopback`, `denyprivate` | `WHITE`, `OPENPROXY`, `ALLOWLOOPBACK`, `DENYPRIVATE` |
| `main` | `socks`, `socks_pass_file` | `SOCKS`, `SOCKSPASSFILE` |
| `main` | `snitimeout`, `sniidletimeout` | `SNITIMEOUT`, `SNIIDLETIMEOUT` |
| `main` | `log`, `user`, `group` | `LOG`, `USER`, `GROUP` |
| `dns` | `enabled` | when `0`, no DNS keys are written |
| `dns` | `listen` | `LDNS` |
| `dns` | `list acl` | `DACL` (joined with commas) |
| `dns` | `dsocks`, `dsocks_pass_file` | `DSOCKS`, `DSOCKSPASSFILE` |
| `dns` | `timeout`, `cache`, `ttl`, `rate`, `connections` | `DTIMEOUT`, `DCACHE`, `DTTL`, `DRATE`, `DNSCONNECTIONS` |
| `dns` | `snip` | `SNIP` |
| `route` | `enabled`, `server`, `via` | `DNS = server [via VIA]`, in order |
| `monitor` | `enabled` | when `0`, no monitor keys are written |
| `monitor` | `listen`, `token_file`, `timeout` | `MONITOR`, `MONITORTOKENFILE`, `MONITORTIMEOUT` |

The package ships with `enabled '0'`, so nothing listens until you turn it on.
The default settings run a direct SNI proxy on loopback port 8443. It needs a
whitelist: zroxy refuses to start SNI listeners without one unless you set
`openproxy '1'` (every host name is then forwarded). Create the whitelist,
then enable the service and inspect status and logs:

```sh
uci set zroxy.main.white='/etc/zroxy/whitelist.txt'
uci set zroxy.main.enabled='1'
uci commit zroxy
/etc/init.d/zroxy enable
/etc/init.d/zroxy restart
/etc/init.d/zroxy status
logread -e zroxy
```

To stop it and prevent it from starting at boot:

```sh
uci set zroxy.main.enabled='0'
uci commit zroxy
/etc/init.d/zroxy stop
/etc/init.d/zroxy disable
```

After changing UCI, run `uci commit zroxy` and then `/etc/init.d/zroxy reload`
(or `reload_config`): procd restarts zroxy only if the generated file has
changed. zroxy picks up whitelist edits by itself, without a reload.
The service sends stderr to `logread` and procd restarts it after an unexpected
exit. If a configured listener cannot start, zroxy exits with an error.

### Legacy mode: a hand-written native file

If `option config_file` is set to a non-empty path, the init script uses that
file exactly as before and generates nothing; every UCI option except
`enabled`, `jail` and `config_file` is then ignored. Routers upgraded from an
earlier package release keep their old `/etc/config/zroxy`, which sets
`config_file '/etc/zroxy/zroxy.conf'`, so they stay in this mode and keep
working. `/etc/zroxy/zroxy.conf` is still installed as an example and is also a
conffile. To migrate, move the settings from that file into UCI (see the table
above), then switch:

```sh
uci delete zroxy.main.config_file
uci commit zroxy
/etc/init.d/zroxy restart
```

A fresh install has no `config_file`, so it uses the UCI settings.

## LAN access and firewall

The packaged listener binds only to loopback. To accept LAN connections,
replace the `listen` entry with the router's LAN address and desired port,
then restart zroxy. Adapt the address and port to your network.

```sh
uci del_list zroxy.main.listen='127.0.0.1:8443@443'
uci add_list zroxy.main.listen='192.168.1.1:8443@443'
uci commit zroxy
/etc/init.d/zroxy restart
```
 Add a firewall rule in `/etc/config/firewall`
for the LAN zone if that zone does not already allow access to the router:

```text
config rule
    option name 'Allow-zroxy-SNI-from-LAN'
    option src 'lan'
    option proto 'tcp'
    option dest_port '8443'
    option target 'ACCEPT'
```

Apply it with `/etc/init.d/firewall reload`. This example does not expose the
listener to WAN. Restrict access to trusted clients: the SNI listener does not
authenticate incoming clients.

## Optional DNS alongside dnsmasq

dnsmasq normally owns port 53, and mDNS (umdns, avahi) uses 5353. To use zroxy
DNS without a port conflict, enable the `dns` section and add upstream routes
(up to 4 enabled, tried in order with failover):

```sh
uci set zroxy.dns.enabled='1'
uci set zroxy.dns.listen='127.0.0.1:5354'
uci add_list zroxy.dns.acl='127.0.0.0/8'
uci set zroxy.dns.connections='8'

uci add zroxy route
uci set zroxy.@route[-1].server='1.1.1.1:53'
uci add zroxy route
uci set zroxy.@route[-1].server='192.168.1.2'
uci set zroxy.@route[-1].via='direct'
uci commit zroxy
/etc/init.d/zroxy restart
```

Each route becomes a `DNS = server [via X]` line. `via` is a SOCKS5 spec
(`127.0.0.1:9050`) for that route only, or `direct` to skip the DNS SOCKS5
proxy (`dsocks`); set `enabled '0'` on a route to skip it. `connections` caps
the upstream DNS-over-TCP connections. Its default of 96 suits a server; a
small number is enough for a home router.

For selected domains, add a dnsmasq forwarding rule in `/etc/config/dhcp`,
within the existing `config dnsmasq` section:

```text
list server '/example.com/127.0.0.1#5354'
```

Then run `/etc/init.d/dnsmasq restart`. Replace `example.com` with your domain
and verify a query through dnsmasq. If you also enable `WHITE` and synthetic
answers, set `snip` to the address clients should use for the SNI listener.
Do not point zroxy's DNS upstream back at dnsmasq when dnsmasq forwards to
zroxy; that creates a forwarding loop.

## Release checklist

The program version is defined in `include/zroxy/version.h`. For a new upstream
release, update that header and `PKG_VERSION` together, pin
`PKG_SOURCE_VERSION` to the intended commit, regenerate `PKG_MIRROR_HASH` from
the OpenWrt source archive, and reset `PKG_RELEASE` to `1`. Increment
`PKG_RELEASE` for package-only changes to the same upstream version. Verify an
SDK build and the installed service on at least one target router.
