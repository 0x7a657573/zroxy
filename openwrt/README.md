# zroxy on OpenWrt

This package installs the zroxy binary, a procd service, and two configuration
files. The service is installed disabled; once enabled, it starts on boot and
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

- `/etc/config/zroxy` is the UCI service control: `enabled` and the path to the
  native configuration file.
- `/etc/zroxy/zroxy.conf` contains all zroxy settings, including any SOCKS5
  credentials. It is always passed with `-c`; the process working directory is
  irrelevant. Keep credentials readable only by root if you add them.
- Both files are package conffiles and are included in the normal configuration
  backup used by sysupgrade. After a firmware upgrade, confirm that the zroxy
  package is installed for the new release before trying to start it.

The package ships with `enabled '0'`, so nothing listens until you turn it on.
The default configuration then runs a direct SNI proxy on loopback port 8443.
Review `/etc/zroxy/zroxy.conf` first, then enable it and inspect status and
logs:

```sh
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

Edit `/etc/zroxy/zroxy.conf` to choose the SNI listener, direct or SOCKS5
upstream, optional whitelist, and optional DNS service. After changing this
file, run `/etc/init.d/zroxy reload`: procd restarts zroxy only if the file has
changed. `uci commit zroxy` followed by `reload_config` applies UCI changes the
same way. zroxy picks up whitelist edits by itself, without a reload.
The service sends stderr to `logread` and procd restarts it after an unexpected
exit. If a configured listener cannot start, zroxy exits with an error.

## LAN access and firewall

The packaged listener binds only to loopback. To accept LAN connections, set
`PORT` in `/etc/zroxy/zroxy.conf` to the router's LAN address and desired port,
for example `PORT = 192.168.1.1:8443@443`, then restart zroxy. Adapt the
address and port to your network. Add a firewall rule in `/etc/config/firewall`
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
DNS without a port conflict, add these lines to `/etc/zroxy/zroxy.conf` and
restart zroxy:

```ini
LDNS = 127.0.0.1:5354
DNS = 1.1.1.1:53
DACL = 127.0.0.0/8
DNSCONNECTIONS = 8
```

`DNSCONNECTIONS` caps the upstream DNS-over-TCP connections. Its default of 96
suits a server; a small number is enough for a home router.

For selected domains, add a dnsmasq forwarding rule in `/etc/config/dhcp`,
within the existing `config dnsmasq` section:

```text
list server '/example.com/127.0.0.1#5354'
```

Then run `/etc/init.d/dnsmasq restart`. Replace `example.com` with your domain
and verify a query through dnsmasq. If you also enable `WHITE` and synthetic
answers, set `SNIP` to the address clients should use for the SNI listener.
Do not point zroxy's DNS upstream back at dnsmasq when dnsmasq forwards to
zroxy; that creates a forwarding loop.

## Release checklist

The program version is defined in `include/zroxy/version.h`. For a new upstream
release, update that header and `PKG_VERSION` together, pin
`PKG_SOURCE_VERSION` to the intended commit, regenerate `PKG_MIRROR_HASH` from
the OpenWrt source archive, and reset `PKG_RELEASE` to `1`. Increment
`PKG_RELEASE` for package-only changes to the same upstream version. Verify an
SDK build and the installed service on at least one target router.
