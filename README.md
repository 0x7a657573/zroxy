
# zroxy

**zroxy is a simple TLS sni proxy (sniproxy) written in pure C with no dependencies.**

This program supports incoming HTTP/HTTPS/IMAPs/POP3s/SMTPs traffic and can upstream to a DIRECT/SOCKS4/SOCKS5 proxy.

## What is SNI?

*Server Name Indication* (**SNI**) is an extension to the Transport Layer Security (**TLS**) protocol that allows a client to indicate which hostname it is attempting to connect to at the start of the handshaking process. This allows a server to present multiple certificates on the same IP address and TCP port number, and therefore allows multiple secure (HTTPS) websites (or any other service over TLS) to be served by the same IP address without requiring all of those sites to use the same certificate.

It is the conceptual equivalent to HTTP/1.1 name-based virtual hosting, but for HTTPS.

This also allows a proxy to forward client traffic to the right server during the TLS/SSL handshake. The desired hostname is not encrypted in the original SNI extension, so an eavesdropper can see which site is being requested.

For more information, see the [SNI Wikipedia article](https://en.wikipedia.org/wiki/Server_Name_Indication).

## How Does it Work?

This project implements a transparent proxy that accepts TLS connections, parses the initial client greeting, and proxies the complete SSL session to the backend corresponding to the server's name (or the default backend if no SNI is specified). This proxy **does NOT** require any cryptographic materials such as private keys, public keys, or certificates. It does not modify the TLS session and does not perform a man-in-the-middle attack. Moreover, it is not even linked with any cryptographic library.

When connecting to a domain through TLS/HTTPS, the initial TCP session contains the domain name **un-encrypted**, and thus zroxy can redirect a TLS connection based on that initial negotiation without decrypting the traffic or needing a private key. This technique requires a custom DNS server that redirects the targeted domains to our zroxy server (e.g., Unbound, Bind, or PowerDNS).

## Features

*   Supports incoming HTTP/HTTPS/IMAPs/POP3s/SMTPs
*   Supports upstream DIRECT/SOCKS5 proxy
*   Supports SOCKS5 user/pass authentication (RFC 1929)
*   Supports independent ports for each service (src/dst)
*   Name-based proxying of HTTPS without decrypting traffic
*   Supports both TLS and HTTP protocols
*   Traffic monitor with a web user interface
*   Forwards DNS requests (**UDP**) from SOCKS5 (**TCP**)
*   Supports domain whitelisting
*   Automatically reloads the whitelist
*   Multi-threaded
*   And more!

## Usage

### Command Details

```
Usage: zroxy [OPTION...]
	zroxy v1.2.3
	simple sni and dns proxy.

	-c, 'config'	path to config		path to config. -c /etc/zroxy.conf
	-p, 'port'	sni port		sni port that listens.
						<bind ip>:<local port>@<remote port>
						-p 127.0.0.1:8080@80,4433@433,853...
	-s, 'socks'	socks proxy		set proxy for up stream. -s 127.0.0.1:9050
	-m, 'monitor'	monitor port		monitor port that listens. -m 1234
	-w, 'white'	white list		white list for host -w /etc/withlist.txt
	-d, 'ldns'	local DNS server		dns server that listens. -d 0.0.0.0:53
	-u, 'dns'	upstream DNS providers		upstream DNS providers. -u 8.8.8.8
	-x, 'dsocks'	DNS upstream socks		DNS upstream socks. -x 127.0.0.1:9050
	-t, 'dtimeout'	DNS timeout in sec		DNS upstream timeout. -t 5
	-i, 'snip'	SNI IP for DNS server		SNI IP for DNS server. -i 127.0.0.1
	-h, 'help'	Give this help list
```

## Build

To build zroxy, you need `CMake` and `gcc`.

### Install Compile Tools for Debian

```
	# apt install cmake build-essential git
```

### Build on Linux/OS X/FreeBSD

1.  Clone the project:

    ```
    git clone https://github.com/0x7a657573/zroxy.git
    cd zroxy
    ```

2.  Create a build directory:

    ```
    mkdir build
    cd build
    ```

3.  Configure the project:

    ```
    cmake ..
    ```

4.  Build the project:

    ```
    make
    ```

### Static Build

I use glibc only for zroxy, but glibc uses other libraries that cannot be linked statically, such as `libnss`. This library is used to resolve hostnames to IP addresses, and we need it. To solve this problem, we can use [musl libc](https://musl.libc.org/). **musl** is an implementation of the C standard library built on top of the Linux system call API, including interfaces defined in the base language standard, POSIX, and widely agreed-upon extensions.

#### Install musl Tools for Debian

```
apt install musl-tools cmake git
```

#### Static Build on Linux/OS X/FreeBSD

1.  Clone the project:

    ```
    git clone https://github.com/0x7a657573/zroxy.git
    cd zroxy
    ```

2.  Create a build directory:

    ```
    mkdir build
    cd build
    ```

3.  Configure the project and use `musl-gcc` for static linking:

    ```
    export CC="musl-gcc -static -Os"
    cmake ..
    ```

4.  Build the project:

    ```
    make
    ```

## OpenWrt Build

See the [`zroxy in openwrt`](openwrt/README.md) document.
