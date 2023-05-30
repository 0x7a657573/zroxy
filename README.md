
# zroxy

**zroxy is a simple TLS sni proxy (sniproxy) written with pure C and no dependensi.**

This program supports incoming HTTP/HTTPS/IMAPs/POP3s/SMTPs … traffic and upstream to DIRECT/SOCKS4/SOCKS5 proxy.

  
### What is SNI?
*Server Name Indication* (**SNI**) is an extension to the Transport Layer Security (**TLS**) computer networking protocol by which a client indicates which hostname it is attempting to connect to at the start of the handshaking process.

This allows a server to present one of multiple possible certificates on the same IP address and TCP port number and hence allows multiple secure (HTTPS) websites (or any other service over TLS) to be served by the same IP address without requiring all those sites to use the same certificate.

It is the conceptual equivalent to HTTP/1.1 name-based virtual hosting, but for HTTPS.

**This** also allows a proxy to forward client traffic to the right server during TLS/SSL handshake. The desired hostname is not encrypted in the original SNI extension, so an eavesdropper can see which site is being requested.
for more read [SNI wiki](https://en.wikipedia.org/wiki/Server_Name_Indication).

  
### How Does it Work?
This project implements a transparent proxy that accepts TLS connection, parses the initial client greeting and proxies the complete SSL session to the backend corresponding to the server's name (or default backend if no SNI specified). This proxy **does NOT** require any cryptographic materials such private keys, public keys, certificates. It does not modify TLS session and does not perform man-in-the middle intrusion. Moreover, it is not even linked with any cryptographic library.

When connecting to a domain through TLS/HTTPS the initial TCP session contain the domain name **un-encrypted** and thus sniproxy can redirect a TLS connection based on that initial negotiation without decrypting the traffic nor needing a private key. this technique require a custom DNS Server that redirect the targeted domains to our zroxy server (dns server like Unbound, Bind or PowerDNS).


#  Features
- Supporting incoming HTTP/HTTPS/IMAPs/POP3s/SMTPs
- Support upstream DIRECT/SOCKS5 proxy
- Support SOCKS5 user/pass Authentication method(RFC 1929)
- Support independent port for one service (src/dst)
- Name-based proxying of HTTPS without decrypting traffic.
- Supports both TLS and HTTP protocols.
- Traffic monitor with web user interface
- forward DNS request (**UDP**) from SOCKS5 (**TCP**)
- Support domain whitelist
- auto reload whitelist
- Multi-thread
- Etc.

#  Usage
## Command Details
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

#  Build
for build zroxy you need `CMake` tools. please check installed CMake on your device.
## Linux/OS X/FreeBSD

```
	# clone the project 
	git clone https://github.com/0x7a657573/zroxy.git
	cd zroxy
	
	# make build dir
	mkdir build
	cd build
	
	# config project
	cmake ..
	
	# build
	make
```