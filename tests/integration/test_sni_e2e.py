#!/usr/bin/env python3
"""End-to-end SNI forwarding through the real zroxy binary."""

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import zroxy_lab


def _exchange(port, hello):
    data, closed = zroxy_lab.tcp_exchange("127.0.0.1", port, hello, timeout=4.0)
    if data != zroxy_lab.HTTP_OK:
        raise AssertionError("client payload mismatch: %r" % data)
    if not closed:
        raise AssertionError("zroxy did not close the client connection")
    return data


def test_sni_direct():
    hello = zroxy_lab.client_hello("localhost")
    with zroxy_lab.Lab() as lab:
        upstream = lab.tcp_server(response=zroxy_lab.HTTP_OK, read_exact=len(hello))
        sni_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            ["-l", "0", "-o", "2", "-p", "127.0.0.1:%s@%s" % (sni_port, upstream.port)],
            tcp_ports=[sni_port],
        )
        _exchange(sni_port, hello)
        proc.check_alive()
        if not upstream.saw_exact(hello):
            raise AssertionError("upstream did not receive the ClientHello: %r" % upstream.payloads())
        if upstream.connection_count() < 1:
            raise AssertionError("upstream accepted no SNI-routed connection")


def test_sni_socks5():
    hello = zroxy_lab.client_hello("localhost")
    with zroxy_lab.Lab() as lab:
        upstream = lab.tcp_server(response=zroxy_lab.HTTP_OK, read_exact=len(hello))
        socks = lab.socks_server(
            upstream_host="127.0.0.1",
            upstream_port=upstream.port,
            fragment=1,
            fragment_gap=0.005,
        )
        sni_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            [
                "-l", "0",
                "-o", "3",
                "-p", "127.0.0.1:%s@%s" % (sni_port, upstream.port),
                "-s", "127.0.0.1:%s" % socks.port,
            ],
            tcp_ports=[sni_port],
        )
        _exchange(sni_port, hello)
        proc.check_alive()
        if not socks.greetings:
            raise AssertionError("SOCKS5 server received no greeting")
        if socks.greetings[0] != b"\x05\x02\x00\x02":
            raise AssertionError("unexpected SOCKS5 greeting %r" % socks.greetings[0])
        if ("localhost", upstream.port) not in socks.connects:
            raise AssertionError("CONNECT target mismatch: %r" % socks.connects)
        if not upstream.saw_exact(hello):
            raise AssertionError("ClientHello did not reach upstream via SOCKS5: %r" % upstream.payloads())


def main():
    tests = [test_sni_direct, test_sni_socks5]
    failed = 0
    for test in tests:
        try:
            test()
        except Exception:
            failed += 1
            traceback.print_exc()
            print("FAIL", test.__name__)
        else:
            print("PASS", test.__name__)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
