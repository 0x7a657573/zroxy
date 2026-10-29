#!/usr/bin/env python3
"""End-to-end DNS forwarding, failure bounds, and whitelist synthesis."""

import os
import socket
import struct
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import zroxy_lab

SYNTHETIC_IP = (10, 9, 8, 7)
UPSTREAM_IP = (9, 9, 9, 9)


def _answer_with(ip):
    def respond(query):
        return zroxy_lab.build_dns_response(query, ip)
    return respond


def _start(lab, upstream, ldns, dtimeout="1"):
    return lab.zroxy(
        [
            "-l", "0",
            "-d", "127.0.0.1:%s" % ldns,
            "-u", "127.0.0.1:%s" % upstream.port,
            "-t", dtimeout,
        ],
        udp_ports=[ldns],
    )


def _expect_exact(ldns, query, timeout):
    started = time.monotonic()
    reply = zroxy_lab.udp_exchange(ldns, query, timeout)
    elapsed = time.monotonic() - started
    if reply is None:
        raise AssertionError("no DNS response within %.2fs" % elapsed)
    if reply != zroxy_lab.build_dns_response(query, UPSTREAM_IP):
        raise AssertionError("DNS payload mismatch: %r" % reply)
    if reply[:2] != query[:2]:
        raise AssertionError("DNS id was not preserved")
    return elapsed


def _expect_rcode(reply, query, rcode):
    if reply is None or len(reply) < 12:
        raise AssertionError("expected a DNS reply with rcode %d, got %r" % (rcode, reply))
    if reply[:2] != query[:2]:
        raise AssertionError("DNS id was not preserved: %r" % reply)
    flags = (reply[2] << 8) | reply[3]
    if (flags & 0x8000) == 0 or (flags & 0x000F) != rcode:
        raise AssertionError("expected rcode %d, got flags %04x" % (rcode, flags))


def _expect_bounded_failure(proc, ldns, query, timeout, prior_errors):
    """An upstream failure is answered with SERVFAIL within the proxy timeout."""
    started = time.monotonic()
    reply = zroxy_lab.udp_exchange(ldns, query, timeout)
    elapsed = time.monotonic() - started
    _expect_rcode(reply, query, 2)
    if elapsed > timeout + 0.75:
        raise AssertionError("DNS failure was not bounded: %.2fs" % elapsed)
    if not proc.wait_log("NO DATA", timeout + 1.0, after=prior_errors):
        raise AssertionError("zroxy did not finish the failed query\n%s" % proc.log_text())
    proc.check_alive()
    return elapsed


def test_dns_forward_fragmented():
    query = zroxy_lab.build_dns_query("example.test", qid=0x1A2B)
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP),
                                   fragment=1, fragment_gap=0.005)
        ldns = zroxy_lab.free_udp_port()
        proc = _start(lab, upstream, ldns)
        _expect_exact(ldns, query, 3.0)
        proc.check_alive()
        if not upstream.wait_queries(1, 2.0):
            raise AssertionError("fake DNS upstream received no query")
        if query not in upstream.queries:
            raise AssertionError("upstream query mismatch: %r" % upstream.queries)


def test_dns_bounded_failures():
    short = b"\x00" * 7
    # A header with one question whose name the decoder rejects.
    malformed = b"\x00\xb0\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xff" * 7
    valid = zroxy_lab.build_dns_query("example.test", qid=0x00B1)
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(
            mode="close",
            response_fn=_answer_with(UPSTREAM_IP),
            stall=8.0,
        )
        ldns = zroxy_lab.free_udp_port()
        proc = _start(lab, upstream, ldns, dtimeout="1")

        before = upstream.query_count()
        if zroxy_lab.udp_exchange(ldns, short, 0.5) is not None:
            raise AssertionError("a datagram shorter than a DNS header was answered")
        if upstream.query_count() != before or upstream.upstream_connections() != 0:
            raise AssertionError("a datagram shorter than a DNS header was forwarded")

        errors = proc.count_log("NO DATA")
        time.sleep(1.05)
        _expect_bounded_failure(proc, ldns, malformed, 4.0, errors)
        if upstream.query_count() <= before:
            raise AssertionError("malformed DNS payload was not forwarded upstream")
        if malformed not in upstream.queries:
            raise AssertionError("malformed bytes were not preserved: %r" % upstream.queries)

        upstream.set_mode("incomplete")
        errors = proc.count_log("NO DATA")
        prefixes = len(upstream.prefix_bytes)
        time.sleep(1.05)
        _expect_bounded_failure(proc, ldns, valid, 4.0, errors)
        if len(upstream.prefix_bytes) <= prefixes:
            raise AssertionError("incomplete length-prefix case accepted no connection")

        upstream.set_mode("close")
        errors = proc.count_log("NO DATA")
        before = upstream.query_count()
        time.sleep(1.05)
        _expect_bounded_failure(proc, ldns, valid, 4.0, errors)
        if upstream.query_count() <= before:
            raise AssertionError("upstream close case did not receive the query")

        upstream.set_mode("timeout")
        errors = proc.count_log("NO DATA")
        time.sleep(1.05)
        elapsed = _expect_bounded_failure(proc, ldns, valid, 4.0, errors)
        if elapsed >= upstream.stall:
            raise AssertionError("proxy waited for the stalled upstream instead of its own timeout")

        upstream.set_mode("reply")
        recovery = zroxy_lab.build_dns_query("example.test", qid=0x00C2)
        _expect_exact(ldns, recovery, 3.0)
        proc.check_alive()


def test_dns_whitelist_synthetic():
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP),
                                   fragment=1, fragment_gap=0.0)
        white = lab.write("white.txt", "allowed.test\n")
        ldns = zroxy_lab.free_udp_port()
        proc = lab.zroxy(
            [
                "-l", "0",
                "-d", "127.0.0.1:%s" % ldns,
                "-u", "127.0.0.1:%s" % upstream.port,
                "-t", "1",
                "-i", "%d.%d.%d.%d" % SYNTHETIC_IP,
                "-w", white,
            ],
            udp_ports=[ldns],
        )
        allowed = zroxy_lab.build_dns_query("allowed.test", qid=0x1111)
        reply = zroxy_lab.udp_exchange(ldns, allowed, 3.0)
        if reply is None:
            raise AssertionError("whitelisted name produced no response\n%s" % proc.log_text())
        parsed = zroxy_lab.parse_dns_message(reply)
        if parsed["id"] != 0x1111:
            raise AssertionError("synthetic response did not keep the query id")
        if (parsed["flags"] & 0x8000) == 0 or (parsed["flags"] & 0x000F) != 0:
            raise AssertionError("synthetic flags are not a NOERROR response: %04x" % parsed["flags"])
        a_records = [a for a in parsed["answers"] if a["type"] == 1 and a["rdata"] == bytes(SYNTHETIC_IP)]
        if not a_records:
            raise AssertionError("synthetic A answer missing: %r" % parsed)
        if a_records[0]["name"] != "allowed.test":
            raise AssertionError("synthetic answer name %r" % a_records[0]["name"])
        if upstream.query_count() != 0:
            raise AssertionError("whitelisted name was forwarded upstream")

        mixed = zroxy_lab.build_dns_query("Allowed.TEST", qid=0x1112)
        reply = zroxy_lab.udp_exchange(ldns, mixed, 3.0)
        if reply is None:
            raise AssertionError("mixed-case whitelisted name produced no response\n%s" % proc.log_text())
        parsed = zroxy_lab.parse_dns_message(reply)
        if not any(a["type"] == 1 and a["rdata"] == bytes(SYNTHETIC_IP) for a in parsed["answers"]):
            raise AssertionError("mixed-case name did not get the synthetic answer: %r" % parsed)
        if upstream.query_count() != 0:
            raise AssertionError("mixed-case whitelisted name was forwarded upstream")

        # IPv6 is not proxied: AAAA and HTTPS get NODATA, never an upstream address.
        for qtype in (28, 65):
            query = zroxy_lab.build_dns_query("allowed.test", qid=0x1113, qtype=qtype)
            reply = zroxy_lab.udp_exchange(ldns, query, 3.0)
            _expect_rcode(reply, query, 0)
            nodata = zroxy_lab.parse_dns_message(reply)
            if nodata["answers"]:
                raise AssertionError("whitelisted type %d was not NODATA: %r" % (qtype, reply))
            if len(nodata["authorities"]) != 1 or nodata["authorities"][0]["type"] != 6:
                raise AssertionError("whitelisted type %d did not carry an SOA: %r" % (qtype, nodata))
        if upstream.query_count() != 0:
            raise AssertionError("whitelisted AAAA/HTTPS was forwarded upstream")

        other = zroxy_lab.build_dns_query("other.test", qid=0x2222)
        _expect_exact(ldns, other, 3.0)
        if other not in upstream.queries:
            raise AssertionError("non-whitelisted name did not follow the upstream path")
        proc.check_alive()


def _expect_synthetic(ldns, name, qid, proc):
    reply = zroxy_lab.udp_exchange(ldns, zroxy_lab.build_dns_query(name, qid=qid), 3.0)
    if reply is None:
        raise AssertionError("%s produced no response\n%s" % (name, proc.log_text()))
    parsed = zroxy_lab.parse_dns_message(reply)
    if not any(a["type"] == 1 and a["rdata"] == bytes(SYNTHETIC_IP) for a in parsed["answers"]):
        raise AssertionError("%s did not get the synthetic answer: %r" % (name, parsed))


def test_dns_whitelist_reload():
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP),
                                   fragment=1, fragment_gap=0.0)
        white = lab.write("white.txt", "first.test\n")
        ldns = zroxy_lab.free_udp_port()
        proc = lab.zroxy(
            [
                "-l", "0",
                "-d", "127.0.0.1:%s" % ldns,
                "-u", "127.0.0.1:%s" % upstream.port,
                "-t", "1",
                "-i", "%d.%d.%d.%d" % SYNTHETIC_IP,
                "-w", white,
            ],
            udp_ports=[ldns],
        )
        _expect_synthetic(ldns, "first.test", 0x3001, proc)
        later = zroxy_lab.build_dns_query("later.test", qid=0x3002)
        _expect_exact(ldns, later, 3.0)
        if later not in upstream.queries:
            raise AssertionError("later.test was answered before it was whitelisted")

        # Atomic save: write a temp file and rename it over the whitelist.
        tmp = lab.write("white.txt.tmp", "later.test\n")
        os.replace(tmp, white)
        if not proc.wait_log("Reload filter:", 3.0):
            raise AssertionError("rename over whitelist did not reload\n%s" % proc.log_text())
        _expect_synthetic(ldns, "later.test", 0x3003, proc)

        # In-place save: the watch must survive the earlier rename.
        lab.write("white.txt", "third.test\n")
        if not proc.wait_log("Reload filter:", 3.0, after=1):
            raise AssertionError("in-place write did not reload\n%s" % proc.log_text())
        _expect_synthetic(ldns, "third.test", 0x3004, proc)
        proc.check_alive()


def test_dns_acl():
    query = zroxy_lab.build_dns_query("example.test", qid=0x3301)
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP))
        denied_port = zroxy_lab.free_udp_port()
        denied = lab.zroxy(
            [
                "-l", "0",
                "-d", "127.0.0.1:%s" % denied_port,
                "-u", "127.0.0.1:%s" % upstream.port,
                "-A", "10.0.0.0/8",
            ],
            tcp_ports=[denied_port],
            udp_ports=[denied_port],
        )
        if zroxy_lab.udp_exchange(denied_port, query, 0.5) is not None:
            raise AssertionError("ACL-denied UDP query received a reply")
        try:
            _tcp_dns(denied_port, query, 1.0)
        except (ConnectionError, TimeoutError):
            pass
        else:
            raise AssertionError("ACL-denied TCP query received a reply")
        if upstream.query_count() != 0:
            raise AssertionError("ACL-denied queries reached upstream")
        denied.check_alive()

        allowed_port = zroxy_lab.free_udp_port()
        allowed = lab.zroxy(
            [
                "-l", "0",
                "-d", "127.0.0.1:%s" % allowed_port,
                "-u", "127.0.0.1:%s" % upstream.port,
                "-A", "127.0.0.0/8",
            ],
            tcp_ports=[allowed_port],
            udp_ports=[allowed_port],
        )
        if zroxy_lab.udp_exchange(allowed_port, query, 3.0) != _answer_with(UPSTREAM_IP)(query):
            raise AssertionError("loopback-allowed UDP query failed")
        tcp_query = zroxy_lab.build_dns_query("example.test", qid=0x3302)
        if _tcp_dns(allowed_port, tcp_query, 3.0) != _answer_with(UPSTREAM_IP)(tcp_query):
            raise AssertionError("loopback-allowed TCP query failed")
        allowed.check_alive()


def test_dns_upstream_reuse():
    # Each DNS worker keeps its upstream connection, so once every worker has
    # connected, further queries must not open new connections.
    workers = 32
    queries = workers + 16
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="keepalive", response_fn=_answer_with(UPSTREAM_IP))
        ldns = zroxy_lab.free_udp_port()
        proc = _start(lab, upstream, ldns)
        for i in range(queries):
            _expect_exact(ldns, zroxy_lab.build_dns_query("reuse%d.test" % i, qid=0x4000 + i), 3.0)
        if upstream.query_count() != queries:
            raise AssertionError("upstream saw %d of %d queries" % (upstream.query_count(), queries))
        if upstream.upstream_connections() > workers:
            raise AssertionError("upstream connections not reused: %d connections for %d queries"
                                 % (upstream.upstream_connections(), queries))

        # The server now closes every idle kept connection. Each worker must
        # notice its stale connection and reconnect instead of failing.
        upstream.set_mode("reply")
        time.sleep(0.5)
        errors = proc.count_log("NO DATA")
        for i in range(queries):
            _expect_exact(ldns, zroxy_lab.build_dns_query("after%d.test" % i, qid=0x4100 + i), 3.0)
        if proc.count_log("NO DATA") != errors:
            raise AssertionError("stale upstream connection caused a failed query\n%s" % proc.log_text())
        proc.check_alive()


def test_dns_cache_and_coalescing():
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP),
                                   fragment=1, fragment_gap=0.0)
        ldns = zroxy_lab.free_udp_port()
        proc = _start(lab, upstream, ldns)

        first = zroxy_lab.build_dns_query("cached.test", qid=0x5001)
        _expect_exact(ldns, first, 3.0)
        again = zroxy_lab.build_dns_query("Cached.TEST", qid=0x5002)
        reply = zroxy_lab.udp_exchange(ldns, again, 3.0)
        _expect_rcode(reply, again, 0)
        parsed = zroxy_lab.parse_dns_message(reply)
        if parsed["questions"][0][0] != "Cached.TEST":
            raise AssertionError("cached reply did not keep the client's spelling: %r" % parsed)
        if not parsed["answers"] or parsed["answers"][0]["rdata"] != bytes(UPSTREAM_IP):
            raise AssertionError("cached reply lost its answer: %r" % parsed)
        if parsed["answers"][0]["ttl"] > 60:
            raise AssertionError("cached TTL grew: %r" % parsed)
        if upstream.query_count() != 1:
            raise AssertionError("cached name went upstream again: %d queries" % upstream.query_count())

        # Identical queries in flight together share one upstream fetch.
        slow = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP),
                              fragment=1, fragment_gap=0.02)
        ldns2 = zroxy_lab.free_udp_port()
        _start(lab, slow, ldns2, dtimeout="3")
        replies = [None] * 8

        def ask(i):
            query = zroxy_lab.build_dns_query("shared.test", qid=0x6000 + i)
            replies[i] = (query, zroxy_lab.udp_exchange(ldns2, query, 4.0))

        threads = [threading.Thread(target=ask, args=(i,)) for i in range(len(replies))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for query, reply in replies:
            _expect_rcode(reply, query, 0)
        if slow.query_count() != 1:
            raise AssertionError("%d concurrent identical queries made %d upstream fetches"
                                 % (len(replies), slow.query_count()))
        proc.check_alive()


def test_dns_cache_disabled():
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_answer_with(UPSTREAM_IP))
        ldns = zroxy_lab.free_udp_port()
        proc = lab.zroxy(
            ["-l", "0", "-d", "127.0.0.1:%s" % ldns,
             "-u", "127.0.0.1:%s" % upstream.port, "-e", "0"],
            udp_ports=[ldns],
        )
        for qid in (0x5101, 0x5102):
            _expect_exact(ldns, zroxy_lab.build_dns_query("uncached.test", qid=qid), 3.0)
        if upstream.query_count() != 2:
            raise AssertionError("cache-disabled queries were cached: %d" % upstream.query_count())
        proc.check_alive()


def _large_answer(query):
    """The query plus enough TXT records to pass 1232 bytes."""
    msg = bytearray(zroxy_lab.build_dns_response(query, UPSTREAM_IP))
    txt = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 200) + bytes([199]) + b"t" * 199
    count = 7
    msg[6:8] = struct.pack("!H", 1 + count)
    msg.extend(txt * count)
    return bytes(msg)


def _tcp_dns(port, query, timeout):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(struct.pack("!H", len(query)) + query)
        prefix = zroxy_lab._read_exact(sock, 2, timeout)
        length = struct.unpack("!H", prefix)[0]
        return zroxy_lab._read_exact(sock, length, timeout)
    finally:
        sock.close()


def test_dns_tcp_fallback():
    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(mode="reply", response_fn=_large_answer,
                                   fragment=4096, fragment_gap=0.0)
        ldns = zroxy_lab.free_udp_port()
        proc = _start(lab, upstream, ldns)

        query = zroxy_lab.build_dns_query("big.test", qid=0x7001)
        expected = _large_answer(query)
        reply = zroxy_lab.udp_exchange(ldns, query, 3.0)
        _expect_rcode(reply, query, 0)
        if not reply[2] & 0x02:
            raise AssertionError("large UDP reply was not truncated: %d bytes" % len(reply))

        tcp_query = zroxy_lab.build_dns_query("big.test", qid=0x7002)
        reply = _tcp_dns(ldns, tcp_query, 3.0)
        if reply != _large_answer(tcp_query):
            raise AssertionError("TCP reply differs: %d bytes, want %d" % (len(reply), len(expected)))
        if reply[2] & 0x02:
            raise AssertionError("TCP reply is truncated")

        small = zroxy_lab.build_dns_query("small.test", qid=0x7003)
        reply = _tcp_dns(ldns, small, 3.0)
        _expect_rcode(reply, small, 0)
        proc.check_alive()


def main():
    tests = [
        test_dns_forward_fragmented,
        test_dns_bounded_failures,
        test_dns_whitelist_synthetic,
        test_dns_whitelist_reload,
        test_dns_acl,
        test_dns_upstream_reuse,
        test_dns_cache_and_coalescing,
        test_dns_cache_disabled,
        test_dns_tcp_fallback,
    ]
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
