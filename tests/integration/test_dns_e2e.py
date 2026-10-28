#!/usr/bin/env python3
"""End-to-end DNS forwarding, failure bounds, and whitelist synthesis."""

import os
import sys
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


def _expect_bounded_failure(proc, ldns, query, timeout, prior_errors):
    started = time.monotonic()
    reply = zroxy_lab.udp_exchange(ldns, query, timeout)
    elapsed = time.monotonic() - started
    if reply is not None:
        raise AssertionError("expected no DNS response, got %r" % reply)
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
    malformed = b"\xff" * 7
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
        errors = proc.count_log("NO DATA")
        _expect_bounded_failure(proc, ldns, malformed, 4.0, errors)
        if upstream.query_count() <= before:
            raise AssertionError("malformed DNS payload was not forwarded upstream")
        if malformed not in upstream.queries:
            raise AssertionError("malformed bytes were not preserved: %r" % upstream.queries)

        upstream.set_mode("incomplete")
        errors = proc.count_log("NO DATA")
        prefixes = len(upstream.prefix_bytes)
        _expect_bounded_failure(proc, ldns, valid, 4.0, errors)
        if len(upstream.prefix_bytes) <= prefixes:
            raise AssertionError("incomplete length-prefix case accepted no connection")

        upstream.set_mode("close")
        errors = proc.count_log("NO DATA")
        before = upstream.query_count()
        _expect_bounded_failure(proc, ldns, valid, 4.0, errors)
        if upstream.query_count() <= before:
            raise AssertionError("upstream close case did not receive the query")

        upstream.set_mode("timeout")
        errors = proc.count_log("NO DATA")
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


def main():
    tests = [
        test_dns_forward_fragmented,
        test_dns_bounded_failures,
        test_dns_whitelist_synthetic,
        test_dns_whitelist_reload,
        test_dns_upstream_reuse,
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
