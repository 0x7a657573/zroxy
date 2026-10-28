#!/usr/bin/env python3
"""End-to-end monitor JSON after real SNI and DNS traffic."""

import os
import re
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import zroxy_lab

UPSTREAM_IP = (9, 9, 9, 9)
COUNTERS = (
    "UpTime",
    "MaxConnection",
    "ActiveConnection",
    "TotalConnection",
    "TotalRx",
    "TotalTx",
)


def _expected_version():
    path = os.path.join(zroxy_lab.ROOT, "src", "version.h")
    with open(path, encoding="utf-8") as f:
        m = re.search(r'^#define\s+version\s+"([^"]+)"', f.read(), re.M)
    if not m:
        raise AssertionError("version not found in %s" % path)
    return m.group(1)


def _dns_reply(query):
    return zroxy_lab.build_dns_response(query, UPSTREAM_IP)


def _number(value, label):
    if type(value) is not int:
        raise AssertionError("%s is not an integer: %r" % (label, value))


def _wait_doc(port, predicate, timeout):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = zroxy_lab.fetch_monitor(port, timeout=2.0)
        if predicate(last["json"]):
            return last
        time.sleep(0.05)
    raise AssertionError("monitor counters did not reach the expected values: %r" % last)


def test_monitor_after_traffic():
    hello = zroxy_lab.client_hello("localhost")
    query = zroxy_lab.build_dns_query("example.test", qid=0x4455)
    with zroxy_lab.Lab() as lab:
        tcp_up = lab.tcp_server(response=zroxy_lab.HTTP_OK, read_exact=len(hello))
        dns_up = lab.dns_server(mode="reply", response_fn=_dns_reply, fragment=1, fragment_gap=0.002)
        sni_port = zroxy_lab.free_tcp_port()
        ldns = zroxy_lab.free_udp_port()
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            [
                "-l", "0",
                "-o", "2",
                "-p", "127.0.0.1:%s@%s" % (sni_port, tcp_up.port),
                "-m", str(mon_port),
                "-d", "127.0.0.1:%s" % ldns,
                "-u", "127.0.0.1:%s" % dns_up.port,
                "-t", "2",
            ],
            tcp_ports=[sni_port, mon_port],
            udp_ports=[ldns],
        )
        base = _wait_doc(
            mon_port,
            lambda doc: doc["SNI_Server"]["ActiveConnection"] == 0,
            3.0,
        )["json"]
        sni_base = base["SNI_Server"]["TotalConnection"]
        dns_base = base["DNS_Server"]["TotalConnection"]

        data, closed = zroxy_lab.tcp_exchange("127.0.0.1", sni_port, hello, timeout=4.0)
        if data != zroxy_lab.HTTP_OK or not closed:
            raise AssertionError("SNI exchange failed before monitor check")
        reply = zroxy_lab.udp_exchange(ldns, query, 3.0)
        if reply != _dns_reply(query):
            raise AssertionError("DNS exchange failed before monitor check: %r" % reply)

        expected_rx = len(zroxy_lab.HTTP_OK)
        expected_tx = len(hello)
        dns_tx = len(query) + 2
        dns_rx = len(reply) + 2

        fetched = _wait_doc(
            mon_port,
            lambda doc: (
                doc["SNI_Server"]["TotalConnection"] >= sni_base + 1
                and doc["SNI_Server"]["TotalRx"] >= expected_rx
                and doc["SNI_Server"]["TotalTx"] >= expected_tx
                and doc["DNS_Server"]["TotalConnection"] >= dns_base + 1
                and doc["DNS_Server"]["TotalTx"] >= dns_tx
                and doc["DNS_Server"]["TotalRx"] >= dns_rx
            ),
            3.0,
        )
        if not fetched["closed"]:
            raise AssertionError("monitor did not close the connection")
        doc = fetched["json"]
        if doc.get("ZroxyVersion") != _expected_version():
            raise AssertionError("unexpected version %r" % doc.get("ZroxyVersion"))
        _number(doc.get("CountOfOpenFile"), "CountOfOpenFile")
        for name in ("SNI_Server", "DNS_Server"):
            obj = doc.get(name)
            if not isinstance(obj, dict):
                raise AssertionError("missing statistic object %s" % name)
            for field in COUNTERS:
                _number(obj.get(field), "%s.%s" % (name, field))

        sni = doc["SNI_Server"]
        dns = doc["DNS_Server"]
        if sni["TotalRx"] - base["SNI_Server"]["TotalRx"] != expected_rx:
            raise AssertionError("SNI TotalRx does not match the upstream response")
        if sni["TotalTx"] - base["SNI_Server"]["TotalTx"] != expected_tx:
            raise AssertionError("SNI TotalTx does not match the ClientHello")
        if dns["TotalTx"] - base["DNS_Server"]["TotalTx"] != dns_tx:
            raise AssertionError(
                "DNS TotalTx delta %s != %s" % (dns["TotalTx"] - base["DNS_Server"]["TotalTx"], dns_tx)
            )
        if dns["TotalRx"] - base["DNS_Server"]["TotalRx"] != dns_rx:
            raise AssertionError(
                "DNS TotalRx delta %s != %s" % (dns["TotalRx"] - base["DNS_Server"]["TotalRx"], dns_rx)
            )
        proc.check_alive()


def main():
    try:
        test_monitor_after_traffic()
    except Exception:
        traceback.print_exc()
        print("FAIL test_monitor_after_traffic")
        return 1
    print("PASS test_monitor_after_traffic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
