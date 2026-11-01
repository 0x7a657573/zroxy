#!/usr/bin/env python3
"""End-to-end monitor JSON after real SNI and DNS traffic."""

import os
import re
import signal
import socket
import sys
import threading
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
DNS_COUNTERS = COUNTERS + (
    "CacheHits",
    "CacheMisses",
    "CacheShared",
    "CacheEntries",
    "CacheEvictions",
    "QueueStaleDropped",
    "QueueFull",
    "AclDropped",
    "RateDropped",
    "TcpRefused",
    "TcpActive",
    "QueueDropped",
    "UpstreamTimeouts",
    "UpstreamErrors",
    "ActiveUpstreams",
)


def _expected_version():
    path = os.path.join(zroxy_lab.ROOT, "include", "zroxy", "version.h")
    with open(path, encoding="utf-8") as f:
        m = re.search(r'^#define\s+version\s+"([^"]+)"', f.read(), re.M)
    if not m:
        raise AssertionError("version not found in %s" % path)
    return m.group(1)


SNI_CLOSE_KEYS = (
    "Relayed",
    "Refused",
    "NoHostname",
    "Blocked",
    "UnsafeDestination",
    "ResolveFailures",
    "SocksFailures",
    "ConnectFailures",
    "HandshakeTimeouts",
    "IdleTimeouts",
    "StallTimeouts",
)


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
        query2 = zroxy_lab.build_dns_query("example.test", qid=0x4456)
        reply2 = zroxy_lab.udp_exchange(ldns, query2, 3.0)
        if reply2 != _dns_reply(query2):
            raise AssertionError("second DNS exchange failed before monitor check: %r" % reply2)

        expected_rx = len(zroxy_lab.HTTP_OK)
        expected_tx = len(hello)
        # The second query is a cache hit; the existing statistics field counts
        # upstream bytes, so only the first response contributes to TotalRx.
        dns_tx = len(query) + len(query2) + 4
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
            fields = DNS_COUNTERS if name == "DNS_Server" else COUNTERS
            for field in fields:
                _number(obj.get(field), "%s.%s" % (name, field))

        # Every counter must be a plain non-negative JSON integer, and the
        # uptime of a process started seconds ago must be small.
        for name in ("SNI_Server", "DNS_Server"):
            for field in COUNTERS:
                if doc[name][field] < 0:
                    raise AssertionError("%s.%s is negative: %r" % (name, field, doc[name]))
            if doc[name]["UpTime"] > 60:
                raise AssertionError("%s.UpTime is implausible: %r" % (name, doc[name]["UpTime"]))
        if doc["CountOfOpenFile"] < 3:
            raise AssertionError("CountOfOpenFile is implausible: %r" % doc["CountOfOpenFile"])

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
        if dns["CacheHits"] < 1 or dns["CacheEntries"] < 1:
            raise AssertionError("DNS cache counters did not report the repeated query: %r" % dns)
        proc.check_alive()


def test_dns_timeout_is_not_also_an_error():
    query = zroxy_lab.build_dns_query("timeout.test", qid=0x4466)
    with zroxy_lab.Lab() as lab:
        dns_up = lab.dns_server(mode="timeout", stall=5.0)
        ldns = zroxy_lab.free_udp_port()
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            ["-l", "0", "-m", str(mon_port), "-d", "127.0.0.1:%s" % ldns,
             "-u", "127.0.0.1:%s" % dns_up.port, "-t", "1"],
            tcp_ports=[mon_port], udp_ports=[ldns],
        )
        base = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)["json"]["DNS_Server"]
        reply = zroxy_lab.udp_exchange(ldns, query, 4.0)
        if reply is None or (reply[3] & 0x0F) != 2:
            raise AssertionError("upstream timeout did not return SERVFAIL: %r" % reply)
        doc = _wait_doc(
            mon_port,
            lambda current: current["DNS_Server"]["UpstreamTimeouts"] >=
            base["UpstreamTimeouts"] + 1,
            3.0,
        )["json"]["DNS_Server"]
        if doc["UpstreamErrors"] != base["UpstreamErrors"]:
            raise AssertionError("timeout also incremented UpstreamErrors: %r" % doc)
        proc.check_alive()


def test_monitor_http_framing():
    with zroxy_lab.Lab() as lab:
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(["-l", "0", "-m", str(mon_port)], tcp_ports=[mon_port])
        got = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)
        fd_dir = "/proc/%d/fd" % proc.proc.pid
        if os.path.isdir(fd_dir):
            # Idle descriptors are stdin, stdout, stderr and the listener; the
            # report is built while the monitor's own client socket is open.
            # The descriptor of the directory scan itself is not counted. The
            # readiness probe's connection may still be closing, so retry.
            deadline = time.monotonic() + 3.0
            while True:
                reported = got["json"]["CountOfOpenFile"]
                expected_fds = len(os.listdir(fd_dir)) + 1
                if reported == expected_fds:
                    break
                if time.monotonic() > deadline:
                    raise AssertionError(
                        "CountOfOpenFile %r, expected %d" % (reported, expected_fds))
                time.sleep(0.1)
                got = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)
        headers = got["headers"]
        if headers.get("connection") != "close":
            raise AssertionError("Connection header is %r" % headers.get("connection"))
        if headers.get("cache-control") != "no-store":
            raise AssertionError("Cache-Control header is %r" % headers.get("cache-control"))
        if not headers.get("content-type", "").startswith("application/json"):
            raise AssertionError("Content-Type header is %r" % headers.get("content-type"))
        if not got["closed"]:
            raise AssertionError("monitor did not close the connection")
        data, closed = zroxy_lab.tcp_exchange(
            "127.0.0.1", mon_port, b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n", timeout=2.0)
        expected = (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n")
        if data != expected or not closed:
            raise AssertionError("unexpected 404 response %r" % data)


def test_monitor_process_object():
    with zroxy_lab.Lab() as lab:
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(["-l", "0", "-m", str(mon_port)], tcp_ports=[mon_port])
        before = int(time.time())
        doc = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)["json"]
        after = int(time.time())
        obj = doc.get("Process")
        if not isinstance(obj, dict):
            raise AssertionError("missing Process object: %r" % doc)
        linux = os.path.isdir("/proc/self")
        keys = ["Pid", "StartTime", "UpTime", "OpenFiles", "MaxOpenFiles",
                "PeakRssBytes", "CpuUserMs", "CpuSystemMs"]
        if linux:
            keys += ["Threads", "RssBytes"]
        for key in keys:
            _number(obj.get(key), "Process." + key)
        if obj["Pid"] != proc.proc.pid:
            raise AssertionError("Process.Pid %r != %r" % (obj["Pid"], proc.proc.pid))
        if not (before - 30 <= obj["StartTime"] <= after):
            raise AssertionError("implausible Process.StartTime %r" % obj["StartTime"])
        if not (0 <= obj["UpTime"] <= 30):
            raise AssertionError("implausible Process.UpTime %r" % obj["UpTime"])
        if obj["OpenFiles"] != doc["CountOfOpenFile"]:
            raise AssertionError("Process.OpenFiles differs from CountOfOpenFile: %r" % obj)
        if obj["MaxOpenFiles"] <= obj["OpenFiles"] and obj["MaxOpenFiles"] != -1:
            raise AssertionError("implausible Process.MaxOpenFiles: %r" % obj)
        if obj["PeakRssBytes"] <= 0:
            raise AssertionError("implausible Process.PeakRssBytes: %r" % obj)
        for key in ("CpuUserMs", "CpuSystemMs"):
            if obj[key] < 0:
                raise AssertionError("negative Process.%s: %r" % (key, obj))
        if linux:
            if obj["Threads"] < 1:
                raise AssertionError("implausible Process.Threads: %r" % obj)
            if obj["RssBytes"] <= 0:
                raise AssertionError("implausible Process.RssBytes: %r" % obj)


def _sni_quiet(port):
    """First report with no SNI connection open (the readiness probe has gone)."""
    return _wait_doc(port, lambda doc: doc["SNI_Server"]["ActiveConnection"] == 0, 3.0)["json"]["SNI_Server"]


def _sni_delta(port, base, expect, timeout=4.0):
    """Wait until SNI_Server counters moved by exactly `expect` (others unchanged)."""
    def settled(doc):
        sni = doc["SNI_Server"]
        return (sni["ActiveConnection"] == 0 and
                all(sni[k] - base[k] == expect.get(k, 0) for k in SNI_CLOSE_KEYS))
    try:
        return _wait_doc(port, settled, timeout)["json"]["SNI_Server"]
    except AssertionError as exc:
        raise AssertionError("expected SNI deltas %r from %r: %s" % (expect, base, exc))


def test_sni_close_reasons():
    hello = zroxy_lab.client_hello("localhost")
    with zroxy_lab.Lab() as lab:
        up = lab.tcp_server(response=zroxy_lab.HTTP_OK, read_exact=len(hello))
        wl = lab.write("white.txt", "localhost\n")
        sni_port = zroxy_lab.free_tcp_port()
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            ["-l", "0", "-o", "2", "-p", "127.0.0.1:%s@%s" % (sni_port, up.port),
             "-m", str(mon_port), "-w", wl],
            tcp_ports=[sni_port, mon_port],
        )
        base = _sni_quiet(mon_port)
        for key in SNI_CLOSE_KEYS:
            _number(base.get(key), "SNI_Server." + key)
        if base["ConnectionLimit"] != 1024:
            raise AssertionError("ConnectionLimit is %r" % base["ConnectionLimit"])

        data, closed = zroxy_lab.tcp_exchange("127.0.0.1", sni_port, hello, timeout=4.0)
        if data != zroxy_lab.HTTP_OK or not closed:
            raise AssertionError("relay failed: %r" % data)
        _sni_delta(mon_port, base, {"Relayed": 1})
        base = _sni_quiet(mon_port)

        # A name outside the whitelist.
        other = zroxy_lab.client_hello("blocked.example")
        data, closed = zroxy_lab.tcp_exchange("127.0.0.1", sni_port, other, timeout=4.0)
        if data != b"" or not closed:
            raise AssertionError("blocked name was not closed: %r" % data)
        _sni_delta(mon_port, base, {"Blocked": 1})
        base = _sni_quiet(mon_port)

        # Bytes that are neither a ClientHello nor an HTTP request, then EOF.
        junk = b"\x00\x01\x02 not a hello\r\n"
        data, closed = zroxy_lab.tcp_exchange("127.0.0.1", sni_port, junk, timeout=1.0)
        if data != b"":
            raise AssertionError("junk got a reply: %r" % data)
        # And a client that connects and leaves without sending anything.
        sock = socket.create_connection(("127.0.0.1", sni_port), timeout=2.0)
        sock.close()
        _sni_delta(mon_port, base, {"NoHostname": 2})
        proc.check_alive()


def test_sni_connect_failure_and_handshake_timeout():
    hello = zroxy_lab.client_hello("localhost")
    with zroxy_lab.Lab() as lab:
        dead_port = zroxy_lab.free_tcp_port()
        sni_port = zroxy_lab.free_tcp_port()
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            ["-l", "0", "-o", "1", "-p", "127.0.0.1:%s@%s" % (sni_port, dead_port),
             "-m", str(mon_port)],
            tcp_ports=[sni_port, mon_port],
        )
        base = _sni_quiet(mon_port)
        data, closed = zroxy_lab.tcp_exchange("127.0.0.1", sni_port, hello, timeout=4.0)
        if data != b"" or not closed:
            raise AssertionError("connect failure was not closed: %r" % data)
        _sni_delta(mon_port, base, {"ConnectFailures": 1})
        base = _sni_quiet(mon_port)

        # A client that never sends its hello is dropped after SNITIMEOUT.
        sock = socket.create_connection(("127.0.0.1", sni_port), timeout=2.0)
        try:
            _sni_delta(mon_port, base, {"HandshakeTimeouts": 1}, timeout=5.0)
        finally:
            sock.close()
        proc.check_alive()


def test_sni_idle_timeout():
    hello = zroxy_lab.client_hello("localhost")
    with zroxy_lab.Lab() as lab:
        hold = threading.Event()
        up = lab.tcp_server(response=b"", read_exact=len(hello), hold=hold)
        sni_port = zroxy_lab.free_tcp_port()
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            ["-l", "0", "-o", "5", "-I", "1", "-p", "127.0.0.1:%s@%s" % (sni_port, up.port),
             "-m", str(mon_port)],
            tcp_ports=[sni_port, mon_port],
        )
        base = _sni_quiet(mon_port)
        sock = socket.create_connection(("127.0.0.1", sni_port), timeout=2.0)
        try:
            sock.sendall(hello)
            # The upstream accepts the hello and then stays silent: the relay
            # is established and idles out after SNIIDLETIMEOUT, not SNITIMEOUT.
            _sni_delta(mon_port, base, {"Relayed": 1, "IdleTimeouts": 1}, timeout=4.0)
        finally:
            sock.close()
            hold.set()
        proc.check_alive()


def test_monitor_whitelist_object():
    with zroxy_lab.Lab() as lab:
        mon_port = zroxy_lab.free_tcp_port()
        bare = lab.zroxy(["-l", "0", "-m", str(mon_port)], tcp_ports=[mon_port])
        if "Whitelist" in zroxy_lab.fetch_monitor(mon_port, timeout=2.0)["json"]:
            raise AssertionError("Whitelist object present without a whitelist file")
        bare.stop()

    with zroxy_lab.Lab() as lab:
        wl = lab.write("white.txt", "a.example\nb.example\n")
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(["-l", "0", "-m", str(mon_port), "-w", wl], tcp_ports=[mon_port])
        keys = ("Entries", "Reloads", "ReloadFailures", "LastReload")
        base = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)["json"].get("Whitelist")
        if not isinstance(base, dict):
            raise AssertionError("missing Whitelist object")
        for key in keys:
            _number(base.get(key), "Whitelist." + key)
        if (base["Entries"], base["Reloads"], base["ReloadFailures"], base["LastReload"]) != (2, 0, 0, 0):
            raise AssertionError("unexpected initial Whitelist: %r" % base)

        # Rewriting the file is picked up by the watcher.
        before = int(time.time())
        lab.write("white.txt", "a.example\nb.example\n*.c.example\n")
        doc = _wait_doc(mon_port, lambda d: d["Whitelist"]["Reloads"] >= 1, 4.0)["json"]["Whitelist"]
        if doc["Entries"] != 3 or doc["ReloadFailures"] != 0:
            raise AssertionError("unexpected Whitelist after reload: %r" % doc)
        if not (before <= doc["LastReload"] <= int(time.time())):
            raise AssertionError("implausible LastReload: %r" % doc)
        reloads = doc["Reloads"]
        stamp = doc["LastReload"]

        # An entry longer than a config line is refused; the old list stays.
        lab.write("white.txt", "x" * 2000 + "\n")
        doc = _wait_doc(mon_port, lambda d: d["Whitelist"]["ReloadFailures"] >= 1, 4.0)["json"]["Whitelist"]
        if doc["Entries"] != 3 or doc["Reloads"] != reloads or doc["LastReload"] != stamp:
            raise AssertionError("failed reload changed the list: %r" % doc)

        # SIGHUP reloads through the same path.
        lab.write("white.txt", "only.example\n")
        doc = _wait_doc(mon_port, lambda d: d["Whitelist"]["Entries"] == 1, 4.0)["json"]["Whitelist"]
        if doc["Reloads"] != reloads + 1 or doc["ReloadFailures"] != 1:
            raise AssertionError("unexpected Whitelist after recovery: %r" % doc)
        os.kill(proc.proc.pid, signal.SIGHUP)
        _wait_doc(mon_port, lambda d: d["Whitelist"]["Reloads"] == reloads + 2, 4.0)
        proc.check_alive()


def main():
    failed = 0
    for test in (test_monitor_after_traffic, test_dns_timeout_is_not_also_an_error,
                 test_monitor_http_framing, test_monitor_process_object,
                 test_sni_close_reasons, test_sni_connect_failure_and_handshake_timeout,
                 test_sni_idle_timeout, test_monitor_whitelist_object):
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
