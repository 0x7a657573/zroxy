#!/usr/bin/env python3
"""Local stress runner for the real zroxy binary.

Capacity rejections are counted apart from crashes, hangs, corruption, and
file-descriptor growth.
"""

import argparse
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "integration"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import resource_sampler
import zroxy_lab

ROOT = zroxy_lab.ROOT
THREAD_SLACK = 4
UPSTREAM_IP = (9, 9, 9, 9)


def read_define(path, name):
    with open(path, "r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "#define" and parts[1] == name:
                return int(parts[2].strip("()"))
    raise zroxy_lab.LabError("missing %s in %s" % (name, path))


def worker_limits():
    return {
        "sni": read_define(os.path.join(ROOT, "src", "sni", "sniclient.c"), "SNI_MAX_WORKERS"),
        "dns": 1,
        "monitor": read_define(os.path.join(ROOT, "src", "stats", "monitor.c"), "MON_MAX_WORKERS"),
    }


class Rate:
    def __init__(self, per_sec):
        self.interval = 0.0 if per_sec <= 0 else 1.0 / float(per_sec)
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def wait(self):
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


def tally(rows):
    def count(kind):
        return sum(1 for row in rows if row.get("kind") == kind)

    return {
        "success": count("success"),
        "failure": count("failure"),
        "timeout": count("timeout"),
        "expected_rejection": count("expected"),
        "bytes_sent": sum(row.get("sent", 0) for row in rows),
        "bytes_received": sum(row.get("recv", 0) for row in rows),
    }


def scenario_record(name, rows, elapsed):
    item = tally(rows)
    item["name"] = name
    item["elapsed_sec"] = round(elapsed, 3)
    return item


def alive(proc, failures):
    code = proc.proc.poll()
    if code is not None:
        failures.append("zroxy exited %s" % code)
        return False
    return True


def threads_of(pid):
    try:
        return resource_sampler.sample_once(pid)["threads"]
    except OSError:
        return None


def fixed_exchange(port, payload, expect, timeout):
    started = time.monotonic()
    try:
        data, closed = zroxy_lab.tcp_exchange("127.0.0.1", port, payload, timeout)
    except (OSError, zroxy_lab.LabError) as exc:
        return {"ok": False, "kind": "failure", "error": str(exc), "sent": len(payload), "recv": 0}
    elapsed = time.monotonic() - started
    if data == expect and closed:
        return {"ok": True, "kind": "success", "sent": len(payload), "recv": len(data), "elapsed": elapsed}
    kind = "timeout" if (not closed and elapsed >= timeout * 0.9) else "failure"
    return {"ok": False, "kind": kind, "sent": len(payload), "recv": len(data), "elapsed": elapsed, "closed": closed}


def expect_close(port, payload, timeout, shutdown_write=False):
    started = time.monotonic()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=min(2.0, timeout))
    except OSError as exc:
        return {"ok": False, "kind": "failure", "error": str(exc), "sent": len(payload), "recv": 0}
    data = bytearray()
    closed = False
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        if shutdown_write:
            sock.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                closed = True
                break
            data.extend(chunk)
    except OSError as exc:
        sock.close()
        return {"ok": False, "kind": "failure", "error": str(exc), "sent": len(payload), "recv": len(data)}
    finally:
        try:
            sock.close()
        except OSError:
            pass
    elapsed = time.monotonic() - started
    if closed and elapsed <= timeout:
        return {"ok": True, "kind": "expected", "sent": len(payload), "recv": len(data), "elapsed": elapsed}
    kind = "timeout" if not closed else "failure"
    return {"ok": False, "kind": kind, "sent": len(payload), "recv": len(data), "elapsed": elapsed}


def loop_until(workers, duration, fn):
    end = time.monotonic() + duration
    rows = []
    lock = threading.Lock()

    def worker():
        while time.monotonic() < end:
            row = fn()
            with lock:
                rows.append(row)

    threads = [threading.Thread(target=worker, name="stress-loop") for _ in range(max(1, workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=duration + 20.0)
    return rows, [thread for thread in threads if thread.is_alive()]


def require_success(name, rows, failures):
    stats = tally(rows)
    if stats["failure"] or stats["timeout"] or stats["success"] == 0:
        failures.append(
            "%s success=%s failure=%s timeout=%s" % (name, stats["success"], stats["failure"], stats["timeout"])
        )


def concurrent_sni(args, proc, upstream, port, request, limits, failures, baseline):
    started = time.monotonic()
    if not alive(proc, failures):
        return scenario_record("concurrent_sni", [], 0)
    hold = threading.Event()
    upstream.mode = "reply"
    upstream.close_after = None
    upstream.response_delay = 0.0
    upstream.read_exact = len(request)
    upstream.response = request
    upstream.hold = hold
    rate_limit = args.rate or 100
    rate = Rate(rate_limit)
    budget = (args.connections / float(rate_limit)) + 3.0
    box = {}

    def clients():
        def one(_i):
            rate.wait()
            return fixed_exchange(port, request, request, budget + 3.0)

        box["rows"], box["errors"] = zroxy_lab.run_pool(args.connections, range(args.connections), one)

    thread = threading.Thread(target=clients, name="concurrent-sni")
    thread.start()
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline and upstream.connection_count() < args.connections:
        if proc.proc.poll() is not None:
            break
        time.sleep(0.01)
    observed = threads_of(proc.proc.pid)
    if observed is not None and observed > baseline + limits["sni"] + THREAD_SLACK:
        failures.append("SNI workers exceeded cap: %s baseline %s cap %s" % (observed, baseline, limits["sni"]))
    hold.set()
    thread.join(timeout=budget + 10.0)
    if thread.is_alive():
        failures.append("concurrent SNI workers did not finish")
        return scenario_record("concurrent_sni", [], time.monotonic() - started)
    rows = box.get("rows", [])
    if box.get("errors"):
        failures.append("concurrent SNI raised %s errors" % len(box["errors"]))
    require_success("concurrent_sni", rows, failures)
    alive(proc, failures)
    return scenario_record("concurrent_sni", rows, time.monotonic() - started)


def short_lived(args, proc, port, hello, failures):
    started = time.monotonic()
    if not alive(proc, failures):
        return scenario_record("short_lived", [], 0)

    def one():
        return fixed_exchange(port, hello, zroxy_lab.HTTP_OK, 3.0)

    rows, stuck = loop_until(args.workers, args.duration, one)
    if stuck:
        failures.append("short-lived workers did not finish")
    require_success("short_lived", rows, failures)
    alive(proc, failures)
    return scenario_record("short_lived", rows, time.monotonic() - started)


def long_lived(args, proc, port, hello, payload, limits, failures, sampler, baseline):
    started = time.monotonic()
    if not alive(proc, failures):
        return scenario_record("long_lived", [], 0)
    count = min(args.workers, args.connections)
    chunk = payload if payload else b"Z"
    mark = sampler.mark()

    def one(_i):
        try:
            ok, sent, recvd = zroxy_lab.stream_echo("127.0.0.1", port, hello, chunk, args.duration)
        except (OSError, zroxy_lab.LabError) as exc:
            return {"ok": False, "kind": "failure", "error": str(exc), "sent": 0, "recv": 0}
        return {"ok": ok, "kind": "success" if ok else "failure", "sent": sent, "recv": recvd}

    rows, errors = zroxy_lab.run_pool(count, range(count), one)
    peak = sampler.thread_peak_since(mark)
    if peak is not None and peak > baseline + limits["sni"] + THREAD_SLACK:
        failures.append("long-lived threads exceeded the SNI cap: %s" % peak)
    if errors:
        failures.append("long-lived raised %s errors" % len(errors))
    require_success("long_lived", rows, failures)
    alive(proc, failures)
    return scenario_record("long_lived", rows, time.monotonic() - started)


def mixed_clients(args, proc, port, hello, failures):
    started = time.monotonic()
    if not alive(proc, failures):
        return scenario_record("mixed_clients", [], 0)
    goods = max(1, args.connections // 2)
    bads = max(1, args.connections - goods)
    jobs = [("valid", i) for i in range(goods)] + [("malformed", i) for i in range(bads)]

    def one(job):
        if job[0] == "valid":
            row = fixed_exchange(port, hello, zroxy_lab.HTTP_OK, 3.0)
            row["role"] = "valid"
            return row
        row = expect_close(port, b"\x00\x01MALFORMED-CLIENT", 3.0, shutdown_write=True)
        row["role"] = "malformed"
        return row

    rows, errors = zroxy_lab.run_pool(args.workers, jobs, one)
    if errors:
        failures.append("mixed clients raised %s errors" % len(errors))
    valid = [row for row in rows if row.get("role") == "valid"]
    malformed = [row for row in rows if row.get("role") == "malformed"]
    if any(row.get("kind") != "success" for row in valid):
        failures.append("malformed clients prevented valid SNI clients from succeeding")
    if any(row.get("kind") == "timeout" for row in malformed):
        failures.append("malformed clients hung")
    alive(proc, failures)
    return scenario_record("mixed_clients", rows, time.monotonic() - started)


def delayed(args, proc, port, hello, failures):
    started = time.monotonic()
    if not alive(proc, failures):
        return scenario_record("delayed_upstream", [], 0)
    count = min(args.connections, 20)
    rows, errors = zroxy_lab.run_pool(
        args.workers, range(count), lambda _i: fixed_exchange(port, hello, zroxy_lab.HTTP_OK, 3.0)
    )
    if errors:
        failures.append("delayed upstream raised %s errors" % len(errors))
    require_success("delayed_upstream", rows, failures)
    alive(proc, failures)
    return scenario_record("delayed_upstream", rows, time.monotonic() - started)


def early_close(args, proc, upstream, port, hello, failures):
    started = time.monotonic()
    if not alive(proc, failures):
        return scenario_record("early_close", [], 0)
    count = min(args.connections, 20)
    rows, errors = zroxy_lab.run_pool(
        args.workers, range(count), lambda _i: expect_close(port, hello, 3.0)
    )
    if errors or any(row.get("kind") not in ("expected", "success") for row in rows):
        failures.append("early close did not end bounded connections")
    upstream.close_after = None
    upstream.read_exact = len(hello)
    upstream.response = zroxy_lab.HTTP_OK
    follow = fixed_exchange(port, hello, zroxy_lab.HTTP_OK, 3.0)
    rows.append(follow)
    if follow.get("kind") != "success":
        failures.append("valid client failed after upstream early close")
    alive(proc, failures)
    return scenario_record("early_close", rows, time.monotonic() - started)


def proxy_timeout(args, lab, hello, failures):
    """Separate process: the relay timeout is fixed for the life of a zroxy."""
    started = time.monotonic()
    count = min(args.connections, 8)
    upstream = lab.tcp_server(mode="blackhole", read_exact=len(hello), hold_timeout=3.0)
    port = zroxy_lab.free_tcp_port()
    proc = lab.zroxy(
        ["-l", "3", "-o", "1", "-p", "127.0.0.1:%s@%s" % (port, upstream.port)],
        tcp_ports=[port],
    )

    def one(_i):
        row = expect_close(port, hello, 4.0)
        if row.get("kind") == "expected" and row.get("elapsed", 99) >= 2.5:
            row["kind"] = "failure"
            row["ok"] = False
        return row

    rows, errors = zroxy_lab.run_pool(min(4, count), range(count), one)
    if errors or any(row.get("kind") != "expected" for row in rows):
        failures.append("connections did not end at the proxy timeout")
    upstream.mode = "reply"
    upstream.read_exact = len(hello)
    upstream.response = zroxy_lab.HTTP_OK
    follow = fixed_exchange(port, hello, zroxy_lab.HTTP_OK, 3.0)
    rows.append(follow)
    if follow.get("kind") != "success":
        failures.append("valid client failed after proxy-timeout load")
    alive(proc, failures)
    proc.stop()
    return scenario_record("proxy_timeout", rows, time.monotonic() - started)


def overload(args, proc, dns_up, ldns, mon_port, limits, failures, anomalies, baseline):
    started = time.monotonic()
    rows = []
    if not alive(proc, failures):
        return scenario_record("overload", rows, 0)
    dns_up.set_mode("timeout")
    dns_up.stall = 3.0
    burst = limits["dns"] + 32
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        for i in range(burst):
            query = zroxy_lab.build_dns_query("load.test", qid=(i % 65535) + 1)
            sock.sendto(query, ("127.0.0.1", ldns))
    finally:
        sock.close()
    peak = baseline
    until = time.monotonic() + 1.5
    while time.monotonic() < until:
        observed = threads_of(proc.proc.pid)
        if observed is not None:
            peak = max(peak, observed)
        time.sleep(0.05)
    if peak > baseline + limits["dns"] + THREAD_SLACK:
        failures.append("DNS event-loop threads exceeded cap: peak %s baseline %s cap %s" % (peak, baseline, limits["dns"]))
    settle = threads_of(proc.proc.pid)
    # A request may make one retry, each bounded by the configured DNS timeout.
    deadline = time.monotonic() + 7.0
    while time.monotonic() < deadline:
        settle = threads_of(proc.proc.pid)
        if settle is not None and settle <= baseline + THREAD_SLACK:
            break
        time.sleep(0.05)
    try:
        doc = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)["json"]
        active = doc.get("DNS_Server", {}).get("ActiveConnection")
        if type(active) is int and active > 0:
            anomalies.append(
                "DNS ActiveConnection stayed at %s after overloaded queries were dropped or finished"
                % active
            )
    except (OSError, zroxy_lab.LabError) as exc:
        failures.append("monitor failed after DNS load: %s" % exc)
    dns_up.set_mode("reply")
    query = zroxy_lab.build_dns_query("example.test", qid=0x5151)
    expected = zroxy_lab.build_dns_response(query, UPSTREAM_IP)
    reply = None
    for _ in range(4):
        reply = zroxy_lab.udp_exchange(ldns, query, 2.0)
        if reply == expected:
            break
    if reply != expected:
        failures.append("valid DNS query failed after overload")
        rows.append({"kind": "failure", "sent": len(query), "recv": 0})
    else:
        rows.append({"kind": "success", "sent": len(query), "recv": len(reply)})

    mon_base = threads_of(proc.proc.pid) or baseline
    sockets = []
    refused = 0
    try:
        for _ in range(limits["monitor"] + 8):
            try:
                client = socket.create_connection(("127.0.0.1", mon_port), timeout=1.0)
                client.settimeout(0.2)
                sockets.append(client)
            except OSError:
                refused += 1
        time.sleep(0.3)
        mon_threads = threads_of(proc.proc.pid)
        closed_fast = 0
        for client in sockets:
            try:
                chunk = client.recv(8)
                if chunk == b"":
                    closed_fast += 1
            except socket.timeout:
                pass
            except OSError:
                closed_fast += 1
        if mon_threads is not None and mon_threads > mon_base + limits["monitor"] + THREAD_SLACK:
            failures.append("monitor workers exceeded cap: %s" % mon_threads)
        if refused + closed_fast == 0:
            failures.append("monitor accepted every connection above its worker cap")
    finally:
        for client in sockets:
            try:
                client.close()
            except OSError:
                pass
    try:
        doc = zroxy_lab.fetch_monitor(mon_port, timeout=2.0)["json"]
    except (OSError, zroxy_lab.LabError) as exc:
        failures.append("monitor did not recover: %s" % exc)
        doc = None
    if not doc or "ZroxyVersion" not in doc:
        failures.append("monitor JSON missing after overload")
    else:
        rows.append({"kind": "expected", "sent": 1, "recv": 1})
    alive(proc, failures)
    return scenario_record("overload", rows, time.monotonic() - started)


def run(args):
    limits = worker_limits()
    hello = zroxy_lab.client_hello("localhost")
    payload = b"Z" * args.payload_size
    request = hello + payload
    failures = []
    anomalies = []
    scenarios = []
    fd_baseline = None
    fd_after = None
    thread_baseline = None
    resources = {}

    with zroxy_lab.Lab() as lab:
        upstream = lab.tcp_server(
            response=zroxy_lab.HTTP_OK,
            read_exact=len(hello),
            hold_timeout=max(10.0, args.duration + 5.0),
        )
        dns_up = lab.dns_server(
            mode="reply",
            response_fn=lambda query: zroxy_lab.build_dns_response(query, UPSTREAM_IP),
            stall=3.0,
        )
        sni_port = zroxy_lab.free_tcp_port()
        ldns = zroxy_lab.free_udp_port()
        mon_port = zroxy_lab.free_tcp_port()
        burst_rate = args.rate or 100
        relay_timeout = max(5, int(args.connections / float(burst_rate) + 3))
        proc = lab.zroxy(
            [
                "-l", "3",
                "-o", str(relay_timeout),
                "-p", "127.0.0.1:%s@%s" % (sni_port, upstream.port),
                "-m", str(mon_port),
                "-d", "127.0.0.1:%s" % ldns,
                "-u", "127.0.0.1:%s" % dns_up.port,
                "-t", "1",
            ],
            tcp_ports=[sni_port, mon_port],
            udp_ports=[ldns],
        )
        sampler = resource_sampler.ResourceSampler(proc.proc.pid, interval=0.1).start()
        try:
            time.sleep(0.2)
            base = resource_sampler.sample_once(proc.proc.pid)
            fd_baseline = base["fds"]
            thread_baseline = base["threads"]
            scenarios.append(concurrent_sni(
                args, proc, upstream, sni_port, request, limits, failures, thread_baseline
            ))
            upstream.hold = None
            upstream.mode = "reply"
            upstream.close_after = None
            upstream.response_delay = 0.0
            upstream.read_exact = len(hello)
            upstream.response = zroxy_lab.HTTP_OK
            scenarios.append(short_lived(args, proc, sni_port, hello, failures))
            upstream.mode = "echo"
            scenarios.append(long_lived(
                args, proc, sni_port, hello, payload, limits, failures, sampler, thread_baseline
            ))
            upstream.mode = "reply"
            upstream.read_exact = len(hello)
            upstream.response = zroxy_lab.HTTP_OK
            upstream.response_delay = 0.0
            scenarios.append(mixed_clients(args, proc, sni_port, hello, failures))
            upstream.response_delay = 0.25
            scenarios.append(delayed(args, proc, sni_port, hello, failures))
            upstream.response_delay = 0.0
            upstream.close_after = len(hello)
            scenarios.append(early_close(args, proc, upstream, sni_port, hello, failures))
            upstream.close_after = None
            scenarios.append(proxy_timeout(args, lab, hello, failures))
            scenarios.append(overload(
                args, proc, dns_up, ldns, mon_port, limits, failures, anomalies, thread_baseline
            ))
            alive(proc, failures)
            settled = threads_of(proc.proc.pid)
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                settled = threads_of(proc.proc.pid)
                try:
                    fd_after = resource_sampler.fd_count(proc.proc.pid)
                except OSError:
                    fd_after = None
                if (
                    settled is not None
                    and fd_after is not None
                    and settled <= thread_baseline + THREAD_SLACK
                    and fd_after <= fd_baseline + 2
                ):
                    break
                time.sleep(0.05)
            if settled is None or settled > thread_baseline + THREAD_SLACK:
                failures.append("workers did not finish (threads %s, baseline %s)" % (settled, thread_baseline))
            if fd_baseline is None or fd_after is None or fd_after > fd_baseline + 2:
                failures.append("persistent fd growth baseline=%s after=%s" % (fd_baseline, fd_after))
        finally:
            resources = sampler.stop()

    return {
        "kind": "stress",
        "duration_sec": args.duration,
        "connections": args.connections,
        "workers": args.workers,
        "payload_size": args.payload_size,
        "rate": args.rate,
        "scenarios": scenarios,
        "fd_baseline": fd_baseline,
        "fd_after": fd_after,
        "thread_baseline": thread_baseline,
        "limits": limits,
        "anomalies": anomalies,
        "failures": failures,
        "passed": not failures,
        "resources": resources,
    }


def print_summary(result):
    print("stress %s" % ("PASS" if result.get("passed") else "FAIL"))
    for item in result.get("scenarios", []):
        print(
            "%s success=%s failure=%s timeout=%s rejected=%s sent=%s recv=%s"
            % (
                item.get("name"),
                item.get("success"),
                item.get("failure"),
                item.get("timeout"),
                item.get("expected_rejection"),
                item.get("bytes_sent"),
                item.get("bytes_received"),
            )
        )
    resources = result.get("resources") or {}
    print(
        "rss_peak_kb=%s fd_peak=%s thread_peak=%s cpu_user=%s cpu_system=%s fd_baseline=%s fd_after=%s"
        % (
            resources.get("rss_peak_kb"),
            resources.get("fd_peak"),
            resources.get("thread_peak"),
            resources.get("cpu_user_seconds"),
            resources.get("cpu_system_seconds"),
            result.get("fd_baseline"),
            result.get("fd_after"),
        )
    )
    for anomaly in result.get("anomalies") or []:
        print("anomaly: %s" % anomaly)
    for failure in result.get("failures") or []:
        print("failure: %s" % failure)


def main():
    parser = argparse.ArgumentParser(description="Stress the local zroxy binary")
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--connections", type=int, default=100)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--payload-size", type=int, default=4096)
    parser.add_argument("--rate", type=float, default=0, help="connection starts per second; 0 uses 100 for bursts")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.duration <= 0 or args.connections <= 0 or args.workers <= 0 or args.payload_size < 0:
        print("duration, connections, and workers must be positive", file=sys.stderr)
        return 2
    try:
        result = run(args)
    except Exception as exc:
        result = {"kind": "stress", "passed": False, "failures": [str(exc)], "scenarios": [], "resources": {}}
        print("FAIL %s" % exc, file=sys.stderr)
    out = os.path.abspath(args.output)
    parent = os.path.dirname(out)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    print_summary(result)
    print("wrote %s" % out)
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
