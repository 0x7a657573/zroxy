#!/usr/bin/env python3
"""Local benchmark of the real zroxy binary.

One invocation records a baseline. It does not claim a regression or an
improvement unless compare_baseline.py is given two result files.
"""

import argparse
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "integration"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "stress"))

import resource_sampler
import zroxy_lab


def parse_ints(text):
    values = [int(part) for part in text.split(",") if part.strip()]
    if not values or any(value <= 0 for value in values):
        raise argparse.ArgumentTypeError("expected a comma-separated list of positive integers")
    return values


def run_load(port, body, workers, duration, hello, chunk, sustained):
    end = time.monotonic() + duration
    rows = []
    lock = threading.Lock()

    def once():
        while time.monotonic() < end:
            started = time.monotonic()
            try:
                if sustained:
                    remaining = max(0.05, end - time.monotonic())
                    samples = []
                    ok, sent, recvd = zroxy_lab.stream_echo(
                        "127.0.0.1", port, hello, chunk, remaining, samples=samples
                    )
                    row = {
                        "ok": ok,
                        "sent": sent,
                        "recv": recvd,
                        "latency_ms": (time.monotonic() - started) * 1000.0,
                        "samples": samples,
                    }
                else:
                    data, ok = zroxy_lab.duplex_exchange("127.0.0.1", port, body, 5.0)
                    row = {
                        "ok": ok,
                        "sent": len(body) if ok else 0,
                        "recv": len(data),
                        "latency_ms": (time.monotonic() - started) * 1000.0,
                    }
            except (OSError, zroxy_lab.LabError) as exc:
                row = {"ok": False, "sent": 0, "recv": 0, "latency_ms": None, "error": str(exc)}
            with lock:
                rows.append(row)
            if sustained:
                return

    threads = [threading.Thread(target=once, name="bench", daemon=True) for _ in range(workers)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=duration + 30.0)
    stuck = any(thread.is_alive() for thread in threads)
    return rows, time.monotonic() - started, stuck, threads


def measure(name, use_socks, concurrency, payload_size, duration, hello, sustained):
    chunk = b"B" * payload_size
    body = hello + chunk
    with zroxy_lab.Lab() as lab:
        upstream = lab.tcp_server(mode="echo")
        socks = None
        args = ["-l", "3", "-o", "5", "-p"]
        sni_port = zroxy_lab.free_tcp_port()
        if use_socks:
            socks = lab.socks_server(
                upstream_host="127.0.0.1",
                upstream_port=upstream.port,
                fragment=0,
                fragment_gap=0.0,
            )
            args.append("127.0.0.1:%s@%s" % (sni_port, upstream.port))
            args.extend(["-s", "127.0.0.1:%s" % socks.port])
        else:
            args.append("127.0.0.1:%s@%s" % (sni_port, upstream.port))
        proc = lab.zroxy(args, tcp_ports=[sni_port])
        baseline = resource_sampler.sample_once(proc.proc.pid)
        sampler = resource_sampler.ResourceSampler(proc.proc.pid, interval=0.1).start()
        try:
            rows, elapsed, stuck, threads = run_load(
                sni_port, body, concurrency, duration, hello, chunk, sustained
            )
        finally:
            sampled = sampler.stop()
        proc.check_alive()
        deadline = time.monotonic() + 2.0
        fd_after = baseline["fds"]
        while time.monotonic() < deadline:
            try:
                fd_after = resource_sampler.fd_count(proc.proc.pid)
            except OSError:
                break
            if fd_after <= baseline["fds"] + 2:
                break
            time.sleep(0.05)
    for thread in threads:
        thread.join(timeout=2.0)
    success = [row for row in rows if row["ok"]]
    failure = len(rows) - len(success)
    sent = sum(row["sent"] for row in rows)
    recvd = sum(row["recv"] for row in rows)
    latencies = []
    for row in success:
        if row.get("samples"):
            latencies.extend(row["samples"])
        elif row.get("latency_ms") is not None:
            latencies.append(row["latency_ms"])
    attempts = success.__len__() + failure
    resources = {
        "rss_peak_kb": sampled.get("rss_peak_kb"),
        "fd_peak": sampled.get("fd_peak"),
        "thread_peak": sampled.get("thread_peak"),
        "fd_baseline": baseline["fds"],
        "fd_after": fd_after,
        "cpu_user_seconds": sampled.get("cpu_user_seconds"),
        "cpu_system_seconds": sampled.get("cpu_system_seconds"),
    }
    return {
        "scenario": name,
        "duration_sec": round(elapsed, 3),
        "connections": attempts,
        "success": len(success),
        "failure": failure,
        "bytes_sent": sent,
        "bytes_received": recvd,
        "throughput_bytes_sec": (sent + recvd) / elapsed if elapsed > 0 else 0.0,
        "error_rate": (failure / attempts) if attempts else 0.0,
        "workers_stuck": stuck,
        "latency_ms": {
            "p50": zroxy_lab.percentile(latencies, 50),
            "p95": zroxy_lab.percentile(latencies, 95),
            "p99": zroxy_lab.percentile(latencies, 99),
        },
        "resources": resources,
    }


def scenarios(conns, payloads):
    plan = []
    for payload in payloads:
        for concurrency in conns:
            plan.append(("direct_short/c%s/p%s" % (concurrency, payload), False, concurrency, payload, False))
            plan.append(("socks_short/c%s/p%s" % (concurrency, payload), True, concurrency, payload, False))
    widest = max(conns)
    for payload in payloads:
        plan.append(("direct_sustained/c%s/p%s" % (widest, payload), False, widest, payload, True))
        plan.append(("socks_sustained/c%s/p%s" % (widest, payload), True, widest, payload, True))
    return plan


def main():
    parser = argparse.ArgumentParser(description="Benchmark local zroxy forwarding")
    parser.add_argument("--connections", type=parse_ints, default=parse_ints("1,10,50,100"))
    parser.add_argument("--payload-size", type=parse_ints, default=parse_ints("1024,65536"))
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.duration <= 0:
        print("duration must be positive", file=sys.stderr)
        return 2
    hello = zroxy_lab.client_hello("localhost")
    results = []
    try:
        for name, use_socks, concurrency, payload, sustained in scenarios(args.connections, args.payload_size):
            print("running %s" % name, flush=True)
            item = measure(name, use_socks, concurrency, payload, args.duration, hello, sustained)
            results.append(item)
            print(
                "%s success=%s failure=%s throughput=%.0f p99=%s"
                % (
                    name,
                    item["success"],
                    item["failure"],
                    item["throughput_bytes_sec"],
                    item["latency_ms"]["p99"],
                ),
                flush=True,
            )
    except Exception as exc:
        print("FAIL %s" % exc, file=sys.stderr)
        return 1
    document = {
        "kind": "benchmark",
        "note": "Single-run baseline. Compare two files before calling a change a regression or an improvement.",
        "duration_requested_sec": args.duration,
        "results": results,
    }
    out = os.path.abspath(args.output)
    parent = os.path.dirname(out)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
        fh.write("\n")
    print("wrote %s" % out)
    if any(item["failure"] and item["success"] == 0 for item in results) or any(item["workers_stuck"] for item in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
