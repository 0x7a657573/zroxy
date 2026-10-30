#!/usr/bin/env python3
"""Controlled local DNS-throughput baseline for the event-loop service."""

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


UPSTREAM_IP = (9, 9, 9, 9)


def percentile(values, pct):
    return zroxy_lab.percentile(values, pct)


def run_load(port, workers, duration):
    end = time.monotonic() + duration
    lock = threading.Lock()
    rows = []
    serial = 0

    def next_query():
        nonlocal serial
        with lock:
            serial += 1
            number = serial
        return zroxy_lab.build_dns_query("bench-%d.test" % number, qid=number & 0xFFFF)

    def worker():
        while time.monotonic() < end:
            query = next_query()
            started = time.monotonic()
            try:
                reply = zroxy_lab.udp_exchange(port, query, 3.0)
                ok = reply == zroxy_lab.build_dns_response(query, UPSTREAM_IP)
            except OSError:
                ok = False
            with lock:
                rows.append((ok, (time.monotonic() - started) * 1000.0))

    threads = [threading.Thread(target=worker, name="dns-bench") for _ in range(workers)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=duration + 5.0)
    return rows, time.monotonic() - started, any(thread.is_alive() for thread in threads)


def main():
    parser = argparse.ArgumentParser(description="Benchmark local zroxy DNS forwarding")
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--upstream-connections", type=int, default=32)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.workers < 1 or not 1 <= args.upstream_connections <= 96 or args.duration <= 0:
        parser.error("workers and duration must be positive; upstream connections must be 1..96")

    with zroxy_lab.Lab() as lab:
        upstream = lab.dns_server(
            mode="keepalive",
            response_fn=lambda query: zroxy_lab.build_dns_response(query, UPSTREAM_IP),
        )
        port = zroxy_lab.free_udp_port()
        proc = lab.zroxy([
            "-l", "0", "-d", "127.0.0.1:%s" % port,
            "-u", "127.0.0.1:%s" % upstream.port,
            "-t", "2", "-e", "0", "-C", str(args.upstream_connections),
        ], udp_ports=[port])
        baseline = resource_sampler.sample_once(proc.proc.pid)
        sampler = resource_sampler.ResourceSampler(proc.proc.pid, interval=0.1).start()
        try:
            rows, elapsed, stuck = run_load(port, args.workers, args.duration)
            proc.check_alive()
        finally:
            resources = sampler.stop()

    success = [latency for ok, latency in rows if ok]
    failures = len(rows) - len(success)
    result = {
        "kind": "dns-benchmark",
        "note": "Single-run local baseline; compare like-for-like result files before claiming an improvement.",
        "duration_sec": round(elapsed, 3),
        "workers": args.workers,
        "upstream_connections": args.upstream_connections,
        "attempts": len(rows),
        "success": len(success),
        "failure": failures,
        "success_qps": len(success) / elapsed if elapsed else 0.0,
        "latency_ms": {"p50": percentile(success, 50), "p95": percentile(success, 95), "p99": percentile(success, 99)},
        "workers_stuck": stuck,
        "resources": {
            "thread_baseline": baseline["threads"],
            "fd_baseline": baseline["fds"],
            "rss_peak_kb": resources.get("rss_peak_kb"),
            "fd_peak": resources.get("fd_peak"),
            "thread_peak": resources.get("thread_peak"),
            "cpu_user_seconds": resources.get("cpu_user_seconds"),
            "cpu_system_seconds": resources.get("cpu_system_seconds"),
        },
    }
    with open(os.path.abspath(args.output), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    print(json.dumps(result, indent=2))
    return 1 if failures or stuck else 0


if __name__ == "__main__":
    sys.exit(main())
