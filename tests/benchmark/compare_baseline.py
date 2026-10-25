#!/usr/bin/env python3
"""Compare two local benchmark JSON files.

Persistent file-descriptor growth fails regardless of the other thresholds.
A higher throughput or a lower latency is reported only because both files
were measured.
"""

import argparse
import json
import sys


def load_results(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and "results" in doc:
        rows = doc["results"]
    elif isinstance(doc, dict) and "scenario" in doc:
        rows = [doc]
    elif isinstance(doc, list):
        rows = doc
    else:
        raise SystemExit("unrecognized benchmark JSON: %s" % path)
    found = {}
    for row in rows:
        name = row.get("scenario")
        if not name:
            raise SystemExit("benchmark row missing scenario in %s" % path)
        found[name] = row
    return found


def pct(new, old):
    if old == 0:
        return None
    return (new - old) / float(old)


def main():
    parser = argparse.ArgumentParser(description="Compare zroxy benchmark JSON files")
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("--throughput-regression", type=float, default=0.15)
    parser.add_argument("--latency-regression", type=float, default=0.20)
    parser.add_argument("--rss-increase", type=float, default=0.25)
    parser.add_argument("--thread-increase", type=float, default=None,
                        help="fail when thread_peak grows by more than this fraction")
    args = parser.parse_args()
    before = load_results(args.baseline)
    after = load_results(args.current)
    failures = []
    names = sorted(set(before) | set(after))
    if not names:
        print("no scenarios to compare")
        return 1
    for name in names:
        old = before.get(name)
        new = after.get(name)
        if old is None or new is None:
            failures.append("%s is missing from one file" % name)
            print("%s missing from %s" % (name, "current" if old else "baseline"))
            continue
        throughput = pct(new["throughput_bytes_sec"], old["throughput_bytes_sec"])
        old_p99 = (old.get("latency_ms") or {}).get("p99")
        new_p99 = (new.get("latency_ms") or {}).get("p99")
        latency = pct(new_p99, old_p99) if old_p99 not in (None, 0) and new_p99 is not None else None
        old_rss = (old.get("resources") or {}).get("rss_peak_kb") or 0
        new_rss = (new.get("resources") or {}).get("rss_peak_kb") or 0
        rss = pct(new_rss, old_rss) if old_rss else None
        old_threads = (old.get("resources") or {}).get("thread_peak") or 0
        new_threads = (new.get("resources") or {}).get("thread_peak") or 0
        threads = pct(new_threads, old_threads) if old_threads else None
        old_fd = (old.get("resources") or {}).get("fd_peak")
        new_fd = (new.get("resources") or {}).get("fd_peak")
        fd_base = (new.get("resources") or {}).get("fd_baseline")
        fd_after = (new.get("resources") or {}).get("fd_after")
        print(name)
        if throughput is None:
            print("  throughput: not comparable")
        elif throughput < -args.throughput_regression:
            failures.append("%s throughput regression %.1f%%" % (name, -throughput * 100))
            print("  throughput regression %.1f%%" % (-throughput * 100))
        elif throughput > 0:
            print("  throughput higher by %.1f%%" % (throughput * 100))
        else:
            print("  throughput change %.1f%%" % (throughput * 100))
        if latency is None:
            print("  p99 latency: not comparable")
        elif latency > args.latency_regression:
            failures.append("%s p99 latency regression %.1f%%" % (name, latency * 100))
            print("  p99 latency regression %.1f%%" % (latency * 100))
        elif latency < 0:
            print("  p99 latency lower by %.1f%%" % (-latency * 100))
        else:
            print("  p99 latency change %.1f%%" % (latency * 100))
        if rss is not None and rss > args.rss_increase:
            failures.append("%s RSS increase %.1f%%" % (name, rss * 100))
            print("  RSS increase %.1f%%" % (rss * 100))
        elif rss is not None:
            print("  RSS change %.1f%%" % (rss * 100))
        if old_fd is not None and new_fd is not None:
            print("  fd peak %s -> %s" % (old_fd, new_fd))
        if fd_base is not None and fd_after is not None and fd_after > fd_base:
            failures.append("%s persistent fd increase %s -> %s" % (name, fd_base, fd_after))
            print("  persistent fd increase %s -> %s" % (fd_base, fd_after))
        if threads is not None:
            print("  thread peak change %.1f%%" % (threads * 100))
            if args.thread_increase is not None and threads > args.thread_increase:
                failures.append("%s thread increase %.1f%%" % (name, threads * 100))
    if failures:
        print("REGRESSION")
        for item in failures:
            print("  %s" % item)
        return 1
    print("within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
