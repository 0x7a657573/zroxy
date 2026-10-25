"""Sample a process from /proc. No third-party packages."""

import os
import threading
import time


def _clk_tck():
    return os.sysconf(os.sysconf_names["SC_CLK_TCK"])


def _status(pid):
    fields = {}
    with open("/proc/%s/status" % pid, "r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return fields


def _kb(text):
    if not text:
        return None
    return int(text.split()[0])


def _optional_int(fields, key):
    text = fields.get(key)
    if text is None:
        return None
    return int(text.split()[0])


def _cpu_ticks(pid):
    with open("/proc/%s/stat" % pid, "r", encoding="ascii", errors="replace") as fh:
        text = fh.read()
    rest = text[text.rfind(")") + 2:].split()
    return int(rest[11]), int(rest[12])


def fd_count(pid):
    return len(os.listdir("/proc/%s/fd" % pid))


def sample_once(pid):
    fields = _status(pid)
    user_ticks, system_ticks = _cpu_ticks(pid)
    return {
        "t": time.time(),
        "rss_kb": _kb(fields.get("VmRSS")),
        "vsz_kb": _kb(fields.get("VmSize")),
        "threads": int(fields["Threads"]),
        "fds": fd_count(pid),
        "cpu_user_ticks": user_ticks,
        "cpu_system_ticks": system_ticks,
        "voluntary_ctxt_switches": _optional_int(fields, "voluntary_ctxt_switches"),
        "nonvoluntary_ctxt_switches": _optional_int(fields, "nonvoluntary_ctxt_switches"),
    }


class ResourceSampler:
    def __init__(self, pid, interval=0.1):
        self.pid = pid
        self.interval = interval
        self.samples = []
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()

    def start(self):
        self._thread = threading.Thread(target=self._run, name="resource-sampler")
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            try:
                item = sample_once(self.pid)
            except (OSError, ProcessLookupError, ValueError, IndexError):
                break
            with self._lock:
                self.samples.append(item)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        return self.summary()

    def mark(self):
        with self._lock:
            return len(self.samples)

    def thread_peak_since(self, mark):
        with self._lock:
            chunk = self.samples[mark:]
        if not chunk:
            return None
        return max(item["threads"] for item in chunk)

    def summary(self):
        with self._lock:
            samples = list(self.samples)
        if not samples:
            return {
                "rss_peak_kb": None,
                "fd_peak": None,
                "thread_peak": None,
                "cpu_user_seconds": 0.0,
                "cpu_system_seconds": 0.0,
                "samples": [],
            }
        clk = float(_clk_tck())
        first = samples[0]
        last = samples[-1]
        vol = _delta(first, last, "voluntary_ctxt_switches")
        nvol = _delta(first, last, "nonvoluntary_ctxt_switches")
        summary = {
            "rss_peak_kb": max(item["rss_kb"] or 0 for item in samples),
            "fd_peak": max(item["fds"] for item in samples),
            "thread_peak": max(item["threads"] for item in samples),
            "cpu_user_seconds": (last["cpu_user_ticks"] - first["cpu_user_ticks"]) / clk,
            "cpu_system_seconds": (last["cpu_system_ticks"] - first["cpu_system_ticks"]) / clk,
            "samples": samples,
        }
        vsz = [item["vsz_kb"] for item in samples if item["vsz_kb"] is not None]
        if vsz:
            summary["vsz_peak_kb"] = max(vsz)
        if vol is not None:
            summary["voluntary_ctxt_switches"] = vol
        if nvol is not None:
            summary["nonvoluntary_ctxt_switches"] = nvol
        return summary


def _delta(first, last, key):
    if first.get(key) is None or last.get(key) is None:
        return None
    return last[key] - first[key]
