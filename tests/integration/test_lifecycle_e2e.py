#!/usr/bin/env python3
"""End-to-end process lifecycle: SIGHUP reload and clean SIGTERM/SIGINT shutdown."""

import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import zroxy_lab

SYNTHETIC_IP = (10, 9, 8, 7)


def _start_full(lab, white):
    upstream = lab.dns_server(mode="reply",
                              response_fn=lambda q: zroxy_lab.build_dns_response(q, (9, 9, 9, 9)))
    sni_port = zroxy_lab.free_tcp_port()
    ldns = zroxy_lab.free_udp_port()
    proc = lab.zroxy(
        [
            "-l", "0",
            "-p", "127.0.0.1:%s" % sni_port,
            "-d", "127.0.0.1:%s" % ldns,
            "-u", "127.0.0.1:%s" % upstream.port,
            "-t", "1",
            "-i", "%d.%d.%d.%d" % SYNTHETIC_IP,
            "-w", white,
        ],
        tcp_ports=[sni_port],
        udp_ports=[ldns],
    )
    return proc, sni_port, ldns


def _wait_exit(proc, timeout):
    try:
        return proc.proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AssertionError("zroxy did not exit within %.1fs\n%s" % (timeout, proc.log_text()))


def test_sighup_reloads_whitelist():
    with zroxy_lab.Lab() as lab:
        white = lab.write("white.txt", "first.test\n")
        proc, _sni_port, _ldns = _start_full(lab, white)
        before = proc.count_log("Reload filter:")
        os.kill(proc.proc.pid, signal.SIGHUP)
        if not proc.wait_log("Reload filter:", 3.0, after=before):
            raise AssertionError("SIGHUP did not reload the whitelist\n%s" % proc.log_text())
        proc.check_alive()


def _check_clean_exit(sig):
    with zroxy_lab.Lab() as lab:
        white = lab.write("white.txt", "first.test\n")
        proc, sni_port, ldns = _start_full(lab, white)

        # An open, idle client connection must not hold up shutdown.
        idle = socket.create_connection(("127.0.0.1", sni_port), timeout=2.0)
        try:
            # Make sure the DNS workers are busy-capable before stopping.
            zroxy_lab.udp_exchange(ldns, zroxy_lab.build_dns_query("first.test"), 2.0)
            started = time.monotonic()
            os.kill(proc.proc.pid, sig)
            code = _wait_exit(proc, 5.0)
            elapsed = time.monotonic() - started
        finally:
            idle.close()

        if code != 0:
            raise AssertionError("exit code %s after signal %d\n%s" % (code, sig, proc.log_text()))
        for needle in ("shutting down on signal %d" % sig, "dns server stopped", "zroxy stopped"):
            if proc.count_log(needle) != 1:
                raise AssertionError("missing %r in log\n%s" % (needle, proc.log_text()))
        if elapsed > 3.0:
            raise AssertionError("shutdown took %.2fs" % elapsed)


def test_sigterm_clean_exit():
    _check_clean_exit(signal.SIGTERM)


def test_sigint_clean_exit():
    _check_clean_exit(signal.SIGINT)


def test_monitor_stop_race():
    with zroxy_lab.Lab() as lab:
        white = lab.write("white.txt", "first.test\n")
        upstream = lab.dns_server(
            mode="reply",
            response_fn=lambda q: zroxy_lab.build_dns_response(q, (9, 9, 9, 9)),
        )
        sni_port = zroxy_lab.free_tcp_port()
        ldns = zroxy_lab.free_udp_port()
        mon_port = zroxy_lab.free_tcp_port()
        proc = lab.zroxy(
            [
                "-l", "0",
                "-p", "127.0.0.1:%s" % sni_port,
                "-m", str(mon_port),
                "-d", "127.0.0.1:%s" % ldns,
                "-u", "127.0.0.1:%s" % upstream.port,
                "-t", "1",
                "-i", "%d.%d.%d.%d" % SYNTHETIC_IP,
                "-w", white,
            ],
            tcp_ports=[sni_port, mon_port],
            udp_ports=[ldns],
        )
        stop = threading.Event()
        errors = []

        def poll_monitor():
            while not stop.is_set():
                try:
                    zroxy_lab.fetch_monitor(mon_port, timeout=0.5)
                except Exception as exc:
                    if not stop.is_set() and not isinstance(exc, ConnectionResetError):
                        errors.append(exc)
                        return

        thread = threading.Thread(target=poll_monitor)
        thread.start()
        try:
            zroxy_lab.udp_exchange(ldns, zroxy_lab.build_dns_query("first.test"), 2.0)
            time.sleep(0.1)
            stop.set()
            os.kill(proc.proc.pid, signal.SIGTERM)
            code = _wait_exit(proc, 5.0)
        finally:
            stop.set()
            thread.join(3.0)
        if code != 0:
            raise AssertionError("monitor race exit code %s\n%s" % (code, proc.log_text()))
        if thread.is_alive():
            raise AssertionError("monitor polling thread did not stop")
        if errors:
            raise AssertionError("monitor polling failed during shutdown: %s" % errors[0])


def main():
    tests = [
        test_sighup_reloads_whitelist,
        test_sigterm_clean_exit,
        test_sigint_clean_exit,
        test_monitor_stop_race,
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
