"""Local integration harness for the real zroxy binary.

The harness speaks to zroxy over loopback sockets only. It uses the Python
standard library and POSIX process control. Readiness is a successful
connection to a TCP listener, or a UDP socket that belongs to the zroxy
process. Process startup alone is not readiness.
"""

import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

signal.signal(signal.SIGPIPE, signal.SIG_IGN)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

HTTP_OK = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 12\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"hello zroxy\n"
)


class LabError(Exception):
    """A harness or environment failure, with logs when they exist."""


def zroxy_binary():
    env = os.environ.get("ZROXY_BIN")
    if env:
        return env
    candidate = os.path.join(ROOT, "build", "zroxy")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    raise LabError("ZROXY_BIN is unset and build/zroxy is not executable")


def _loopback_or_die(exc):
    if isinstance(exc, OSError) and exc.errno in (1, 13, 97, 99):
        raise LabError(
            "loopback sockets are not available in this environment: %s" % exc
        ) from exc
    raise exc


def free_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    except OSError as exc:
        _loopback_or_die(exc)
    finally:
        sock.close()


def free_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    except OSError as exc:
        _loopback_or_die(exc)
    finally:
        sock.close()


def client_hello(server_name="localhost"):
    """Build a real TLS ClientHello with the ssl module."""
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    data = outgoing.read()
    if not data or data[0] != 0x16:
        raise LabError("ssl did not produce a TLS ClientHello")
    encoded = server_name.encode("ascii")
    if encoded not in data:
        raise LabError("ClientHello does not contain SNI %s" % server_name)
    if len(data) > 0x1F00:
        raise LabError("ClientHello does not fit in the zroxy read buffer")
    return data


def encode_dns_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise LabError("invalid DNS label %r" % label)
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_dns_query(name, qid=0x1234, qtype=1):
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + encode_dns_name(name) + struct.pack("!HH", qtype, 1)


def build_dns_response(query, ip):
    """Return a response whose body is the query plus one A record."""
    if len(query) < 12:
        raise LabError("query is too short to answer")
    msg = bytearray(query)
    flags = struct.unpack("!H", msg[2:4])[0] | 0x8000
    msg[2:4] = struct.pack("!H", flags)
    msg[6:8] = struct.pack("!H", 1)
    msg.extend(b"\xc0\x0c")
    msg.extend(struct.pack("!HHIH", 1, 1, 60, 4))
    msg.extend(bytes(ip))
    return bytes(msg)


def _read_dns_name(msg, offset):
    labels = []
    pos = offset
    end = offset
    jumped = False
    hops = 0
    while True:
        if pos >= len(msg):
            raise LabError("DNS name exceeds message")
        lab = msg[pos]
        if lab == 0:
            if not jumped:
                end = pos + 1
            return ".".join(labels), end
        if lab & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise LabError("truncated DNS compression pointer")
            ptr = ((lab & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            hops += 1
            if hops > 16:
                raise LabError("DNS compression loop")
            continue
        if lab & 0xC0:
            raise LabError("unsupported DNS label")
        pos += 1
        if pos + lab > len(msg):
            raise LabError("truncated DNS label")
        labels.append(msg[pos:pos + lab].decode("ascii"))
        pos += lab
        if not jumped:
            end = pos


def parse_dns_message(msg):
    if len(msg) < 12:
        raise LabError("DNS message shorter than header")
    qid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", msg, 0)
    off = 12
    questions = []
    for _ in range(qd):
        name, off = _read_dns_name(msg, off)
        qtype, qclass = struct.unpack_from("!HH", msg, off)
        off += 4
        questions.append((name, qtype, qclass))
    answers = []
    for _ in range(an):
        name, off = _read_dns_name(msg, off)
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
        off += 10
        rdata = bytes(msg[off:off + rdlen])
        off += rdlen
        answers.append({
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "rdata": rdata,
        })
    return {
        "id": qid,
        "flags": flags,
        "questions": questions,
        "answers": answers,
    }


def tcp_exchange(host, port, payload, timeout):
    """Send payload and read until EOF or the deadline."""
    return _tcp_session(host, port, payload, timeout, until_eof=True)


def tcp_roundtrip(host, port, payload, timeout):
    """Send payload and read exactly len(payload) bytes. Used with an echo peer."""
    return _tcp_session(host, port, payload, timeout, until_eof=False)


def _tcp_session(host, port, payload, timeout, until_eof):
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((host, port), timeout=min(2.0, timeout))
    except OSError as exc:
        _loopback_or_die(exc)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        sock.sendall(payload)
        buf = bytearray()
        while time.monotonic() < deadline:
            if not until_eof and len(buf) >= len(payload):
                return bytes(buf), True
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                return bytes(buf), until_eof
            buf.extend(chunk)
            if len(buf) > 8 * 1024 * 1024:
                break
        if not until_eof and len(buf) >= len(payload):
            return bytes(buf[:len(payload)]), True
        return bytes(buf), False
    except OSError as exc:
        _loopback_or_die(exc)
    finally:
        sock.close()


def duplex_exchange(host, port, payload, timeout):
    """Send and read concurrently so a large echo cannot stall the proxy."""
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((host, port), timeout=min(2.0, timeout))
    except OSError as exc:
        _loopback_or_die(exc)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setblocking(False)
    sent = 0
    received = bytearray()
    try:
        while time.monotonic() < deadline and (sent < len(payload) or len(received) < len(payload)):
            left = deadline - time.monotonic()
            readable, writable, _ = select.select(
                [sock] if len(received) < len(payload) else [],
                [sock] if sent < len(payload) else [],
                [],
                min(0.2, left),
            )
            if sock in writable:
                try:
                    n = sock.send(payload[sent:])
                except (BlockingIOError, InterruptedError):
                    n = 0
                if n <= 0 and sent < len(payload):
                    continue
                sent += n
            if sock in readable:
                try:
                    chunk = sock.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    break
                received.extend(chunk)
        data = bytes(received)
        return data, sent == len(payload) and data == payload
    except OSError as exc:
        _loopback_or_die(exc)
    finally:
        sock.close()


def stream_echo(host, port, preamble, chunk, duration, timeout=3.0, samples=None):
    """Echo a ClientHello, then keep exchanging chunks until duration elapses."""
    end = time.monotonic() + duration
    try:
        sock = socket.create_connection((host, port), timeout=min(2.0, timeout))
    except OSError as exc:
        _loopback_or_die(exc)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setblocking(False)
    sent = 0
    received = 0
    try:
        def exchange(payload):
            started = time.monotonic()
            data, matched = duplex_on_socket(sock, payload, timeout)
            if samples is not None and matched:
                samples.append((time.monotonic() - started) * 1000.0)
            return data, matched

        data, matched = exchange(preamble)
        received += len(data)
        if not matched:
            return False, sent, received
        sent += len(preamble)
        while time.monotonic() < end:
            data, matched = exchange(chunk)
            received += len(data)
            if not matched:
                return False, sent, received
            sent += len(chunk)
        return True, sent, received
    except OSError as exc:
        _loopback_or_die(exc)
    finally:
        sock.close()


def duplex_on_socket(sock, payload, timeout):
    deadline = time.monotonic() + timeout
    sent = 0
    received = bytearray()
    while time.monotonic() < deadline and (sent < len(payload) or len(received) < len(payload)):
        left = deadline - time.monotonic()
        readable, writable, _ = select.select(
            [sock] if len(received) < len(payload) else [],
            [sock] if sent < len(payload) else [],
            [],
            min(0.2, max(0.0, left)),
        )
        if sock in writable:
            try:
                n = sock.send(payload[sent:])
            except (BlockingIOError, InterruptedError):
                n = 0
            if n > 0:
                sent += n
        if sock in readable:
            try:
                chunk = sock.recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            if not chunk:
                break
            received.extend(chunk)
    data = bytes(received)
    return data, sent == len(payload) and data == payload


def udp_exchange(port, payload, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(timeout)
        sock.sendto(payload, ("127.0.0.1", port))
        try:
            data, _addr = sock.recvfrom(4096)
        except socket.timeout:
            return None
        return data
    except OSError as exc:
        _loopback_or_die(exc)
    finally:
        sock.close()


def fetch_monitor(port, timeout=3.0):
    """HTTP GET implemented with a raw TCP socket. Returns (raw, json_doc)."""
    import json

    deadline = time.monotonic() + timeout
    sock = socket.create_connection(("127.0.0.1", port), timeout=min(2.0, timeout))
    try:
        sock.settimeout(timeout)
        sock.sendall(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        buf = bytearray()
        closed = False
        while time.monotonic() < deadline:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                closed = True
                break
            buf.extend(chunk)
            if len(buf) > 1024 * 1024:
                break
        raw = bytes(buf)
        sep = raw.find(b"\n\n")
        if sep < 0:
            raise LabError("monitor response has no header terminator: %r" % raw[:200])
        head = raw[:sep].decode("iso-8859-1", "replace")
        body = raw[sep + 2:]
        status = head.split("\n", 1)[0]
        if not status.startswith("HTTP/1.1 200"):
            raise LabError("monitor status %r" % status)
        length = None
        for line in head.split("\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
        if length is not None and length != len(body):
            raise LabError(
                "monitor Content-Length %s does not match body %s" % (length, len(body))
            )
        try:
            doc = json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise LabError("monitor body is not JSON: %r" % body[:300]) from exc
        return {"raw": raw, "closed": closed, "json": doc}
    finally:
        sock.close()


def percentile(values, pct):
    """Linear rank interpolation. An empty sample has no percentile."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return float(ordered[low])
    weight = rank - low
    return float(ordered[low] * (1.0 - weight) + ordered[high] * weight)


def run_pool(workers, jobs, fn):
    """Run fn(job) on a bounded pool. Every worker is joined."""
    import queue

    pending = queue.Queue()
    for job in jobs:
        pending.put(job)
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        while True:
            try:
                job = pending.get_nowait()
            except queue.Empty:
                return
            try:
                item = fn(job)
            except Exception as exc:
                item = exc
                with lock:
                    errors.append(exc)
            with lock:
                if not isinstance(item, Exception):
                    results.append(item)
            pending.task_done()

    threads = [threading.Thread(target=worker, name="zroxy-pool") for _ in range(max(1, workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results, errors


def _write_fragmented(stop, sock, data, chunk, gap):
    if not data:
        return
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if chunk <= 0 or chunk >= len(data):
        sock.sendall(data)
        return
    view = memoryview(data)
    off = 0
    while off < len(view):
        if stop.is_set():
            return
        n = sock.send(view[off:off + chunk])
        if n <= 0:
            raise ConnectionError("fragmented send returned %s" % n)
        off += n
        if gap and off < len(view):
            stop.wait(gap)


def _read_exact(sock, n, timeout):
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("timed out reading %s bytes" % n)
        sock.settimeout(left)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof after %s of %s bytes" % (len(buf), n))
        buf.extend(chunk)
    return bytes(buf)


def _read_some(sock, exact, timeout):
    """Read until exact bytes arrive, or until EOF when exact is None."""
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while True:
        if exact is not None and len(buf) >= exact:
            return bytes(buf)
        left = deadline - time.monotonic()
        if left <= 0:
            return bytes(buf)
        sock.settimeout(min(0.2, left))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            if exact is None and buf:
                return bytes(buf)
            continue
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)


class _ConnRecord:
    def __init__(self):
        self.received = bytearray()
        self.sent = 0
        self.closed = False


class FakeTcpServer:
    """Loopback TCP peer that records requests and writes a scripted reply."""

    def __init__(self, response=b"", read_exact=None, fragment=0, fragment_gap=0.0,
                 response_delay=0.0, close_after=None, mode="reply", hold=None,
                 hold_timeout=10.0):
        self.response = response
        self.read_exact = read_exact
        self.fragment = fragment
        self.fragment_gap = fragment_gap
        self.response_delay = response_delay
        self.close_after = close_after
        self.mode = mode
        self.hold = hold
        self.hold_timeout = hold_timeout
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._conns = []
        self._threads = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(128)
            self.sock.settimeout(0.2)
            self.port = self.sock.getsockname()[1]
        except OSError as exc:
            self.sock.close()
            _loopback_or_die(exc)
        self._accept_thread = threading.Thread(target=self._accept_loop, name="fake-tcp")
        self._accept_thread.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle, args=(conn,), name="fake-tcp-conn")
            with self._lock:
                self._threads.append(worker)
            worker.start()

    def _handle(self, conn):
        rec = _ConnRecord()
        with self._lock:
            self._conns.append(rec)
            mode = self.mode
            close_after = self.close_after
            read_exact = self.read_exact
            response = self.response
            response_delay = self.response_delay
            fragment = self.fragment
            fragment_gap = self.fragment_gap
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            if mode == "echo":
                self._echo(conn, rec)
                return
            if close_after is not None:
                data = _read_some(conn, close_after, 3.0)
                rec.received.extend(data[:close_after])
                return
            if mode == "blackhole":
                data = _read_some(conn, read_exact, 3.0)
                rec.received.extend(data)
                self._stop.wait(self.hold_timeout)
                return
            data = _read_some(conn, read_exact, 3.0)
            rec.received.extend(data)
            if self.hold is not None:
                self.hold.wait(self.hold_timeout)
            if response_delay:
                self._stop.wait(response_delay)
            if self._stop.is_set():
                return
            _write_fragmented(self._stop, conn, response, fragment, fragment_gap)
            rec.sent = len(response)
        except (OSError, TimeoutError, ConnectionError):
            pass
        finally:
            rec.closed = True
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def _echo(self, conn, rec):
        conn.settimeout(0.5)
        while not self._stop.is_set():
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            rec.received.extend(chunk)
            if self.response_delay:
                self._stop.wait(self.response_delay)
            try:
                _write_fragmented(self._stop, conn, chunk, self.fragment, self.fragment_gap)
                rec.sent += len(chunk)
            except OSError:
                break

    def stop(self):
        self._stop.set()
        if self.hold is not None:
            self.hold.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        with self._lock:
            workers = list(self._threads)
        for worker in workers:
            worker.join(timeout=2.0)

    def connection_count(self):
        with self._lock:
            return len(self._conns)

    def payloads(self):
        with self._lock:
            return [bytes(c.received) for c in self._conns]

    def saw_exact(self, payload):
        return any(item == payload for item in self.payloads())

    def wait_connection(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.connection_count() > 0:
                return True
            time.sleep(0.01)
        return False

    def wait_idle(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                busy = any(not c.closed for c in self._conns)
            if not busy:
                return True
            time.sleep(0.01)
        return False


class FakeSocks5Server:
    """Minimal SOCKS5 server: no-auth, CONNECT, then bidirectional relay."""

    def __init__(self, upstream_host, upstream_port, fragment=1, fragment_gap=0.005):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.fragment = fragment
        self.fragment_gap = fragment_gap
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.greetings = []
        self.connects = []
        self._threads = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(128)
            self.sock.settimeout(0.2)
            self.port = self.sock.getsockname()[1]
        except OSError as exc:
            self.sock.close()
            _loopback_or_die(exc)
        self._accept_thread = threading.Thread(target=self._accept_loop, name="fake-socks")
        self._accept_thread.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle, args=(conn,), name="fake-socks-conn")
            with self._lock:
                self._threads.append(worker)
            worker.start()

    def _handle(self, conn):
        upstream = None
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(3.0)
            ver_n = _read_exact(conn, 2, 3.0)
            methods = _read_exact(conn, ver_n[1], 3.0)
            greeting = ver_n + methods
            with self._lock:
                self.greetings.append(greeting)
            _write_fragmented(self._stop, conn, b"\x05\x00", self.fragment, self.fragment_gap)
            head = _read_exact(conn, 4, 3.0)
            ver, cmd, _rsv, atyp = head
            if ver != 5 or cmd != 1:
                return
            if atyp == 3:
                nlen = _read_exact(conn, 1, 3.0)[0]
                host = _read_exact(conn, nlen, 3.0).decode("ascii")
                port = struct.unpack("!H", _read_exact(conn, 2, 3.0))[0]
            elif atyp == 1:
                host = socket.inet_ntoa(_read_exact(conn, 4, 3.0))
                port = struct.unpack("!H", _read_exact(conn, 2, 3.0))[0]
            else:
                return
            with self._lock:
                self.connects.append((host, port))
            upstream = socket.create_connection(
                (self.upstream_host, self.upstream_port), timeout=3.0
            )
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            reply = (
                b"\x05\x00\x00\x01"
                + socket.inet_aton("127.0.0.1")
                + struct.pack("!H", self.upstream_port)
            )
            _write_fragmented(self._stop, conn, reply, self.fragment, self.fragment_gap)
            self._relay(conn, upstream)
        except (OSError, TimeoutError, ConnectionError, UnicodeError):
            pass
        finally:
            for fd in (upstream, conn):
                if fd is None:
                    continue
                try:
                    fd.close()
                except OSError:
                    pass

    def _relay(self, left, right):
        pair = {left: right, right: left}
        for sock in (left, right):
            sock.settimeout(0.5)
        idle_deadline = time.monotonic() + 5.0
        while not self._stop.is_set() and time.monotonic() < idle_deadline:
            for src in (left, right):
                try:
                    chunk = src.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    try:
                        pair[src].shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                idle_deadline = time.monotonic() + 5.0
                try:
                    pair[src].sendall(chunk)
                except OSError:
                    return

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        with self._lock:
            workers = list(self._threads)
        for worker in workers:
            worker.join(timeout=2.0)


class FakeDnsUpstream:
    """DNS-over-TCP peer. Modes exercise the proxy's length-prefix reads."""

    def __init__(self, mode="reply", response_fn=None, fragment=1, fragment_gap=0.005,
                 stall=1.5):
        self.mode = mode
        self.response_fn = response_fn
        self.fragment = fragment
        self.fragment_gap = fragment_gap
        self.stall = stall
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.queries = []
        self.prefix_bytes = []
        self.accepted = 0
        self._threads = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(128)
            self.sock.settimeout(0.2)
            self.port = self.sock.getsockname()[1]
        except OSError as exc:
            self.sock.close()
            _loopback_or_die(exc)
        self._accept_thread = threading.Thread(target=self._accept_loop, name="fake-dns")
        self._accept_thread.start()

    def set_mode(self, mode):
        with self._lock:
            self.mode = mode

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle, args=(conn,), name="fake-dns-conn")
            with self._lock:
                self.accepted += 1
                self._threads.append(worker)
            worker.start()

    def _handle(self, conn):
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(3.0)
            with self._lock:
                mode = self.mode
            if mode == "keepalive":
                self._serve_keepalive(conn)
                return
            if mode == "incomplete":
                first = _read_exact(conn, 1, 3.0)
                with self._lock:
                    self.prefix_bytes.append(first)
                self._stop.wait(self.stall)
                return
            prefix = _read_exact(conn, 2, 3.0)
            length = struct.unpack("!H", prefix)[0]
            query = _read_exact(conn, length, 3.0) if length else b""
            with self._lock:
                self.queries.append(query)
                mode = self.mode
            if mode in ("close", "timeout"):
                if mode == "timeout":
                    self._stop.wait(self.stall)
                return
            body = self.response_fn(query) if self.response_fn else query
            packet = struct.pack("!H", len(body)) + body
            if self.response_fn and mode == "reply":
                _write_fragmented(self._stop, conn, packet, self.fragment, self.fragment_gap)
        except (OSError, TimeoutError, ConnectionError, struct.error):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        with self._lock:
            workers = list(self._threads)
        for worker in workers:
            worker.join(timeout=2.0)

    def _serve_keepalive(self, conn):
        """Answer queries on one connection until the client closes it or the mode changes."""
        while not self._stop.is_set():
            with self._lock:
                if self.mode != "keepalive":
                    return
            conn.settimeout(0.2)
            try:
                prefix = conn.recv(2, socket.MSG_WAITALL)
            except socket.timeout:
                continue
            if len(prefix) < 2:
                return
            length = struct.unpack("!H", prefix)[0]
            query = _read_exact(conn, length, 3.0) if length else b""
            with self._lock:
                self.queries.append(query)
            body = self.response_fn(query) if self.response_fn else query
            conn.sendall(struct.pack("!H", len(body)) + body)

    def upstream_connections(self):
        with self._lock:
            return self.accepted

    def wait_queries(self, n, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.queries) >= n:
                    return True
            time.sleep(0.01)
        return False

    def query_count(self):
        with self._lock:
            return len(self.queries)

    def wait_idle(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                workers = [t for t in self._threads if t.is_alive()]
            if not workers:
                return True
            time.sleep(0.01)
        return False


def _tcp_listening(port):
    """True when /proc/net/tcp shows this port listening on loopback or any."""
    suffixes = ("0100007F:%04X" % port, "00000000:%04X" % port)
    try:
        with open("/proc/net/tcp", "r", encoding="ascii", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "0A":
                    continue
                local = parts[1].upper()
                if local in suffixes:
                    return True
    except OSError as exc:
        raise LabError("cannot read /proc/net/tcp: %s" % exc) from exc
    return False


def _udp_owned_by(pid, port):
    """True when pid has a UDP socket bound to 127.0.0.1:port."""
    token = "0100007F:%04X" % port
    inode = None
    try:
        with open("/proc/net/udp", "r", encoding="ascii", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 10 and parts[1].upper() == token:
                    inode = parts[9]
                    break
    except OSError as exc:
        raise LabError("cannot read /proc/net/udp: %s" % exc) from exc
    if inode is None:
        return False
    fd_dir = "/proc/%s/fd" % pid
    try:
        names = os.listdir(fd_dir)
    except OSError:
        return False
    needle = "socket:[%s]" % inode
    for name in names:
        try:
            target = os.readlink(os.path.join(fd_dir, name))
        except OSError:
            continue
        if target == needle:
            return True
    return False


class ZroxyProcess:
    def __init__(self, args, log_path, tcp_ports, udp_ports, ready_timeout=5.0):
        self.log_path = log_path
        self.binary = zroxy_binary()
        self.log_fh = open(log_path, "wb", buffering=0)
        try:
            self.proc = subprocess.Popen(
                [self.binary, *args],
                stdout=self.log_fh,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            self.log_fh.close()
            raise LabError("failed to start zroxy: %s" % exc) from exc
        try:
            self._wait_ready(tcp_ports, udp_ports, ready_timeout)
        except Exception:
            self.stop()
            raise

    def _wait_ready(self, tcp_ports, udp_ports, timeout):
        deadline = time.monotonic() + timeout
        pending_tcp = set(tcp_ports)
        pending_udp = set(udp_ports)
        last = "listener not ready"
        while time.monotonic() < deadline:
            code = self.proc.poll()
            if code is not None:
                raise LabError(
                    "zroxy exited %s before ready\n%s" % (code, self.log_text())
                )
            still_tcp = []
            for port in pending_tcp:
                if _tcp_listening(port):
                    try:
                        sock = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                        sock.close()
                    except OSError as exc:
                        last = str(exc)
                        still_tcp.append(port)
                else:
                    still_tcp.append(port)
            pending_tcp = set(still_tcp)
            pending_udp = {port for port in pending_udp if not _udp_owned_by(self.proc.pid, port)}
            if not pending_tcp and not pending_udp:
                return
            time.sleep(0.02)
        raise LabError(
            "readiness timed out tcp=%s udp=%s (%s)\n%s"
            % (sorted(pending_tcp), sorted(pending_udp), last, self.log_text())
        )

    def log_text(self, limit=6000):
        try:
            with open(self.log_path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return "(unable to read log %s: %s)" % (self.log_path, exc)
        if len(data) > limit:
            data = data[-limit:]
        return data.decode("utf-8", "replace")

    def count_log(self, needle):
        return self.log_text(limit=1024 * 1024).count(needle)

    def wait_log(self, needle, timeout, after=0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.count_log(needle) > after:
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.02)
        return False

    def check_alive(self):
        code = self.proc.poll()
        if code is not None:
            raise LabError("zroxy exited unexpectedly (%s)\n%s" % (code, self.log_text()))

    def stop(self):
        proc = getattr(self, "proc", None)
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass
        fh = getattr(self, "log_fh", None)
        if fh is not None and not fh.closed:
            fh.close()


class Lab:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="zroxy-lab-")
        self.servers = []
        self.procs = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, _tb):
        for proc in self.procs:
            proc.stop()
        for server in self.servers:
            server.stop()
        if exc is not None:
            sys.stderr.write("\n--- zroxy diagnostics ---\n")
            if not self.procs:
                sys.stderr.write("(no zroxy process)\n")
            for proc in self.procs:
                sys.stderr.write(proc.log_text())
                sys.stderr.write("\n")
        self.tmp.cleanup()
        return False

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def write(self, name, text):
        path = self.path(name)
        with open(path, "w", encoding="ascii") as fh:
            fh.write(text)
        return path

    def tcp_server(self, **kwargs):
        server = FakeTcpServer(**kwargs)
        self.servers.append(server)
        return server

    def socks_server(self, **kwargs):
        server = FakeSocks5Server(**kwargs)
        self.servers.append(server)
        return server

    def dns_server(self, **kwargs):
        server = FakeDnsUpstream(**kwargs)
        self.servers.append(server)
        return server

    def zroxy(self, args, tcp_ports=(), udp_ports=(), ready_timeout=5.0):
        log_path = self.path("zroxy-%s.log" % len(self.procs))
        proc = ZroxyProcess(args, log_path, tcp_ports, udp_ports, ready_timeout)
        self.procs.append(proc)
        return proc
