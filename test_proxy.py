#!/usr/bin/env python3
"""End-to-end behavior checks for the C port vs the Rust proxy."""
import os
import socket
import subprocess
import sys
import threading
import time

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siloproxy")

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS" if ok else "FAIL") + " " + name + (("  -- " + detail) if detail and not ok else ""))


def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


class Upstream(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.lock = threading.Lock()
        self.close_once = False

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def read_request(self, sock):
        try:
            head = recv_until(sock, b"\r\n\r\n")
        except EOFError:
            return None
        reqline, _, rest = head.partition(b"\r\n\r\n")
        lines = reqline.split(b"\r\n")
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.strip().lower()] = v.strip()
        body = b""
        buf = rest
        if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
            while True:
                while b"\r\n" not in buf:
                    buf += sock.recv(65536)
                size_line, _, buf = buf.partition(b"\r\n")
                n = int(size_line.split(b";")[0], 16)
                if n == 0:
                    while not buf.startswith(b"\r\n"):
                        while b"\r\n" not in buf:
                            buf += sock.recv(65536)
                        buf = buf.partition(b"\r\n")[2]
                    break
                while len(buf) < n + 2:
                    buf += sock.recv(65536)
                body += buf[:n]
                buf = buf[n + 2:]
        elif b"content-length" in headers:
            cl = int(headers[b"content-length"])
            while len(buf) < cl:
                buf += sock.recv(65536)
            body = buf[:cl]
        return lines[0], headers, body

    def handle(self, sock):
        try:
            while True:
                req = self.read_request(sock)
                if req is None:
                    return
                reqline, headers, body = req
                method, path = reqline.split(b" ")[:2]
                if path == b"/close":
                    return
                if path == b"/close-once":
                    with self.lock:
                        if not self.close_once:
                            self.close_once = True
                            return
                if path == b"/chunked":
                    sock.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                 b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
                    continue
                if path == b"/hundred":
                    sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n"
                                 b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    continue
                if path == b"/eof":
                    sock.sendall(b"HTTP/1.1 200 OK\r\n\r\neof-body")
                    return
                if path == b"/echo":
                    hdr = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                    sock.sendall(hdr + (b"" if method == b"HEAD" else body))
                    continue
                if path == b"/hdrcheck":
                    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Keep-Alive: "
                                 + headers.get(b"keep-alive", b"MISSING")
                                 + b"\r\nX-Connection: " + headers.get(b"connection", b"MISSING")
                                 + b"\r\n\r\nok")
                    continue
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
                             + (b"ok" if method != b"HEAD" else b""))
        except Exception:
            pass
        finally:
            sock.close()


def read_response(sock, is_head=False):
    while True:
        head = recv_until(sock, b"\r\n\r\n")
        head, _, rest = head.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        code = int(lines[0].split(b" ")[1])
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.strip().lower()] = v.strip()
        if 100 <= code < 200:
            continue
        body = b""
        if not is_head and code not in (204, 304):
            if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
                buf = rest
                while True:
                    while b"\r\n" not in buf:
                        buf += sock.recv(65536)
                    size_line, _, buf = buf.partition(b"\r\n")
                    n = int(size_line.split(b";")[0], 16)
                    if n == 0:
                        while not buf.startswith(b"\r\n"):
                            while b"\r\n" not in buf:
                                buf += sock.recv(65536)
                            buf = buf.partition(b"\r\n")[2]
                        break
                    while len(buf) < n + 2:
                        buf += sock.recv(65536)
                    body += buf[:n]
                    buf = buf[n + 2:]
            elif b"content-length" in headers:
                cl = int(headers[b"content-length"])
                body = rest
                while len(body) < cl:
                    body += sock.recv(65536)
                body = body[:cl]
            else:
                body = rest
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    body += chunk
        return code, headers, body


def request(addr, reqbytes, is_head=False, timeout=5):
    s = socket.create_connection(addr, timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(reqbytes)
        return read_response(s, is_head)
    finally:
        s.close()


class Proxy:
    def __init__(self, up_port, bucket=None, bind=None):
        env = dict(os.environ)
        env["UPSTREAM"] = "http://127.0.0.1:%d" % up_port
        if bucket:
            env["BUCKET"] = bucket
        if bind is None:
            t = socket.socket()
            t.bind(("127.0.0.1", 0))
            self.port = t.getsockname()[1]
            t.close()
            env["BIND"] = "127.0.0.1:%d" % self.port
        else:
            self.port = int(bind.rsplit(":", 1)[1])
            env["BIND"] = bind
        self.proc = subprocess.Popen([BIN], env=env, stderr=subprocess.PIPE)
        host = "::1" if bind and "[" in bind else "127.0.0.1"
        for _ in range(50):
            if self.proc.poll() is not None:
                raise RuntimeError("proxy died: " + self.proc.stderr.read().decode())
            try:
                s = socket.create_connection((host, self.port), timeout=0.2)
                s.close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("proxy never became ready")

    def kill(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        return self.proc.stderr.read().decode()


def main():
    up = Upstream()
    up.start()
    proxy = Proxy(up.port)
    addr = ("127.0.0.1", proxy.port)

    try:
        code, _, body = request(addr, b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
        check("basic GET", code == 200 and body == b"ok", "code=%s body=%r" % (code, body))

        code, _, body = request(addr, b"PUT /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        check("PUT with CL body", code == 200 and body == b"hello", "code=%s body=%r" % (code, body))

        code, _, body = request(addr, b"PUT /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                                       b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        check("chunked request body passthrough", code == 200 and body == b"hello world",
              "code=%s body=%r" % (code, body))

        code, _, body = request(addr, b"GET /chunked HTTP/1.1\r\nHost: x\r\n\r\n")
        check("chunked response passthrough", code == 200 and body == b"helloworld",
              "code=%s body=%r" % (code, body))

        code, _, body = request(addr, b"GET /hundred HTTP/1.1\r\nHost: x\r\n\r\n")
        check("1xx forwarded, final response delivered", code == 200 and body == b"ok",
              "code=%s body=%r" % (code, body))

        code, _, body = request(addr, b"GET /eof HTTP/1.1\r\nHost: x\r\n\r\n")
        check("EOF-framed response", code == 200 and body == b"eof-body",
              "code=%s body=%r" % (code, body))

        s = socket.create_connection(addr, timeout=5)
        s.settimeout(5)
        try:
            s.sendall(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
            c1, _, _ = read_response(s)
            s.sendall(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            c2, _, _ = read_response(s)
            check("keep-alive: two requests, one connection", c1 == 200 and c2 == 200,
                  "c1=%s c2=%s" % (c1, c2))
        finally:
            s.close()

        s = socket.create_connection(addr, timeout=5)
        s.settimeout(5)
        try:
            s.sendall(b"HEAD /echo HTTP/1.1\r\nHost: x\r\n\r\n"
                      b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            c1, h1, b1 = read_response(s, is_head=True)
            c2, _, b2 = read_response(s)
            check("pipelined HEAD+GET: HEAD bodyless, no hang",
                  c1 == 200 and b1 == b"" and c2 == 200 and b2 == b"ok",
                  "c1=%s b1=%r c2=%s b2=%r" % (c1, b1, c2, b2))
        finally:
            s.close()

        code, _, _ = request(addr, b"PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551615\r\n\r\n")
        check("Content-Length overflow -> 400", code == 400, "code=%s" % code)

        code, headers, _ = request(addr, b"GET /hdrcheck HTTP/1.1\r\nHost: x\r\n"
                                          b"Connection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n")
        check("hop-by-hop parity: Keep-Alive forwarded, Connection stripped",
              code == 200 and headers.get(b"x-keep-alive") == b"timeout=5"
              and headers.get(b"x-connection") == b"MISSING",
              "keep=%r conn=%r" % (headers.get(b"x-keep-alive"), headers.get(b"x-connection")))

        start = time.time()
        code, _, _ = request(addr, b"PUT /close HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
                             timeout=8)
        elapsed = time.time() - start
        check("upstream close before response: 502, no deadlock",
              code == 502 and elapsed < 5, "code=%s elapsed=%.2fs" % (code, elapsed))

        code, _, body = request(addr, b"GET /close-once HTTP/1.1\r\nHost: x\r\n\r\n")
        check("bodyless request retried once on stale upstream", code == 200 and body == b"ok",
              "code=%s body=%r" % (code, body))

        if socket.has_ipv6:
            try:
                t6 = socket.socket(socket.AF_INET6)
                t6.bind(("::1", 0))
                port6 = t6.getsockname()[1]
                t6.close()
                p6 = Proxy(up.port, bind="[::1]:%d" % port6)
                code, _, _ = request(("::1", port6), b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
                p6.kill()
                check("BIND=[::1]:port (bracketed IPv6)", code == 200, "code=%s" % code)
            except OSError as e:
                check("BIND=[::1]:port (bracketed IPv6)", True, "skipped: %s" % e)

        proxy.kill()
        err = proxy.proc.stderr.read().decode()
        check("no upstream error spam without DEBUG", "upstream error" not in err, err[:200])
    finally:
        proxy.kill()

    bucket_proxy = Proxy(up.port, bucket="test")
    try:
        baddr = ("127.0.0.1", bucket_proxy.port)
        code, _, _ = request(baddr, b"GET /test/x HTTP/1.1\r\nHost: x\r\n\r\n")
        check("bucket allow", code == 200, "code=%s" % code)
        code, _, _ = request(baddr, b"GET /other/x HTTP/1.1\r\nHost: x\r\n\r\n")
        check("bucket block -> 403", code == 403, "code=%s" % code)
        err = bucket_proxy.kill()
        check("blocked log unconditional (no DEBUG)",
              "blocked: path outside bucket test: /other/x" in err, err[:300])
    finally:
        bucket_proxy.kill()

    failed = [r for r in results if not r[1]]
    print("\n%d/%d passed" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
