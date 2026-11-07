#!/usr/bin/env python3
"""CEA sinkhole - runs INSIDE the sandbox (network namespace has no route out).

* Fake DNS on 127.0.0.1:53: logs every query, answers A records with 127.0.0.1
  so the client's next move (HTTP request, TLS hello, raw TCP) lands here too.
* Catch-all TCP listeners on common ports: logs HTTP requests (method, host,
  path, headers, body), TLS ClientHello SNI (which host it wanted), or raw bytes.

* TLS is intercepted with a throw-away CA that only the sandbox trusts
  (generated at start-up, never leaves the container), so HTTPS request bodies
  can be checked for stolen honeypot secrets too.

Usage: sinkhole.py <log.jsonl> <ready-file> [tls-dir]
"""
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import struct
import sys
import threading
import time
import zlib

TCP_PORTS = [21, 22, 23, 25, 80, 443, 465, 587, 1337, 2375, 3000, 4444, 5000,
             5555, 6667, 8000, 8080, 8443, 8888, 9000, 9001, 9999]
MAX_CAPTURE = 256 * 1024

_log = None   # opened in main(); module stays importable for unit tests
_lock = threading.Lock()


def log(**ev):
    ev["t"] = round(time.time(), 3)
    with _lock:
        if _log:
            _log.write(json.dumps(ev) + "\n")


# --------------------------------------------------------------------- DNS
def parse_qname(data, off=12):
    labels = []
    while off < len(data):
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0:
            off += 2
            break
        labels.append(data[off + 1:off + 1 + n].decode("latin-1"))
        off += 1 + n
    return ".".join(labels), off


def dns_reply(data):
    name, off = parse_qname(data)
    qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
    question = data[12:off + 4]
    is_a = qtype == 1
    header = data[:2] + b"\x81\x80" + b"\x00\x01" + (b"\x00\x01" if is_a else b"\x00\x00") + b"\x00\x00\x00\x00"
    answer = b""
    if is_a:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
    return name, qtype, header + question + answer


def dns_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 53))
    while True:
        data, addr = s.recvfrom(4096)
        try:
            name, qtype, reply = dns_reply(data)
            log(type="dns", name=name, qtype=qtype)
            s.sendto(reply, addr)
        except Exception as e:  # malformed query - still worth logging
            log(type="dns", name="", error=str(e), raw=base64.b64encode(data[:512]).decode())


# --------------------------------------------------------------------- TLS
def parse_sni(d):
    try:
        if d[0] != 0x16 or d[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32
        p += 1 + d[p]                                   # session id
        p += 2 + struct.unpack("!H", d[p:p + 2])[0]     # cipher suites
        p += 1 + d[p]                                   # compression
        end = p + 2 + struct.unpack("!H", d[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", d[p:p + 4])
            p += 4
            if etype == 0:
                nlen = struct.unpack("!H", d[p + 3:p + 5])[0]
                return d[p + 5:p + 5 + nlen].decode("latin-1")
            p += elen
    except Exception:
        return None
    return None


# ------------------------------------------------------------ TLS intercept
TLS_DIR = None
_ctx_cache = {}
_ctx_lock = threading.Lock()


def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def make_ca():
    os.makedirs(TLS_DIR, exist_ok=True)
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", f"{TLS_DIR}/ca.key", "-out", f"{TLS_DIR}/ca.pem", "-days", "3",
             "-subj", "/O=Internal/CN=Internal Root CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")


def host_ctx(host):
    host = re.sub(r"[^A-Za-z0-9.-]", "", host or "")[:200] or "localhost"
    with _ctx_lock:
        if host in _ctx_cache:
            return _ctx_cache[host]
        base = f"{TLS_DIR}/h-{len(_ctx_cache)}"
        open(f"{base}.ext", "w").write(f"subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n")
        _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", f"{base}.key", "-out", f"{base}.csr", "-subj", f"/CN={host}")
        _openssl("x509", "-req", "-in", f"{base}.csr", "-CA", f"{TLS_DIR}/ca.pem", "-CAkey", f"{TLS_DIR}/ca.key",
                 "-CAcreateserial", "-out", f"{base}.pem", "-days", "2", "-extfile", f"{base}.ext")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{base}.pem", f"{base}.key")
        ctx.set_alpn_protocols(["http/1.1"])
        _ctx_cache[host] = ctx
        return ctx


def read_http(conn, data=b""):
    try:
        while len(data) < MAX_CAPTURE:
            if b"\r\n\r\n" in data:
                head, _, body = data.partition(b"\r\n\r\n")
                m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
                if len(body) >= min(int(m.group(1)) if m else 0, MAX_CAPTURE):
                    break
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError, ssl.SSLError):
        pass
    return data


def parse_http(data):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, path = (lines[0].split(" ") + ["", ""])[:2]
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    return method, path, headers, decode_body(headers, body)


def handle_tls(conn, port):
    try:
        hello = conn.recv(16384, socket.MSG_PEEK)
    except OSError:
        hello = b""
    sni = parse_sni(hello)
    if not TLS_DIR:
        log(type="tls", port=port, sni=sni, intercepted=False, raw=base64.b64encode(hello).decode())
        return
    try:
        tls = host_ctx(sni or "localhost").wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError, subprocess.SubprocessError) as e:
        # client refused our certificate (pinning / custom CA bundle) - we still know where it wanted to go
        log(type="tls", port=port, sni=sni, intercepted=False, error=str(e)[:200], raw=base64.b64encode(hello).decode())
        return
    data = read_http(tls)
    if HTTP_RE.match(data):
        method, path, headers, body = parse_http(data)
        log(type="http", tls=True, port=port, sni=sni, method=method, path=path, host=headers.get("host", sni or ""),
            headers=headers, body=base64.b64encode(body).decode(), raw=base64.b64encode(data).decode())
        try:
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
    else:
        log(type="tls", port=port, sni=sni, intercepted=True, bytes=len(data), raw=base64.b64encode(data).decode())
    try:
        tls.close()
    except OSError:
        pass


# -------------------------------------------------------------------- HTTP
HTTP_RE = re.compile(rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|PROPFIND) (\S+) HTTP/\d")


def decode_body(headers, body):
    enc = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        if "deflate" in enc:
            return zlib.decompress(body)
    except Exception:
        pass
    return body


def handle(conn, port):
    conn.settimeout(4)
    try:
        first = conn.recv(1, socket.MSG_PEEK)
    except OSError:
        first = b""
    if first == b"\x16":
        handle_tls(conn, port)
    else:
        data = read_http(conn)
        if HTTP_RE.match(data):
            method, path, headers, body = parse_http(data)
            log(type="http", tls=False, port=port, method=method, path=path, host=headers.get("host", ""),
                headers=headers, body=base64.b64encode(body).decode(), raw=base64.b64encode(data).decode())
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        else:
            log(type="tcp", port=port, bytes=len(data), raw=base64.b64encode(data).decode())
    try:
        conn.close()
    except OSError:
        pass


def tcp_listener(sock, port):
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn, port), daemon=True).start()


def main():
    global TLS_DIR, _log
    _log = open(sys.argv[1], "a", buffering=1)
    TLS_DIR = sys.argv[3] if len(sys.argv) > 3 else None
    if TLS_DIR:
        try:
            make_ca()
        except Exception as e:
            log(type="sinkhole_error", error=f"TLS interception disabled: {e}")
            TLS_DIR = None
    threading.Thread(target=dns_udp, daemon=True).start()
    for port in TCP_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(64)
            threading.Thread(target=tcp_listener, args=(s, port), daemon=True).start()
        except OSError as e:
            log(type="sinkhole_error", port=port, error=str(e))
    time.sleep(0.2)
    open(sys.argv[2], "w").write("ready")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
