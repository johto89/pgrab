from __future__ import annotations

import errno
import ipaddress
import random
import socket
import ssl
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, Optional

from pgrab.ports import WELL_KNOWN_PORTS

# Optional: only needed to parse certificates. Tool degrades gracefully without it.
try:
    from cryptography import x509
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

# --- service classification -------------------------------------------------

HTTP_PORTS = {80, 3000, 3128, 8000, 8008, 8080, 8081, 8888, 9000}
HTTPS_WEB = {443, 4443, 8443, 9443, 10443}  # TLS + speaks HTTP inside the tunnel
TLS_PORTS = HTTPS_WEB | {465, 636, 989, 990, 993, 995, 5061, 6443, 8883}

# Ports that start plaintext then upgrade via a STARTTLS-style command.
STARTTLS_PORTS = {
    21: "ftp", 25: "smtp", 587: "smtp", 2525: "smtp",
    110: "pop3", 143: "imap",
    389: "ldap", 5222: "xmpp", 5432: "postgres",
}
# Protocols where the server greets immediately on connect (client reads first).
_STARTTLS_GREETS = {"ftp", "smtp", "pop3", "imap"}

# LDAP StartTLS extended request (OID 1.3.6.1.4.1.1466.20037), messageID 1.
_LDAP_STARTTLS = bytes.fromhex(
    "301d02010177188016312e332e362e312e342e312e313436362e3230303337"
)
# PostgreSQL SSLRequest: length=8, magic code 80877103.
_PG_SSLREQUEST = struct.pack(">ii", 8, 80877103)

_TLS_SERVICE_NAMES = {
    "https", "https-alt", "imaps", "pop3s", "smtps", "ldaps", "ftps",
    "nntps", "telnets", "sip-tls",
}
_HTTP_SERVICE_NAMES = {"http", "http-alt", "http-proxy", "http-dev"}


def status_code(code: str) -> str:
    """Return the category of an HTTP response code."""
    try:
        code_int = int(code)
    except (TypeError, ValueError):
        return "unknown"
    if 200 <= code_int < 300:
        return "success"
    if 300 <= code_int < 400:
        return "redirect"
    if 400 <= code_int < 500:
        return "client_error"
    if code_int >= 500:
        return "server_error"
    return "unknown"


def get_service_name(port: int, proto: str = "tcp") -> str:
    """Best-effort service name: system services DB first, then our own list."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return WELL_KNOWN_PORTS.get(port, "unknown")


def _is_tls_port(port: int, service: str) -> bool:
    return port in TLS_PORTS or service in _TLS_SERVICE_NAMES


def _is_http_port(port: int, service: str) -> bool:
    return port in HTTP_PORTS or service in _HTTP_SERVICE_NAMES


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# --- rate limiting ----------------------------------------------------------

class RateLimiter:
    """Caps new connections to `rate`/second. rate <= 0 disables limiting."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self._next = max(now, self._next) + self._interval


_NO_LIMIT = RateLimiter(0)


# --- low-level I/O ----------------------------------------------------------

def _recv_all(sock: socket.socket, timeout: float, max_bytes: int = 8192) -> bytes:
    """Read available data until timeout, peer close, or max_bytes."""
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    try:
        while total < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


# --- HTTP body handling -----------------------------------------------------

def _dechunk(body: bytes) -> bytes:
    """Decode HTTP chunked transfer-encoding; tolerant of truncated input."""
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        size_token = body[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        end = start + size
        if end > n:  # last chunk truncated by our read cap
            out += body[start:n]
            break
        out += body[start:end]
        i = end + 2  # skip the CRLF after the chunk data
    return bytes(out)


def _decompress(body: bytes, encoding: str) -> bytes:
    """Best-effort Content-Encoding decode; returns raw body on any failure."""
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc:
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompressobj().decompress(body)
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body)
        if "br" in enc:
            import brotli  # optional dependency
            return brotli.decompress(body)
    except Exception:  # noqa: BLE001 - never let a decode error kill a scan
        return body
    return body


def _grab_http_over(sock: socket.socket, host: str, path: str, timeout: float,
                    user_agent: str = "pgrab") -> dict:
    """Send an HTTP request over an already-connected (plain or TLS) socket."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        sock.sendall(request.encode())
    except OSError as e:
        return {"http_status": "error", "http_error": str(e)}

    raw = _recv_all(sock, timeout, max_bytes=16384)
    if not raw:
        return {"http_status": "no_response"}
    if not raw.startswith(b"HTTP/"):
        # Open port that answered our GET but isn't HTTP — treat as a banner.
        return {"banner": raw.decode(errors="replace").strip()[:500]}

    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status_line = lines[0]

    hdr: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdr[k.strip().lower()] = v.strip()

    if "chunked" in hdr.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    if hdr.get("content-encoding"):
        body = _decompress(body, hdr["content-encoding"])

    parts = status_line.split()
    code = parts[1] if len(parts) > 1 else ""

    result = {
        "http_status": status_code(code),
        "status_line": status_line,
        "server": hdr.get("server"),
        "powered_by": hdr.get("x-powered-by"),
        "content_type": hdr.get("content-type"),
        "location": hdr.get("location"),
        "headers": lines[1:],
        "body_preview": body.decode(errors="replace")[:500],
    }
    return {k: v for k, v in result.items() if v not in (None, "")}


# --- TLS --------------------------------------------------------------------

def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False           # recon targets often have bad certs;
    ctx.verify_mode = ssl.CERT_NONE      # we still want to read them.
    return ctx


def _parse_cert(der: bytes) -> dict:
    if not der:
        return {}
    if not _HAVE_CRYPTO:
        return {"cert_note": "install 'cryptography' to parse certificate details"}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:  # noqa: BLE001
        return {"cert_error": str(e)}

    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    info = {
        "cert_subject": cert.subject.rfc4514_string(),
        "cert_issuer": cert.issuer.rfc4514_string(),
        "cert_not_before": not_before.isoformat(),
        "cert_not_after": not_after.isoformat(),
        "cert_expired": not_after < datetime.now(timezone.utc),
    }
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if san:
            info["cert_san"] = san
    except x509.ExtensionNotFound:
        pass
    return info


def _wrap_tls(sock: socket.socket, host: str, timeout: float) -> ssl.SSLSocket:
    """Upgrade a connected plaintext socket to TLS. Raises on handshake failure."""
    ctx = _build_ssl_context()
    sni = host if not _looks_like_ip(host) else None
    sock.settimeout(timeout)
    return ctx.wrap_socket(sock, server_hostname=sni, do_handshake_on_connect=True)


def _tls_info_and_app(tls_sock: ssl.SSLSocket, host: str, port: int,
                      path: str, timeout: float, try_http: bool,
                      user_agent: str = "pgrab") -> dict:
    """Collect TLS version/cipher/cert and, if applicable, the app-layer banner."""
    info: dict = {"tls_status": "success", "tls_version": tls_sock.version()}
    cipher = tls_sock.cipher()
    if cipher:
        info["cipher"] = cipher[0]
    info.update(_parse_cert(tls_sock.getpeercert(binary_form=True)))

    # Some TLS services greet immediately (SMTPS/IMAPS/POP3S). Try a short
    # passive read first; only fall back to an HTTP GET for web-ish ports.
    greeting = _recv_all(tls_sock, min(timeout, 2.0), max_bytes=1024)
    if greeting:
        info["banner"] = greeting.decode(errors="replace").strip()[:500]
    elif try_http:
        info.update(_grab_http_over(tls_sock, host, path, timeout, user_agent))
    return info


def _grab_tls(sock: socket.socket, host: str, port: int, path: str,
              timeout: float, try_http: bool, user_agent: str = "pgrab") -> dict:
    """Wrap the socket in TLS (taking ownership) and grab TLS + app info."""
    try:
        tls_sock = _wrap_tls(sock, host, timeout)
    except (ssl.SSLError, OSError) as e:
        return {"tls_status": "error", "tls_error": str(e)}
    try:
        return _tls_info_and_app(tls_sock, host, port, path, timeout, try_http, user_agent)
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass


# --- STARTTLS ---------------------------------------------------------------

def _read_line_block(sock: socket.socket, timeout: float) -> bytes:
    return _recv_all(sock, timeout, max_bytes=2048)


def _grab_starttls(sock: socket.socket, host: str, port: int,
                   proto: str, timeout: float) -> dict:
    """Grab the plaintext greeting, upgrade via STARTTLS, then grab the cert."""
    result: dict = {}
    if proto in _STARTTLS_GREETS:
        greeting = _read_line_block(sock, timeout)
        if greeting:
            result["banner"] = greeting.decode(errors="replace").strip()[:500]

    try:
        if proto == "smtp":
            sock.sendall(b"EHLO pgrab.local\r\n")
            caps = _read_line_block(sock, timeout)
            if b"STARTTLS" not in caps.upper():
                result["starttls"] = "not offered"
                return result
            sock.sendall(b"STARTTLS\r\n")
            resp = _read_line_block(sock, timeout)
            ok = resp.startswith(b"220")
        elif proto == "imap":
            sock.sendall(b"a001 STARTTLS\r\n")
            resp = _read_line_block(sock, timeout)
            ok = b"OK" in resp.split(b"\r\n")[0]
        elif proto == "pop3":
            sock.sendall(b"STLS\r\n")
            resp = _read_line_block(sock, timeout)
            ok = resp.startswith(b"+OK")
        elif proto == "ftp":
            sock.sendall(b"AUTH TLS\r\n")
            resp = _read_line_block(sock, timeout)
            ok = resp.startswith(b"234")
        elif proto == "ldap":
            sock.sendall(_LDAP_STARTTLS)
            resp = _read_line_block(sock, timeout)
            # ExtendedResponse with resultCode success (ENUMERATED 0 -> 0x0a 01 00)
            ok = b"\x0a\x01\x00" in resp
        elif proto == "postgres":
            sock.sendall(_PG_SSLREQUEST)
            resp = _recv_all(sock, timeout, max_bytes=1)
            ok = resp[:1] == b"S"  # 'S' = SSL supported, 'N' = not
            if resp[:1] == b"N":
                result["starttls"] = "not offered"
                return result
        elif proto == "xmpp":
            stream = (
                "<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams' "
                f"to='{host}' version='1.0'>"
            )
            sock.sendall(stream.encode())
            feats = _read_line_block(sock, timeout)
            if b"starttls" not in feats.lower():
                result["starttls"] = "not offered"
                return result
            sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            resp = _read_line_block(sock, timeout)
            ok = b"proceed" in resp.lower()
        else:
            result["starttls"] = f"unsupported proto {proto}"
            return result
    except OSError as e:
        result["starttls"] = f"error: {e}"
        return result

    if not ok:
        result["starttls"] = "refused"
        return result

    try:
        tls_sock = _wrap_tls(sock, host, timeout)
    except (ssl.SSLError, OSError) as e:
        result["starttls"] = "upgrade_failed"
        result["tls_error"] = str(e)
        return result
    try:
        result["starttls"] = "upgraded"
        info = {"tls_status": "success", "tls_version": tls_sock.version()}
        cipher = tls_sock.cipher()
        if cipher:
            info["cipher"] = cipher[0]
        info.update(_parse_cert(tls_sock.getpeercert(binary_form=True)))
        result.update(info)
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass
    return result


# --- generic banner ---------------------------------------------------------

def _grab_generic(sock: socket.socket, timeout: float) -> dict:
    """Read a greeting banner; nudge once with a newline if the peer is silent."""
    data = _recv_all(sock, timeout)
    if not data:
        try:
            sock.sendall(b"\r\n")
            data = _recv_all(sock, timeout)
        except OSError:
            data = b""
    if data:
        return {"banner": data.decode(errors="replace").strip()[:500]}
    return {"note": "open, no banner"}


def _classify_connect_error(err: int) -> str:
    if err in (errno.ECONNREFUSED, errno.ECONNRESET):
        return "closed"
    if err in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
        return "filtered"
    return "closed"


def _fresh_connect(ip: str, port: int, family: int, timeout: float) -> Optional[socket.socket]:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            return s
    except OSError:
        pass
    s.close()
    return None


# --- TCP port scan ----------------------------------------------------------

def scan_port_tcp(ip: str, port: int, host_header: str, path: str, timeout: float,
                  family: int = socket.AF_INET, limiter: RateLimiter = _NO_LIMIT,
                  tls_detect: bool = True, starttls: bool = True,
                  source_port: int = 0, user_agent: str = "pgrab",
                  jitter: float = 0.0) -> dict:
    """Connect to one TCP port; if open, grab a protocol-appropriate banner."""
    service = get_service_name(port, "tcp")
    result: dict = {"port": port, "proto": "tcp", "service": service, "state": "closed"}

    limiter.wait()
    if jitter:
        time.sleep(random.uniform(0, jitter))
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if source_port:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", source_port))
        except OSError as e:
            result["state"] = "error"
            result["error"] = f"source-port bind failed: {e}"
            sock.close()
            return result
    owned = True
    try:
        conn = sock.connect_ex((ip, port))
        if conn != 0:
            result["state"] = _classify_connect_error(conn)
            return result
        result["state"] = "open"

        if tls_detect and _is_tls_port(port, service):
            owned = False
            result.update(_grab_tls(sock, host_header, port, path, timeout,
                                    try_http=(port in HTTPS_WEB), user_agent=user_agent))
        elif _is_http_port(port, service):
            result.update(_grab_http_over(sock, host_header, path, timeout, user_agent))
        elif starttls and port in STARTTLS_PORTS:
            result.update(_grab_starttls(sock, host_header, port,
                                         STARTTLS_PORTS[port], timeout))
        elif tls_detect and service == "unknown":
            # Unknown service: try TLS first; on failure, reconnect for plaintext.
            owned = False
            tls_res = _grab_tls(sock, host_header, port, path, timeout,
                                try_http=True, user_agent=user_agent)
            if tls_res.get("tls_status") == "success":
                result.update(tls_res)
            else:
                fresh = _fresh_connect(ip, port, family, timeout)
                if fresh is not None:
                    try:
                        result.update(_grab_generic(fresh, timeout))
                    finally:
                        fresh.close()
                else:
                    result["note"] = "open, no banner (tls handshake failed)"
        else:
            result.update(_grab_generic(sock, timeout))
    except socket.timeout:
        result["state"] = "filtered"
    except OSError as e:
        result["state"] = "error"
        result["error"] = str(e)
    finally:
        if owned:
            try:
                sock.close()
            except OSError:
                pass
    return result


# --- UDP port scan ----------------------------------------------------------

def _dns_probe() -> bytes:
    """A DNS CHAOS TXT query for version.bind (elicits a reply from resolvers)."""
    header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    qname = b"\x07version\x04bind\x00"
    question = qname + struct.pack(">HH", 0x0010, 0x0003)  # TXT, CHAOS
    return header + question


# community "public", GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
_SNMP_PROBE = bytes.fromhex(
    "302902010004067075626c6963a01c020400000000020100020100"
    "300e300c06082b060102010101000500"
)
# NTP mode 3 (client) request, 48 bytes
_NTP_PROBE = b"\x1b" + b"\x00" * 47

UDP_PROBES = {
    53: _dns_probe(),
    123: _NTP_PROBE,
    161: _SNMP_PROBE,
}

_DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}


def _skip_qname(data: bytes, off: int) -> int:
    """Advance past a DNS name (labels or a compression pointer)."""
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return off + 2
        off += 1 + length
    return off


def _parse_dns_response(data: bytes) -> dict:
    """Turn a DNS reply into fields (rcode, answer count, version.bind TXT)."""
    if len(data) < 12:
        return {}
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    info = {"dns_rcode": _DNS_RCODES.get(flags & 0xF, str(flags & 0xF)),
            "dns_answers": an}
    off = 12
    try:
        for _ in range(qd):
            off = _skip_qname(data, off) + 4  # + type + class
        for _ in range(an):
            off = _skip_qname(data, off)
            atype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if atype == 16 and rdata:  # TXT
                txtlen = rdata[0]
                info["dns_version"] = rdata[1:1 + txtlen].decode(errors="replace")
                break
    except (struct.error, IndexError):
        pass
    return info


def _ber_len(data: bytes, off: int) -> tuple[int, int]:
    """Decode a BER length at off; return (length, new_off)."""
    first = data[off]
    off += 1
    if first < 0x80:
        return first, off
    n = first & 0x7F
    length = int.from_bytes(data[off:off + n], "big")
    return length, off + n


def _parse_snmp_response(data: bytes) -> dict:
    """Extract sysDescr (and error-status) from an SNMP GetResponse."""
    info: dict = {}
    # sysDescr.0 OID as encoded in the request/response.
    oid = bytes.fromhex("06082b06010201010100")
    idx = data.find(oid)
    if idx == -1:
        return info
    voff = idx + len(oid)
    try:
        tag = data[voff]
        length, voff = _ber_len(data, voff + 1)
        value = data[voff:voff + length]
        if tag == 0x04:  # OCTET STRING
            info["snmp_sysdescr"] = value.decode(errors="replace").strip()
        elif tag == 0x05:  # NULL -> no such object
            info["snmp_note"] = "no value returned"
    except (IndexError, struct.error):
        pass
    return info


def scan_port_udp(ip: str, port: int, timeout: float,
                  family: int = socket.AF_INET, limiter: RateLimiter = _NO_LIMIT,
                  retries: int = 1) -> dict:
    """Best-effort UDP scan. States: open, closed, open|filtered.

    Relies on the Linux behaviour where a connected UDP socket surfaces an ICMP
    port-unreachable as ECONNREFUSED on recv. No response + no error is
    reported as open|filtered (the fundamental ambiguity of UDP scanning).
    """
    service = get_service_name(port, "udp")
    result: dict = {"port": port, "proto": "udp", "service": service, "state": "open|filtered"}
    probe = UDP_PROBES.get(port, b"\x00")

    limiter.wait()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        for _ in range(retries + 1):
            try:
                sock.send(probe)
                data = sock.recv(4096)
                result["state"] = "open"
                if data:
                    parsed = {}
                    if port == 53:
                        parsed = _parse_dns_response(data)
                    elif port == 161:
                        parsed = _parse_snmp_response(data)
                    if parsed:
                        result.update(parsed)
                    else:
                        text = data.decode(errors="replace").strip()
                        result["banner"] = text[:500] if text.isprintable() else data.hex()[:200]
                return result
            except socket.timeout:
                continue  # retry
            except ConnectionRefusedError:
                result["state"] = "closed"
                return result
            except OSError as e:
                if e.errno == errno.ECONNREFUSED:
                    result["state"] = "closed"
                else:
                    result["state"] = "error"
                    result["error"] = str(e)
                return result
    finally:
        sock.close()
    return result


# --- orchestration ----------------------------------------------------------

def _resolve(domain: str) -> tuple[str, int]:
    infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0], family
    return infos[0][4][0], infos[0][0]


def scan(ip: str, ports: list[int], host_header: str, path: str = "/",
         timeout: float = 1.0, threads: int = 200, show_closed: bool = False,
         family: int = socket.AF_INET, max_rate: float = 0.0,
         protocol: str = "tcp", tls_detect: bool = True, starttls: bool = True,
         source_port: int = 0, user_agent: str = "pgrab", jitter: float = 0.0,
         randomize: bool = False,
         progress: Optional[Callable[[int, int], None]] = None) -> list[dict]:
    """Scan ports concurrently; returns per-port results sorted by port."""
    results: list[dict] = []
    scan_order = list(ports)
    if randomize:
        random.shuffle(scan_order)
    max_workers = max(1, min(threads, len(scan_order)))
    limiter = RateLimiter(max_rate)
    total = len(scan_order)
    done = 0

    def worker(port: int) -> dict:
        if protocol == "udp":
            return scan_port_udp(ip, port, timeout, family, limiter)
        return scan_port_tcp(ip, port, host_header, path, timeout, family,
                             limiter, tls_detect, starttls, source_port,
                             user_agent, jitter)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(worker, port): port for port in scan_order}
        try:
            for future in as_completed(futures):
                res = future.result()
                done += 1
                if progress:
                    progress(done, total)
                if show_closed or res["state"] in ("open", "open|filtered"):
                    results.append(res)
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    results.sort(key=lambda r: r["port"])
    return results


def run_scan(domain: str, ports: list[int], path: str = "/", timeout: float = 1.0,
             threads: int = 200, show_closed: bool = False, max_rate: float = 0.0,
             protocol: str = "tcp", tls_detect: bool = True, starttls: bool = True,
             source_port: int = 0, user_agent: str = "pgrab", jitter: float = 0.0,
             randomize: bool = False,
             progress: Optional[Callable[[int, int], None]] = None) -> dict:
    """Resolve the target and scan it, returning a structured result dict."""
    key = "domain" if not _looks_like_ip(domain) else "ip"
    try:
        resolved_ip, family = _resolve(domain)
    except socket.gaierror as e:
        return {key: domain, "error": f"Could not resolve host: {e}"}

    results = scan(resolved_ip, ports, host_header=domain, path=path, timeout=timeout,
                   threads=threads, show_closed=show_closed, family=family,
                   max_rate=max_rate, protocol=protocol, tls_detect=tls_detect,
                   starttls=starttls, source_port=source_port, user_agent=user_agent,
                   jitter=jitter, randomize=randomize, progress=progress)

    open_states = ("open", "open|filtered")
    return {
        key: domain,
        "resolved_ip": resolved_ip,
        "protocol": protocol,
        "ports_scanned": len(ports),
        "open_ports_found": sum(1 for r in results if r["state"] in open_states),
        "results": results,
    }


def grabber(domain: str, ports: list[int], path: str = "/", timeout: float = 1.0,
            threads: int = 200, show_closed: bool = False) -> str:
    """Backward-compatible wrapper returning a JSON string."""
    import json
    return json.dumps(run_scan(domain, ports, path, timeout, threads, show_closed), indent=2)
