from __future__ import annotations

import re
import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from pgrab.ports import WELL_KNOWN_PORTS

HTTP_PORTS = {80, 3000, 3128, 8000, 8008, 8080, 8081, 8888, 9000}
HTTPS_PORTS = {443, 8443}


def status_code(code: str) -> str:
    """
    Returns the status category of an HTTP response code.

    :param code: The response code, e.g. "200"
    :type code: str
    :return: The status category ("success", "redirect", "client_error", "server_error", "unknown")
    :rtype: str
    """
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


def get_service_name(port: int) -> str:
    """
    Best-effort lookup of the service name for a port: tries the system
    services database first, then falls back to PGrab's own well-known list.
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return WELL_KNOWN_PORTS.get(port, "unknown")


def _recv_all(sock: socket.socket, timeout: float, max_bytes: int = 8192) -> bytes:
    """Reads whatever data is available on the socket until timeout or close."""
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except socket.timeout:
        pass
    except OSError:
        pass
    return b"".join(chunks)


def _grab_http(sock: socket.socket, host: str, path: str, timeout: float) -> dict:
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pgrab\r\nConnection: close\r\n\r\n"
    sock.sendall(request.encode())
    raw = _recv_all(sock, timeout).decode(errors="replace")

    if not raw:
        return {"status": "no_response"}

    lines = raw.split("\r\n")
    status_line = lines[0]

    try:
        blank_index = lines.index("")
        headers = lines[1:blank_index]
        body = lines[blank_index + 1:]
    except ValueError:
        headers = lines[1:]
        body = []

    code = status_line.split()[1] if len(status_line.split()) > 1 else ""

    return {
        "status": status_code(code),
        "status_line": status_line,
        "headers": headers,
        "body_preview": "\n".join(body)[:500],
    }


def _grab_tls(ip: str, port: int, timeout: float) -> dict:
    info: dict = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                cert = tls_sock.getpeercert()
                info["status"] = "success"
                info["tls_version"] = tls_sock.version()
                info["cipher"] = tls_sock.cipher()[0] if tls_sock.cipher() else None
                if cert:
                    info["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                    info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    info["cert_not_after"] = cert.get("notAfter")
    except Exception as e:
        info["status"] = "error"
        info["error"] = str(e)
    return info


def _grab_generic(sock: socket.socket, timeout: float) -> dict:
    """
    Generic banner grab for services PGrab doesn't have a dedicated parser for.
    Many protocols (SSH, FTP, SMTP, POP3, IMAP, ...) send a greeting banner as
    soon as the connection is opened, so we just try to read it. If nothing
    arrives, we send a harmless newline probe and try once more.
    """
    data = _recv_all(sock, timeout)

    if not data:
        try:
            sock.sendall(b"\r\n")
            data = _recv_all(sock, timeout)
        except OSError:
            data = b""

    if data:
        return {"status": "success", "raw_banner": data.decode(errors="replace").strip()}
    return {"status": "open_no_banner"}


def scan_port(ip: str, port: int, host_header: str, path: str, timeout: float) -> dict:
    """
    Connects to a single port, determines whether it's open and, if so,
    attempts to grab a protocol-appropriate banner.

    :return: a result dict with at least "port", "service" and "state"
    """
    service = get_service_name(port)
    result = {"port": port, "service": service, "state": "closed"}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            conn_result = sock.connect_ex((ip, port))

            if conn_result != 0:
                result["state"] = "closed"
                return result

            result["state"] = "open"

            if port in HTTPS_PORTS or service in ("https",):
                # HTTPS needs its own TLS-wrapped connection
                result.update(_grab_tls(ip, port, timeout))
            elif port in HTTP_PORTS or service in ("http", "http-alt", "http-proxy"):
                result.update(_grab_http(sock, host_header, path, timeout))
            else:
                result.update(_grab_generic(sock, timeout))

    except socket.timeout:
        result["state"] = "filtered"
    except OSError as e:
        result["state"] = "error"
        result["error"] = str(e)

    return result


def scan(
    ip: str,
    ports: list[int],
    host_header: str,
    path: str = "/",
    timeout: float = 1.0,
    threads: int = 200,
    show_closed: bool = False,
) -> list[dict]:
    """
    Scans a list of ports concurrently and returns their results.

    :param ip: resolved IP address to connect to
    :param ports: list of port numbers to scan
    :param host_header: value to send in the HTTP Host header (original hostname)
    :param path: HTTP path to request on web ports
    :param timeout: per-port socket timeout in seconds
    :param threads: max number of concurrent worker threads
    :param show_closed: include closed/filtered ports in the results
    :return: list of per-port result dicts, sorted by port number
    """
    results = []
    max_workers = max(1, min(threads, len(ports)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, host_header, path, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            res = future.result()
            if show_closed or res["state"] == "open":
                results.append(res)

    results.sort(key=lambda r: r["port"])
    return results


def grabber(
    domain: str,
    ports: list[int],
    path: str = "/",
    timeout: float = 1.0,
    threads: int = 200,
    show_closed: bool = False,
) -> str:
    """
    Resolves the target and grabs banners across the requested ports.

    :param domain: The IP address or hostname
    :param ports: list of port numbers to scan (use pgrab.ports.parse_ports)
    :param path: The HTTP path to request on web ports
    :param timeout: per-port socket timeout in seconds
    :param threads: max number of concurrent worker threads
    :param show_closed: include closed/filtered ports in the JSON output
    :return: A JSON string with scan results
    :rtype: str
    """

    pattern = r'\b[A-Za-z0-9-]+\.[A-Za-z]{2,}\b'
    key = "domain" if re.match(pattern, domain) else "ip"

    try:
        resolved_ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return json.dumps({key: domain, "error": f"Could not resolve host: {e}"}, indent=2)

    results = scan(
        resolved_ip,
        ports,
        host_header=domain,
        path=path,
        timeout=timeout,
        threads=threads,
        show_closed=show_closed,
    )

    output = {
        key: domain,
        "resolved_ip": resolved_ip,
        "ports_scanned": len(ports),
        "open_ports_found": sum(1 for r in results if r["state"] == "open"),
        "results": results,
    }

    return json.dumps(output, indent=2)
