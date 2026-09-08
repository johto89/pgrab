"""
Raw-socket scan engine for PGrab (root / CAP_NET_RAW required).

This bypasses the OS TCP stack to craft TCP probes directly, enabling stealth
scan types and packet-level firewall/IDS evasion that a connect() scan cannot do:

  - SYN (half-open): never completes the handshake.
  - FIN / NULL / Xmas: elicit RST only from closed ports on RFC-793 stacks.
  - Decoys: interleave probes with spoofed source IPs.
  - Fragmentation: split the TCP header across tiny IP fragments.
  - TTL / source-port control.

IMPORTANT
  * Requires root. On Linux the kernel will emit an RST when it sees the target's
    SYN/ACK for a connection it doesn't know about; drop it so it doesn't reset
    the target early, e.g.:
      iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <your_ip> -j DROP
  * FIN/NULL/Xmas report closed only on RFC-793-compliant stacks. Windows sends
    RST for open ports too, so everything shows as closed there.
  * This is IPv4-only.
"""

from __future__ import annotations

import os
import random
import select
import socket
import struct
import time
from typing import Callable, Optional

from pgrab.ports import WELL_KNOWN_PORTS

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

SCAN_FLAGS = {
    "syn": SYN,
    "fin": FIN,
    "null": 0x00,
    "xmas": FIN | PSH | URG,
}


def _checksum(data: bytes) -> int:
    """Standard 16-bit one's-complement Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _tcp_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 flags: int, seq: int, ttl_seed: int = 0) -> bytes:
    """Build a bare TCP header (no options) with a correct checksum."""
    offset_res = (5 << 4)  # data offset 5 words, no options
    window = 1024
    # header with checksum field zeroed
    tcp = struct.pack(">HHIIBBHHH",
                      src_port, dst_port, seq, 0,
                      offset_res, flags, window, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
        struct.pack(">BBH", 0, socket.IPPROTO_TCP, len(tcp))
    chk = _checksum(pseudo + tcp)
    tcp = struct.pack(">HHIIBBHHH",
                      src_port, dst_port, seq, 0,
                      offset_res, flags, window, chk, 0)
    return tcp


def _ip_header(src_ip: str, dst_ip: str, payload_len: int, ident: int,
               ttl: int, frag_off: int = 0, mf: int = 0) -> bytes:
    """Build an IPv4 header. frag_off is in 8-byte units; mf = More-Fragments."""
    ver_ihl = (4 << 4) | 5
    total_len = 20 + payload_len
    flags_frag = (mf << 13) | (frag_off & 0x1FFF)
    ip = struct.pack(">BBHHHBBH4s4s",
                     ver_ihl, 0, total_len, ident, flags_frag,
                     ttl, socket.IPPROTO_TCP, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    chk = _checksum(ip)
    ip = struct.pack(">BBHHHBBH4s4s",
                     ver_ihl, 0, total_len, ident, flags_frag,
                     ttl, socket.IPPROTO_TCP, chk,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip


def _fragment(ip_payload: bytes, mtu: int, src_ip: str, dst_ip: str,
              ident: int, ttl: int) -> list[bytes]:
    """Split a TCP segment into IP fragments of at most `mtu` payload bytes.

    mtu must be a multiple of 8 (IP fragment offsets are counted in 8-byte units).
    """
    step = max(8, (mtu // 8) * 8)
    frags = []
    offset = 0
    total = len(ip_payload)
    while offset < total:
        piece = ip_payload[offset:offset + step]
        more = 1 if (offset + step) < total else 0
        hdr = _ip_header(src_ip, dst_ip, len(piece), ident, ttl,
                         frag_off=offset // 8, mf=more)
        frags.append(hdr + piece)
        offset += step
    return frags


def _local_ip(dst_ip: str) -> str:
    """Best-effort local source IP the kernel would use to reach dst_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _parse_reply(packet: bytes) -> Optional[tuple[int, int, int]]:
    """Parse a received IP packet, returning (src_port, dst_port, tcp_flags)."""
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + 20:
        return None
    if packet[9] != socket.IPPROTO_TCP:
        return None
    tcp = packet[ihl:ihl + 20]
    src_port, dst_port = struct.unpack(">HH", tcp[0:4])
    flags = tcp[13]
    return src_port, dst_port, flags


def _get_service(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return WELL_KNOWN_PORTS.get(port, "unknown")


def raw_scan(dst_ip: str, ports: list[int], scan_type: str = "syn",
             timeout: float = 2.0, src_port: int = 0, ttl: int = 64,
             decoys: Optional[list[str]] = None, mtu: int = 0,
             max_rate: float = 0.0, jitter: float = 0.0,
             randomize: bool = True,
             progress: Optional[Callable[[int, int], None]] = None) -> list[dict]:
    """Perform a raw TCP scan. Returns per-port result dicts.

    scan_type: one of syn, fin, null, xmas.
    decoys: list of source IPs to spoof; the literal 'ME' marks the real host.
    mtu: if > 0, fragment probes to this payload size (multiple of 8).
    """
    if scan_type not in SCAN_FLAGS:
        raise ValueError(f"unknown scan_type {scan_type!r}")
    flags = SCAN_FLAGS[scan_type]

    real_src = _local_ip(dst_ip)
    if not src_port:
        src_port = random.randint(1025, 65000)

    # Resolve decoy sources; 'ME' -> our real IP.
    sources = [real_src]
    if decoys:
        sources = [(real_src if d.strip().upper() == "ME" else d.strip())
                   for d in decoys]
        if real_src not in sources:
            sources.append(real_src)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.setblocking(False)
    except PermissionError:
        raise PermissionError("raw scan requires root / CAP_NET_RAW")

    scan_order = list(ports)
    if randomize:
        random.shuffle(scan_order)

    min_interval = 1.0 / max_rate if max_rate and max_rate > 0 else 0.0
    ident_base = os.getpid() & 0xFFFF

    def send_probe(port: int) -> None:
        seq = random.randint(0, 0xFFFFFFFF)
        for i, src in enumerate(sources):
            tcp = _tcp_segment(src, dst_ip, src_port, port, flags, seq)
            ident = (ident_base + port + i) & 0xFFFF
            if mtu and mtu >= 8:
                packets = _fragment(tcp, mtu, src, dst_ip, ident, ttl)
            else:
                packets = [_ip_header(src, dst_ip, len(tcp), ident, ttl) + tcp]
            for pkt in packets:
                try:
                    send_sock.sendto(pkt, (dst_ip, 0))
                except OSError:
                    pass

    # 1) Fire all probes.
    total = len(scan_order)
    for idx, port in enumerate(scan_order):
        send_probe(port)
        if progress:
            progress(idx + 1, total)
        if min_interval:
            time.sleep(min_interval)
        elif jitter:
            time.sleep(random.uniform(0, jitter))

    # 2) Collect replies until the timeout window elapses.
    state: dict[int, str] = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([recv_sock], [], [], max(0.0, deadline - time.time()))
        if not ready:
            break
        try:
            packet, _ = recv_sock.recvfrom(65535)
        except OSError:
            continue
        parsed = _parse_reply(packet)
        if not parsed:
            continue
        rsrc_port, rdst_port, rflags = parsed
        if rdst_port != src_port or rsrc_port not in ports:
            continue
        if rflags & SYN and rflags & ACK:
            state[rsrc_port] = "open"          # SYN scan: SYN/ACK => open
        elif rflags & RST:
            state[rsrc_port] = "closed"        # RST => closed
    send_sock.close()
    recv_sock.close()

    # 3) Classify.
    results = []
    for port in ports:
        st = state.get(port)
        if st is None:
            # No reply: filtered for SYN; open|filtered for FIN/NULL/Xmas.
            st = "filtered" if scan_type == "syn" else "open|filtered"
        results.append({
            "port": port, "proto": "tcp", "scan": scan_type,
            "service": _get_service(port), "state": st,
        })
    results.sort(key=lambda r: r["port"])
    return results
