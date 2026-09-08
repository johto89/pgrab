import csv
import io
import json
import logging
import os
import random
import sys
import time
import argparse

import colorlog

from pgrab import grabber, rawscan
from pgrab.ports import parse_ports, MIN_PORT, MAX_PORT

VERSION = "0.5"

# Timing templates (nmap-style). Each sets defaults the user can still override.
# (threads, max_rate, timeout, jitter, randomize)
TIMING = {
    0: dict(threads=1,   max_rate=0.1, timeout=5.0, jitter=2.0, randomize=True),   # paranoid
    1: dict(threads=1,   max_rate=1.0, timeout=4.0, jitter=1.0, randomize=True),   # sneaky
    2: dict(threads=10,  max_rate=10,  timeout=3.0, jitter=0.3, randomize=True),   # polite
    3: dict(threads=200, max_rate=0,   timeout=1.0, jitter=0.0, randomize=False),  # normal
    4: dict(threads=400, max_rate=0,   timeout=0.7, jitter=0.0, randomize=False),  # aggressive
    5: dict(threads=800, max_rate=0,   timeout=0.4, jitter=0.0, randomize=False),  # insane
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "curl/8.5.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]



def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="PGrab is a banner grabber tool used to gather information about a remote server or device.",
        epilog=(
            "Examples:\n"
            "  python3 main.py example.com                 # scan ALL ports (1-65535, default)\n"
            "  python3 main.py example.com -p 80            # scan a single port\n"
            "  python3 main.py example.com -p 22,80,443      # scan multiple ports\n"
            "  python3 main.py example.com -p 1-1024          # scan a port range\n"
            "  python3 main.py example.com -p known             # scan well-known ports only\n"
            "  python3 main.py example.com -p known --max-rate 50 -o out.csv --format csv\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ip/hostname", help="IP address or hostname")
    parser.add_argument(
        "-p", "--port", default=None,
        help=(
            "Port(s) to scan. Accepts a single port ('80'), a comma-separated list "
            "('80,443,8080'), a range ('1-1024'), or the keyword 'known' for a curated "
            "well-known port list. If omitted, ALL ports (1-65535) are scanned."
        ),
    )
    parser.add_argument("--path", default="/", help="Path to request on HTTP(S) ports (default: /)")
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=200,
        help="Maximum number of concurrent scan threads (default: 200)",
    )
    parser.add_argument(
        "--max-rate", type=float, default=0.0, metavar="N",
        help="Cap new connections at N per second (stealth/rate-limit; 0 = unlimited)",
    )
    parser.add_argument(
        "--udp", action="store_true",
        help="Scan UDP instead of TCP (best-effort; states may be open|filtered)",
    )
    parser.add_argument(
        "--both", action="store_true",
        help="Scan both TCP and UDP in one run and merge the results",
    )
    parser.add_argument(
        "--scan-type", choices=("connect", "syn", "fin", "null", "xmas"),
        default="connect",
        help="TCP scan technique. connect=full handshake (no root). "
             "syn/fin/null/xmas=raw stealth scans (root required).",
    )
    scan_evasion = parser.add_argument_group("firewall / IDS evasion")
    scan_evasion.add_argument(
        "-T", "--timing", type=int, choices=range(0, 6), metavar="0-5", default=3,
        help="Timing template: 0 paranoid .. 3 normal .. 5 insane (default: 3)",
    )
    scan_evasion.add_argument(
        "--randomize-ports", action=argparse.BooleanOptionalAction, default=None,
        help="Scan ports in random order (default follows -T template)",
    )
    scan_evasion.add_argument(
        "--jitter", type=float, default=None, metavar="SEC",
        help="Random 0..SEC delay before each probe (default follows -T)",
    )
    scan_evasion.add_argument(
        "-g", "--source-port", type=int, default=0, metavar="PORT",
        help="Bind probes to this source port (e.g. 53, 443). <1024 needs root.",
    )
    scan_evasion.add_argument(
        "--user-agent", default=None,
        help="Custom HTTP User-Agent for banner grabs (default: pgrab)",
    )
    scan_evasion.add_argument(
        "--random-agent", action="store_true",
        help="Pick a random real-browser User-Agent per run",
    )
    scan_evasion.add_argument(
        "--decoy", default=None, metavar="IP1,ME,IP2",
        help="[raw] Spoofed decoy source IPs; 'ME' marks your real position",
    )
    scan_evasion.add_argument(
        "--mtu", type=int, default=0, metavar="N",
        help="[raw] Fragment probes to N-byte IP payloads (multiple of 8)",
    )
    scan_evasion.add_argument(
        "--frag", action="store_true",
        help="[raw] Shorthand for --mtu 8 (tiny fragments)",
    )
    scan_evasion.add_argument(
        "--ttl", type=int, default=64, metavar="N",
        help="[raw] IP TTL for crafted probes (default: 64)",
    )
    parser.add_argument(
        "--tls-detect", action=argparse.BooleanOptionalAction, default=True,
        help="On unknown open ports, probe for TLS before plaintext (default: on)",
    )
    parser.add_argument(
        "--starttls", action=argparse.BooleanOptionalAction, default=True,
        help="Attempt STARTTLS on SMTP/IMAP/POP3/FTP/LDAP/XMPP/Postgres (default: on)",
    )
    parser.add_argument(
        "--show-closed", action="store_true",
        help="Include closed/filtered ports in the output (default: only open ports)",
    )
    parser.add_argument(
        "--format", choices=("json", "csv"), default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "-o", "--output", metavar="file_path", default=None,
        help="Write results to this file (in addition to stdout)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress/log output on stderr",
    )
    parser.add_argument("-v", "--version", action="version", version=VERSION)
    return parser.parse_args()


def _setup_logging(quiet: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(colorlog.ColoredFormatter("%(log_color)s%(levelname)s%(reset)s %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.CRITICAL if quiet else logging.INFO)


def _to_csv(data: dict) -> str:
    """Flatten the results list into CSV; falls back to a summary if no results."""
    results = data.get("results", [])
    buf = io.StringIO()
    fields = [
        "port", "proto", "scan", "service", "state", "status_line", "server",
        "powered_by", "content_type", "tls_version", "cipher", "cert_subject",
        "cert_issuer", "cert_not_after", "cert_expired", "starttls", "banner",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in results:
        writer.writerow({k: row.get(k, "") for k in fields})
    return buf.getvalue()


def _apply_timing(args) -> dict:
    """Merge the -T template with any explicit overrides the user passed."""
    tpl = TIMING[args.timing]
    threads = args.threads if args.threads != 200 else tpl["threads"]
    max_rate = args.max_rate if args.max_rate else tpl["max_rate"]
    timeout = args.timeout if args.timeout != 1.0 else tpl["timeout"]
    jitter = args.jitter if args.jitter is not None else tpl["jitter"]
    randomize = args.randomize_ports if args.randomize_ports is not None else tpl["randomize"]
    return dict(threads=threads, max_rate=max_rate, timeout=timeout,
                jitter=jitter, randomize=randomize)


def _run_raw(args, ip_or_hostname, ports, progress) -> dict:
    """Route a stealth scan-type to the raw-socket engine."""
    if getattr(os, "geteuid", lambda: 1)() != 0:
        print(f"error: --scan-type {args.scan_type} needs root (raw sockets).",
              file=sys.stderr)
        sys.exit(1)
    import socket as _s
    try:
        resolved_ip = _s.gethostbyname(ip_or_hostname)
    except _s.gaierror as e:
        return {"target": ip_or_hostname, "error": f"Could not resolve host: {e}"}

    t = _apply_timing(args)
    mtu = 8 if args.frag else args.mtu
    decoys = args.decoy.split(",") if args.decoy else None
    results = rawscan.raw_scan(
        resolved_ip, ports, scan_type=args.scan_type, timeout=t["timeout"],
        src_port=args.source_port, ttl=args.ttl, decoys=decoys, mtu=mtu,
        max_rate=t["max_rate"], jitter=t["jitter"], randomize=t["randomize"],
        progress=progress,
    )
    open_states = ("open", "open|filtered")
    if not args.show_closed:
        results = [r for r in results if r["state"] in open_states]
    return {
        "ip": ip_or_hostname, "resolved_ip": resolved_ip, "protocol": "tcp",
        "scan_type": args.scan_type, "ports_scanned": len(ports),
        "open_ports_found": sum(1 for r in results if r["state"] in open_states),
        "results": results,
    }


def _scan_tcp(args, host, ports, user_agent, t, progress) -> dict:
    """Run a TCP scan (connect or raw depending on --scan-type)."""
    if args.scan_type != "connect":
        return _run_raw(args, host, ports, progress)
    return grabber.run_scan(
        host, ports, path=args.path, timeout=t["timeout"], threads=t["threads"],
        show_closed=args.show_closed, max_rate=t["max_rate"], protocol="tcp",
        tls_detect=args.tls_detect, starttls=args.starttls,
        source_port=args.source_port, user_agent=user_agent, jitter=t["jitter"],
        randomize=t["randomize"], progress=progress,
    )


def _scan_udp(args, host, ports, t, progress) -> dict:
    """Run a UDP scan."""
    return grabber.run_scan(
        host, ports, timeout=t["timeout"], threads=t["threads"],
        show_closed=args.show_closed, max_rate=t["max_rate"], protocol="udp",
        jitter=t["jitter"], randomize=t["randomize"], progress=progress,
    )


def _merge(tcp_data: dict, udp_data: dict) -> dict:
    """Merge a TCP and a UDP scan of the same target into one result dict."""
    merged = dict(tcp_data)
    merged["protocol"] = "tcp+udp"
    results = tcp_data.get("results", []) + udp_data.get("results", [])
    results.sort(key=lambda r: (r["port"], r.get("proto", "")))
    open_states = ("open", "open|filtered")
    merged["results"] = results
    merged["ports_scanned"] = tcp_data.get("ports_scanned", 0) + udp_data.get("ports_scanned", 0)
    merged["open_ports_found"] = sum(1 for r in results if r["state"] in open_states)
    errs = [d["error"] for d in (tcp_data, udp_data) if d.get("error")]
    if errs:
        merged["errors"] = errs
    return merged


def main() -> None:
    args = parse_arguments()
    ip_or_hostname = args.__dict__["ip/hostname"]

    try:
        ports = parse_ports(args.port)
    except ValueError as e:
        print(f"Invalid port specification: {e}", file=sys.stderr)
        print(f"Ports must be between {MIN_PORT} and {MAX_PORT}.", file=sys.stderr)
        sys.exit(1)

    _setup_logging(args.quiet)

    # Resolve User-Agent for evasion.
    user_agent = args.user_agent or (random.choice(USER_AGENTS) if args.random_agent else "pgrab")
    t = _apply_timing(args)

    mode = "tcp+udp" if args.both else ("udp" if args.udp else args.scan_type)
    logging.info("started grab at " + time.ctime())
    logging.info(
        f"scanning {len(ports)} port(s) on {ip_or_hostname} "
        f"[mode={mode} T{args.timing} threads={t['threads']} "
        f"rate={t['max_rate'] or 'unlimited'} jitter={t['jitter']}]"
    )

    last_pct = [-1]

    def progress(done: int, total: int) -> None:
        if args.quiet or total < 500:
            return
        pct = done * 100 // total
        if pct != last_pct[0]:
            last_pct[0] = pct
            print(f"\rprogress: {pct}% ({done}/{total})", end="", file=sys.stderr, flush=True)

    try:
        if args.both:
            if not args.quiet:
                logging.info("scanning TCP...")
            tcp_data = _scan_tcp(args, ip_or_hostname, ports, user_agent, t, progress)
            if not args.quiet:
                logging.info("scanning UDP...")
            udp_data = _scan_udp(args, ip_or_hostname, ports, t, progress)
            data = _merge(tcp_data, udp_data)
        elif args.udp:
            data = _scan_udp(args, ip_or_hostname, ports, t, progress)
        else:
            data = _scan_tcp(args, ip_or_hostname, ports, user_agent, t, progress)
    except KeyboardInterrupt:
        print("\ninterrupted; partial results discarded.", file=sys.stderr)
        sys.exit(130)

    if not args.quiet and len(ports) >= 500:
        print("", file=sys.stderr)  # newline after progress line

    output = _to_csv(data) if args.format == "csv" else json.dumps(data, indent=2)

    if args.output:
        with open(args.output, "w", newline="") as f:
            f.write(output)
        logging.info(f"results written to {args.output}")

    print(output)
    logging.info("finished grab at " + time.ctime())


if __name__ == "__main__":
    main()
