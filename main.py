import sys
import time
import logging
import argparse
import colorlog

from pgrab import grabber
from pgrab.ports import parse_ports, MIN_PORT, MAX_PORT


def parse_arguments() -> argparse.Namespace:
    """
    Parses the arguments passed to the script

    :return: The arguments
    :rtype: argparse.Namespace
    """

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
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ip/hostname", help="IP address or hostname")
    parser.add_argument(
        "-p", "--port",
        required=False,
        default=None,
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
        "--show-closed", action="store_true",
        help="Include closed/filtered ports in the output (default: only open ports are shown)",
    )
    parser.add_argument(
        "-o", "--output", type=argparse.FileType('w'), metavar='file_path',
        action='store', dest='output', help="Output file name",
    )
    parser.add_argument("-v", "--version", action="version", version="0.2")
    args = parser.parse_args()

    return args


def main() -> None:

    args = parse_arguments()
    ip_or_hostname = args.__dict__["ip/hostname"]
    path = args.path
    out = args.output

    try:
        ports = parse_ports(args.port)
    except ValueError as e:
        print(f"Invalid port specification: {e}")
        print(f"Ports must be between {MIN_PORT} and {MAX_PORT}.")
        sys.exit(1)

    # Set up the logging system with a ColorFormatter
    handler = logging.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)s%(reset)s %(message)s'))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # start time
    logging.info("started grab at " + time.ctime())
    logging.info(f"scanning {len(ports)} port(s) on {ip_or_hostname} "
                 f"(timeout={args.timeout}s, threads={args.threads})")

    # grab the banner(s)
    output = grabber.grabber(
        ip_or_hostname,
        ports,
        path=path,
        timeout=args.timeout,
        threads=args.threads,
        show_closed=args.show_closed,
    )

    # write to file
    if out:
        with open(out.name, "w") as f:
            f.write(output)

    print(output)

    # end time
    logging.info("finished grab at " + time.ctime())


if __name__ == "__main__":
    main()
