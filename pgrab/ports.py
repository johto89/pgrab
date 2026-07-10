"""
Port list definitions and port-argument parsing for PGrab.
"""

from __future__ import annotations

# A curated list of well-known / commonly probed ports and their typical service name.
# Used when the user passes -p known (or --well-known).
WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    515: "printer", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt",
    3000: "http-dev", 3128: "http-proxy", 3306: "mysql", 3389: "rdp",
    3690: "svn", 5000: "upnp", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch-node",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    50000: "sap",
}

MIN_PORT = 1
MAX_PORT = 65535


def _validate(port: int) -> int:
    if not (MIN_PORT <= port <= MAX_PORT):
        raise ValueError(f"Port {port} is out of range ({MIN_PORT}-{MAX_PORT})")
    return port


def parse_ports(port_arg: str | None) -> list[int]:
    """
    Parses the -p/--port argument into a sorted list of unique port numbers.

    Supported formats:
      None / "all"        -> every port, 1-65535 (default behaviour)
      "known" / "well-known" / "common" -> curated well-known port list
      "80"                 -> a single port
      "80,443,8080"         -> a comma separated list of ports
      "1-1024"              -> an inclusive port range
      "22,80,1000-1010"      -> ranges and single ports can be mixed

    :param port_arg: the raw string passed via -p/--port (or None)
    :return: sorted list of unique port numbers
    """

    if port_arg is None or port_arg.strip().lower() == "all":
        return list(range(MIN_PORT, MAX_PORT + 1))

    if port_arg.strip().lower() in ("known", "well-known", "well_known", "common"):
        return sorted(WELL_KNOWN_PORTS.keys())

    ports: set[int] = set()
    for chunk in port_arg.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                ports.add(_validate(p))
        else:
            ports.add(_validate(int(chunk)))

    if not ports:
        raise ValueError("No valid ports were parsed from the -p/--port argument")

    return sorted(ports)
