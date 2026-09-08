# PGrab
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab?ref=badge_shield)

PGrab is a banner grabber tool used to gather information about a remote server or device, specifically the banner, headers, and TLS certificate that are sent when a connection is made. It also works as a lightweight port scanner (TCP/UDP), with an optional raw-socket engine for stealth scans and firewall/IDS evasion.

## What's new in this version
- Scans **all 65,535 ports by default** when `-p` is omitted; `-p` accepts a single port, a list (`22,80,443`), a range (`1-1024`), `known`, or `all`.
- **Multi-threaded** scanning (`-t`) with a `-T 0..5` speed template and configurable `--timeout`.
- **TLS** (`--tls`, on by default): reports certificate subject/issuer/expiry/SAN and the TLS version/cipher for HTTPS and any TLS-speaking port, and does **STARTTLS** for SMTP, IMAP, POP3, FTP, LDAP, XMPP and PostgreSQL. `--no-tls` turns all of this off.
- **UDP scanning** (`--udp`) with parsed DNS/SNMP/NTP probes, or **both** protocols at once (`--both`).
- **One-flag evasion** (`--bypass`): randomizes port order, adds jitter, and uses a random real-browser User-Agent on web ports.
- **Raw stealth scans** (`--scan-type syn|fin|null|xmas|ack|idle`, root): half-open SYN, FIN/NULL/Xmas, ACK (firewall-rule mapping), and an experimental idle/zombie scan, plus fragmentation (`--mtu`), decoys (`--decoy`) and TTL control.
- HTTP bodies are de-chunked and gzip/deflate-decoded; output as JSON (default) or CSV.

## Installation Through PIP
To install dependencies, use the following command:

```bash
pip3 install -r requirements.txt
```

## Installation with Docker
This tool can also be used with [Docker](https://www.docker.com/). To set up the Docker environment, follow these steps (try using with sudo, if you get any error):

```bash
docker build -t pgrab:latest .
```

# Using PGrab
To run PGrab on a domain or IP, provide the domain/IP as an argument. Ports are chosen with `-p` (if omitted, all ports are scanned):

```bash
python3 main.py example.com                         # scan ALL TCP ports
python3 main.py example.com -p 80                     # a single port
python3 main.py example.com -p 22,80,443              # multiple ports
python3 main.py example.com -p known                  # well-known ports only
python3 main.py example.com -p known --both           # TCP + UDP in one run
python3 main.py example.com -p known --bypass         # firewall/IDS evasion
sudo python3 main.py example.com -p known --scan-type syn   # SYN stealth (root)
sudo python3 main.py example.com -p 1-1000 --scan-type ack  # map firewall rules
```

For an overview of all commands use the following command:

```bash
python3 main.py -h
```

The output shown below are the latest supported commands.

```bash
usage: python main.py [-h] [-p PORT] [--timeout TIMEOUT] [-t THREADS]
                      [--max-rate N] [--udp] [--both]
                      [--scan-type {connect,syn,fin,null,xmas,ack,idle}]
                      [--zombie IP] [--tls | --no-tls] [-T 0-5] [--bypass]
                      [-g PORT] [--decoy IP1,ME,IP2] [--mtu N]
                      [--ttl N] [--show-closed] [--format {json,csv}]
                      [-o file_path] [-q] [-v]
                      ip/hostname

positional arguments:
  ip/hostname           IP address or hostname

options:
  -h, --help            show this help message and exit
  -p, --port PORT       '80', '80,443,8080', '1-1024', 'known', or 'all'.
                        If omitted, ALL ports are scanned.
  --timeout TIMEOUT     Per-port connection timeout in seconds (default: 1.0)
  -t, --threads N       Maximum concurrent scan threads (default: 200)
  --max-rate N          Cap new connections at N per second (0 = unlimited)
  --udp                 Scan UDP instead of TCP (best-effort)
  --both                Scan both TCP and UDP in one run and merge the results
  --scan-type {connect,syn,fin,null,xmas,ack,idle}
                        connect=no root; the rest are raw (root). ack maps
                        firewall rules; idle needs --zombie.
  --zombie IP           Zombie host for --scan-type idle (incremental IP ID)
  --tls / --no-tls      TLS detection + STARTTLS grabbing (default: on)
  -T, --timing 0-5      Speed: 0 slowest .. 3 normal .. 5 fastest (default: 3)
  --bypass              Firewall/IDS evasion: randomize ports + jitter +
                        random real-browser User-Agent on web ports
  -g, --source-port N   Bind probes to this source port (<1024 needs root)
  --decoy IP1,ME,IP2    [raw] Spoofed decoy source IPs; ME = your real host
  --mtu N               [raw] Split probes into N-byte IP fragments (N is a multiple of 8)
  --ttl N               [raw] IP TTL for crafted probes (default: 64)
  --show-closed         Include closed/filtered ports in the output
  --format {json,csv}   Output format (default: json)
  -o file_path          Write results to this file (in addition to stdout)
  -q, --quiet           Suppress progress/log output on stderr
  -v, --version         show program's version number and exit

Example: python3 main.py 192.168.0.1 -p 22
```

## Using the Docker Container

A typical run through Docker would look as follows:

```bash
docker run -it --rm pgrab example.com -p 80
```

**NOTE:** Banner grabbing and port scanning can be used for legitimate purposes, such as network auditing and security testing, but can also be used for malicious purposes, so use this script responsibly and with permission from the target owner. A few practical points: raw scans (`--scan-type syn|fin|null|xmas|ack|idle`) and their evasion options require root and are IPv4-only; a full `connect()` scan is logged by the target application regardless of timing, so evasion here means the raw engine plus `--bypass`, not invisibility; and `--udp` against all ports is slow, so prefer `-p known` for UDP. The **idle/zombie** scan is experimental and unvalidated: it needs a zombie host with a predictable, globally incremental IP ID (rare on modern systems) — confirm against a known-state target before trusting its output.

**TODO:**
  * Broaden DNS/SNMP response parsing (currently version.bind and sysDescr).
  * Validate the idle scan and add IP-ID predictability checks for the zombie.
  * Add STARTTLS for more protocols (NNTP, IMAP/POP3 edge cases).

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab?ref=badge_large)
