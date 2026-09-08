# PGrab
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab?ref=badge_shield)

PGrab is a banner grabber tool used to gather information about a remote server or device, specifically the banner, headers, and TLS certificate that are sent when a connection is made. It also works as a lightweight port scanner (TCP/UDP), with an optional raw-socket engine for stealth scans and firewall/IDS evasion.

## What's new in this version
- Scans **all 65,535 ports by default** when `-p` is omitted; `-p` accepts a single port, a list (`22,80,443`), a range (`1-1024`), `known`, or `all`.
- **Multi-threaded** scanning (`-t`, default 200) and a configurable `--timeout`.
- **TLS support**: for HTTPS ports (and any port that answers a TLS handshake) it reports the certificate subject/issuer/expiry/SAN and the negotiated TLS version and cipher.
- **STARTTLS** upgrade for SMTP, IMAP, POP3, FTP, LDAP, XMPP and PostgreSQL.
- **UDP scanning** (`--udp`) with DNS/NTP/SNMP probes, or **both** protocols at once (`--both`).
- **Firewall/IDS evasion**: timing templates (`-T 0..5`), random port order, per-probe jitter, source port, and HTTP User-Agent control; plus a raw-socket engine (root) for SYN/FIN/NULL/Xmas scans, IP fragmentation, and decoys.
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
python3 main.py example.com -p 80 --path /           # a single port
python3 main.py example.com -p 22,80,443             # multiple ports
python3 main.py example.com -p 1-1024               # a port range
python3 main.py example.com -p known                 # well-known ports only
python3 main.py example.com -p 53,123,161 --udp      # UDP scan
python3 main.py example.com -p known --both          # TCP + UDP in one run
sudo python3 main.py example.com -p known --scan-type syn   # SYN stealth scan (root)
```

For an overview of all commands use the following command:

```bash
python3 main.py -h
```

The output shown below are the latest supported commands.

```bash
usage: python main.py [-h] [-p PORT] [--path PATH] [--timeout TIMEOUT]
                      [-t THREADS] [--max-rate N] [--udp] [--both]
                      [--scan-type {connect,syn,fin,null,xmas}] [-T 0-5]
                      [--randomize-ports | --no-randomize-ports] [--jitter SEC]
                      [-g PORT] [--user-agent USER_AGENT] [--random-agent]
                      [--decoy IP1,ME,IP2] [--mtu N] [--frag] [--ttl N]
                      [--tls-detect | --no-tls-detect]
                      [--starttls | --no-starttls] [--show-closed]
                      [--format {json,csv}] [-o file_path] [-q] [-v]
                      ip/hostname

PGrab is a banner grabber tool used to gather information about a remote server or device.

positional arguments:
  ip/hostname           IP address or hostname

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port(s) to scan: '80', '80,443,8080', '1-1024',
                        'known', or 'all'. If omitted, ALL ports are scanned.
  --path PATH           Path to request on HTTP(S) ports (default: /)
  --timeout TIMEOUT     Per-port connection timeout in seconds (default: 1.0)
  -t, --threads N       Maximum number of concurrent scan threads (default: 200)
  --max-rate N          Cap new connections at N per second (0 = unlimited)
  --udp                 Scan UDP instead of TCP (best-effort)
  --both                Scan both TCP and UDP in one run and merge the results
  --scan-type {connect,syn,fin,null,xmas}
                        TCP technique. connect=full handshake (no root);
                        syn/fin/null/xmas=raw stealth scans (root required).
  --tls-detect / --no-tls-detect
                        On unknown open ports, probe for TLS (default: on)
  --starttls / --no-starttls
                        STARTTLS on SMTP/IMAP/POP3/FTP/LDAP/XMPP/Postgres
                        (default: on)
  --show-closed         Include closed/filtered ports in the output
  --format {json,csv}   Output format (default: json)
  -o file_path          Write results to this file (in addition to stdout)
  -q, --quiet           Suppress progress/log output on stderr
  -v, --version         show program's version number and exit

firewall / IDS evasion:
  -T, --timing 0-5      Timing template: 0 paranoid .. 3 normal .. 5 insane
  --randomize-ports     Scan ports in random order (default follows -T)
  --jitter SEC          Random 0..SEC delay before each probe
  -g, --source-port PORT
                        Bind probes to this source port (<1024 needs root)
  --user-agent STR      Custom HTTP User-Agent for banner grabs
  --random-agent        Pick a random real-browser User-Agent per run
  --decoy IP1,ME,IP2    [raw] Spoofed decoy source IPs; 'ME' = your real host
  --mtu N / --frag      [raw] Fragment probes (--frag = --mtu 8)
  --ttl N               [raw] IP TTL for crafted probes (default: 64)

Example: python3 main.py 192.168.0.1 -p 22 --path /
```

## Using the Docker Container

A typical run through Docker would look as follows:

```bash
docker run -it --rm pgrab example.com -p 80 --path /
```

**NOTE:** Banner grabbing and port scanning can be used for legitimate purposes, such as network auditing and security testing, but can also be used for malicious purposes, so use this script responsibly and with permission from the target owner. A few practical points: the raw stealth scans (`--scan-type syn|fin|null|xmas`) and their evasion options (fragmentation, decoys) require root and are IPv4-only; a full `connect()` scan is logged by the target application regardless of timing, so "stealth" here means the SYN engine plus low-and-slow timing, not invisibility; and `--udp` against all ports is slow, so prefer `-p known` or a small list for UDP.

**TODO:**
  * Add UDP response parsing for SNMP/DNS (currently the raw reply is returned).
  * Add idle (zombie) and ACK scan types.
  * Add STARTTLS for more protocols (NNTP, PostgreSQL post-auth edge cases).

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab?ref=badge_large)
