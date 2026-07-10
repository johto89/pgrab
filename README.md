# PGrab
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab?ref=badge_shield)

PGrab is a banner grabber tool used to gather information about a remote server or device, specifically the banner or header information that is sent when a connection is made.

## What's new in this version
- **Default behaviour is now to scan ALL 65,535 ports** when `-p`/`--port` is omitted (previously `-p` was required and only ports 80/22 were supported).
- **Flexible port selection**:
  - Single port: `-p 80`
  - Multiple ports: `-p 22,80,443`
  - Port range: `-p 1-1024`
  - Mixed: `-p 22,80,1000-1010`
  - Well-known ports only: `-p known` (curated list of ~70 commonly probed service ports)
  - All ports (explicit): `-p all`
- **Multi-threaded scanning** (`-t/--threads`, default 200) so scanning thousands of ports is practical.
- **Generic banner grabbing** for any port/service (not just HTTP and SSH) — reads greeting banners such as FTP, SMTP, POP3, IMAP, etc.
- **HTTPS/TLS support** — for 443/8443 PGrab performs a TLS handshake and reports the certificate subject/issuer/expiry and negotiated TLS version/cipher.
- **Open/closed/filtered state detection**, with `--show-closed` to include non-open ports in the output.
- **Configurable timeout** (`--timeout`) per port connection.

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

## Scan all ports (default)
```bash
python3 main.py example.com
```

## Scan a single port
```bash
python3 main.py example.com -p 80 --path /
```

## Scan multiple ports
```bash
python3 main.py example.com -p 22,80,443,8080
```

## Scan a port range
```bash
python3 main.py example.com -p 1-1024
```

## Scan only well-known ports
```bash
python3 main.py example.com -p known
```

For an overview of all commands use the following command:

```bash
python3 main.py -h
```

The output shown below are the latest supported commands.

```bash
usage: python main.py [-h] [-p PORT] [--path PATH] [--timeout TIMEOUT]
                       [-t THREADS] [--show-closed] [-o file_path] [-v]
                       ip/hostname

PGrab is a banner grabber tool used to gather information about a remote server or device.

positional arguments:
  ip/hostname           IP address or hostname

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port(s) to scan. Accepts a single port ('80'), a
                        comma-separated list ('80,443,8080'), a range
                        ('1-1024'), or the keyword 'known' for a curated
                        well-known port list. If omitted, ALL ports
                        (1-65535) are scanned.
  --path PATH           Path to request on HTTP(S) ports (default: /)
  --timeout TIMEOUT     Per-port connection timeout in seconds (default: 1.0)
  -t THREADS, --threads THREADS
                        Maximum number of concurrent scan threads (default: 200)
  --show-closed         Include closed/filtered ports in the output
                        (default: only open ports are shown)
  -o file_path, --output file_path
                        Output file name
  -v, --version         show program's version number and exit

Examples:
  python3 main.py example.com                    # scan ALL ports (1-65535, default)
  python3 main.py example.com -p 80               # scan a single port
  python3 main.py example.com -p 22,80,443         # scan multiple ports
  python3 main.py example.com -p 1-1024              # scan a port range
  python3 main.py example.com -p known                # scan well-known ports only
```

## Example output
```bash
python3 main.py example.com -p 80,443,22 --timeout 1.5
```
```json
{
  "domain": "example.com",
  "resolved_ip": "93.184.216.34",
  "ports_scanned": 3,
  "open_ports_found": 2,
  "results": [
    {
      "port": 80,
      "service": "http",
      "state": "open",
      "status": "success",
      "status_line": "HTTP/1.1 200 OK",
      "headers": ["..."],
      "body_preview": "..."
    },
    {
      "port": 443,
      "service": "https",
      "state": "open",
      "status": "success",
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "cert_subject": {"commonName": "example.com"},
      "cert_issuer": {"organizationName": "..."},
      "cert_not_after": "..."
    }
  ]
}
```

## Using the Docker Container

A typical run through Docker would look as follows:

```bash
docker run -it --rm pgrab example.com -p 80 --path /
```

**NOTE:** Banner grabbing can be used for legitimate purposes, such as network auditing and security testing, but can also be used for malicious purposes, so use this script responsibly and with permission from the target owner. Scanning all 65,535 ports against a host you do not own or have explicit authorization to test may violate laws or acceptable-use policies — always get permission first, and consider narrowing scope with `-p known` or a specific range for routine checks.

**TODO:**
  * Add UDP scanning support
  * Add banner grabbing for more protocols (DNS, SNMP, ...)
  * Add rate limiting / stealth timing options

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fshivamsaraswat%2Fpgrab?ref=badge_large)
