# PGrab

PGrab is a banner grabber / port scanner: it gathers the banner, headers, and
TLS certificate a host exposes, with a connect() engine plus a raw-socket
stealth engine and firewall/IDS evasion options.

## Requirements
```bash
pip3 install -r requirements.txt   # colorlog, cryptography (brotli optional)
```
Raw scans use only the standard library but need root / CAP_NET_RAW.

## Usage
```bash
python3 main.py example.com                         # connect scan, all TCP ports
python3 main.py example.com -p 22,80,443            # specific ports
python3 main.py example.com -p 53,123,161 --udp     # UDP
python3 main.py example.com -p known --both         # TCP + UDP in one run
sudo python3 main.py example.com -p known --scan-type syn        # SYN stealth
sudo python3 main.py example.com -p 1-1024 --scan-type syn --frag --decoy 1.2.3.4,ME
python3 main.py example.com -p known -T 1 --random-agent -g 53   # quiet + evasive
```

```
scan technique:
  --scan-type {connect,syn,fin,null,xmas}   connect=no root; others=raw (root)
  --udp                                     UDP instead of TCP
  --both                                    TCP + UDP in one run (merged output)

firewall / IDS evasion:
  -T, --timing 0-5      0 paranoid .. 3 normal (default) .. 5 insane
  --randomize-ports     scan ports in random order (default follows -T)
  --jitter SEC          random 0..SEC delay before each probe
  -g, --source-port N   bind probes to source port N (e.g. 53/443; <1024 root)
  --user-agent STR      custom HTTP User-Agent
  --random-agent        random real-browser User-Agent
  --decoy IP1,ME,IP2    [raw] spoofed decoy sources; ME = your real host
  --mtu N / --frag      [raw] fragment probes (--frag = --mtu 8)
  --ttl N               [raw] IP TTL of crafted probes
```

## Evasion — read this before relying on it
- **A connect() scan cannot do packet-level evasion.** Fragmentation, decoys,
  and SYN half-open all require crafting packets, which is why they live in the
  raw engine (`--scan-type syn|fin|null|xmas`, root). On the connect engine only
  timing, port randomization, source port, and User-Agent apply.
- **Evading network IDS is not evading the host.** A completed connect() +
  HTTP GET is fully logged by the target application regardless of timing tricks.
  Stealth here means the SYN engine (no app-layer session) plus low-and-slow
  timing, not invisibility.
- **Kernel RST interference (raw):** when the target's SYN/ACK arrives for a
  connection your kernel didn't open, the kernel sends an RST that can reset the
  target early. Drop it during real scans, e.g.:
  `iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <you> -j DROP`
- **FIN/NULL/Xmas** report `closed` only on RFC-793-compliant stacks; Windows
  RSTs open ports too, so all show `closed`.
- The raw engine is IPv4-only.

## Tested vs. not (be aware)
- **Live-tested** (loopback / mocks): SYN + FIN + fragmented-SYN + decoy raw
  scans; SMTP/PostgreSQL/LDAP/XMPP STARTTLS; TLS auto-detect + plaintext
  fallback; UDP open/closed; chunked/gzip decode; User-Agent rotation; timing.
- **Not tested against production services in this build**: NULL/Xmas semantics
  on a real RFC-793 host, IMAP/POP3/FTP STARTTLS against real daemons, SNMP/NTP
  UDP replies from real servers, decoys/fragmentation traversing a real firewall.
  Validate in your own lab before an engagement.

## TODO
- SNMP/DNS UDP response parsing (currently the raw reply is returned).
- Idle (zombie) scan; ACK scan for firewall-rule mapping.
- STARTTLS for PostgreSQL after auth negotiation edge cases.

## Authorization
Scanning or evading controls on hosts you do not own or lack written
authorization to test may violate law or acceptable-use policy. Only use against
targets you are explicitly authorized to assess.
