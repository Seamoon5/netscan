# netscan

A fast TCP port scanner for your local network. Point it at a `/24` (or any
IPv4 CIDR), it finds every host with something listening and tells you which
ports and which service.

No dependencies — just Python 3.9 or newer. Built for Salman, Oct 2026.

## Why it exists

To find out what is actually on your network. Which boxes are up, what they
are running, whether something is listening that you forgot about, and whether
a port you expected to be closed is not.

## Quick start

Double-click `scan.bat`, or from a terminal:

```
python netscan.py
```

With no arguments it works out your own network automatically and scans your
`/24` for the ~70 most common ports.

## Options

| Flag | Meaning |
|---|---|
| `--cidr NET` | Network to scan, e.g. `192.168.1.0/24`. Default: your own `/24`. |
| `--ports SPEC` | Which ports. Default `common`. See presets below. |
| `--timeout SEC` | Per-connection timeout. Default `0.4`. Raise it for slow links. |
| `--workers N` | Parallel connections. Default: auto (usually 256–512). |
| `--exclude IP,IP` | Skip these addresses. |
| `--no-names` | Skip reverse DNS lookups. Faster on big networks. |
| `--quiet` / `-q` | No progress bar (good for scripts). |
| `--json` | Write the report as JSON. |
| `--output FILE` / `-o` | Save the report to a file. |
| `--version` | Print the version. |

### Port presets

| Preset | What it covers |
|---|---|
| `top20` | The 20 most common ports. Fastest useful scan. |
| `common` | ~70 common ports. **Default.** |
| `web` | 80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000 … |
| `db` | MySQL, Postgres, MSSQL, Oracle, Redis, Mongo, Cassandra, CouchDB. |
| `remote` | SSH, Telnet, RPC, NetBIOS, SMB, RDP, VNC, WinRM. |
| `full` | Every port 1–65535. Slow. |

### Custom ports

Mix presets with explicit ports and ranges:

```
--ports web
--ports 22,80,443
--ports 8000-8010
--ports common,9000-9010
```

## Examples

```bash
# my own network, common ports
python netscan.py

# specific network, web ports only
python netscan.py --cidr 192.168.1.0/24 --ports web

# find SSH and RDP machines on the network
python netscan.py --ports remote

# everything, carefully, saved to a file
python netscan.py --full --timeout 1.0 -o full-report.txt

# machine-readable output for another tool
python netscan.py --json -o scan.json
```

## Example output

```
  ╭ netscan  ·  192.168.1.0/24  ·  254 hosts  ·  70 ports  ·  17,780 checks ╮
  │                                                                    │
  ╰                                                                    ╯

  ▸ 192.168.1.1   openrouter.lan
      22/ssh   53/dns   80/http   443/https   8080/http-proxy

  ▸ 192.168.1.14  DESKTOP-ABCD.local
      135/msrpc   139/netbios-ssn   445/microsoft-ds   3389/rdp

  ▸ 192.168.1.27  pi.lan
      22/ssh   548/vsftpd   5900/vnc

  ----------------------------------------------------------
  3 host(s) up  ·  11 open port(s)  ·  12.4s
```

## Reading the output

- `▸ IP hostname` — a host with at least one open port. The name after the IP is
  the reverse-DNS name; if it shows nothing, the machine has no DNS record.
- `port/service` — `3389/rdp` means port 3389 is open and is normally Remote
  Desktop. Names are educated guesses from the port number, not proof — confirm
  the service before you rely on it.
- Only hosts with **something open** are printed. A host that is up but has all
  closed ports does not appear, because "a computer with no open ports" is not
  a useful scan result.

## How fast is it?

Measured on this machine (WSL2, Python 3.14):

| Scan | Time |
|---|---|
| 1 host × all 65,535 ports | 47 s |
| 254 hosts × 63 ports (a full `/24`) | 27 s |
| 254 hosts × 14 ports | 6.5 s |

Roughly 600 checks/second. A dead host costs one full timeout per port, so a
sparse `/24` on a fast LAN takes longer than a busy one.

## Troubleshooting

**Windows Firewall pops up a prompt.** Expected the first time. Allow Python on
private networks, or the scan will report everything as closed.

**Everything shows closed but you know a service is up.** Two usual causes:
Windows Firewall is blocking inbound connections, or the service is bound to
`127.0.0.1` only (some apps do this) and is therefore not reachable from other
machines.

**It says 0 hosts up on a network you know has devices.** Try
`--timeout 1.0`. The default 0.4 s is tuned for a local LAN and may be too
aggressive over Wi-Fi or a slow link.

**"Python was not found" from the .bat.** Install Python from python.org and
tick **Add python.exe to PATH**.

**Ctrl+C mid-scan.** Fine — it stops and prints what it found so far.

## Notes

- This finds **open TCP ports only**. A UDP service will not appear, because
  probing UDP reliably is a different and much noisier job. If you need UDP,
  reach for `nmap -sU`.
- Scanning a network you do not own or administer without permission is
  illegal in most jurisdictions, including under the UK Computer Misuse Act and
  the US Computer Fraud and Abuse Act. Scan your own gear.
- A firewall or IDS on the network can slow scans or drop probes, which shows up
  as missed ports. That is the network working as intended, not a bug.

## Version history

| Version | Date | Change |
|---|---|---|
| 1.0 | Oct 2026 | First release. Threaded scanner, port presets and ranges, progress bar, JSON and text reports, reverse DNS, exclude list. |
