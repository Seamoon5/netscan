#!/usr/bin/env python3
"""
netscan - fast TCP port scanner for a /24 (or any IPv4 CIDR).

No external dependencies. Runs on Windows, Linux and macOS with Python 3.9+.

    python netscan.py                                  # 192.168.1.0/24, common ports
    python netscan.py --cidr 10.0.0.0/24 --ports web
    python netscan.py --ports 22,80,443,8000-8010
    python netscan.py --full --timeout 1.0
    python netscan.py --json -o results.json
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as futures
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Terminal setup
# ---------------------------------------------------------------------------

_ANSI = os.name != "nt"


class C:
    """ANSI colour codes. Empty strings when the terminal cannot render them."""

    RESET = "\033[0m" if _ANSI else ""
    BOLD = "\033[1m" if _ANSI else ""
    DIM = "\033[2m" if _ANSI else ""
    GREY = "\033[90m" if _ANSI else ""
    RED = "\033[31m" if _ANSI else ""
    GREEN = "\033[32m" if _ANSI else ""
    YELLOW = "\033[33m" if _ANSI else ""
    BLUE = "\033[34m" if _ANSI else ""
    CYAN = "\033[36m" if _ANSI else ""


def enable_vt() -> None:
    """Ask the Windows console to interpret ANSI escapes. Safe to call twice."""
    global _ANSI
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            _ANSI = False
            return
        ok = kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not ok:
            _ANSI = False
            for name in ("RESET", "BOLD", "DIM", "GREY", "RED", "GREEN", "YELLOW", "BLUE", "CYAN"):
                setattr(C, name, "")
    except Exception:
        _ANSI = False


# ASCII fallbacks so output stays readable on a plain Windows console.
BAR_FULL = "\u2588"
BAR_EMPTY = "\u2591"
if os.name == "nt" and not _ANSI:
    BAR_FULL, BAR_EMPTY = "#", "."

# ---------------------------------------------------------------------------
# Port presets
# ---------------------------------------------------------------------------

TOP_20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
          443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

COMMON = sorted(set(TOP_20 + [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995,
    1080, 1433, 1434, 1521, 2049, 2181, 2375, 3000, 3306, 3389, 5432, 5000, 5001,
    5060, 5900, 5984, 6379, 7000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9999,
]))

WEB = [80, 443, 3000, 4000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090]

DB = [1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001, 9042, 9200, 27017]

REMOTE = [22, 23, 135, 139, 445, 3389, 5900, 5985, 5986, 22, 5900, 5986]

PRESETS = {
    "top20": TOP_20,
    "common": COMMON,
    "web": WEB,
    "db": DB,
    "remote": sorted(set(REMOTE)),
    "full": list(range(1, 65536)),
}

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    515: "printer", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1434: "mssql-browse",
    1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "http-dev", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5000: "upnp", 5001: "commplex-link", 5060: "sip",
    5900: "vnc", 5901: "vnc-1", 5985: "winrm", 5986: "winrm-tls",
    5984: "couchdb", 6379: "redis", 7000: "cassandra", 7001: "cassandra",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "coyote",
    9200: "elasticsearch", 9999: "cisco-ccm", 27017: "mongodb",
}


def service(port: int) -> str:
    return SERVICES.get(port, "unknown")


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    """Turn a port spec into a sorted list of ints.

    Accepts preset names (top20, common, web, db, remote, full) and/or an
    explicit list: "22,80,443,8000-8010".
    """
    spec = spec.strip().lower()
    if spec == "full":
        return PRESETS["full"]

    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk in PRESETS:
            out.update(PRESETS[chunk])
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                raise ValueError(f"bad port range: {chunk!r}")
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"port range out of bounds: {chunk!r}")
            out.update(range(lo, hi + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                raise ValueError(f"bad port: {chunk!r}")
            if not 1 <= p <= 65535:
                raise ValueError(f"port out of bounds: {p}")
            out.add(p)

    if not out:
        raise ValueError("no ports selected")
    return sorted(out)


def parse_cidr(cidr: str, default: str) -> ipaddress.IPv4Network:
    """Parse the --cidr value, falling back to the machine's own /24."""
    if cidr is None:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("10.255.255.255", 1))  # no packets sent, just picks a route
            local_ip = probe.getsockname()[0]
            probe.close()
        except OSError:
            raise SystemExit(
                "Could not work out your local network. Pass it explicitly:\n"
                "  python netscan.py --cidr 192.168.1.0/24"
            )
        cidr = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise SystemExit(f"error: invalid network {cidr!r}: {exc}")
    if net.version != 4:
        raise SystemExit("Only IPv4 networks are supported.")
    return net


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def tcp_open(ip: str, port: int, timeout: float) -> bool:
    """True if a TCP connection to ip:port completes.

    Connection refused (port closed) and unreachable host both return False,
    which is exactly what we want - both mean "nothing listening here".
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, TimeoutError):
        return False
    except OSError:
        return False


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def scan_all(
    hosts: list[str],
    ports: list[int],
    timeout: float,
    workers: int,
    quiet: bool,
) -> tuple[dict[str, list[int]], float]:
    """Scan every (host, port) pair. Returns {ip: [open ports]} and elapsed seconds.

    Submissions are kept in a bounded window so a 65535-port run does not try to
    queue sixteen million futures at once.
    """
    results: dict[str, list[int]] = {}
    total = len(hosts) * len(ports)
    completed = 0
    t0 = time.perf_counter()
    interactive = sys.stdout.isatty()

    def draw(done: int) -> None:
        if quiet or not interactive:
            return
        frac = done / total if total else 1.0
        width = 28
        filled = int(frac * width)
        elapsed = time.perf_counter() - t0
        rate = done / elapsed if elapsed > 0 else 0
        eta = (total - done) / rate if rate > 0 else 0
        bar = BAR_FULL * filled + BAR_EMPTY * (width - filled)
        sys.stdout.write(
            f"\r  {C.CYAN}{bar}{C.RESET} {frac * 100:5.1f}%  "
            f"{done}/{total}  {C.GREY}{rate:6.0f}/s  ETA {eta:4.0f}s{C.RESET}"
        )
        sys.stdout.flush()

    queue: collections.deque[str] = collections.deque(hosts)
    inflight: dict[object, tuple[str, int]] = {}
    window = max(workers * 4, 64)

    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        def top_up() -> None:
            while queue and len(inflight) < window:
                ip = queue.popleft()
                for p in ports:
                    fut = pool.submit(tcp_open, ip, p, timeout)
                    inflight[fut] = (ip, p)

        top_up()
        while inflight:
            done_set, _ = futures.wait(
                list(inflight), return_when=futures.FIRST_COMPLETED
            )
            for fut in done_set:
                ip, p = inflight.pop(fut)
                completed += 1
                try:
                    if fut.result():
                        results.setdefault(ip, []).append(p)
                except Exception:
                    pass
            draw(completed)
            top_up()

    if not quiet and interactive:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    return results, time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def banner(net, n_hosts: int, n_ports: int) -> None:
    label = (
        f"netscan  \u00b7  {net.with_prefixlen}  \u00b7  "
        f"{n_hosts} hosts  \u00b7  {n_ports} ports  \u00b7  "
        f"{n_hosts * n_ports:,} checks"
    )
    width = len(label) + 2
    print()
    print(f"  {C.CYAN}\u256d{' ' * width}\u256e{C.RESET}")
    print(f"  {C.CYAN}\u2502{C.RESET} {C.BOLD}{label}{C.RESET}{C.CYAN} \u2502{C.RESET}")
    print(f"  {C.CYAN}\u2570{' ' * width}\u256f{C.RESET}")
    print()


def render(results: dict[str, list[int]], show_names: bool) -> list[dict]:
    """Print one block per live host. Also returns the structured records."""
    records: list[dict] = []
    name_worker: dict[str, str | None] = {}

    for ip in sorted(results, key=lambda s: ipaddress.ip_address(s)):
        open_ports = sorted(results[ip])
        if not open_ports:
            continue
        name = None
        if show_names and ip not in name_worker:
            name_worker[ip] = reverse_dns(ip)
        name = name_worker.get(ip)
        records.append({"ip": ip, "hostname": name, "open_ports": open_ports})

        head = f"  {C.GREEN}\u25b8{C.RESET} {C.BOLD}{ip}{C.RESET}"
        if name:
            head += f"  {C.GREY}{name}{C.RESET}"
        print(head)
        print(f"      " + "   ".join(f"{C.YELLOW}{p}{C.RESET}/{service(p)}" for p in open_ports))
        print()

    return records


def write_report(records: list[dict], elapsed: float, path: str | None, as_json: bool) -> None:
    if not path:
        return
    if as_json:
        payload = {
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "elapsed_seconds": round(elapsed, 2),
            "hosts": records,
            "total_open_ports": sum(len(r["open_ports"]) for r in records),
        }
        text = json.dumps(payload, indent=2)
    else:
        lines = [
            "netscan report",
            f"generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"elapsed   : {elapsed:.2f}s",
            f"hosts up  : {len(records)}",
            f"open ports: {sum(len(r['open_ports']) for r in records)}",
            "-" * 58,
        ]
        for r in records:
            label = f"{r['ip']}  {r['hostname']}" if r["hostname"] else r["ip"]
            lines.append(label)
            for p in r["open_ports"]:
                lines.append(f"    {p:<6}{service(p)}")
        text = "\n".join(lines)

    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"  {C.GREEN}\u2713{C.RESET} report written to {C.BOLD}{path}{C.RESET}")
    except OSError as exc:
        print(f"  {C.RED}\u2717{C.RESET} could not write {path}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="Fast TCP port scanner for a /24 network.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
port presets:
  top20    the 20 most common ports
  common   ~70 common ports (default)
  web      web server ports
  db       database ports
  remote   ssh / rdp / vnc / winrm / smb
  full     every port 1-65535 (slow)

examples:
  netscan.py
  netscan.py --cidr 192.168.1.0/24 --ports web
  netscan.py --ports 22,80,443,8000-8010
  netscan.py --full --timeout 1.0 -o full.txt
  netscan.py --json -o scan.json
""",
    )
    p.add_argument("--cidr", metavar="NET", help="network to scan, e.g. 192.168.1.0/24 (default: your own /24)")
    p.add_argument("--ports", default="common", metavar="SPEC", help="port preset or list, e.g. common, web, 22,80,443,8000-8010")
    p.add_argument("--timeout", type=float, default=0.4, metavar="SEC", help="per-connection timeout (default: 0.4)")
    p.add_argument("--workers", type=int, default=0, metavar="N", help="parallel connections (default: auto)")
    p.add_argument("--exclude", metavar="IP[,IP]", help="addresses to skip")
    p.add_argument("--no-names", action="store_true", help="skip reverse DNS lookups (faster)")
    p.add_argument("--quiet", "-q", action="store_true", help="no progress bar")
    p.add_argument("--json", action="store_true", help="write the report as JSON")
    p.add_argument("--output", "-o", metavar="FILE", help="save the report to FILE")
    p.add_argument("--version", action="version", version="netscan 1.0")
    return p


def main(argv: list[str] | None = None) -> int:
    enable_vt()
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    net = parse_cidr(args.cidr, default="")
    excluded = {s.strip() for s in (args.exclude or "").split(",") if s.strip()}
    hosts = [str(h) for h in net.hosts() if str(h) not in excluded]

    if not hosts:
        print("error: that network has no usable host addresses (a /32 holds only one)", file=sys.stderr)
        return 2

    workers = args.workers if args.workers > 0 else min(512, (os.cpu_count() or 4) * 64)
    workers = max(8, min(workers, 2000))

    if len(ports) > 1000 and not args.quiet:
        print(f"  {C.YELLOW}note{C.RESET} {len(ports):,} ports x {len(hosts)} hosts "
              f"= {len(hosts) * len(ports):,} checks. This will take a while.")

    banner(net, len(hosts), len(ports))

    try:
        results, elapsed = scan_all(
            hosts, ports, args.timeout, workers, quiet=args.quiet or len(hosts) * len(ports) > 50000
        )
    except KeyboardInterrupt:
        print("\n  interrupted.")
        return 130

    records = render(results, show_names=not args.no_names)
    total_ports = sum(len(r["open_ports"]) for r in records)

    print(f"  {C.GREY}{'-' * 58}{C.RESET}")
    print(f"  {C.BOLD}{len(records)}{C.RESET} host(s) up  \u00b7  "
          f"{C.BOLD}{total_ports}{C.RESET} open port(s)  \u00b7  "
          f"{C.GREY}{elapsed:.1f}s{C.RESET}")
    print()

    write_report(records, elapsed, args.output, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
