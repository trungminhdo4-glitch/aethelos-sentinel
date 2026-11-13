"""Netz: Link, IPv4-Adresse (DHCP), DNS-Aufloesung, optional HTTPS. Ohne iproute2: /sys/class/net + ioctl."""
from __future__ import annotations

import concurrent.futures
import fcntl
import os
import socket
import struct
import time
import urllib.request

from sentinel import config
from sentinel.model import Finding, Severity

CHECK = "network"
DNS_ATTEMPTS = 3
DNS_TIMEOUT = 5.0
SIOCGIFADDR = 0x8915


def ifaddr(name: str) -> str | None:
    """IPv4-Adresse eines Interfaces oder None."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", name[:15].encode()))
        except OSError:
            return None
    return socket.inet_ntoa(res[20:24])


def _resolve(host: str):
    return socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)


def _fetch(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status


def _read(p: str) -> str:
    try:
        with open(p) as f:
            return f.read().strip()
    except OSError:
        return ""


def check(net_dir="/sys/class/net", ifaddr=ifaddr, resolve=_resolve, dns_name=config.DNS_NAME,
          https_url=config.HTTPS_URL, fetch=_fetch, sleep=time.sleep, dns_timeout=DNS_TIMEOUT) -> list[Finding]:
    out: list[Finding] = []
    ifaces = sorted(n for n in os.listdir(net_dir) if n != "lo")
    up = [n for n in ifaces if _read(os.path.join(net_dir, n, "operstate")) == "up"]
    if not up:
        states = ", ".join(f"{n}={_read(os.path.join(net_dir, n, 'operstate'))}" for n in ifaces) or "keine Interfaces"
        return [Finding(CHECK, Severity.WARN, "link", f"kein Interface mit Link ({states})")]
    addrs = {n: ifaddr(n) for n in up}
    if not any(addrs.values()):
        out.append(Finding(CHECK, Severity.WARN, "ipv4", f"keine IPv4-Adresse auf {', '.join(up)} (DHCP?)"))
    last = None
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=DNS_ATTEMPTS)
    for i in range(DNS_ATTEMPTS):
        try:
            pool.submit(resolve, dns_name).result(timeout=dns_timeout)
            last = None
            break
        except concurrent.futures.TimeoutError:
            last = f"Zeitlimit {dns_timeout}s"
        except OSError as e:
            last = e
        if i < DNS_ATTEMPTS - 1:
            sleep(2)
    pool.shutdown(wait=False, cancel_futures=True)       # haengende Abfrage nicht abwarten
    if last is not None:
        out.append(Finding(CHECK, Severity.WARN, f"dns:{dns_name}",
                           f"Aufloesung fehlgeschlagen nach {DNS_ATTEMPTS} Versuchen: {last}"))
    if https_url:
        try:
            fetch(https_url)
        except OSError as e:
            out.append(Finding(CHECK, Severity.WARN, f"https:{https_url}", f"Abruf fehlgeschlagen: {e}"))
    return out
