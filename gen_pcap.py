"""Generate a sample pcap with benign traffic plus three embedded attacks:
a port scan, DNS tunneling, and C2 beaconing. Deterministic.

  python gen_pcap.py [output.pcap]
"""
from __future__ import annotations

import hashlib
import logging
import sys

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap  # noqa: E402

T0 = 1_700_000_000.0


def build():
    pkts = []

    # --- benign web traffic (random-ish timing, one dst)
    for i in range(40):
        p = Ether() / IP(src="10.0.0.20", dst="93.184.216.34") / TCP(
            sport=40000 + i, dport=443, flags="S")
        p.time = T0 + i * 1.7 + (i % 3) * 0.4
        pkts.append(p)

    # --- benign DNS to common domains
    for i, d in enumerate(["example.com", "google.com", "github.com"] * 3):
        p = Ether() / IP(src="10.0.0.20", dst="8.8.8.8") / UDP(
            sport=50000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=d))
        p.time = T0 + i * 2.0
        pkts.append(p)

    # --- ATTACK 1: port scan (10.0.0.66 -> 10.0.0.5, ports 1..30, rapid)
    for i, port in enumerate(range(1, 31)):
        p = Ether() / IP(src="10.0.0.66", dst="10.0.0.5") / TCP(
            sport=55000, dport=port, flags="S")
        p.time = T0 + 100 + i * 0.05
        pkts.append(p)

    # --- ATTACK 2: DNS tunneling (long high-entropy subdomains -> exfil.evil.com)
    for i in range(30):
        sub = hashlib.sha256(str(i).encode()).hexdigest()  # 64 hex chars
        p = Ether() / IP(src="10.0.0.7", dst="8.8.8.8") / UDP(
            sport=51000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{sub}.exfil.evil.com"))
        p.time = T0 + 200 + i * 1.0
        pkts.append(p)

    # --- ATTACK 3: beaconing (10.0.0.7 -> 185.1.2.3:443 every 60s, 10x)
    for i in range(10):
        p = Ether() / IP(src="10.0.0.7", dst="185.1.2.3") / TCP(
            sport=56000 + i, dport=443, flags="S")
        p.time = T0 + 500 + i * 60.0
        pkts.append(p)

    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    wrpcap(out, build())
    print(f"wrote {out}")
