"""Parse a pcap file into normalized records using Scapy.

Reading pcap files does not require libpcap (only live capture does), so this
works anywhere Scapy installs.
"""
from __future__ import annotations

import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import DNSQR, IP, TCP, UDP, rdpcap  # noqa: E402


def parse_pcap(path: str) -> list[dict]:
    records = []
    for pkt in rdpcap(path):
        if IP not in pkt:
            continue
        rec = {
            "ts": float(pkt.time),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": None,
            "sport": None,
            "dport": None,
            "dns_qname": None,
        }
        if TCP in pkt:
            rec["proto"] = "TCP"
            rec["sport"] = int(pkt[TCP].sport)
            rec["dport"] = int(pkt[TCP].dport)
        elif UDP in pkt:
            rec["proto"] = "UDP"
            rec["sport"] = int(pkt[UDP].sport)
            rec["dport"] = int(pkt[UDP].dport)
        if pkt.haslayer(DNSQR):
            try:
                rec["dns_qname"] = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            except Exception:  # noqa: BLE001
                pass
        records.append(rec)
    return records
