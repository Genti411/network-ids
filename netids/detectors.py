"""Network intrusion detectors operating on normalized packet records.

A record is a dict: {ts, src, dst, proto, sport, dport, dns_qname}. Keeping the
detectors independent of Scapy makes them fast and unit-testable; the pcap layer
just produces these records.
"""
from __future__ import annotations

import statistics
from collections import defaultdict, deque


def detect_port_scan(records, distinct_ports: int = 15, window: float = 60.0):
    """One source hitting many distinct ports on one host within a time window."""
    by_pair: dict[tuple, list] = defaultdict(list)
    for r in records:
        if r.get("proto") == "TCP" and r.get("dport") is not None:
            by_pair[(r["src"], r["dst"])].append((r["ts"], r["dport"]))

    alerts = []
    for (src, dst), evs in by_pair.items():
        evs.sort()
        dq: deque = deque()
        counts: dict[int, int] = defaultdict(int)
        max_distinct = 0
        for ts, port in evs:
            dq.append((ts, port))
            counts[port] += 1
            while dq and ts - dq[0][0] > window:
                _, old = dq.popleft()
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
            max_distinct = max(max_distinct, len(counts))
        if max_distinct >= distinct_ports:
            alerts.append({"type": "port_scan", "src": src, "dst": dst,
                           "distinct_ports": max_distinct})
    return alerts


def detect_dns_tunneling(records, min_queries: int = 20, min_avg_len: float = 30.0):
    """Many DNS queries to one domain with long, high-entropy subdomains."""
    by_domain: dict[str, list] = defaultdict(list)
    for r in records:
        q = r.get("dns_qname")
        if q:
            parent = ".".join(q.rstrip(".").split(".")[-2:])
            by_domain[parent].append(q)

    alerts = []
    for domain, qs in by_domain.items():
        avg_len = sum(len(q) for q in qs) / len(qs)
        if len(qs) >= min_queries and avg_len >= min_avg_len:
            alerts.append({"type": "dns_tunneling", "domain": domain,
                           "queries": len(qs), "avg_qname_len": round(avg_len, 1)})
    return alerts


def detect_beaconing(records, min_events: int = 6, min_interval: float = 5.0,
                     max_jitter: float = 0.2):
    """Regular, low-jitter connections to one destination — classic C2 beacon."""
    by_pair: dict[tuple, list] = defaultdict(list)
    for r in records:
        by_pair[(r["src"], r["dst"])].append(r["ts"])

    alerts = []
    for (src, dst), times in by_pair.items():
        if len(times) < min_events:
            continue
        times.sort()
        deltas = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(deltas)
        if mean < min_interval:  # ignore bursts (e.g. a scan), only periodic traffic
            continue
        jitter = statistics.pstdev(deltas) / mean
        if jitter <= max_jitter:
            alerts.append({"type": "beaconing", "src": src, "dst": dst,
                           "interval_s": round(mean, 1), "count": len(times),
                           "jitter": round(jitter, 3)})
    return alerts


def analyze(records) -> list[dict]:
    return (detect_port_scan(records)
            + detect_dns_tunneling(records)
            + detect_beaconing(records))
