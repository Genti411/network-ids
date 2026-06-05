import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netids.detectors import (analyze, detect_beaconing, detect_dns_tunneling,
                              detect_port_scan)


def rec(ts, src, dst, proto="TCP", dport=443, qname=None):
    return {"ts": ts, "src": src, "dst": dst, "proto": proto,
            "sport": 5, "dport": dport, "dns_qname": qname}


def test_port_scan_detected():
    recs = [rec(100 + i * 0.05, "1.1.1.1", "2.2.2.2", dport=p)
            for i, p in enumerate(range(1, 31))]
    assert any(a["type"] == "port_scan" for a in detect_port_scan(recs))


def test_no_port_scan_single_port():
    recs = [rec(i, "1.1.1.1", "2.2.2.2", dport=443) for i in range(40)]
    assert detect_port_scan(recs) == []


def test_dns_tunneling_detected():
    recs = [rec(i, "1.1.1.1", "8.8.8.8", proto="UDP", dport=53,
                qname=f"{hashlib.sha256(str(i).encode()).hexdigest()}.exfil.evil.com")
            for i in range(30)]
    alerts = detect_dns_tunneling(recs)
    assert any(a["domain"] == "evil.com" for a in alerts)


def test_no_dns_tunneling_normal_queries():
    recs = [rec(i, "1.1.1.1", "8.8.8.8", proto="UDP", dport=53, qname="google.com")
            for i in range(40)]
    assert detect_dns_tunneling(recs) == []


def test_beaconing_detected():
    recs = [rec(1000 + i * 60, "1.1.1.1", "3.3.3.3") for i in range(10)]
    assert any(a["type"] == "beaconing" for a in detect_beaconing(recs))


def test_no_beaconing_irregular():
    deltas = [10, 70, 15, 90, 20, 80, 12, 65, 30]
    ts, t = [], 1000
    for d in deltas:
        ts.append(t)
        t += d
    ts.append(t)
    recs = [rec(t, "1.1.1.1", "3.3.3.3") for t in ts]
    assert detect_beaconing(recs) == []


def test_analyze_combines():
    recs = ([rec(100 + i * 0.05, "9.9.9.9", "2.2.2.2", dport=p)
             for i, p in enumerate(range(1, 31))]
            + [rec(1000 + i * 60, "9.9.9.9", "3.3.3.3") for i in range(10)])
    kinds = {a["type"] for a in analyze(recs)}
    assert "port_scan" in kinds and "beaconing" in kinds
