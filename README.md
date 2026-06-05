# Network IDS — pcap Intrusion Detection

A network-security tool that analyzes packet captures and raises alerts for three
common malicious patterns: **port scans**, **DNS tunneling**, and **C2
beaconing**. Built on Scapy; detectors are pure functions over normalized packet
records, so they're fast and unit-tested.

| Area | What's shown |
|------|--------------|
| **Network security** | traffic analysis, intrusion detection heuristics |
| **Scapy** | pcap parsing and synthetic-traffic crafting |
| **Detection logic** | windowed port-scan counting, DNS entropy/volume, beacon jitter analysis |

## Detections

| Pattern | Heuristic |
|---------|-----------|
| **Port scan** | one source hitting ≥15 distinct ports on a host within 60s |
| **DNS tunneling** | ≥20 queries to one domain with long (high-entropy) subdomains |
| **C2 beaconing** | ≥6 connections to one dst at a regular interval (low jitter) |

## Run

```bash
docker build -t network-ids .

# generate a sample capture with 3 embedded attacks, then analyze it
docker run --rm --entrypoint sh network-ids -c \
  "python gen_pcap.py /tmp/s.pcap && python -m netids.cli /tmp/s.pcap"
```

Against your own capture:

```bash
docker run --rm -v "$PWD:/data" network-ids /data/capture.pcap
```

The CLI exits non-zero when any alert fires (so it can gate a pipeline).

## Tests

```bash
pip install -r requirements.txt pytest && python -m pytest
```

Tests assert each attack pattern is detected and that benign traffic (single
port, normal DNS, irregular timing) produces no alerts.

## Layout

```
netids/detectors.py  port-scan / DNS-tunneling / beaconing detectors (pure)
netids/pcap.py       Scapy pcap -> normalized records
netids/cli.py        analyze a pcap, print alerts
gen_pcap.py          build a sample pcap with embedded attacks
tests/               detector tests
```
