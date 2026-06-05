"""CLI: analyze a pcap file and print alerts. Exits non-zero if anything fires."""
from __future__ import annotations

import argparse
import sys

from .detectors import analyze
from .pcap import parse_pcap


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netids", description="pcap intrusion detector")
    p.add_argument("pcap", help="path to a .pcap file")
    args = p.parse_args(argv)

    records = parse_pcap(args.pcap)
    alerts = analyze(records)

    print(f"parsed {len(records)} packets; {len(alerts)} alert(s)\n")
    for a in alerts:
        kind = a.pop("type")
        detail = "  ".join(f"{k}={v}" for k, v in a.items())
        print(f"[ALERT] {kind:14} {detail}")
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
