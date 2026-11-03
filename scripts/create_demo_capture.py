"""Write a synthetic PCAP fixture with a deterministic SYN-port-scan signature."""

import argparse
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="datasets/demo_syn_scan.pcap")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="198.51.100.10", dst="203.0.113.20")
        / TCP(sport=41000 + port, dport=port, flags="S")
        for port in range(20, 30)
    ]
    wrpcap(str(output), packets)
    print(f"Wrote {len(packets)} synthetic packets to {output}")
    print("The capture is a local file fixture; no packets are transmitted.")


if __name__ == "__main__":
    main()
