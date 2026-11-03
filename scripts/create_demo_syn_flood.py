"""Generate a synthetic SYN-flood PCAP for local IDS testing."""

from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap

output = Path(__file__).resolve().parent.parent / "datasets" / "demo_syn_flood.pcap"
output.parent.mkdir(parents=True, exist_ok=True)

packets = []

for i in range(120):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="198.51.100.10", dst="203.0.113.20")
        / TCP(sport=42000 + i, dport=80, flags="S", seq=i)
    )
    packet.time = 1_700_000_000 + (i * 0.005)
    packets.append(packet)

wrpcap(str(output), packets)

print(f"Created {len(packets)} synthetic SYN packets: {output}")