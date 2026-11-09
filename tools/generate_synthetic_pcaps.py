
from pathlib import Path
from scapy.all import Ether, IP, TCP, Padding, wrpcap

OUTPUT_DIR = Path("performance_pcaps")
TARGET_SIZES_MB = [24]
FRAME_TARGET_BYTES = 1200

# Documentation-only IP addresses; no real hosts are targeted.
SRC_IP = "192.0.2.10"
DST_IP = "198.51.100.20"
DST_PORT = 8080


def make_packet(index):
    packet = (
        Ether()
        / IP(src=SRC_IP, dst=DST_IP, id=index % 65536)
        / TCP(
            sport=40000 + (index % 20000),
            dport=DST_PORT,
            seq=index,
            flags="S",
        )
    )

    # Pad each packet to approximately 1200 bytes.
    padding_size = max(0, FRAME_TARGET_BYTES - len(bytes(packet)))
    packet = packet / Padding(load=b"\x00" * padding_size)

    # Synthetic timestamps, grouped into 1-second windows.
    packet.time = 1700000000 + (index % 100) / 100.0
    return packet


def generate_capture(target_mb):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output = OUTPUT_DIR / f"synthetic_{target_mb}mb.pcap"
    target_bytes = target_mb * 1024 * 1024

    packets = []
    current_size = 24  # PCAP global header
    index = 0

    while current_size < target_bytes:
        packet = make_packet(index)
        current_size += len(bytes(packet)) + 16
        packets.append(packet)
        index += 1

    wrpcap(str(output), packets)

    actual_size = output.stat().st_size
    print(
        f"{output}: {actual_size / (1024 * 1024):.2f} MiB, "
        f"{len(packets)} packets"
    )


if __name__ == "__main__":
    for size in TARGET_SIZES_MB:
        generate_capture(size)
