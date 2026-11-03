"""PCAP and PCAPNG source adapter. No live capture is performed."""

from collections.abc import Iterator
from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from scapy.utils import PcapNgReader, PcapReader, RawPcapNgReader, RawPcapReader

from app.ingestion.base import (
    EmptyCaptureError,
    InvalidCaptureError,
    SourceAdapter,
    UnsupportedCaptureError,
)

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
READ_CHUNK_BYTES = 65_536


def identify_capture_format(path: Path) -> str:
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise UnsupportedCaptureError()


def _open_packet_reader(path: Path, capture_format: str):
    if capture_format == "pcapng":
        return PcapNgReader(str(path))
    return PcapReader(str(path))


def _open_raw_reader(path: Path, capture_format: str):
    if capture_format == "pcapng":
        return RawPcapNgReader(str(path))
    return RawPcapReader(str(path))


def _safe_record(packet) -> dict:
    timestamp = getattr(packet, "time", None)
    try:
        length = int(len(packet))
    except TypeError:
        length = 0
    record = {
        "timestamp": float(timestamp) if timestamp is not None else None,
        "length": length,
        "layers": [layer.name for layer in packet.layers()][:8],
    }
    ip = packet.getlayer("IP") or packet.getlayer("IPv6")
    if ip is not None:
        record.update({"src_ip": str(ip.src), "dst_ip": str(ip.dst)})
    tcp = packet.getlayer("TCP")
    udp = packet.getlayer("UDP")
    transport = tcp or udp
    if transport is not None:
        record.update({"src_port": int(transport.sport), "dst_port": int(transport.dport)})
    if tcp is not None:
        record.update({"protocol": "tcp", "tcp_flags": str(tcp.flags)})
    elif udp is not None:
        record["protocol"] = "udp"
    elif packet.haslayer("ICMP"):
        record["protocol"] = "icmp"
        record["icmp_type"] = int(packet.getlayer("ICMP").type)
    elif packet.haslayer("ARP"):
        record["protocol"] = "arp"
    else:
        record["protocol"] = "other"
    return record


class PcapSourceAdapter(SourceAdapter):
    source_type = "pcap"

    def validate(self, path: Path) -> None:
        if not path.is_file() or path.stat().st_size <= 0:
            raise EmptyCaptureError()
        capture_format = identify_capture_format(path)
        try:
            reader = _open_raw_reader(path, capture_format)
        except Exception as exc:
            raise InvalidCaptureError() from exc
        try:
            first = next(iter(reader), None)
        except Exception as exc:
            raise InvalidCaptureError() from exc
        finally:
            close = getattr(reader, "close", None)
            if callable(close):
                close()
        if first is None:
            raise EmptyCaptureError()

    def iter_records(self, path: Path) -> Iterator[dict]:
        capture_format = identify_capture_format(path)
        try:
            reader = _open_packet_reader(path, capture_format)
        except Exception as exc:
            raise InvalidCaptureError() from exc
        try:
            for packet in reader:
                    if isinstance(packet, Raw) and capture_format == "pcap":
                        packet = Ether(bytes(packet))
                    yield _safe_record(packet)
        except InvalidCaptureError:
            raise
        except Exception as exc:
            raise InvalidCaptureError() from exc
        finally:
            close = getattr(reader, "close", None)
            if callable(close):
                close()

    def metadata(self, path: Path) -> dict:
        capture_format = identify_capture_format(path)
        return {
            "source_type": self.source_type,
            "source_format": capture_format,
            "file_size": path.stat().st_size,
            "supports_live_capture": False,
            "retains_payloads": False,
        }


def get_source_adapter(source_type: str) -> SourceAdapter:
    if source_type == PcapSourceAdapter.source_type:
        return PcapSourceAdapter()
    raise UnsupportedCaptureError()
