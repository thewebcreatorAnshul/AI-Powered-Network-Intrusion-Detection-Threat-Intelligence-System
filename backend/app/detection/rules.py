"""Small, explicit signature catalog for the controlled MVP demonstration."""

from collections import defaultdict


def detect_syn_port_scan(records: list[dict], *, min_ports: int = 10, window_seconds: float = 60.0) -> list[dict]:
    """Flag one source probing many destination ports on one host with SYN-only packets."""
    probes: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    for record in records:
        if record.get("protocol") != "tcp" or record.get("src_ip") is None:
            continue
        flags = str(record.get("tcp_flags", ""))
        if "S" not in flags or "A" in flags or record.get("timestamp") is None:
            continue
        if record.get("dst_port") is None:
            continue
        probes[(record["src_ip"], record.get("dst_ip", "unknown"))].append(
            (float(record["timestamp"]), int(record["dst_port"]))
        )

    findings = []
    for (source, target), attempts in probes.items():
        attempts.sort()
        left = 0
        for right, (timestamp, _port) in enumerate(attempts):
            while timestamp - attempts[left][0] > window_seconds:
                left += 1
            ports = sorted({port for _time, port in attempts[left : right + 1]})
            if len(ports) >= min_ports:
                findings.append({
                    "rule_id": "SIG-NET-001",
                    "rule_version": "1.0.0",
                    "title": "TCP SYN port scan pattern",
                    "description": "A source sent SYN-only probes to at least 10 distinct TCP ports on one destination within 60 seconds.",
                    "severity": "high",
                    "category": "reconnaissance",
                    "method": "signature",
                    "detection_type": "signature",
                    "evidence": {
                        "source_ip": source,
                        "destination_ip": target,
                        "distinct_destination_ports": ports,
                        "probe_count": right - left + 1,
                        "window_seconds": window_seconds,
                    },
                })
                break
    return findings


def detect_syn_flood(records: list[dict], *, min_packets: int = 100, window_seconds: float = 1.0) -> list[dict]:
    """Flag a high-rate burst of SYN-only packets to one service endpoint."""
    attempts: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    for record in records:
        if record.get("protocol") != "tcp" or record.get("src_ip") is None or record.get("timestamp") is None:
            continue
        flags = str(record.get("tcp_flags", ""))
        if "S" in flags and "A" not in flags and record.get("dst_port") is not None:
            attempts[(record["src_ip"], record.get("dst_ip", "unknown"), int(record["dst_port"]))].append(float(record["timestamp"]))

    findings = []
    for (source, target, port), timestamps in attempts.items():
        timestamps.sort()
        left = 0
        for right, timestamp in enumerate(timestamps):
            while timestamp - timestamps[left] > window_seconds:
                left += 1
            count = right - left + 1
            if count >= min_packets:
                findings.append({
                    "rule_id": "SIG-NET-002",
                    "rule_version": "1.0.0",
                    "title": "High-rate TCP SYN burst",
                    "description": "A source sent at least 100 SYN-only packets to one TCP service endpoint within one second.",
                    "severity": "high",
                    "category": "denial_of_service_pattern",
                    "method": "signature",
                    "detection_type": "signature",
                    "evidence": {
                        "source_ip": source,
                        "destination_ip": target,
                        "destination_port": port,
                        "probe_count": count,
                        "window_seconds": window_seconds,
                    },
                })
                break
    return findings


SIGNATURE_RULES = (detect_syn_port_scan, detect_syn_flood)
