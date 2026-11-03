"""Feature aggregation and explainable detection orchestration."""

from collections import Counter, defaultdict

from app.detection.rules import SIGNATURE_RULES


def extract_features(records: list[dict]) -> dict:
    protocols = Counter(record.get("protocol", "other") for record in records)
    flows: dict[tuple, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": None, "last": None})
    for record in records:
        if record.get("src_ip") is None or record.get("dst_ip") is None:
            continue
        key = (record["src_ip"], record.get("src_port"), record["dst_ip"], record.get("dst_port"), record.get("protocol"))
        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += int(record.get("length", 0))
        stamp = record.get("timestamp")
        if stamp is not None:
            flow["first"] = stamp if flow["first"] is None else min(flow["first"], stamp)
            flow["last"] = stamp if flow["last"] is None else max(flow["last"], stamp)
    return {
        "packet_count": len(records),
        "flow_count": len(flows),
        "protocol_counts": dict(protocols),
        "flows": [
            {**{"src_ip": key[0], "src_port": key[1], "dst_ip": key[2], "dst_port": key[3], "protocol": key[4]}, **value,
             "duration_seconds": max(0.0, value["last"] - value["first"]) if value["first"] is not None else 0.0}
            for key, value in flows.items()
        ],
    }


def analyze_records(records: list[dict]) -> tuple[dict, list[dict]]:
    features = extract_features(records)
    findings = [finding for rule in SIGNATURE_RULES for finding in rule(records)]
    return features, findings
