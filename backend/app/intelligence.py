"""Optional local-only indicator context. No provider or IOC is bundled."""

import json
from datetime import datetime, timezone
from pathlib import Path


MAX_INTELLIGENCE_FILE_BYTES = 5 * 1024 * 1024


def enrich_findings(findings: list[dict], mode: str, source: str) -> tuple[list[dict], dict]:
    if mode != "local":
        return findings, {"status": "skipped", "reason": "offline mode"}
    path = Path(source) if source else None
    if path is None or not path.is_file():
        return findings, {"status": "skipped", "reason": "no local indicator file is configured"}
    try:
        if path.stat().st_size > MAX_INTELLIGENCE_FILE_BYTES:
            return findings, {"status": "skipped", "reason": "local indicator file exceeds the 5 MB limit"}
        parsed = json.loads(path.read_text(encoding="utf-8"))
        indicators = parsed.get("indicators", []) if isinstance(parsed, dict) else parsed
        if not isinstance(indicators, list):
            raise ValueError("Expected an indicator list.")
        by_value = {}
        for item in indicators:
            if not isinstance(item, dict) or not isinstance(item.get("indicator"), str):
                continue
            by_value[item["indicator"].strip().lower()] = {
                "type": str(item.get("type", "unknown"))[:40],
                "source": str(item.get("source", "local dataset"))[:120],
            }
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return findings, {"status": "skipped", "reason": "local indicator file could not be read"}

    enriched = []
    matches = 0
    lookup_time = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        copy = dict(finding)
        values = finding.get("evidence", {}).values()
        context = []
        for value in values:
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate.lower() in by_value:
                    context.append({"indicator": candidate, **by_value[candidate.lower()], "lookup_time": lookup_time})
        copy["indicator_context"] = context
        matches += bool(context)
        enriched.append(copy)
    return enriched, {"status": "completed", "indicator_matches": int(matches)}
