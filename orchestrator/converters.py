"""Generate SARIF for scanners that have no native SARIF output.

The raw native report is always preserved; these converters add a SARIF file
next to it so SARIF-only ASPM/ASOC tools can ingest the findings too (and so
the normalizer can read every tool uniformly as SARIF).
"""
from __future__ import annotations

import json
from pathlib import Path

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _sarif_doc(tool_name: str, rules: dict, results: list) -> dict:
    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "rules": [{"id": rid, "name": rid} for rid in rules],
            }},
            "results": results,
        }],
    }


def trufflehog_json_to_sarif(json_path: Path, sarif_path: Path) -> bool:
    """Convert TruffleHog JSON-lines output to SARIF. Returns True if written.

    Writes a valid SARIF even when TruffleHog found nothing (empty input), so a
    tool that ran cleanly with zero findings is reported as present, not missing.
    Returns False only when the tool produced no file at all (it didn't run).
    """
    if not json_path.exists():
        return False

    rules: dict[str, None] = {}
    results: list[dict] = []
    for line in json_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or "DetectorName" not in rec:
            continue  # skip log/non-finding lines

        detector = str(rec.get("DetectorName") or "secret")
        verified = bool(rec.get("Verified"))
        rule_id = f"trufflehog.{detector}"
        rules.setdefault(rule_id, None)

        fs = (((rec.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        uri = fs.get("file", "")
        line_no = fs.get("line")

        location = {}
        if uri:
            phys = {"artifactLocation": {"uri": uri}}
            if isinstance(line_no, int) and line_no > 0:
                phys["region"] = {"startLine": line_no}
            location = {"physicalLocation": phys}

        results.append({
            "ruleId": rule_id,
            # Verified secrets are exploitable now -> error; unverified -> warning.
            "level": "error" if verified else "warning",
            "message": {"text": f"{detector} secret"
                                + (" (verified)" if verified else " (unverified)")},
            "locations": [location] if location else [],
            # security-severity drives our severity mapping: verified secrets
            # are treated as critical, unverified as high.
            "properties": {
                "verified": verified,
                "security-severity": "9.5" if verified else "7.5",
            },
        })

    sarif_path.write_text(json.dumps(_sarif_doc("trufflehog", rules, results), indent=2))
    return True
