"""appsec-compose collector entrypoint.

Runs after every scanner service has finished. Loads native SARIF reports,
normalizes them, writes a consolidated findings.json + summary.{md,html} and
exits with a CI-meaningful code derived from the configured fail_on policy.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from config import load_config
from converters import trufflehog_json_to_sarif
from dedup import merge
from normalize import load_findings, finding_to_dict, expected_reports
from policy import evaluate
from summary import render
from suppress import apply as apply_ignore

REPORTS_DIR = "/reports"
NATIVE_DIR = f"{REPORTS_DIR}/native"


def main() -> int:
    cfg = load_config()

    # Generate SARIF for tools that have no native SARIF (keeps the raw report).
    trufflehog_json_to_sarif(Path(NATIVE_DIR, "trufflehog.json"),
                             Path(NATIVE_DIR, "trufflehog.sarif"))

    result = load_findings(NATIVE_DIR, expected=expected_reports(cfg.enabled_scanners))
    merged, stats = merge(result.findings, enabled=cfg.dedup)
    kept, suppressed = apply_ignore(merged, cfg.ignore)
    policy = evaluate(kept, cfg, raw_findings=result.findings)

    # Machine-readable consolidated output (for ASPM/ASOC ingestion).
    consolidated = {
        "policy": {
            "fail_on": policy.threshold,
            "breaching": policy.breaching,
            "exit_code": policy.exit_code,
        },
        "dedup": {
            "enabled": cfg.dedup,
            "raw_findings": stats.raw,
            "unique_findings": stats.unique,
            "duplicates_removed": stats.removed,
        },
        "suppressed_count": len(suppressed),
        "severity_counts": policy.severity_counts,
        "category_counts": policy.category_counts,
        "tool_counts": policy.tool_counts,
        "reports_found": result.reports_found,
        "reports_missing": result.reports_missing,
        "reports_errored": result.reports_errored,
        "findings": [finding_to_dict(f) for f in kept],
        "suppressed": [{**finding_to_dict(s.finding), "reason": s.reason}
                       for s in suppressed],
    }
    Path(REPORTS_DIR, "findings.json").write_text(json.dumps(consolidated, indent=2))

    render(result, policy, kept, stats, REPORTS_DIR, suppressed_count=len(suppressed))

    # Console summary.
    total = sum(policy.severity_counts.values())
    print("=" * 60)
    dup_note = (f" ({stats.removed} duplicate(s) merged)"
                if cfg.dedup and stats.removed else "")
    print(f"appsec-compose: {total} unique finding(s) across "
          f"{len(result.reports_found)} report(s){dup_note}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        print(f"  {sev:>8}: {policy.severity_counts[sev]}")
    if suppressed:
        print(f"  (suppressed by ignore rules: {len(suppressed)})")
    if result.reports_missing:
        print(f"  ! missing reports: {', '.join(result.reports_missing)}")
    if result.reports_errored:
        print(f"  ! unreadable reports: {'; '.join(result.reports_errored)}")
    verdict = "FAIL" if policy.exit_code else "PASS"
    print(f"Policy fail_on={policy.threshold} -> {verdict} "
          f"({policy.breaching} at/above threshold)")
    sboms = sorted(p.name for p in Path(REPORTS_DIR).glob("sbom.*.cdx.json"))
    sbom_note = (" | " + " | ".join(sboms)) if sboms else ""
    print(f"Reports: {REPORTS_DIR}/summary.md | summary.html | findings.json"
          f"{sbom_note} | native/")
    print("=" * 60)
    return policy.exit_code


if __name__ == "__main__":
    sys.exit(main())
