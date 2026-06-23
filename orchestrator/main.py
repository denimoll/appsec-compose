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
from normalize import load_findings, finding_to_dict, expected_stems
from policy import evaluate
from summary import render

REPORTS_DIR = "/reports"
NATIVE_DIR = f"{REPORTS_DIR}/native"


def main() -> int:
    cfg = load_config()
    result = load_findings(NATIVE_DIR, expected=expected_stems(cfg.enabled_scanners))
    policy = evaluate(result.findings, cfg)

    # Machine-readable consolidated output (for ASPM/ASOC ingestion).
    consolidated = {
        "policy": {
            "fail_on": policy.threshold,
            "breaching": policy.breaching,
            "exit_code": policy.exit_code,
        },
        "severity_counts": policy.severity_counts,
        "category_counts": policy.category_counts,
        "tool_counts": policy.tool_counts,
        "reports_found": result.reports_found,
        "reports_missing": result.reports_missing,
        "reports_errored": result.reports_errored,
        "findings": [finding_to_dict(f) for f in result.findings],
    }
    Path(REPORTS_DIR, "findings.json").write_text(json.dumps(consolidated, indent=2))

    render(result, policy, REPORTS_DIR)

    # Console summary.
    total = sum(policy.severity_counts.values())
    print("=" * 60)
    print(f"appsec-compose: {total} finding(s) across {len(result.reports_found)} report(s)")
    for sev in ["critical", "high", "medium", "low", "info"]:
        print(f"  {sev:>8}: {policy.severity_counts[sev]}")
    if result.reports_missing:
        print(f"  ! missing reports: {', '.join(result.reports_missing)}")
    if result.reports_errored:
        print(f"  ! unreadable reports: {'; '.join(result.reports_errored)}")
    verdict = "FAIL" if policy.exit_code else "PASS"
    print(f"Policy fail_on={policy.threshold} -> {verdict} "
          f"({policy.breaching} at/above threshold)")
    sbom = Path(REPORTS_DIR, "sbom.cdx.json")
    sbom_note = " | sbom.cdx.json" if sbom.exists() else ""
    print(f"Reports: {REPORTS_DIR}/summary.md | summary.html | findings.json"
          f"{sbom_note} | native/")
    print("=" * 60)
    return policy.exit_code


if __name__ == "__main__":
    sys.exit(main())
