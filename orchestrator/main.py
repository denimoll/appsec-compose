"""appsec-compose collector entrypoint.

Runs after every scanner service has finished. Loads native SARIF reports,
normalizes them, writes a consolidated findings.json + summary.{md,html} and
exits with a CI-meaningful code derived from the configured fail_on policy.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import baseline as bl
from config import load_config
from converters import trufflehog_json_to_sarif
from dedup import merge
from normalize import load_findings, finding_to_dict, expected_reports
from policy import evaluate
from summary import render
from suppress import apply as apply_ignore

REPORTS_DIR = "/reports"
NATIVE_DIR = f"{REPORTS_DIR}/native"
BASELINE_PATH = "/app/appsec-baseline.json"


def main() -> int:
    cfg = load_config()

    # Generate SARIF for tools that have no native SARIF (keeps the raw report).
    trufflehog_json_to_sarif(Path(NATIVE_DIR, "trufflehog.json"),
                             Path(NATIVE_DIR, "trufflehog.sarif"))

    expected = expected_reports(cfg.enabled_scanners)
    if os.environ.get("ASS_IMAGE"):
        expected.discard("trivy-config.sarif")   # no IaC config scan in image mode
    result = load_findings(NATIVE_DIR, expected=expected)
    merged, stats = merge(result.findings, enabled=cfg.dedup)
    kept, suppressed = apply_ignore(merged, cfg.ignore)

    # --update-baseline: snapshot current findings as the accepted state, no gate.
    if os.environ.get("ASS_UPDATE_BASELINE") == "1":
        n = bl.save(BASELINE_PATH, kept)
        print(f"Baseline updated: {n} fingerprint(s) -> appsec-baseline.json")
        return 0

    # Baseline mode: gate only on findings new since the accepted baseline.
    delta = None
    if cfg.baseline:
        delta = bl.classify(kept, bl.load(BASELINE_PATH))
    gate_findings = delta.new if delta is not None else None
    policy = evaluate(kept, cfg, raw_findings=result.findings, gate_findings=gate_findings)
    new_fps = {bl.fingerprint(f) for f in delta.new} if delta else set()
    for f in kept:                       # transient flag for the HTML report
        f.is_new = bool(delta) and bl.fingerprint(f) in new_fps

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
        "baseline": {
            "enabled": cfg.baseline,
            "new": len(delta.new) if delta else None,
            "known": len(delta.known) if delta else None,
            "fixed": delta.fixed if delta else None,
        },
        "severity_counts": policy.severity_counts,
        "category_counts": policy.category_counts,
        "tool_counts": policy.tool_counts,
        "reports_found": result.reports_found,
        "reports_missing": result.reports_missing,
        "reports_errored": result.reports_errored,
        "findings": [{**finding_to_dict(f),
                      **({"new": bl.fingerprint(f) in new_fps} if delta else {})}
                     for f in kept],
        "suppressed": [{**finding_to_dict(s.finding), "reason": s.reason}
                       for s in suppressed],
    }
    Path(REPORTS_DIR, "findings.json").write_text(json.dumps(consolidated, indent=2))

    render(result, policy, kept, stats, REPORTS_DIR,
           suppressed_count=len(suppressed), delta=delta)

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
    if delta is not None:
        print(f"  baseline: {len(delta.new)} new, {len(delta.known)} known, "
              f"{delta.fixed} fixed")
    verdict = "FAIL" if policy.exit_code else "PASS"
    gate_scope = "new " if delta is not None else ""
    print(f"Policy fail_on={policy.threshold} -> {verdict} "
          f"({policy.breaching} {gate_scope}at/above threshold)")
    sboms = sorted(p.name for p in Path(REPORTS_DIR).glob("sbom.*.json"))
    sbom_note = (" | " + " | ".join(sboms)) if sboms else ""
    print(f"Reports: {REPORTS_DIR}/summary.md | summary.html | findings.json"
          f"{sbom_note} | native/")
    print("=" * 60)
    return policy.exit_code


if __name__ == "__main__":
    sys.exit(main())
