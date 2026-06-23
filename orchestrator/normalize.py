"""Normalize heterogeneous SARIF reports into a single findings model.

Every supported scanner can emit SARIF, so SARIF is our common denominator.
We parse the generic SARIF structure and apply small per-tool hints (severity
source, default category) keyed off the report filename.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

# Maps a native report filename (stem prefix) -> (tool label, category).
# A tool may emit several files (e.g. trivy-fs / trivy-config).
SOURCE_MAP = {
    "semgrep": ("semgrep", "sast"),
    "trivy-fs": ("trivy", "sca"),
    "trivy-config": ("trivy", "iac"),
    "gitleaks": ("gitleaks", "secrets"),
    "checkov": ("checkov", "iac"),
}

# Which report stems each configured scanner is expected to produce.
SCANNER_STEMS = {
    "semgrep": ["semgrep"],
    "trivy": ["trivy-fs", "trivy-config"],
    "gitleaks": ["gitleaks"],
    "checkov": ["checkov"],
}


def expected_stems(enabled_scanners) -> set[str]:
    """Report stems we should expect, given the set of enabled scanners."""
    stems: set[str] = set()
    for name in enabled_scanners:
        stems.update(SCANNER_STEMS.get(name, []))
    return stems

# SARIF level -> our severity when no numeric CVSS is available.
_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

# Categories where a finding is inherently serious; floor its severity.
_CATEGORY_FLOOR = {
    "secrets": "high",
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    tool: str
    category: str
    rule_id: str
    severity: str
    message: str
    file: str
    line: int | None


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def _security_severity(props: dict) -> str | None:
    """Read the SARIF `security-severity` (CVSS string) if present."""
    if not props:
        return None
    raw = props.get("security-severity")
    if raw is None:
        return None
    try:
        return _severity_from_cvss(float(raw))
    except (TypeError, ValueError):
        return None


def _parse_sarif(path: Path, tool: str, category: str) -> list[Finding]:
    """Parse one SARIF file. Raises ValueError if the file is not valid SARIF."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"{path.name}: unreadable SARIF ({exc})") from exc

    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        # Build ruleId -> rule properties for severity lookups.
        rules = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id")] = rule.get("properties") or {}

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or res.get("ruleIndex") or "unknown"

            # Severity: prefer CVSS from result, then rule, then SARIF level.
            sev = (
                _security_severity(res.get("properties") or {})
                or _security_severity(rules.get(rule_id, {}))
                or _LEVEL_TO_SEVERITY.get(res.get("level", "warning"), "medium")
            )
            floor = _CATEGORY_FLOOR.get(category)
            if floor:
                sev = _max_severity(sev, floor)

            msg = ((res.get("message") or {}).get("text") or "").strip()

            file_path, line = "", None
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                file_path = (phys.get("artifactLocation") or {}).get("uri", "")
                line = (phys.get("region") or {}).get("startLine")

            findings.append(Finding(
                tool=tool,
                category=category,
                rule_id=str(rule_id),
                severity=sev,
                message=msg or str(rule_id),
                file=file_path,
                line=line,
            ))
    return findings


@dataclass
class ScanResult:
    findings: list[Finding]
    reports_found: list[str]
    reports_missing: list[str]
    reports_errored: list[str]


def load_findings(native_dir: str = "/reports/native",
                  expected: set[str] | None = None) -> ScanResult:
    base = Path(native_dir)
    findings: list[Finding] = []
    found, missing, errored = [], [], []

    for stem, (tool, category) in SOURCE_MAP.items():
        if expected is not None and stem not in expected:
            continue  # scanner disabled in config — don't expect its report
        path = base / f"{stem}.sarif"
        if path.exists() and path.stat().st_size > 0:
            try:
                findings.extend(_parse_sarif(path, tool, category))
                found.append(path.name)
            except ValueError as exc:
                errored.append(str(exc))
        else:
            missing.append(path.name)

    return ScanResult(findings=findings, reports_found=found,
                      reports_missing=missing, reports_errored=errored)


def finding_to_dict(f: Finding) -> dict:
    return asdict(f)
