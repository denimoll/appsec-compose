"""Apply ignore/suppression rules from scan-config.yml.

An ignore entry may specify any of: `rule` (glob, matched against the finding's
rule_id OR any alias), `file` (glob on the path), `package` (glob on
name@version), `category`. A finding is suppressed when EVERY field present in
the entry matches. Suppressed findings are removed from the gate and the
summary counts, but recorded with their reason for the audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from normalize import Finding


@dataclass
class Suppressed:
    finding: Finding
    reason: str


def _matches(entry: dict, f: Finding) -> bool:
    rule = entry.get("rule")
    if rule:
        ids = [f.rule_id, *f.aliases]
        if not any(fnmatch(i.upper(), str(rule).upper()) for i in ids):
            return False
    if entry.get("file") and not fnmatch(f.file or "", str(entry["file"])):
        return False
    if entry.get("package") and not fnmatch(f.package or "", str(entry["package"])):
        return False
    if entry.get("category") and f.category != entry["category"]:
        return False
    # An empty entry (no selectors) must not match everything.
    return any(entry.get(k) for k in ("rule", "file", "package", "category"))


def apply(findings: list[Finding], ignore: list[dict]) -> tuple[list[Finding], list[Suppressed]]:
    if not ignore:
        return list(findings), []

    kept: list[Finding] = []
    suppressed: list[Suppressed] = []
    for f in findings:
        entry = next((e for e in ignore if isinstance(e, dict) and _matches(e, f)), None)
        if entry is None:
            kept.append(f)
        else:
            suppressed.append(Suppressed(f, str(entry.get("reason", "")).strip()))
    return kept, suppressed
