"""Merge duplicate findings reported by multiple tools.

Operates only on our internal model (the raw native per-tool reports are left
untouched for ASPM import). Dedup key depends on category:

- secrets : same location (file, line) is the same secret, regardless of tool.
- sca     : same package@version + file, clustered by overlapping vuln IDs so
            that e.g. Trivy's CVE-2018-1000656 and Grype's GHSA-562c-5r94-xh97
            (whose relatedVulnerabilities lists that CVE) collapse into one.
- sast/iac: same rule at the same (file, line).

A merged finding keeps the highest severity and records every tool that
reported it (provenance) plus the union of equivalent IDs (aliases).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from normalize import Finding, _SEVERITY_RANK, _max_severity


@dataclass
class DedupStats:
    raw: int
    unique: int

    @property
    def removed(self) -> int:
        return self.raw - self.unique


def _norm_file(path: str) -> str:
    # Align paths across tools: some report relative ("app.py"), others report
    # the container mount ("/code/app.py"). /code is our fixed mount root.
    p = (path or "").lstrip("./").lstrip("/")
    if p.startswith("code/"):
        p = p[len("code/"):]
    return p


def _id_tokens(f: Finding) -> set[str]:
    return {f.rule_id.upper()} | {a.upper() for a in f.aliases}


def _merge_group(group: list[Finding]) -> Finding:
    rep = max(group, key=lambda f: _SEVERITY_RANK[f.severity])
    tools = sorted({t for f in group for t in f.tools})
    ids = sorted({t for f in group for t in _id_tokens(f)})

    severity = "info"
    for f in group:
        severity = _max_severity(severity, f.severity)

    # Prefer a CVE id as the canonical rule_id for readability/ASPM matching.
    rule_id = next((i for i in ids if i.startswith("CVE-")), rep.rule_id)
    aliases = [i for i in ids if i != rule_id]

    return Finding(
        tool=rep.tool, category=rep.category, rule_id=rule_id, severity=severity,
        message=rep.message, file=rep.file, line=rep.line, package=rep.package,
        aliases=aliases, tools=tools,
    )


def _cluster_sca(findings: list[Finding]) -> list[list[Finding]]:
    """Union-find within each (package, file) bucket, joined by shared vuln IDs."""
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.package or f.rule_id, _norm_file(os.path.basename(f.file)))
        buckets.setdefault(key, []).append(f)

    groups: list[list[Finding]] = []
    for bucket in buckets.values():
        parent = list(range(len(bucket)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            parent[find(a)] = find(b)

        token_owner: dict[str, int] = {}
        for i, f in enumerate(bucket):
            for tok in _id_tokens(f):
                if tok in token_owner:
                    union(i, token_owner[tok])
                else:
                    token_owner[tok] = i

        clusters: dict[int, list[Finding]] = {}
        for i, f in enumerate(bucket):
            clusters.setdefault(find(i), []).append(f)
        groups.extend(clusters.values())
    return groups


def merge(findings: list[Finding], enabled: bool = True) -> tuple[list[Finding], DedupStats]:
    raw = len(findings)
    if not enabled:
        return list(findings), DedupStats(raw=raw, unique=raw)

    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    groups: list[list[Finding]] = []
    for category, items in by_cat.items():
        if category == "sca":
            groups.extend(_cluster_sca(items))
        else:
            keyed: dict[tuple, list[Finding]] = {}
            for f in items:
                if category == "secrets":
                    sig = (_norm_file(f.file), f.line)
                else:
                    sig = (f.rule_id, _norm_file(f.file), f.line)
                keyed.setdefault(sig, []).append(f)
            groups.extend(keyed.values())

    merged = [_merge_group(g) for g in groups]
    merged.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.category, f.tools))
    return merged, DedupStats(raw=raw, unique=len(merged))
