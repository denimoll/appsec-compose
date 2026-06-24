"""Baseline / delta support: gate only on findings new since an accepted run.

A baseline is a set of finding fingerprints stored in a JSON file the user
commits as their accepted state. On a scan we classify each current finding as
`new` (not in the baseline) or `known`, and report baseline entries no longer
seen as `fixed`. When baseline mode is on, the policy gate applies to `new`
findings only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from dedup import _norm_file
from normalize import Finding


def fingerprint(f: Finding) -> str:
    """Stable identity for a finding (independent of tool and run order)."""
    parts = [f.category, f.rule_id, _norm_file(f.file), f.package or "",
             str(f.line) if f.line is not None else ""]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()


@dataclass
class Delta:
    new: list[Finding]
    known: list[Finding]
    fixed: int           # baseline fingerprints not seen in this run


def load(path: str) -> set[str]:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return set()
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        return set()
    return set(data.get("fingerprints", []))


def classify(findings: list[Finding], baseline: set[str]) -> Delta:
    new, known, seen = [], [], set()
    for f in findings:
        fp = fingerprint(f)
        seen.add(fp)
        (known if fp in baseline else new).append(f)
    fixed = len(baseline - seen)
    return Delta(new=new, known=known, fixed=fixed)


def save(path: str, findings: list[Finding]) -> int:
    fps = sorted({fingerprint(f) for f in findings})
    Path(path).write_text(json.dumps({
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "fingerprints": fps,
    }, indent=2))
    return len(fps)
