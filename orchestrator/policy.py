"""Turn findings + policy into severity counts and a CI exit code."""
from __future__ import annotations

from dataclasses import dataclass

from config import Config, SEVERITY_ORDER
from normalize import Finding

_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass
class PolicyResult:
    exit_code: int
    threshold: str            # effective fail_on level ("none" => never fail)
    breaching: int            # number of findings at/above threshold
    severity_counts: dict     # severity -> count
    category_counts: dict     # category -> count
    tool_counts: dict         # tool -> count


def _bump_unknown(findings: list[Finding], unknown_severity: str) -> None:
    """Resolve any stray 'unknown' severities (defensive; normalizer avoids them)."""
    for f in findings:
        if f.severity not in _RANK:
            f.severity = unknown_severity


def evaluate(findings: list[Finding], cfg: Config,
             raw_findings: list[Finding] | None = None,
             gate_findings: list[Finding] | None = None) -> PolicyResult:
    """Counts come from `findings` (deduped, kept); per-tool counts from the raw
    set. The gate (breaching/exit_code) is computed over `gate_findings` when
    given (e.g. only NEW findings in baseline mode), else over `findings`."""
    _bump_unknown(findings, cfg.unknown_severity)

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    category_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] += 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    tool_counts: dict[str, int] = {}
    for f in (raw_findings if raw_findings is not None else findings):
        tool_counts[f.tool] = tool_counts.get(f.tool, 0) + 1

    gate = gate_findings if gate_findings is not None else findings
    if cfg.fail_on == "none":
        return PolicyResult(0, "none", 0, severity_counts, category_counts, tool_counts)

    threshold_rank = _RANK[cfg.fail_on]
    breaching = sum(1 for f in gate if _RANK[f.severity] >= threshold_rank)
    exit_code = 1 if breaching > 0 else 0
    return PolicyResult(exit_code, cfg.fail_on, breaching,
                        severity_counts, category_counts, tool_counts)
