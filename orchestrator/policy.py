"""Turn findings + policy into severity counts and a CI exit code."""
from __future__ import annotations

from dataclasses import dataclass, field

from config import Config, SEVERITY_ORDER
from normalize import Finding

_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass
class PolicyResult:
    exit_code: int
    threshold: str            # default fail_on level ("none" => never fail)
    breaching: int            # number of findings at/above their threshold
    severity_counts: dict     # severity -> count
    category_counts: dict     # category -> count
    tool_counts: dict         # tool -> count
    thresholds: dict = field(default_factory=dict)  # category -> level override
    label: str = ""           # human-readable rendering of the whole policy

    def __post_init__(self):
        if not self.label:
            self.label = self.threshold


def _bump_unknown(findings: list[Finding], unknown_severity: str) -> None:
    """Resolve any stray 'unknown' severities (defensive; normalizer avoids them)."""
    for f in findings:
        if f.severity not in _RANK:
            f.severity = unknown_severity


def breaches(finding: Finding, cfg: Config) -> bool:
    """True when a finding is at or above the threshold for its category."""
    threshold = cfg.threshold_for(finding.category)
    if threshold == "none":
        return False
    return _RANK[finding.severity] >= _RANK[threshold]


def evaluate(findings: list[Finding], cfg: Config,
             raw_findings: list[Finding] | None = None,
             gate_findings: list[Finding] | None = None) -> PolicyResult:
    """Counts come from `findings` (deduped, kept); per-tool counts from the raw
    set. The gate (breaching/exit_code) is computed over `gate_findings` when
    given (e.g. only NEW findings in baseline mode), else over `findings`.

    `fail_on` may be a single level or a per-category map, so each finding is
    compared against the threshold configured for its own category.
    """
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
    breaching = sum(1 for f in gate if breaches(f, cfg))
    exit_code = 1 if breaching > 0 else 0

    return PolicyResult(exit_code, cfg.fail_on, breaching,
                        severity_counts, category_counts, tool_counts,
                        thresholds=dict(cfg.fail_on_by_category),
                        label=cfg.threshold_label())
