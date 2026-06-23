"""Render human-readable summaries (Markdown + HTML) from the scan."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment

from config import SEVERITY_ORDER
from normalize import Finding, ScanResult
from policy import PolicyResult

# Severities shown high -> low in the summary.
_DISPLAY_ORDER = list(reversed(SEVERITY_ORDER))
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_MD_TEMPLATE = """# appsec-compose report

_Generated: {{ generated }} UTC_

**Policy:** fail_on = `{{ policy.threshold }}` -> **{{ verdict }}**
({{ policy.breaching }} finding(s) at/above threshold)

## Totals by severity

| {{ sev_order | join(" | ") }} | Total |
|{{ "---|" * (sev_order | length + 1) }}
| {% for s in sev_order %}{{ policy.severity_counts[s] }} | {% endfor %}{{ total }} |

## By category

{% for cat, n in category_counts %}- **{{ cat }}**: {{ n }}
{% endfor %}
## By tool

{% for tool, n in tool_counts %}- **{{ tool }}**: {{ n }}
{% endfor %}
## Reports

- Found: {{ reports_found | join(", ") or "none" }}
- Missing: {{ reports_missing | join(", ") or "none" }}
- Errored: {{ reports_errored | join("; ") or "none" }}

## Top findings (up to {{ top_n }})

{% if top_findings %}| Severity | Tool | Category | Rule | Location |
|---|---|---|---|---|
{% for f in top_findings %}| {{ f.severity }} | {{ f.tool }} | {{ f.category }} | `{{ f.rule_id }}` | {{ f.file }}{% if f.line %}:{{ f.line }}{% endif %} |
{% endfor %}{% else %}_No findings._
{% endif %}
> Native reports per tool are in `reports/native/`.
"""

_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>appsec-compose report</title>
<style>
 body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1b1f23}
 h1{margin-bottom:.2rem} .muted{color:#6a737d}
 table{border-collapse:collapse;margin:.6rem 0} td,th{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left}
 th{background:#f6f8fa}
 .verdict-pass{color:#1a7f37;font-weight:600} .verdict-fail{color:#cf222e;font-weight:600}
 .sev-critical{color:#fff;background:#cf222e;padding:.1rem .4rem;border-radius:4px}
 .sev-high{color:#fff;background:#bc4c00;padding:.1rem .4rem;border-radius:4px}
 .sev-medium{color:#fff;background:#9a6700;padding:.1rem .4rem;border-radius:4px}
 .sev-low{color:#fff;background:#0969da;padding:.1rem .4rem;border-radius:4px}
 .sev-info{color:#fff;background:#6a737d;padding:.1rem .4rem;border-radius:4px}
 code{background:#f6f8fa;padding:.05rem .3rem;border-radius:4px}
</style></head><body>
<h1>appsec-compose report</h1>
<p class="muted">Generated: {{ generated }} UTC</p>
<p>Policy: fail_on = <code>{{ policy.threshold }}</code> &rarr;
   <span class="verdict-{{ 'fail' if policy.exit_code else 'pass' }}">{{ verdict }}</span>
   ({{ policy.breaching }} finding(s) at/above threshold)</p>

<h2>Totals by severity</h2>
<table><tr>{% for s in sev_order %}<th>{{ s }}</th>{% endfor %}<th>Total</th></tr>
<tr>{% for s in sev_order %}<td>{{ policy.severity_counts[s] }}</td>{% endfor %}<td>{{ total }}</td></tr></table>

<h2>By category</h2>
<table><tr><th>Category</th><th>Count</th></tr>
{% for cat, n in category_counts %}<tr><td>{{ cat }}</td><td>{{ n }}</td></tr>{% endfor %}</table>

<h2>By tool</h2>
<table><tr><th>Tool</th><th>Count</th></tr>
{% for tool, n in tool_counts %}<tr><td>{{ tool }}</td><td>{{ n }}</td></tr>{% endfor %}</table>

<h2>Reports</h2>
<p>Found: {{ reports_found | join(", ") or "none" }}<br>
Missing: {{ reports_missing | join(", ") or "none" }}<br>
Errored: {{ reports_errored | join("; ") or "none" }}</p>

<h2>Top findings (up to {{ top_n }})</h2>
{% if top_findings %}<table><tr><th>Severity</th><th>Tool</th><th>Category</th><th>Rule</th><th>Location</th></tr>
{% for f in top_findings %}<tr><td><span class="sev-{{ f.severity }}">{{ f.severity }}</span></td>
<td>{{ f.tool }}</td><td>{{ f.category }}</td><td><code>{{ f.rule_id }}</code></td>
<td>{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</td></tr>{% endfor %}</table>
{% else %}<p><em>No findings.</em></p>{% endif %}
<p class="muted">Native reports per tool are in <code>reports/native/</code>.</p>
</body></html>
"""

_TOP_N = 50


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-_RANK[f.severity], f.tool, f.file))


def _context(result: ScanResult, policy: PolicyResult) -> dict:
    total = sum(policy.severity_counts.values())
    top = _sort_findings(result.findings)[:_TOP_N]
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "policy": policy,
        "verdict": "FAIL" if policy.exit_code else "PASS",
        "sev_order": _DISPLAY_ORDER,
        "total": total,
        "category_counts": sorted(policy.category_counts.items()),
        "tool_counts": sorted(policy.tool_counts.items()),
        "reports_found": result.reports_found,
        "reports_missing": result.reports_missing,
        "reports_errored": result.reports_errored,
        "top_findings": top,
        "top_n": _TOP_N,
    }


def render(result: ScanResult, policy: PolicyResult, out_dir: str = "/reports") -> None:
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    ctx = _context(result, policy)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(env.from_string(_MD_TEMPLATE).render(**ctx))

    html_env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    (out / "summary.html").write_text(html_env.from_string(_HTML_TEMPLATE).render(**ctx))
