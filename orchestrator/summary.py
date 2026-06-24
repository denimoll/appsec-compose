"""Render human-readable summaries (Markdown + HTML) from the scan."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment

from config import SEVERITY_ORDER
from dedup import DedupStats
from normalize import Finding, ScanResult
from policy import PolicyResult

# Severities shown high -> low in the summary.
_DISPLAY_ORDER = list(reversed(SEVERITY_ORDER))
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_MD_TEMPLATE = """# appsec-compose report

_Generated: {{ generated }} UTC_

**Policy:** fail_on = `{{ policy.threshold }}` -> **{{ verdict }}**
({{ policy.breaching }} finding(s) at/above threshold)
{% if stats.removed %}
_Deduplicated: {{ total }} unique of {{ stats.raw }} raw findings ({{ stats.removed }} merged)._
{% endif %}
{% if suppressed_count %}
_Suppressed by ignore rules: {{ suppressed_count }} (excluded from the gate)._
{% endif %}
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

{% if top_findings %}| Severity | Tools | Category | Rule | Location |
|---|---|---|---|---|
{% for f in top_findings %}| {{ f.severity }} | {{ f.tools | join(", ") }} | {{ f.category }} | `{{ f.rule_id }}` | {{ f.file }}{% if f.line %}:{{ f.line }}{% endif %} |
{% endfor %}{% else %}_No findings._
{% endif %}
> Native reports per tool are in `reports/native/`.
"""

_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>appsec-compose report</title>
<style>
 :root{
   --bg:#f4f6fb; --card:#fff; --ink:#1b2230; --muted:#5b6678; --line:#e3e8f0;
   --crit:#b3122b; --high:#d9531e; --med:#c98a00; --low:#1f6feb; --info:#7a8699;
   --pass:#1a7f37; --fail:#cf222e; --accent:#4451f0;
 }
 @media (prefers-color-scheme:dark){
   :root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#9aa5b1;--line:#283040}
 }
 *{box-sizing:border-box}
 body{font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
   margin:0;background:var(--bg);color:var(--ink)}
 .wrap{max-width:1040px;margin:0 auto;padding:0 20px 56px}
 header{background:linear-gradient(135deg,#2b2f6f,#4451f0);color:#fff;padding:26px 0 22px;margin-bottom:24px}
 header .wrap{padding-top:0;padding-bottom:0}
 .brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700;letter-spacing:.2px}
 .brand .dot{width:11px;height:11px;border-radius:50%;background:#aab4ff}
 .sub{opacity:.82;font-size:12.5px;margin-top:4px}
 .pill{display:inline-flex;align-items:center;gap:7px;padding:6px 13px;border-radius:999px;
   font-weight:700;font-size:13px;margin-top:14px}
 .pill.pass{background:rgba(255,255,255,.16);color:#d7ffe2}
 .pill.fail{background:#fff;color:var(--fail)}
 .pill .big{font-size:14px}
 h2{font-size:15px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
   margin:30px 0 12px;font-weight:700}
 .cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
 @media(max-width:720px){.cards{grid-template-columns:repeat(3,1fr)}}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 14px 12px;
   box-shadow:0 1px 2px rgba(20,30,60,.04)}
 .card .n{font-size:26px;font-weight:750;line-height:1}
 .card .l{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-top:7px}
 .card.total .n{color:var(--accent)}
 .card.s-critical{border-top:3px solid var(--crit)} .card.s-critical .n{color:var(--crit)}
 .card.s-high{border-top:3px solid var(--high)} .card.s-high .n{color:var(--high)}
 .card.s-medium{border-top:3px solid var(--med)} .card.s-medium .n{color:var(--med)}
 .card.s-low{border-top:3px solid var(--low)} .card.s-low .n{color:var(--low)}
 .card.s-info{border-top:3px solid var(--info)} .card.s-info .n{color:var(--info)}
 .bar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:6px 0 2px;background:var(--line)}
 .bar i{display:block;height:100%}
 .bar .b-critical{background:var(--crit)} .bar .b-high{background:var(--high)}
 .bar .b-medium{background:var(--med)} .bar .b-low{background:var(--low)} .bar .b-info{background:var(--info)}
 .panels{display:grid;grid-template-columns:1fr 1fr;gap:18px}
 @media(max-width:720px){.panels{grid-template-columns:1fr}}
 .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
 .panel h3{margin:0 0 10px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
 .row{display:flex;align-items:center;gap:10px;margin:7px 0}
 .row .k{flex:0 0 96px;font-weight:600;text-transform:capitalize}
 .row .t{flex:1;height:9px;border-radius:5px;background:var(--line);overflow:hidden}
 .row .t i{display:block;height:100%;background:var(--accent);opacity:.85}
 .row .v{flex:0 0 34px;text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
 .chips{display:flex;flex-wrap:wrap;gap:8px}
 .chip{font-size:12px;padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:var(--card)}
 .chip.ok{border-color:#bce3c8;color:var(--pass)} .chip.warn{border-color:#f3d2a6;color:#9a6700}
 .chip.err{border-color:#f0bcc2;color:var(--fail)}
 table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
   border-radius:12px;overflow:hidden}
 thead th{position:sticky;top:0;background:var(--card);text-align:left;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:11px 12px;border-bottom:1px solid var(--line)}
 td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
 tbody tr:last-child td{border-bottom:0}
 tbody tr:nth-child(even){background:rgba(127,140,170,.05)}
 .sev{display:inline-block;min-width:62px;text-align:center;color:#fff;font-weight:700;font-size:11px;
   text-transform:uppercase;letter-spacing:.4px;padding:3px 8px;border-radius:6px}
 .sev-critical{background:var(--crit)} .sev-high{background:var(--high)}
 .sev-medium{background:var(--med)} .sev-low{background:var(--low)} .sev-info{background:var(--info)}
 code,.loc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
 .loc{color:var(--muted)} .tool{font-weight:600}
 footer{color:var(--muted);font-size:12px;margin-top:26px}
</style></head><body>
<header><div class="wrap">
  <div class="brand"><span class="dot"></span>appsec-compose</div>
  <div class="sub">Generated {{ generated }} UTC &middot; policy fail_on = {{ policy.threshold }}{% if stats.removed %} &middot; {{ total }} unique of {{ stats.raw }} ({{ stats.removed }} merged){% endif %}{% if suppressed_count %} &middot; {{ suppressed_count }} suppressed{% endif %}</div>
  <div class="pill {{ 'fail' if policy.exit_code else 'pass' }}">
    <span class="big">{{ '✗' if policy.exit_code else '✓' }} {{ verdict }}</span>
    &middot; {{ policy.breaching }} at/above threshold
  </div>
</div></header>

<div class="wrap">

<h2>Severity overview</h2>
<div class="cards">
  <div class="card total"><div class="n">{{ total }}</div><div class="l">Total</div></div>
  {% for s in sev_order %}
  <div class="card s-{{ s }}"><div class="n">{{ policy.severity_counts[s] }}</div><div class="l">{{ s }}</div></div>
  {% endfor %}
</div>
{% if total %}
<div class="bar">
  {% for s in sev_order %}{% set c = policy.severity_counts[s] %}{% if c %}<i class="b-{{ s }}" style="width:{{ '%.2f'|format(c / total * 100) }}%"></i>{% endif %}{% endfor %}
</div>
{% endif %}

<h2>Breakdown</h2>
<div class="panels">
  <div class="panel"><h3>By category</h3>
    {% for cat, n in category_counts %}
    <div class="row"><span class="k">{{ cat }}</span>
      <span class="t"><i style="width:{{ '%.1f'|format(n / total * 100 if total else 0) }}%"></i></span>
      <span class="v">{{ n }}</span></div>
    {% else %}<p class="loc">No findings.</p>{% endfor %}
  </div>
  <div class="panel"><h3>By tool</h3>
    {% for tool, n in tool_counts %}
    <div class="row"><span class="k">{{ tool }}</span>
      <span class="t"><i style="width:{{ '%.1f'|format(n / total * 100 if total else 0) }}%"></i></span>
      <span class="v">{{ n }}</span></div>
    {% else %}<p class="loc">No findings.</p>{% endfor %}
  </div>
</div>

<h2>Reports</h2>
<div class="chips">
  {% for r in reports_found %}<span class="chip ok">✓ {{ r }}</span>{% endfor %}
  {% for r in reports_missing %}<span class="chip warn">– {{ r }}</span>{% endfor %}
  {% for r in reports_errored %}<span class="chip err">! {{ r }}</span>{% endfor %}
  {% if not reports_found and not reports_missing and not reports_errored %}<span class="chip">none</span>{% endif %}
</div>

<h2>Top findings <span style="text-transform:none;color:var(--muted);font-weight:400">(up to {{ top_n }})</span></h2>
{% if top_findings %}
<table>
  <thead><tr><th>Severity</th><th>Tools</th><th>Category</th><th>Rule</th><th>Location</th></tr></thead>
  <tbody>
  {% for f in top_findings %}
    <tr>
      <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td class="tool">{{ f.tools | join(", ") }}</td>
      <td>{{ f.category }}</td>
      <td><code>{{ f.rule_id }}</code>{% if f.aliases %}<br><span class="loc">{{ f.aliases | join(", ") }}</span>{% endif %}</td>
      <td class="loc">{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p class="loc">No findings 🎉</p>{% endif %}

<footer>Native per-tool reports are in <code>reports/native/</code>;
consolidated machine output in <code>reports/findings.json</code>.</footer>

</div></body></html>
"""

_TOP_N = 50


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-_RANK[f.severity], f.category, f.file))


def _context(result: ScanResult, policy: PolicyResult, findings: list[Finding],
             stats: DedupStats, suppressed_count: int) -> dict:
    total = sum(policy.severity_counts.values())
    top = _sort_findings(findings)[:_TOP_N]
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "policy": policy,
        "stats": stats,
        "suppressed_count": suppressed_count,
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


def render(result: ScanResult, policy: PolicyResult, findings: list[Finding],
           stats: DedupStats, out_dir: str = "/reports",
           suppressed_count: int = 0) -> None:
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    ctx = _context(result, policy, findings, stats, suppressed_count)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(env.from_string(_MD_TEMPLATE).render(**ctx))

    html_env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    (out / "summary.html").write_text(html_env.from_string(_HTML_TEMPLATE).render(**ctx))
