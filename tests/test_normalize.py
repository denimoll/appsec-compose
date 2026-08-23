import json

import pytest

from normalize import (Finding, _clean_path, _severity_from_cvss, expected_reports,
                       load_findings)


@pytest.mark.parametrize("uri,expected", [
    ("/code/app.py", "app.py"),                       # gitleaks, trivy
    ("code/orchestrator/Dockerfile", "orchestrator/Dockerfile"),   # checkov
    ("file:///code/requirements.txt", "requirements.txt"),         # osv
    ("file:///code/a%20b.py", "a b.py"),              # percent-encoded
    ("app.py", "app.py"),                             # already relative
    ("/code", ""),
    ("code", ""),
    ("", ""),
    ("/usr/lib/libssl.so", "/usr/lib/libssl.so"),     # image mode: OS path kept
])
def test_clean_path(uri, expected):
    assert _clean_path(uri) == expected


@pytest.mark.parametrize("score,severity", [
    (9.8, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "info"),
])
def test_severity_from_cvss(score, severity):
    assert _severity_from_cvss(score) == severity


def test_expected_reports_tracks_enabled_scanners():
    assert expected_reports({"trivy"}) == {"trivy-fs.sarif", "trivy-config.sarif"}
    assert expected_reports({"syft"}) == set()       # SBOM only, no findings
    assert expected_reports({"nope"}) == set()


def _sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "t", "rules": rules or []}},
        "results": results,
    }]}


def test_secrets_severity_is_floored_to_high(tmp_path):
    (tmp_path / "gitleaks.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "generic-api-key",
        "level": "note",                              # tool says "low"...
        "message": {"text": "key found"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "/code/a.py"},
            "region": {"startLine": 3}}}],
    }])))
    result = load_findings(str(tmp_path), expected={"gitleaks.sarif"})
    assert [f.severity for f in result.findings] == ["high"]   # ...secrets floor


def test_unreadable_report_is_errored_not_missing(tmp_path):
    (tmp_path / "semgrep.sarif").write_text("{not json")
    result = load_findings(str(tmp_path), expected={"semgrep.sarif"})
    assert result.findings == []
    assert result.reports_found == []
    assert result.reports_missing == []
    assert len(result.reports_errored) == 1


def test_empty_report_counts_as_missing(tmp_path):
    (tmp_path / "semgrep.sarif").write_text("")
    result = load_findings(str(tmp_path), expected={"semgrep.sarif"})
    assert result.reports_missing == ["semgrep.sarif"]


def test_cvss_beats_sarif_level(tmp_path):
    (tmp_path / "trivy-fs.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "CVE-2021-1", "level": "note",
        "message": {"text": "Package: flask\nInstalled Version: 1.0"},
        "properties": {"security-severity": "9.4"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "/code/requirements.txt"}}}],
    }])))
    result = load_findings(str(tmp_path), expected={"trivy-fs.sarif"})
    f = result.findings[0]
    assert f.severity == "critical"
    assert f.package == "flask@1.0"


def test_finding_defaults_tools_to_its_own_tool():
    assert Finding("semgrep", "sast", "r", "high", "m", "a.py", 1).tools == ["semgrep"]
