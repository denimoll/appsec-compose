import pytest

from schema import check, validate


def test_a_valid_config_has_no_problems():
    assert validate({"fail_on": "high", "scanners": {"trivy": {"enabled": True}}}) == []


@pytest.mark.parametrize("raw,fragment", [
    ({"fail_on_severity": "high"}, "did you mean 'fail_on'"),
    ({"strickt": True}, "did you mean 'strict'"),
    ({"excludes": []}, "did you mean 'exclude'"),
    ({"sbom_format": []}, "did you mean 'sbom_formats'"),
    ({"secrets_history_rage": ""}, "did you mean 'secrets_history_range'"),
])
def test_top_level_typos_are_caught_with_a_suggestion(raw, fragment):
    problems = validate(raw)
    assert len(problems) == 1 and fragment in problems[0]


def test_a_suffixed_key_points_at_the_key_it_extends():
    """Edit distance alone maps fail_on_severity to unknown_severity. It should not."""
    assert "'fail_on'" in validate({"fail_on_severity": "high"})[0]


def test_nested_typos_are_caught():
    assert "scanners.trivy" in validate(
        {"scanners": {"trivy": {"enabeld": True}}})[0]
    assert "enrich: unknown key 'cve-paas'" in validate(
        {"enrich": {"cve-paas": {}}})[0]
    assert "enrich.cve_paas" in validate(
        {"enrich": {"cve_paas": {"moad": "annotate"}}})[0]
    assert "ignore[0]" in validate({"ignore": [{"expiers": "2026-01-01"}]})[0]
    assert "fail_on: unknown key 'sast_'" in validate({"fail_on": {"sast_": "low"}})[0]


def test_an_unknown_scanner_is_caught_when_the_tool_list_is_known():
    assert validate({"scanners": {"semgrap": {}}}) == []          # not checked
    problems = validate({"scanners": {"semgrap": {}}}, {"semgrep", "trivy"})
    assert "did you mean 'semgrep'" in problems[0]


def test_every_problem_is_reported_at_once():
    problems = validate({"strickt": True, "excludes": [],
                         "scanners": {"trivy": {"enabeld": True}}})
    assert len(problems) == 3


def test_wrong_types_are_reported():
    assert "expected a list" in validate({"exclude": "node_modules"})[0]
    assert "expected a mapping" in validate({"scanners": ["trivy"]})[0]
    assert "top level" in validate(["nope"])[0]


def test_check_raises_with_all_problems_in_the_message():
    with pytest.raises(ValueError) as excinfo:
        check({"strickt": True, "excludes": []})
    assert "strickt" in str(excinfo.value) and "excludes" in str(excinfo.value)


def test_the_shipped_config_passes_its_own_schema():
    import yaml
    from pathlib import Path
    raw = yaml.safe_load((Path(__file__).resolve().parent.parent
                          / "scan-config.yml").read_text())
    assert validate(raw) == []
