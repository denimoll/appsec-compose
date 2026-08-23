import pytest

from config import Config, load_config
from normalize import Finding
from policy import evaluate


def f(category, severity, tool="t"):
    return Finding(tool, category, "r", severity, "m", "a.py", 1)


def test_scalar_fail_on_gates_every_category_the_same():
    cfg = Config(fail_on="high")
    r = evaluate([f("sast", "high"), f("iac", "medium")], cfg)
    assert r.breaching == 1 and r.exit_code == 1 and r.label == "high"


def test_fail_on_none_never_fails():
    r = evaluate([f("sast", "critical")], Config(fail_on="none"))
    assert r.breaching == 0 and r.exit_code == 0


def test_per_category_thresholds_apply_independently():
    cfg = Config(fail_on="high", fail_on_by_category={
        "secrets": "low", "iac": "none", "sast": "critical"})
    findings = [
        f("secrets", "low"),       # breaches: secrets gate is low
        f("iac", "critical"),      # does not: iac is report-only
        f("sast", "high"),         # does not: sast gate is critical
        f("sast", "critical"),     # breaches
        f("sca", "high"),          # breaches via the default
    ]
    r = evaluate(findings, cfg)
    assert r.breaching == 3 and r.exit_code == 1
    assert "iac=none" in r.label and "default=high" in r.label


def test_counts_come_from_kept_findings_and_tool_counts_from_raw():
    kept = [f("sca", "high")]
    raw = [f("sca", "high", tool="trivy"), f("sca", "high", tool="grype")]
    r = evaluate(kept, Config(), raw_findings=raw)
    assert r.severity_counts["high"] == 1
    assert r.tool_counts == {"trivy": 1, "grype": 1}


def test_gate_findings_narrow_the_gate_but_not_the_counts():
    kept = [f("sca", "critical"), f("sca", "critical")]
    r = evaluate(kept, Config(fail_on="high"), gate_findings=[])   # baseline mode
    assert r.severity_counts["critical"] == 2
    assert r.breaching == 0 and r.exit_code == 0


def test_unknown_severity_is_resolved_before_comparison():
    finding = f("sast", "bogus")
    r = evaluate([finding], Config(fail_on="high", unknown_severity="critical"))
    assert finding.severity == "critical" and r.breaching == 1


def _write(tmp_path, body):
    p = tmp_path / "scan-config.yml"
    p.write_text(body)
    return str(p)


def test_load_config_accepts_a_per_category_map(tmp_path):
    cfg = load_config(_write(tmp_path, """
fail_on:
  secrets: low
  iac: none
  default: medium
"""))
    assert cfg.fail_on == "medium"
    assert cfg.threshold_for("secrets") == "low"
    assert cfg.threshold_for("iac") == "none"
    assert cfg.threshold_for("sca") == "medium"


def test_load_config_defaults_the_map_default_to_high(tmp_path):
    cfg = load_config(_write(tmp_path, "fail_on:\n  secrets: low\n"))
    assert cfg.fail_on == "high"


def test_env_fail_on_overrides_the_whole_map(tmp_path, monkeypatch):
    monkeypatch.setenv("FAIL_ON", "critical")
    cfg = load_config(_write(tmp_path, "fail_on:\n  secrets: low\n"))
    assert cfg.fail_on == "critical" and cfg.fail_on_by_category == {}


def test_strict_env_overrides_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ASS_STRICT", "1")
    assert load_config(_write(tmp_path, "strict: false\n")).strict is True


def test_invalid_level_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Invalid fail_on"):
        load_config(_write(tmp_path, "fail_on: catastrophic\n"))


def test_unknown_category_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unknown fail_on category"):
        load_config(_write(tmp_path, "fail_on:\n  secret: low\n"))


def test_shipped_config_is_valid():
    cfg = load_config("scan-config.yml")
    assert cfg.fail_on in {"critical", "high", "medium", "low", "none"}
