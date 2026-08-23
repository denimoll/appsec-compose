import json

from converters import trufflehog_json_to_sarif


def test_returns_false_when_the_tool_did_not_run(tmp_path):
    assert trufflehog_json_to_sarif(tmp_path / "none.json",
                                    tmp_path / "out.sarif") is False


def test_empty_input_still_yields_a_valid_empty_sarif(tmp_path):
    src, dst = tmp_path / "th.json", tmp_path / "th.sarif"
    src.write_text("")
    assert trufflehog_json_to_sarif(src, dst) is True
    assert json.loads(dst.read_text())["runs"][0]["results"] == []


def test_verified_and_unverified_secrets_get_different_severities(tmp_path):
    src, dst = tmp_path / "th.json", tmp_path / "th.sarif"
    src.write_text("\n".join(json.dumps(r) for r in [
        {"DetectorName": "AWS", "Verified": True,
         "SourceMetadata": {"Data": {"Filesystem": {"file": "/code/a.env", "line": 2}}}},
        {"DetectorName": "Slack", "Verified": False,
         "SourceMetadata": {"Data": {"Filesystem": {"file": "/code/b.env"}}}},
        "not a finding",
        "{broken json",
    ]))
    trufflehog_json_to_sarif(src, dst)
    results = json.loads(dst.read_text())["runs"][0]["results"]
    assert len(results) == 2                       # log lines and junk skipped
    assert results[0]["level"] == "error"
    assert results[0]["properties"]["security-severity"] == "9.5"
    assert results[1]["level"] == "warning"
    assert results[1]["properties"]["security-severity"] == "7.5"
