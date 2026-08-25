import json

from datetime import date

import pytest

import baseline as bl
from normalize import Finding
from suppress import apply


def f(**kw):
    base = dict(tool="trivy", category="sca", rule_id="CVE-1", severity="high",
                message="m", file="app.py", line=1, package="flask@1.0")
    base.update(kw)
    return Finding(**base)


def test_rule_glob_matches_aliases_too():
    finding = f(rule_id="GHSA-xxxx", aliases=["CVE-2018-1000656"])
    kept, suppressed, _ = apply([finding], [{"rule": "CVE-2018-1000656",
                                          "reason": "accepted"}])
    assert kept == [] and suppressed[0].reason == "accepted"


def test_all_present_fields_must_match():
    entry = [{"rule": "CVE-1", "category": "secrets", "reason": "r"}]
    kept, suppressed, _ = apply([f()], entry)      # category differs
    assert len(kept) == 1 and suppressed == []


def test_file_glob():
    kept, _, _ = apply([f(file="tests/fixture.py")], [{"file": "tests/*", "reason": "r"}])
    assert kept == []


def test_empty_entry_never_matches_everything():
    kept, suppressed, _ = apply([f()], [{"reason": "oops"}])
    assert len(kept) == 1 and suppressed == []


def test_no_rules_is_a_passthrough():
    kept, suppressed, _ = apply([f()], [])
    assert len(kept) == 1 and suppressed == []


def test_fingerprint_is_stable_and_tool_independent():
    assert bl.fingerprint(f(tool="trivy")) == bl.fingerprint(f(tool="grype"))
    assert bl.fingerprint(f(line=1)) != bl.fingerprint(f(line=2))


def test_fingerprint_ignores_the_code_mount_prefix():
    assert bl.fingerprint(f(file="/code/app.py")) == bl.fingerprint(f(file="app.py"))


def test_classify_splits_new_known_and_counts_fixed():
    known, new = f(rule_id="CVE-1"), f(rule_id="CVE-2")
    accepted = {bl.fingerprint(known), "stale-fingerprint"}
    delta = bl.classify([known, new], accepted)
    assert delta.known == [known] and delta.new == [new] and delta.fixed == 1


def test_save_then_load_roundtrips(tmp_path):
    path = str(tmp_path / "baseline.json")
    assert bl.save(path, [f(), f()]) == 1          # identical findings dedupe
    assert bl.load(path) == {bl.fingerprint(f())}
    assert "generated" in json.loads(open(path).read())


def test_load_tolerates_a_missing_or_corrupt_baseline(tmp_path):
    assert bl.load(str(tmp_path / "nope.json")) == set()
    corrupt = tmp_path / "bad.json"
    corrupt.write_text("{oops")
    assert bl.load(str(corrupt)) == set()


# --- suppression expiry ---------------------------------------------------

def _entry(expires):
    return [{"rule": "CVE-1", "reason": "accepted for now", "expires": expires}]


def test_an_unexpired_entry_still_suppresses():
    kept, suppressed, expired = apply([f()], _entry("2099-01-01"),
                                      today=date(2026, 8, 23))
    assert kept == [] and len(suppressed) == 1 and expired == []


def test_an_expired_entry_stops_suppressing_and_is_reported():
    kept, suppressed, expired = apply([f()], _entry("2026-01-01"),
                                      today=date(2026, 8, 23))
    assert len(kept) == 1 and suppressed == []
    assert [e.expires for e in expired] == ["2026-01-01"]
    assert "rule=CVE-1" in expired[0].label


def test_expiry_is_inclusive_of_its_last_day():
    kept, _, expired = apply([f()], _entry("2026-08-23"), today=date(2026, 8, 23))
    assert kept == [] and expired == []


def test_yaml_may_hand_us_a_real_date_object():
    kept, _, expired = apply([f()], _entry(date(2026, 1, 1)), today=date(2026, 8, 23))
    assert len(kept) == 1 and len(expired) == 1


def test_a_malformed_expiry_is_rejected_loudly():
    with pytest.raises(ValueError, match="expected YYYY-MM-DD"):
        apply([f()], _entry("soon"), today=date(2026, 8, 23))


def test_entries_without_an_expiry_are_unaffected():
    kept, suppressed, expired = apply([f()], [{"rule": "CVE-1", "reason": "r"}],
                                      today=date(2026, 8, 23))
    assert kept == [] and len(suppressed) == 1 and expired == []
