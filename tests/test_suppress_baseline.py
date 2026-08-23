import json

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
    kept, suppressed = apply([finding], [{"rule": "CVE-2018-1000656",
                                          "reason": "accepted"}])
    assert kept == [] and suppressed[0].reason == "accepted"


def test_all_present_fields_must_match():
    entry = [{"rule": "CVE-1", "category": "secrets", "reason": "r"}]
    kept, suppressed = apply([f()], entry)      # category differs
    assert len(kept) == 1 and suppressed == []


def test_file_glob():
    kept, _ = apply([f(file="tests/fixture.py")], [{"file": "tests/*", "reason": "r"}])
    assert kept == []


def test_empty_entry_never_matches_everything():
    kept, suppressed = apply([f()], [{"reason": "oops"}])
    assert len(kept) == 1 and suppressed == []


def test_no_rules_is_a_passthrough():
    kept, suppressed = apply([f()], [])
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
