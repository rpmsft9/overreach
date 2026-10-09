import os

from overreach import collect_dcspm

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-dcspm.json")


def test_load_findings_maps_each_recommendation():
    findings = collect_dcspm.load_findings(FIXTURE)
    assert len(findings) == 4
    rules = {f.rule for f in findings}
    assert rules == {"DCSPM-OVERPROV", "DCSPM-UNUSED", "DCSPM-SUPER", "DCSPM-STALE"}
    # all DCSPM findings are tagged as resource-plane and high confidence
    assert all(f.source == "defender-cspm" for f in findings)
    assert all(f.confidence == "high" for f in findings)


def test_classify_matches_display_names():
    assert collect_dcspm._classify("... overprovisioned identities ...")[0] == "DCSPM-OVERPROV"
    assert collect_dcspm._classify("Unused identities should be removed")[0] == "DCSPM-UNUSED"
    assert collect_dcspm._classify("Super identities should be removed")[0] == "DCSPM-SUPER"
    assert collect_dcspm._classify("Stale accounts with owner permissions")[0] == "DCSPM-STALE"
    assert collect_dcspm._classify("something else entirely")[0] == "DCSPM"


def test_severity_mapping():
    findings = collect_dcspm.load_findings(FIXTURE)
    by_rule = {f.rule: f for f in findings}
    assert by_rule["DCSPM-OVERPROV"].severity == "high"
    assert by_rule["DCSPM-UNUSED"].severity == "medium"
