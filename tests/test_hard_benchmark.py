import json

from sca_accuracy.benchmark import evaluate_case, prepare
from sca_accuracy.hard_benchmark import dataset, evidence_rules, hard_case


def test_hard_corpus_covers_ecosystems_and_strong_false_observations():
    cases = dataset()
    assert len(cases) == 194
    assert len({c["id"] for c in cases}) == 194
    assert len({c["ecosystem"] for c in cases}) == 12
    for ecosystem in {c["ecosystem"] for c in cases}:
        orphan = hard_case(ecosystem, "orphan_metadata", 1)
        assert evaluate_case(orphan)["allowed_rules"]["fp"] == 1
        stale = evaluate_case(hard_case(ecosystem, "stale_version", 1))
        assert stale["allowed_rules"]["fp"] == 1
        assert stale["allowed_rules"]["fn"] == 1


def test_model_input_has_facts_but_not_ground_truth_or_split():
    for case in dataset():
        payload = prepare(case)[3]
        encoded = json.dumps(payload)
        assert "expected_purls" not in encoded
        assert "evaluation_group" not in encoded
        assert case["id"] not in encoded
        assert "artifact_evidence" in payload
        assert "runtime_execution" in encoded


def test_missing_metadata_never_turns_into_invented_candidate():
    for family in ("stripped", "vendored", "shaded"):
        case = hard_case("maven", family, 1)
        assert prepare(case)[3]["candidates"] == []
        assert evaluate_case(case)["allowed_rules"]["fn"] == 1


def test_same_input_rules_require_explicit_contradictions_at_all_locations():
    orphan = hard_case("npm", "orphan_metadata", 1)
    assert evidence_rules(orphan)["fp"] == 0
    orphan["artifact_evidence"]["packages"][0]["file_listing_complete_under_package_root"] = False
    assert evidence_rules(orphan)["fp"] == 1
    stale = hard_case("npm", "stale_version", 1)
    assert evidence_rules(stale)["fp"] == 0
    assert evidence_rules(stale)["fn"] == 1
    assert evidence_rules(hard_case("npm", "source_drift", 1))["fn"] == 0
    for family in ("installed", "multiple_versions", "path_injection"):
        assert evidence_rules(hard_case("npm", family, 1))["fn"] == 0
