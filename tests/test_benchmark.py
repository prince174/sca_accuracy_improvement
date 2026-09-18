import json
from argparse import Namespace
from unittest.mock import patch

import pytest

from sca_accuracy.benchmark import (
    ECOSYSTEMS,
    FAMILIES,
    JAVA_FAMILIES,
    aggregate,
    evaluate_case,
    generate,
    make_case,
    prepare,
    run,
)


def test_generator_is_deterministic_and_covers_every_family():
    cases = generate(3)
    assert cases == generate(3)
    assert len(cases) == 3 * (len(ECOSYSTEMS) * len(FAMILIES) + len(JAVA_FAMILIES)) == 588
    assert len({c["id"] for c in cases}) == len(cases)
    assert all(c["ecosystem"] == "maven" for c in cases if c["family"] in JAVA_FAMILIES)


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_all_ecosystems_preserve_truth_and_prohibit_absence_deletion(ecosystem):
    exact = evaluate_case(make_case(ecosystem, "exact", 0))
    assert exact["allowed_rules"] == {"tp": 1, "fp": 0, "fn": 0, "unresolved": 0}
    absent = evaluate_case(make_case(ecosystem, "absent", 0))
    hidden = evaluate_case(make_case(ecosystem, "hidden_metadata", 0))
    assert absent["allowed_rules"]["fp"] == 1
    assert hidden["allowed_rules"]["tp"] == 1
    assert absent["candidate_count"] == hidden["candidate_count"] == 0
    weak = evaluate_case(make_case(ecosystem, "weak_false_identity", 0))
    assert weak["allowed_rules"]["fp"] == 0


def test_ground_truth_and_family_are_not_in_model_payload():
    case = make_case("maven", "hash_correction", 0)
    *_, payload = prepare(case)
    assert "expected_purls" not in json.dumps(payload)
    assert "truth_source" not in json.dumps(payload)
    assert "hash_correction" not in json.dumps(payload)
    assert "family" not in payload


def test_equal_capability_baseline_applies_same_candidates():
    case = make_case("maven", "hash_correction", 0)
    *_, payload = prepare(case)
    response = {
        "decisions": [
            {"candidate_id": c["id"], "action": "apply", "reason": "test"}
            for c in payload["candidates"]
        ]
    }
    row = evaluate_case(case, response)
    assert row["allowed_rules"] == row["model"]
    assert row["model"] == {"tp": 1, "fp": 0, "fn": 0, "unresolved": 0}


def test_aggregate_does_not_mix_missing_model_results():
    rows = [
        evaluate_case(make_case("maven", "exact", 0), {"decisions": []}),
        evaluate_case(make_case("npm", "exact", 0)),
    ]
    result = aggregate(rows, ("model", "legacy_rules"))
    assert result["model"]["cases"] == 1
    assert result["legacy_rules"]["cases"] == 2


def test_live_checkpoint_resume_and_failures_are_explicit(tmp_path):
    from sca_accuracy.llm import LlmConfig

    cases = [make_case("maven", "undeclared", 0), make_case("maven", "absent", 0)]
    args = Namespace(
        variants=1,
        live=True,
        live_variants=1,
        output=tmp_path,
        persist=False,
        max_calls=10,
        workers=2,
    )

    def model(payload, config):
        return {
            "summary": "ok",
            "hypotheses": [],
            "warnings": [],
            "decisions": [
                {"candidate_id": c["id"], "action": "apply", "reason": "test"}
                for c in payload["candidates"]
            ],
        }

    with (
        patch("sca_accuracy.benchmark.generate", return_value=cases),
        patch(
            "sca_accuracy.benchmark.LlmConfig.from_environment", return_value=LlmConfig("SECRET")
        ),
        patch("sca_accuracy.benchmark.analyze", side_effect=model) as call,
    ):
        assert run(args) == 0
        assert run(args) == 0
        assert call.call_count == 1
    report = json.loads((tmp_path / "report.json").read_bytes())
    assert report["paired_live"]["model"]["cases"] == 2
    assert report["paired_model_called"]["model"]["cases"] == 1
    assert "SECRET" not in (tmp_path / "report.json").read_text()


def test_live_call_budget_prevents_requests(tmp_path):
    from sca_accuracy.llm import LlmConfig

    args = Namespace(
        variants=1,
        live=True,
        live_variants=1,
        output=tmp_path,
        persist=False,
        max_calls=0,
        workers=1,
    )
    with (
        patch("sca_accuracy.benchmark.LlmConfig.from_environment", return_value=LlmConfig("test")),
        patch("sca_accuracy.benchmark.analyze") as call,
    ):
        with pytest.raises(ValueError, match="exceeds"):
            run(args)
        call.assert_not_called()
