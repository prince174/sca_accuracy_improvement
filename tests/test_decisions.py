import copy
import json
from unittest.mock import patch

import pytest

from sca_accuracy.decisions import apply_plan, candidates
from sca_accuracy.llm import LlmConfig
from sca_accuracy.models import ComponentIdentity, Observation
from sca_accuracy.pipeline import AnalysisConfig, run_analysis


def fixture():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "demo",
                "version": "1",
                "purl": "pkg:maven/org/demo@1",
                "bom-ref": "stable",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            }
        ],
        "dependencies": [{"ref": "stable", "dependsOn": []}],
    }
    observation = Observation(
        ComponentIdentity("org", "demo", "2"), "/app/demo.jar", "jar-metadata", "a" * 64
    )
    return bom, [observation]


def plan_for(bom, observations):
    return [
        {"candidate_id": c["id"], "action": "apply", "reason": "metadata and hash"}
        for c in candidates(bom, observations)
    ]


def test_hash_correction_removes_wrong_version_preserves_graph_and_original():
    bom, obs = fixture()
    original = copy.deepcopy(bom)
    result, audit = apply_plan(bom, obs, plan_for(bom, obs))
    assert bom == original
    assert len(result["components"]) == 1
    assert result["components"][0]["purl"] == "pkg:maven/org/demo@2"
    assert result["dependencies"] == bom["dependencies"]
    assert audit["accepted"][0]["before"]["version"] == "1"
    assert result["version"] == 2


@pytest.mark.parametrize(
    "condition", ["no_hash", "weak", "ambiguous", "old_present", "vulnerabilities"]
)
def test_correction_requires_unambiguous_hash_evidence(condition):
    bom, obs = fixture()
    if condition == "no_hash":
        obs[0].sha256 = None
    elif condition == "weak":
        obs[0].confidence = 0.45
    elif condition == "ambiguous":
        obs.append(
            Observation(ComponentIdentity("org", "other", "3"), "/other", "metadata", "a" * 64)
        )
    elif condition == "old_present":
        obs.append(Observation(ComponentIdentity("org", "demo", "1"), "/old", "metadata"))
    else:
        bom["vulnerabilities"] = [{"id": "CVE-test", "affects": [{"ref": "stable"}]}]
    assert all(c["operation"] != "replace_identity" for c in candidates(bom, obs))


@pytest.mark.parametrize(
    "bad", [{"candidate_id": []}, {"operation": "remove", "bom_ref": "stable"}, None, "delete all"]
)
def test_untrusted_model_cannot_edit_arbitrary_fields(bad):
    bom, obs = fixture()
    result, audit = apply_plan(bom, obs, [bad])
    assert result == bom
    assert len(audit["rejected"]) == 1


@pytest.mark.parametrize(
    "ecosystem",
    ["maven", "npm", "pypi", "nuget", "golang", "cargo", "gem", "composer", "apk", "deb"],
)
def test_additions_are_ecosystem_neutral_and_model_can_defer(ecosystem):
    bom = {"components": []}
    obs = [Observation(ComponentIdentity("", "demo", "1", ecosystem), "/app/demo", "metadata")]
    plan = plan_for(bom, obs)
    result, audit = apply_plan(bom, obs, plan)
    assert result["components"][0]["purl"] == obs[0].identity.purl
    assert len(audit["accepted"]) == 1
    plan[0]["action"] = "defer"
    assert apply_plan(bom, obs, plan)[0] == bom


def test_pipeline_model_plan_changes_real_output(tmp_path):
    bom, obs = fixture()
    path = tmp_path / "input.json"
    path.write_text(json.dumps(bom))
    config = AnalysisConfig(path, "demo:latest", tmp_path / "result", with_llm=True)

    def model(payload, config):
        assert payload["candidates"]
        return {
            "summary": "correct",
            "hypotheses": [],
            "warnings": [],
            "decisions": plan_for(bom, obs),
        }

    with (
        patch(
            "sca_accuracy.pipeline.inspect_image",
            return_value=("sha256:test", obs, {"artifacts": []}),
        ),
        patch("sca_accuracy.pipeline.analyze", side_effect=model),
        patch("sca_accuracy.pipeline.LlmConfig.from_environment", return_value=LlmConfig("test")),
    ):
        result = run_analysis(config)
    output = json.loads((config.output / "sbom.enriched.json").read_text())
    assert output["components"][0]["version"] == "2"
    assert result["changes_applied"] == 1
    assert json.loads((config.output / "sbom.original.json").read_text()) == bom
    assert json.loads((config.output / "assessment.json").read_text())["decisions"]["accepted"]


def test_model_defer_is_not_overridden_by_automatic_enrichment(tmp_path):
    bom, obs = fixture()
    path = tmp_path / "input.json"
    path.write_text(json.dumps(bom))
    with (
        patch(
            "sca_accuracy.pipeline.inspect_image", return_value=("digest", obs, {"artifacts": []})
        ),
        patch("sca_accuracy.pipeline.analyze", return_value={"summary": "defer", "decisions": []}),
        patch("sca_accuracy.pipeline.LlmConfig.from_environment", return_value=LlmConfig("test")),
    ):
        run_analysis(AnalysisConfig(path, "demo", tmp_path / "out", with_llm=True))
    output = json.loads((tmp_path / "out/sbom.enriched.json").read_text())
    assert len(output["components"]) == 1
    assert output["components"][0]["version"] == "1"


def test_malformed_action_and_duplicate_are_audited():
    bom, obs = fixture()
    plan = plan_for(bom, obs)
    bad = {**plan[0], "action": []}
    result, audit = apply_plan(bom, obs, [bad, plan[0], plan[0]])
    assert len(audit["rejected"]) == 2
    assert len(result["components"]) == 2


def test_model_contract_requires_decisions():
    from sca_accuracy.llm import _extract_json

    with pytest.raises(TypeError, match="decisions"):
        _extract_json(json.dumps({"summary": "ok", "hypotheses": [], "warnings": []}))
