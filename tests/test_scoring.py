import copy

import pytest

from sca_accuracy.models import ComponentIdentity, Observation
from sca_accuracy.scoring import component_catalog, filter_sbom


def component(name, ref=None, children=None):
    return {
        "type": "library",
        "name": name,
        "version": "1",
        "purl": f"pkg:npm/{name}@1",
        "bom-ref": ref or name,
        **({"components": children} if children is not None else {}),
    }


def scores(bom, obs=(), values=None, source=()):
    return [
        {
            "component_id": c["id"],
            "tp_score": (values or {}).get(c["component"]["name"], 95),
            "reason": "Controlled test evidence",
            "evidence_ids": [c["evidence"][0]["id"]],
            "missing_evidence": [],
        }
        for c in component_catalog(bom, obs, source)
    ]


def test_strict_threshold_preserves_original_and_all_assessments():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [component(n) for n in ("a", "b", "c", "d")],
    }
    original = copy.deepcopy(bom)
    result, audit = filter_sbom(
        bom, [], scores(bom, values={"a": 70, "b": 70.01, "c": 0, "d": 100})
    )
    assert [c["name"] for c in result["components"]] == ["b", "d"]
    assert len(audit["assessments"]) == 4
    assert audit["components_removed"] == 2
    assert bom == original
    assert result["version"] == 2


@pytest.mark.parametrize("score", [-1, 101, True, "90", None, float("nan"), float("inf")])
def test_invalid_scores_fail_without_publishing(score):
    bom = {"components": [component("a")]}
    with pytest.raises(ValueError, match="finite number"):
        filter_sbom(bom, [], scores(bom, values={"a": score}))


@pytest.mark.parametrize("invalid", ["missing", "duplicate", "invented", "extra", "evidence"])
def test_incomplete_or_invented_assessments_are_not_silently_filtered(invalid):
    bom = {"components": [component("a"), component("b")]}
    plan = scores(bom)
    if invalid == "missing":
        plan.pop()
    elif invalid == "duplicate":
        plan[1] = plan[0]
    elif invalid == "invented":
        plan[0]["component_id"] = "made-up"
    elif invalid == "extra":
        plan[0]["action"] = "remove"
    else:
        plan[0]["evidence_ids"] = ["unknown-evidence"]
    with pytest.raises(ValueError):
        filter_sbom(bom, [], plan)


def test_nested_child_and_subject_survive_removed_parents():
    bom = {
        "metadata": {"component": component("subject", children=[component("nested")])},
        "components": [component("parent", children=[component("child")])],
    }
    catalog = component_catalog(bom, [])
    assert {c["component"]["name"] for c in catalog} == {"nested", "parent", "child"}
    result, _ = filter_sbom(bom, [], scores(bom, values={"parent": 10, "nested": 10}))
    assert result["metadata"]["component"]["name"] == "subject"
    assert result["metadata"]["component"]["components"] == []
    assert [c["name"] for c in result["components"]] == ["child"]


def test_observed_components_are_scored_and_added_without_inventing_names():
    obs = [Observation(ComponentIdentity("", "image-only", "2", "npm"), "/app/pkg", "syft")]
    bom = {"components": []}
    result, audit = filter_sbom(bom, obs, scores(bom, obs))
    assert result["components"][0]["purl"] == "pkg:npm/image-only@2"
    assert audit["components_added"] == 1
    assert filter_sbom(bom, obs, scores(bom, obs, {"image-only": 70}))[0]["components"] == []


def test_source_only_packages_are_context_not_delivery_candidates():
    bom = {"components": [component("a")]}
    source = [
        Observation(ComponentIdentity("", n, "1", "npm"), "/src", "syft") for n in ("a", "dev-only")
    ]
    catalog = component_catalog(bom, [], source)
    assert len(catalog) == 1
    assert {e["origin"] for e in catalog[0]["evidence"]} == {"build_sbom", "source_checkout"}


def test_reference_cleanup_does_not_assert_not_affected_or_rewire_dependencies():
    bom = {
        "components": [component("a"), component("b")],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}, {"ref": "b", "dependsOn": []}],
        "vulnerabilities": [
            {"bom-ref": "v1", "id": "TEST-1", "affects": [{"ref": "b"}]},
            {"id": "TEST-2", "affects": [{"ref": "a"}, {"ref": "b"}]},
        ],
        "compositions": [
            {"aggregate": "complete", "assemblies": ["a", "b"], "vulnerabilities": ["v1"]}
        ],
        "annotations": [
            {"subjects": ["b"], "text": "removed"},
            {"subjects": ["a", "b"], "text": "kept"},
        ],
        "signature": {"value": "old"},
    }
    result, audit = filter_sbom(bom, [], scores(bom, values={"b": 10}))
    assert result["dependencies"] == [{"ref": "a", "dependsOn": []}]
    assert result["vulnerabilities"] == [{"id": "TEST-2", "affects": [{"ref": "a"}]}]
    assert result["compositions"][0]["aggregate"] == "unknown"
    assert result["annotations"] == [{"subjects": ["a"], "text": "kept"}]
    assert audit["references_pruned"]["signatures"] == 1
    assert "signature" not in result
    assert len(bom["vulnerabilities"]) == 2


def test_unknown_reference_structures_fail_closed():
    bom = {"components": [component("a")], "formulation": [{"workflow": {"ref": "a"}}]}
    with pytest.raises(ValueError, match="Unsupported reference"):
        filter_sbom(bom, [], scores(bom, values={"a": 0}))


def test_duplicate_purls_share_score_but_duplicate_refs_are_rejected():
    bom = {"components": [component("a", "first"), component("a", "second")]}
    assert len(component_catalog(bom, [])) == 1
    assert len(filter_sbom(bom, [], scores(bom))[0]["components"]) == 2
    bom["components"][1]["bom-ref"] = "first"
    with pytest.raises(ValueError, match="unique"):
        filter_sbom(bom, [], scores(bom))
