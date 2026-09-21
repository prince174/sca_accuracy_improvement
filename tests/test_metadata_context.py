import copy
import json

import pytest

from sca_accuracy.catalog import observations_from_catalog
from sca_accuracy.llm import scoring_batches
from sca_accuracy.metadata import metadata_evidence
from sca_accuracy.scoring import component_catalog, validate_scores


def artifact(purl, path, metadata):
    return {
        "id": purl,
        "purl": purl,
        "name": "scanner-label",
        "version": "1",
        "locations": [{"path": path}],
        "foundBy": "fixture-cataloger",
        "metadataType": "fixture",
        "metadata": metadata,
    }


def test_manifest_and_embedded_identity_reach_model_without_changing_scanner_identity():
    artifacts = [
        artifact(
            "pkg:maven/alias/alias@1",
            "/app/a.jar",
            {
                "manifest": {
                    "main": [
                        {"key": "Implementation-Title", "value": "actual-library"},
                        {"key": "Private-Token", "value": "do-not-forward"},
                    ]
                },
            },
        ),
        artifact(
            "pkg:maven/org.example/actual-library@1",
            "/app/a.jar",
            {
                "pomProperties": {
                    "groupId": "org.example",
                    "artifactId": "actual-library",
                    "version": "1",
                },
            },
        ),
    ]
    original = copy.deepcopy(artifacts)
    obs = observations_from_catalog({"artifacts": artifacts})
    catalog = component_catalog({"components": []}, obs)
    assert len(catalog) == 2  # Conflicting labels are shown to the model, not silently deleted.
    assert catalog[0]["identity"] == "pkg:maven/alias/alias@1"
    assert "actual-library" in json.dumps(catalog[0]["evidence"][0]["scanner_metadata"])
    assert "do-not-forward" not in json.dumps(catalog)
    assert catalog[0]["evidence"][-1]["candidates"][0]["relations"] == ["same_image_location"]
    assert artifacts == original
    batch = scoring_batches({"components": catalog}, batch_size=1)[0]
    assert len(batch["components"]) == 1
    relation = batch["components"][0]["evidence"][-1]
    assert relation["candidates"][0]["identity"] == catalog[1]["identity"]
    validate_scores(
        batch["components"],
        [
            {
                "component_id": catalog[0]["id"],
                "tp_score": 50,
                "reason": "Compare labels",
                "evidence_ids": [relation["id"]],
                "missing_evidence": [],
            }
        ],
    )


def test_declared_old_version_can_cite_observed_version_even_in_another_batch():
    bom = {"components": [{"name": "demo", "purl": "pkg:npm/demo@1"}]}
    obs = observations_from_catalog(
        {
            "artifacts": [
                artifact(
                    "pkg:npm/demo@2",
                    "/app/node_modules/demo/package.json",
                    {"name": "demo", "version": "2"},
                ),
                artifact("pkg:pypi/demo@3", "/other", {"name": "demo", "version": "3"}),
            ]
        }
    )
    catalog = component_catalog(bom, obs)
    relation = catalog[0]["evidence"][-1]
    assert [c["identity"] for c in relation["candidates"]] == ["pkg:npm/demo@2"]
    assert relation["candidates"][0]["relations"] == ["same_package_other_version"]


def test_source_only_and_unknown_locations_do_not_manufacture_image_conflicts():
    obs = observations_from_catalog(
        {
            "artifacts": [
                artifact("pkg:npm/a@1", "unknown", {}),
                artifact("pkg:npm/b@1", "unknown", {}),
            ]
        }
    )
    source = observations_from_catalog({"artifacts": [artifact("pkg:npm/a@2", "unknown", {})]})
    catalog = component_catalog({}, obs, source)
    assert len(catalog) == 2
    assert all(len(c["evidence"]) == 1 for c in catalog)


def test_shaded_archive_comparisons_are_bounded_and_not_a_deduplication_verdict():
    obs = observations_from_catalog(
        {"artifacts": [artifact(f"pkg:maven/org/a{i}@1", "/app/shaded.jar", {}) for i in range(12)]}
    )
    catalog = component_catalog({}, obs)
    assert len(catalog) == 12
    for c in catalog:
        relation = c["evidence"][-1]
        assert len(relation["candidates"]) == 8
        assert relation["candidates_truncated"] is True
        assert "do not prove exclusion" in relation["scope"]


def test_metadata_projection_is_bounded_and_hash_changes_with_omitted_fields():
    a = artifact("pkg:npm/a@1", "/a", {"name": "я" * 5000, "unselected": "a"})
    evidence = metadata_evidence(a)
    assert evidence["projection_truncated"] is True
    assert len(evidence["identity_metadata"]) == 4000
    a["metadata"]["unselected"] = "b"
    assert evidence["metadata_sha256"] != metadata_evidence(a)["metadata_sha256"]


def test_byte_limited_batches_preserve_every_component_and_context():
    payload = {
        "digest": "fixed",
        "components": [{"id": str(i), "value": "я" * 100} for i in range(5)],
    }
    batches = scoring_batches(payload, max_bytes=600)
    assert [len(b["components"]) for b in batches] == [2, 2, 1]
    assert [c for b in batches for c in b["components"]] == payload["components"]
    assert all(len(json.dumps(b, ensure_ascii=False).encode()) <= 600 for b in batches)
    assert all(b["digest"] == "fixed" for b in batches)
    with pytest.raises(ValueError, match="Single component"):
        scoring_batches(payload, max_bytes=100)
