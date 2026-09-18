import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from sca_accuracy.evidence import EvidenceStore
from sca_accuracy.models import ComponentIdentity, Observation
from sca_accuracy.service import create_app


@pytest.fixture
def store(tmp_path):
    dsn = os.getenv("SCA_TEST_EVIDENCE_DSN")
    if not dsn:
        pytest.skip("Set SCA_TEST_EVIDENCE_DSN to run real PostgreSQL tests")
    schema = "test_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    value = EvidenceStore(
        make_conninfo(dsn, options=f"-c search_path={schema}"), tmp_path / "blobs"
    )
    value.migrate()
    yield value
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "bundle"
    path.mkdir()
    component = {
        "type": "library",
        "name": "demo",
        "version": "1",
        "purl": "pkg:npm/demo@1",
        "bom-ref": "demo",
    }
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [component]}
    obs = Observation(
        ComponentIdentity("", "demo", "1", "npm"), "/demo/package.json", "test", "a" * 64
    )
    documents = {
        "sbom.original.json": bom,
        "sbom.enriched.json": bom,
        "inventory.json": {"generated_at": "first", "observations": [obs.to_dict()]},
        "assessment.json": {"generated_at": "first", "summary": {"confirmed_present": 1}},
        "provenance.json": {
            "repository_url": "https://bitbucket.xxx/a",
            "commit": "c" * 40,
            "image_id": "sha256:123",
        },
    }
    for name, value in documents.items():
        (path / name).write_text(json.dumps(value), encoding="utf-8")
    return path


def test_roundtrip_dedup_search_and_exact_artifacts(store, bundle):
    store.migrate()
    run = store.ingest(bundle)
    assert store.ingest(bundle) == run
    data = json.loads((bundle / "inventory.json").read_text())
    data["generated_at"] = "later"
    (bundle / "inventory.json").write_text(json.dumps(data))
    assert store.ingest(bundle) == run
    assert len(store.get(run)["observations"]) == 3
    assert len(store.search(purl="pkg:npm/demo@1", kind="build")) == 1
    assert (
        len(
            store.search(
                sha256="a" * 64,
                commit="c" * 40,
                repository="https://bitbucket.xxx/a",
                image_id="sha256:123",
            )
        )
        == 1
    )
    assert store.search(purl="' OR TRUE --") == []
    assert store.search(kind="synthetic") == []
    assert (
        store.artifact(run, "sbom.original.json").read_bytes()
        == (bundle / "sbom.original.json").read_bytes()
    )


def test_new_model_and_synthetic_runs_remain_separate(store, bundle):
    first = store.ingest(bundle)
    synthetic = store.ingest(bundle, kind="synthetic")
    (bundle / "analysis-context.json").write_text(
        json.dumps({"model": "another", "prompt_sha256": "x"})
    )
    changed = store.ingest(bundle)
    assert len({first, synthetic, changed}) == 3
    assert len(store.search(limit=1, offset=1)) == 1


def test_concurrent_import_is_idempotent(store, bundle):
    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(lambda _: store.ingest(bundle), range(4)))
    assert len(set(ids)) == 1
    assert len(store.search()) == 1


def test_labels_append_history_and_require_existing_observation(store, bundle):
    run = store.ingest(bundle)
    oid = store.get(run)["observations"][0]["id"]
    store.label(run, oid, "confirmed", "Checked metadata", "reviewer")
    store.label(run, oid, "refuted", "Later contradictory evidence", "second reviewer")
    assert len(store.get(run)["labels"]) == 2
    with pytest.raises(KeyError):
        store.label(run, "unknown", "confirmed", "proof", "reviewer")
    with pytest.raises(ValueError):
        store.label(run, oid, "confirmed", " ", "reviewer")


def test_integrity_failure_cannot_return_modified_artifact(store, bundle):
    run = store.ingest(bundle)
    path = store.artifact(run, "sbom.original.json")
    path.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="integrity"):
        store.artifact(run, "sbom.original.json")
    with pytest.raises(ValueError):
        store.blob_path("../secret")


def test_incomplete_bundle_does_not_create_a_run(store, tmp_path):
    with pytest.raises(ValueError, match="incomplete"):
        store.ingest(tmp_path)
    assert store.search() == []


def test_evidence_api_authentication_labels_and_download(store, bundle, monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_API_TOKEN", "test-api")
    monkeypatch.setenv("SCA_EVIDENCE_DSN", store.dsn)
    monkeypatch.setenv("SCA_EVIDENCE_BLOBS", str(store.blobs))
    run = store.ingest(bundle)
    client = TestClient(create_app(tmp_path / "api"))
    base = "/v2/evidence/runs"
    assert client.get(base).status_code == 401
    headers = {"Authorization": "Bearer test-api"}
    assert (
        client.get(base, headers=headers, params={"purl": "pkg:npm/demo@1"}).json()["runs"][0]["id"]
        == run
    )
    detail = client.get(f"{base}/{run}", headers=headers).json()
    response = client.post(
        f"{base}/{run}/labels",
        headers=headers,
        json={
            "observation_id": detail["observations"][0]["id"],
            "verdict": "confirmed",
            "rationale": "Manual check",
            "reviewer": "alice",
        },
    )
    assert response.status_code == 201
    assert (
        client.get(f"{base}/{run}/artifacts/sbom.original.json", headers=headers).content
        == (bundle / "sbom.original.json").read_bytes()
    )
    assert client.get(f"{base}/unknown", headers=headers).status_code == 404
    assert client.get(base, headers=headers, params={"limit": 101}).status_code == 422


def test_evidence_disabled_without_config(monkeypatch, tmp_path):
    monkeypatch.delenv("SCA_EVIDENCE_DSN", raising=False)
    monkeypatch.setenv("SCA_API_TOKEN", "token")
    client = TestClient(create_app(tmp_path))
    assert (
        client.get("/v2/evidence/runs", headers={"Authorization": "Bearer token"}).status_code
        == 503
    )


def test_service_persists_completed_analysis_with_context(store, bundle, monkeypatch, tmp_path):
    from unittest.mock import patch

    from sca_accuracy.pipeline import AnalysisConfig, run_analysis

    monkeypatch.setenv("SCA_EVIDENCE_DSN", store.dsn)
    monkeypatch.setenv("SCA_EVIDENCE_BLOBS", str(store.blobs))
    observation = Observation(ComponentIdentity("", "demo", "1", "npm"), "/demo", "fixture")
    with patch(
        "sca_accuracy.pipeline.inspect_image",
        return_value=("sha256:123", [observation], {"artifacts": []}),
    ):
        result = run_analysis(
            AnalysisConfig(bundle / "sbom.original.json", "image", tmp_path / "analysis")
        )
    assert result["evidence_id"]
    names = {a["name"] for a in store.get(result["evidence_id"])["artifacts"]}
    assert {"analysis-context.json", "sbom.original.json", "sbom.enriched.json"} <= names
