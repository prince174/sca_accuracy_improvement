import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sca_accuracy.service import JobManager, create_app


def test_service_health_and_bearer_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCA_API_TOKEN", "secret")
    client = TestClient(create_app(tmp_path))

    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/ready").status_code == 401
    response = client.get("/ready", headers={"Authorization": "Bearer secret"})
    assert response.status_code == 200
    assert response.json()["workspace"] == str(tmp_path.resolve())


def test_job_manager_rejects_paths_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "bom.json"
    outside.write_text("{}", encoding="utf-8")
    manager = JobManager(workspace, workers=1)

    with pytest.raises(ValueError, match="inside SCA_WORKSPACE"):
        manager.resolve_input("../bom.json")

    with pytest.raises(ValueError, match="inside SCA_WORKSPACE"):
        manager.resolve_source("..")


def test_submit_rejects_missing_sbom(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path))

    response = client.post(
        "/v1/analyses",
        json={"sbom_path": "missing.json", "image": "example:latest"},
    )

    assert response.status_code == 422


def test_job_manager_restores_results_and_marks_interrupted_job_failed(tmp_path: Path) -> None:
    job_dir = tmp_path / "results" / "job-1"
    job_dir.mkdir(parents=True)
    (job_dir / "job.json").write_text(
        json.dumps(
            {
                "id": "job-1",
                "status": "running",
                "result": None,
                "error": None,
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )

    manager = JobManager(tmp_path, workers=1)
    restored = manager.get("job-1")

    assert restored.status == "failed"
    assert restored.error == "Service restarted before the analysis completed."
    persisted = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))
    assert persisted["status"] == "failed"
