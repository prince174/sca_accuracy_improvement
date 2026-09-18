import io
import json
import time
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sca_accuracy.remote import (
    NoRedirects,
    RemoteAnalysisRequest,
    checkout,
    download_sbom,
    image_reference,
    run_remote,
    validate_request,
)
from sca_accuracy.service import create_app

COMMIT = "a" * 40


def request_data():
    return {
        "repository_url": "https://bitbucket.xxx/scm/team/app.git",
        "commit": COMMIT,
        "targets": [
            {
                "name": "backend",
                "sbom_url": "https://teamcity.xxx/build/1/bom.json",
                "images": ["nexus.xxx/backend:1", "nexus.xxx/backend:2"],
            },
            {
                "name": "frontend",
                "sbom_url": "https://teamcity.xxx/build/2/bom.json",
                "images": ["nexus.xxx/frontend:1"],
            },
        ],
    }


@pytest.fixture(autouse=True)
def hosts(monkeypatch):
    monkeypatch.setenv("SCA_TEAMCITY_HOSTS", "teamcity.xxx")
    monkeypatch.setenv("SCA_BITBUCKET_HOSTS", "bitbucket.xxx")
    monkeypatch.setenv("SCA_NEXUS_HOSTS", "nexus.xxx")
    monkeypatch.setenv("SCA_API_TOKEN", "api-test-secret")


@pytest.mark.parametrize(
    "url",
    [
        "http://teamcity.xxx/a",
        "file:///etc/passwd",
        "https://elsewhere/a",
        "https://teamcity.xxx@elsewhere/a",
        "https://user:secret@teamcity.xxx/a",
        "https://teamcity.xxx/a?token=secret",
        "https://teamcity.xxx/a#fragment",
        "https://teamcity.xxx:9443/a",
        "https://teamcity.xxx\\@elsewhere/a",
    ],
)
def test_remote_rejects_untrusted_urls(url):
    data = request_data()
    data["targets"][0]["sbom_url"] = url
    with pytest.raises(ValueError):
        validate_request(RemoteAnalysisRequest(**data))


@pytest.mark.parametrize(
    "image",
    [
        "ubuntu:latest",
        "nexus.xxx/backend",
        "--help",
        "http://nexus.xxx/app:1",
        "https://nexus.xxx/#browse",
        "nexus.xxx/app@sha256:short",
    ],
)
def test_invalid_image_reference(image):
    with pytest.raises(ValueError):
        image_reference(image)


def test_https_image_reference_is_normalized():
    assert image_reference("https://nexus.xxx/team/app:1") == "nexus.xxx/team/app:1"


def test_exact_commit_and_unique_groups_required():
    data = request_data()
    data["commit"] = "main"
    with pytest.raises(ValueError):
        RemoteAnalysisRequest(**data)
    data["commit"] = COMMIT
    data["targets"][1]["name"] = "backend"
    with pytest.raises(ValueError):
        RemoteAnalysisRequest(**data)


def test_downloader_checks_json_size_and_keeps_secret_out_of_url(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_TEAMCITY_TOKEN", "teamcity-test-secret")
    document = b'{"bomFormat":"CycloneDX","components":[]}'
    response = MagicMock()
    response.__enter__.return_value = io.BytesIO(document)
    with patch("sca_accuracy.remote.urllib.request.build_opener") as factory:
        factory.return_value.open.return_value = response
        checksum = download_sbom("https://teamcity.xxx/bom.json", tmp_path / "bom.json")
        sent = factory.return_value.open.call_args.args[0]
        assert sent.get_header("Authorization") == "Bearer teamcity-test-secret"
        assert "secret" not in sent.full_url
    assert len(checksum) == 64
    monkeypatch.setenv("SCA_MAX_SBOM_BYTES", "2")
    response.__enter__.return_value = io.BytesIO(document)
    with patch("sca_accuracy.remote.urllib.request.build_opener") as factory:
        factory.return_value.open.return_value = response
        with pytest.raises(ValueError, match="exceeds"):
            download_sbom("https://teamcity.xxx/bom.json", tmp_path / "too-big.json")


def test_redirect_and_error_body_never_forward_credentials(tmp_path):
    with pytest.raises(RuntimeError, match="redirects"):
        NoRedirects().redirect_request(None, None, 302, "", {}, "https://elsewhere/")
    with patch("sca_accuracy.remote.urllib.request.build_opener") as factory:
        factory.return_value.open.side_effect = urllib.error.HTTPError(
            "https://teamcity.xxx/a", 403, "secret", {}, io.BytesIO(b"secret")
        )
        with pytest.raises(RuntimeError, match="HTTP 403") as error:
            download_sbom("https://teamcity.xxx/a", tmp_path / "bom.json")
        assert "secret" not in str(error.value)


def test_checkout_pins_commit_and_isolates_git_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_BITBUCKET_TOKEN", "git-test-secret")
    monkeypatch.setenv("GIT_TRACE_CURL", "1")
    with patch("sca_accuracy.remote.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0, stdout=COMMIT)
        assert (
            checkout("https://bitbucket.xxx/scm/t/app.git", COMMIT, tmp_path / "source") == COMMIT
        )
    commands = [call.args[0] for call in run.call_args_list]
    assert ["git", "fetch", "--depth=1", "--no-tags", "origin", COMMIT] in commands
    assert not any("submodule" in command for command in commands)
    assert "git-test-secret" not in str(commands)
    environment = run.call_args.kwargs["env"]
    assert "GIT_TRACE_CURL" not in environment
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"


def test_checkout_rejects_wrong_commit(tmp_path):
    with patch("sca_accuracy.remote.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0, stdout="b" * 40)
        with pytest.raises(RuntimeError, match="does not match"):
            checkout("https://bitbucket.xxx/scm/t/app.git", COMMIT, tmp_path / "source")


def fake_download(url, destination):
    destination.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    return "c" * 64


def fake_analysis(config):
    assert config.pull_image is True
    config.output.mkdir(parents=True)
    (config.output / "sbom.enriched.json").write_text(config.sbom.read_text())
    return {"image_digest": "sha256:" + "d" * 64}


def test_batch_preserves_explicit_mapping_and_emits_provenance(tmp_path):
    with (
        patch("sca_accuracy.remote.checkout", return_value=COMMIT),
        patch("sca_accuracy.remote.download_sbom", side_effect=fake_download) as download,
        patch("sca_accuracy.remote.run_analysis", side_effect=fake_analysis) as analyze,
    ):
        result = run_remote(RemoteAnalysisRequest(**request_data()), tmp_path)
    assert download.call_count == 2
    assert analyze.call_count == 3
    assert [target["target_id"] for target in result["targets"]] == [
        "backend-1",
        "backend-2",
        "frontend-1",
    ]
    bom = json.loads((tmp_path / "targets/backend-2/sbom.enriched.json").read_text())
    properties = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert properties["sca-accuracy:input:commit"] == COMMIT
    assert properties["sca-accuracy:input:image"] == "nexus.xxx/backend:2"
    assert not list(tmp_path.glob("sca-inputs-*"))


def test_remote_http_job_download_and_authorization(tmp_path):
    client = TestClient(create_app(tmp_path))
    assert client.post("/v2/analyses", json=request_data()).status_code == 401
    headers = {"Authorization": "Bearer api-test-secret"}
    with (
        patch("sca_accuracy.remote.checkout", return_value=COMMIT),
        patch("sca_accuracy.remote.download_sbom", side_effect=fake_download),
        patch("sca_accuracy.remote.run_analysis", side_effect=fake_analysis),
    ):
        submitted = client.post("/v2/analyses", json=request_data(), headers=headers)
        assert submitted.status_code == 202
        url = submitted.json()["status_url"]
        for _ in range(100):
            job = client.get(url, headers=headers).json()
            if job["status"] in {"failed", "succeeded"}:
                break
            time.sleep(0.01)
    assert job["status"] == "succeeded", job
    artifact = client.get(f"{url}/targets/backend-1/artifacts/sbom.enriched.json", headers=headers)
    assert artifact.status_code == 200
    assert artifact.json()["bomFormat"] == "CycloneDX"
    assert (
        client.get(
            f"{url}/targets/missing/artifacts/sbom.enriched.json", headers=headers
        ).status_code
        == 404
    )
    assert (
        client.get(f"{url}/targets/backend-1/artifacts/job.json", headers=headers).status_code
        == 404
    )


def test_remote_disabled_without_api_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SCA_API_TOKEN")
    monkeypatch.delenv("SCA_API_TOKEN_FILE", raising=False)
    assert (
        TestClient(create_app(tmp_path)).post("/v2/analyses", json=request_data()).status_code
        == 503
    )


def test_failed_job_does_not_publish_partial_results(tmp_path):
    client = TestClient(create_app(tmp_path))
    headers = {"Authorization": "Bearer api-test-secret"}
    with patch("sca_accuracy.service.run_remote", side_effect=RuntimeError("Checkout failed")):
        response = client.post("/v2/analyses", json=request_data(), headers=headers)
        url = response.json()["status_url"]
        for _ in range(100):
            job = client.get(url, headers=headers).json()
            if job["status"] == "failed":
                break
            time.sleep(0.01)
    assert job["status"] == "failed"
    assert (
        client.get(
            f"{url}/targets/backend-1/artifacts/sbom.enriched.json", headers=headers
        ).status_code
        == 409
    )
