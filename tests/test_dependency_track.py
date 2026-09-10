import json
import urllib.request
from pathlib import Path
from typing import Self
from unittest.mock import MagicMock, patch

from sca_accuracy.dependency_track import DependencyTrackClient, DependencyTrackConfig


class Response:
    def __init__(self, payload: str) -> None:
        self.payload = payload

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.payload.encode()


def test_apply_vex_posts_project_and_file_without_exposing_key(tmp_path: Path) -> None:
    vex = tmp_path / "vex.json"
    vex.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
    client = DependencyTrackClient(
        DependencyTrackConfig("https://dtrack.example", "top-secret-key")
    )

    with patch.object(urllib.request, "urlopen", return_value=Response("{}")) as urlopen:
        client.apply_vex("37803005-05ff-46c5-9571-9ac7857fd07d", vex)

    request = urlopen.call_args.args[0]
    assert isinstance(request, urllib.request.Request)
    assert request.full_url == "https://dtrack.example/api/v1/vex"
    assert request.get_header("X-api-key") == "top-secret-key"
    assert b'form-data; name="project"' in request.data
    assert b"37803005-05ff-46c5-9571-9ac7857fd07d" in request.data
    assert b'form-data; name="vex"; filename="vex.json"' in request.data


def test_export_vdr_validates_cyclonedx_response() -> None:
    client = DependencyTrackClient(DependencyTrackConfig("https://dtrack.example", "key"))
    payload = json.dumps({"bomFormat": "CycloneDX", "vulnerabilities": []})
    response = MagicMock(return_value=Response(payload))

    with patch.object(urllib.request, "urlopen", response):
        result = client.export_vdr("37803005-05ff-46c5-9571-9ac7857fd07d")

    assert result["bomFormat"] == "CycloneDX"
    request = response.call_args.args[0]
    assert request.full_url.endswith(
        "/api/v1/bom/cyclonedx/project/37803005-05ff-46c5-9571-9ac7857fd07d?variant=vdr"
    )


def test_wait_for_bom_polls_until_processing_finishes() -> None:
    client = DependencyTrackClient(DependencyTrackConfig("https://dtrack.example", "key"))
    responses = [Response("true"), Response('{"processing":false,"status":"completed"}')]

    with (
        patch.object(urllib.request, "urlopen", side_effect=responses) as urlopen,
        patch("sca_accuracy.dependency_track.time.sleep"),
    ):
        result = client.wait_for_bom(
            "8bb712b3-bb51-42da-8e7e-af3a138c1844", wait_seconds=30, poll_seconds=0
        )

    assert result["processing"] is False
    assert result["status"] == "completed"
    assert urlopen.call_count == 2
