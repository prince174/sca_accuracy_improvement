from __future__ import annotations

import json
import mimetypes
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True, frozen=True)
class DependencyTrackConfig:
    base_url: str
    api_key: str
    timeout_seconds: int = 120

    @classmethod
    def from_environment(cls) -> DependencyTrackConfig:
        base_url = os.getenv("DEPENDENCY_TRACK_URL", "").rstrip("/")
        api_key = os.getenv("DEPENDENCY_TRACK_API_KEY", "")
        if not base_url:
            raise RuntimeError("DEPENDENCY_TRACK_URL is not configured")
        if not api_key:
            raise RuntimeError("DEPENDENCY_TRACK_API_KEY is not configured")
        return cls(
            base_url=base_url,
            api_key=api_key,
            timeout_seconds=int(os.getenv("DEPENDENCY_TRACK_TIMEOUT_SECONDS", "120")),
        )


class DependencyTrackClient:
    def __init__(self, config: DependencyTrackConfig) -> None:
        self.config = config

    def export_vdr(self, project_uuid: str) -> dict[str, Any]:
        project = _validated_uuid(project_uuid)
        query = urllib.parse.urlencode({"variant": "vdr"})
        data = self._request("GET", f"/api/v1/bom/cyclonedx/project/{project}?{query}")
        document = json.loads(data)
        if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
            raise TypeError("Dependency-Track VDR response is not a CycloneDX JSON object")
        return document

    def upload_bom(self, project_uuid: str, path: Path) -> dict[str, Any]:
        return self._upload("/api/v1/bom", "bom", project_uuid, path)

    def apply_vex(self, project_uuid: str, path: Path) -> dict[str, Any]:
        return self._upload("/api/v1/vex", "vex", project_uuid, path)

    def wait_for_bom(
        self, token: str, wait_seconds: int = 300, poll_seconds: float = 2.0
    ) -> dict[str, Any]:
        task_token = _validated_uuid(token)
        deadline = time.monotonic() + wait_seconds
        while True:
            payload = json.loads(self._request("GET", f"/api/v1/bom/token/{task_token}"))
            processing, status = _processing_state(payload)
            if not processing:
                return {"token": task_token, "processing": False, "status": status}
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"Dependency-Track BOM processing timed out after {wait_seconds}s"
                )
            time.sleep(poll_seconds)

    def _upload(
        self, endpoint: str, file_field: str, project_uuid: str, path: Path
    ) -> dict[str, Any]:
        project = _validated_uuid(project_uuid)
        if not path.is_file():
            raise FileNotFoundError(path)
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        body, boundary = _multipart(
            fields={"project": project},
            files={file_field: (path.name, content_type, path.read_bytes())},
        )
        data = self._request(
            "POST",
            endpoint,
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )
        if not data.strip():
            return {"accepted": True}
        result = json.loads(data)
        return result if isinstance(result, dict) else {"result": result}

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> str:
        headers = {"X-Api-Key": self.config.api_key, "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            f"{self.config.base_url}{path}", data=body, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(f"Dependency-Track returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Dependency-Track request failed: {exc.reason}") from exc


def _validated_uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValueError(f"Invalid Dependency-Track project UUID: {value}") from exc


def _processing_state(payload: Any) -> tuple[bool, str]:
    if isinstance(payload, bool):
        return payload, "processing" if payload else "completed"
    if isinstance(payload, dict):
        if isinstance(payload.get("processing"), bool):
            return payload["processing"], str(payload.get("status", "processing"))
        status = str(payload.get("status", "")).lower()
        if status in {"completed", "complete", "succeeded", "success"}:
            return False, status
        if status in {"failed", "cancelled", "canceled"}:
            raise RuntimeError(f"Dependency-Track BOM processing ended with status {status}")
        if status:
            return True, status
    raise TypeError("Unexpected Dependency-Track BOM processing response")


def _multipart(
    fields: dict[str, str], files: dict[str, tuple[str, str, bytes]]
) -> tuple[bytes, str]:
    boundary = f"sca-accuracy-{uuid.uuid4().hex}"
    marker = boundary.encode("ascii")
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                b"--" + marker + b"\r\n",
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode("utf-8") + b"\r\n",
            ]
        )
    for name, (filename, content_type, data) in files.items():
        chunks.extend(
            [
                b"--" + marker + b"\r\n",
                (
                    f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                data,
                b"\r\n",
            ]
        )
    chunks.append(b"--" + marker + b"--\r\n")
    return b"".join(chunks), boundary
