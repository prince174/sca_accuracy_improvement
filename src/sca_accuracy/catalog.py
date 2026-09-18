"""Offline multi-ecosystem cataloging. Never executes the target application/build."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .image import _run, pull_image, save_image, scan_saved_image
from .models import ComponentIdentity, Observation
from .sbom import identity_from_component


def scan(target: str, output: Path) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    # Do not load repository-provided Syft configuration or enable network enrichers.
    with tempfile.TemporaryDirectory(prefix="sca-syft-") as directory:
        config = Path(directory) / "syft.yaml"
        config.write_text(
            "check-for-app-update: false\njava:\n  use-network: false\n", encoding="utf-8"
        )
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("SYFT_")
        }
        environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
        try:
            result = subprocess.run(
                [
                    os.getenv("SCA_SYFT_BINARY", "syft"),
                    "scan",
                    target,
                    "--config",
                    str(config),
                    "--scope",
                    "squashed",
                    "-o",
                    "syft-json",
                ],
                cwd=directory,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=900,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Syft is required. Use the analyzer Docker image or install Syft and set SCA_SYFT_BINARY."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Syft scan exceeded 900 seconds") from exc
    if result.returncode:
        raise RuntimeError(f"Syft scan failed: {result.stderr[-4000:]}")
    data = json.loads(result.stdout)
    if not isinstance(data.get("artifacts"), list):
        raise TypeError("Invalid Syft inventory: artifacts array is required")
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def observations_from_catalog(data: dict[str, Any]) -> list[Observation]:
    result = []
    for artifact in data["artifacts"]:
        identity = identity_from_component(artifact)
        if identity is None:
            identity = ComponentIdentity(
                "",
                str(artifact.get("name", "unknown")),
                str(artifact.get("version", "")),
                "generic",
            )
        locations = artifact.get("locations") or [{}]
        for location in locations:
            result.append(
                Observation(
                    identity,
                    location.get("path") or "unknown",
                    "syft:" + artifact.get("foundBy", "unknown"),
                    confidence=1.0 if identity.ecosystem != "generic" and identity.version else 0.4,
                )
            )
    return result


def inspect_image(
    image: str, evidence: Path, *, pull: bool = False
) -> tuple[str, list[Observation], dict[str, Any]]:
    if pull:
        pull_image(image)
    # Resolve once and save by immutable local image ID, including mutable latest tags.
    image_id = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    with tempfile.TemporaryDirectory(prefix="sca-image-") as directory:
        archive = Path(directory) / "image.tar"
        save_image(image_id, archive)
        data = scan(f"docker-archive:{archive}", evidence / "image.syft.json")
        observations = observations_from_catalog(data)
        # JVM references are optional evidence; the general catalog remains authoritative.
        java = scan_saved_image(archive)
        references: dict[str, set[str]] = {}
        for entry in java:
            references.setdefault(entry.identity.gav, set()).update(entry.referenced_symbols)
        for observation in observations:
            observation.referenced_symbols = sorted(references.get(observation.identity.gav, set()))
            matches = [
                entry
                for entry in java
                if entry.identity == observation.identity
                and entry.location == observation.location
                and entry.confidence >= 0.8
            ]
            hashes = {entry.sha256 for entry in matches if entry.sha256}
            if len(hashes) == 1:
                digest = next(iter(hashes))
                identities = {entry.identity for entry in java if entry.sha256 == digest}
                if identities == {observation.identity}:
                    observation.sha256 = digest
    return image_id, observations, data


def coverage(image: dict[str, Any], source: dict[str, Any] | None) -> dict[str, Any]:
    def summarize(data: dict[str, Any]) -> dict[str, Any]:
        return {
            "scanner": data.get("descriptor", {}),
            "package_types_observed": sorted({a.get("type", "unknown") for a in data["artifacts"]}),
            "catalogers_observed": sorted({a.get("foundBy", "unknown") for a in data["artifacts"]}),
            "components": len(data["artifacts"]),
            "unidentified": sum(
                identity_from_component(a) is None or not a.get("purl") for a in data["artifacts"]
            ),
        }

    return {
        "image": summarize(image),
        "source": summarize(source) if source is not None else None,
        "absence_proven": False,
        "runtime_execution": False,
        "reachability": "JVM static references only; runtime reachability not assessed",
        "limitations": [
            "Cataloger support depends on available metadata, package format and scanner version.",
            "Source inventory describes declarations, not the original build resolution or delivered packages.",
            "No detection is not proof of absence: vendoring, shading, bundling and stripped binaries may hide identities.",
            "Inventory and static references do not prove exploitability; VEX remains in_triage.",
        ],
    }
