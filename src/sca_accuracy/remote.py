"""Fetch build inputs and produce one independently scoped SBOM per image."""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .pipeline import AnalysisConfig, run_analysis
from .sbom import load_sbom


class BuildTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    sbom_url: str = Field(min_length=1, max_length=4096)
    images: list[str] = Field(min_length=1, max_length=16)


class RemoteAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str = Field(min_length=1, max_length=2048)
    commit: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    targets: list[BuildTarget] = Field(min_length=1, max_length=16)
    with_llm: bool = False

    @model_validator(mode="after")
    def unique_targets(self) -> RemoteAnalysisRequest:
        if len({target.name for target in self.targets}) != len(self.targets):
            raise ValueError("Target names must be unique")
        if sum(len(target.images) for target in self.targets) > 32:
            raise ValueError("At most 32 SBOM/image pairs are allowed per job")
        return self


def secret(name: str) -> str:
    filename = os.getenv(f"{name}_FILE")
    value = Path(filename).read_text(encoding="utf-8").strip() if filename else os.getenv(name, "")
    if "\r" in value or "\n" in value:
        raise ValueError(f"Invalid multiline secret: {name}")
    return value


def validate_url(value: str, hosts_variable: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    allowed = {
        host.strip().lower() for host in os.getenv(hosts_variable, "").split(",") if host.strip()
    }
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.netloc.lower() not in allowed
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or any(character.isspace() or ord(character) < 32 for character in value)
        or "\\" in value
    ):
        raise ValueError(
            f"Expected an HTTPS URL on a host configured in {hosts_variable}; credentials, query and fragment are not allowed"
        )
    return value


def image_reference(value: str) -> str:
    reference = value.removeprefix("https://")
    if "://" in reference or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/@+-]*", reference):
        raise ValueError("Expected a Nexus Docker image reference, not a web UI link")
    host, separator, path = reference.partition("/")
    allowed = {item.strip().lower() for item in os.getenv("SCA_NEXUS_HOSTS", "").split(",")}
    if not separator or not path or host.lower() not in allowed or "@" in host:
        raise ValueError("Image registry must be configured in SCA_NEXUS_HOSTS")
    if not ("@sha256:" in path or ":" in path.rsplit("/", 1)[-1]):
        raise ValueError("Image reference must contain an explicit tag or sha256 digest")
    if "@" in path and not re.fullmatch(r".+@sha256:[a-fA-F0-9]{64}", path):
        raise ValueError("Invalid image digest")
    return reference


def validate_request(request: RemoteAnalysisRequest) -> None:
    validate_url(request.repository_url, "SCA_BITBUCKET_HOSTS")
    for target in request.targets:
        validate_url(target.sbom_url, "SCA_TEAMCITY_HOSTS")
        for image in target.images:
            image_reference(image)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError(
            "Artifact redirects are disabled; supply the direct TeamCity artifact URL"
        )


def download_sbom(url: str, destination: Path) -> str:
    validate_url(url, "SCA_TEAMCITY_HOSTS")
    headers = {"Accept": "application/json"}
    token = secret("SCA_TEAMCITY_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    limit = int(os.getenv("SCA_MAX_SBOM_BYTES", str(64 * 1024 * 1024)))
    context = ssl.create_default_context(cafile=os.getenv("SCA_CA_BUNDLE") or None)
    opener = urllib.request.build_opener(
        NoRedirects(), urllib.request.HTTPSHandler(context=context)
    )
    digest = hashlib.sha256()
    try:
        with opener.open(request, timeout=60) as response, destination.open("wb") as output:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > limit:
                    raise ValueError("SBOM exceeds SCA_MAX_SBOM_BYTES")
                digest.update(block)
                output.write(block)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"TeamCity artifact download failed: HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise RuntimeError("TeamCity artifact download failed: network or TLS error") from None
    load_sbom(destination)
    return digest.hexdigest()


def checkout(repository: str, commit: str, destination: Path) -> str:
    validate_url(repository, "SCA_BITBUCKET_HOSTS")
    if not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", commit):
        raise ValueError("An exact commit hash is required")
    destination.mkdir(parents=True)
    # Isolate credentials/config; do not execute repository hooks, LFS or submodules.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    config = {
        "core.hooksPath": os.devnull,
        "http.followRedirects": "false",
        "protocol.allow": "never",
        "protocol.https.allow": "always",
        "credential.helper": "",
        "submodule.recurse": "false",
    }
    token = secret("SCA_BITBUCKET_TOKEN")
    if token:
        config[f"http.{repository}.extraHeader"] = f"Authorization: Bearer {token}"
    if os.getenv("SCA_CA_BUNDLE"):
        config["http.sslCAInfo"] = os.environ["SCA_CA_BUNDLE"]
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_COUNT": str(len(config)),
        }
    )
    for index, (key, value) in enumerate(config.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=destination,
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Bitbucket checkout timed out") from None
        if result.returncode:
            # Git stderr may contain credential material or server HTML.
            raise RuntimeError(f"Bitbucket checkout failed during git {arguments[0]}")
        return result.stdout.strip()

    git(
        "init",
        "--quiet",
        f"--object-format={'sha256' if len(commit) == 64 else 'sha1'}",
        "--template=",
    )
    git("remote", "add", "origin", repository)
    git("fetch", "--depth=1", "--no-tags", "origin", commit)
    git("checkout", "--detach", "--force", "FETCH_HEAD")
    resolved = git("rev-parse", "HEAD")
    if resolved.lower() != commit.lower():
        raise RuntimeError("Fetched commit does not match requested commit")
    # Syft must only inspect checkout files, never host files through escaping symlinks.
    for path in destination.rglob("*"):
        if path.is_symlink() and not path.resolve().is_relative_to(destination.resolve()):
            raise ValueError("Checkout contains a symlink outside the repository")
    return resolved


def run_remote(request: RemoteAnalysisRequest, output: Path) -> dict[str, Any]:
    validate_request(request)
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="sca-inputs-", dir=output) as temporary:
        inputs = Path(temporary)
        resolved = checkout(request.repository_url, request.commit, inputs / "source")
        for target in request.targets:
            sbom = inputs / f"{target.name}.json"
            checksum = download_sbom(target.sbom_url, sbom)
            for index, image in enumerate(target.images, 1):
                target_id = f"{target.name}-{index}"
                directory = output / "targets" / target_id
                result = run_analysis(
                    AnalysisConfig(
                        sbom=sbom,
                        image=image_reference(image),
                        output=directory,
                        pull_image=True,
                        source=inputs / "source",
                        with_llm=request.with_llm,
                    )
                )
                provenance = {
                    "repository_url": request.repository_url,
                    "commit": resolved,
                    "sbom_url": target.sbom_url,
                    "sbom_sha256": checksum,
                    "image": image_reference(image),
                    "image_id": result["image_digest"],
                }
                bom_path = directory / "sbom.enriched.json"
                bom = load_sbom(bom_path)
                bom.setdefault("metadata", {}).setdefault("properties", []).extend(
                    {"name": f"sca-accuracy:input:{key}", "value": value}
                    for key, value in provenance.items()
                )
                bom_path.write_text(
                    json.dumps(bom, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
                (directory / "provenance.json").write_text(
                    json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
                )
                results.append(
                    {
                        "target_id": target_id,
                        "name": target.name,
                        **result,
                        "sbom_artifact": f"targets/{target_id}/artifacts/sbom.enriched.json",
                    }
                )
    manifest = {"repository_url": request.repository_url, "commit": resolved, "targets": results}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
