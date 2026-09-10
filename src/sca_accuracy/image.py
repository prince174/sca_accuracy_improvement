from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .models import ComponentIdentity, Observation

_JAR_NAME = re.compile(r"^(?P<name>.+)-(?P<version>[0-9][A-Za-z0-9_.+\-]*)\.jar$")


def _run(args: list[str]) -> str:
    process = subprocess.run(args, check=False, capture_output=True, text=True)
    if process.returncode:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"Command failed ({' '.join(args[:2])}): {detail}")
    return process.stdout.strip()


def inspect_digest(image: str) -> str:
    output = _run(["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"])
    digests = json.loads(output)
    if digests:
        return str(digests[0]).rsplit("@", 1)[-1]
    image_id = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    return image_id


def export_image(image: str, destination: Path) -> None:
    container_id = _run(["docker", "create", image])
    try:
        _run(["docker", "export", "--output", str(destination), container_id])
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_id],
            check=False,
            capture_output=True,
            text=True,
        )


def _pom_properties(zf: zipfile.ZipFile) -> list[ComponentIdentity]:
    identities: list[ComponentIdentity] = []
    for name in zf.namelist():
        if not name.startswith("META-INF/maven/") or not name.endswith("/pom.properties"):
            continue
        values: dict[str, str] = {}
        content = zf.read(name).decode("iso-8859-1", errors="replace")
        for line in content.splitlines():
            if "=" in line and not line.lstrip().startswith(("#", "!")):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        if values.get("artifactId") and values.get("version"):
            identities.append(
                ComponentIdentity(
                    values.get("groupId", ""), values["artifactId"], values["version"]
                )
            )
    return identities


def _inspect_jar(data: bytes, location: str, source: str) -> list[Observation]:
    observations: list[Observation] = []
    digest = hashlib.sha256(data).hexdigest()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as jar:
            identities = _pom_properties(jar)
            for identity in identities:
                observations.append(Observation(identity, location, source, digest, 1.0))
            for member in jar.namelist():
                if member.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")) and member.endswith(".jar"):
                    nested_data = jar.read(member)
                    nested_location = f"{location}!/{member}"
                    nested = _inspect_jar(nested_data, nested_location, "nested-jar-metadata")
                    if nested:
                        observations.extend(nested)
                    else:
                        guessed = identity_from_filename(PurePosixPath(member).name)
                        if guessed:
                            observations.append(
                                Observation(
                                    guessed,
                                    nested_location,
                                    "nested-jar-filename",
                                    hashlib.sha256(nested_data).hexdigest(),
                                    0.55,
                                )
                            )
    except (zipfile.BadZipFile, KeyError, RuntimeError):
        return observations
    return observations


def identity_from_filename(filename: str) -> ComponentIdentity | None:
    matched = _JAR_NAME.match(filename)
    if not matched:
        return None
    return ComponentIdentity("", matched.group("name"), matched.group("version"))


def scan_exported_image(
    tar_path: Path, max_jar_bytes: int = 512 * 1024 * 1024
) -> list[Observation]:
    observations: list[Observation] = []
    with tarfile.open(tar_path, "r:*") as archive:
        for member in archive:
            if not member.isfile() or not member.name.lower().endswith((".jar", ".war")):
                continue
            location = "/" + member.name.lstrip("./")
            if member.size > max_jar_bytes:
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            data = stream.read(max_jar_bytes + 1)
            if len(data) > max_jar_bytes:
                continue
            found = _inspect_jar(data, location, "jar-maven-metadata")
            if found:
                observations.extend(found)
            else:
                guessed = identity_from_filename(PurePosixPath(member.name).name)
                if guessed:
                    observations.append(
                        Observation(
                            guessed,
                            location,
                            "jar-filename",
                            hashlib.sha256(data).hexdigest(),
                            0.45,
                        )
                    )
    unique: dict[tuple[str, str], Observation] = {}
    for observation in observations:
        unique[(observation.identity.gav, observation.location)] = observation
    return list(unique.values())


def inspect_image(image: str) -> tuple[str, list[Observation]]:
    digest = inspect_digest(image)
    with tempfile.TemporaryDirectory(prefix="sca-accuracy-") as directory:
        archive = Path(directory) / "rootfs.tar"
        export_image(image, archive)
        return digest, scan_exported_image(archive)
