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
from typing import BinaryIO

from .bytecode import class_names_from_jar_entries, method_references, symbol_owner
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


def save_image(image: str, destination: Path) -> None:
    _run(["docker", "image", "save", "--output", str(destination), image])


def pull_image(image: str) -> None:
    _run(["docker", "pull", image])


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
            application_references: set[str] = set()
            for class_name in jar.namelist():
                if not _is_application_class(class_name):
                    continue
                application_references.update(method_references(jar.read(class_name)))
            identities = _pom_properties(jar)
            for identity in identities:
                observations.append(Observation(identity, location, source, digest, 1.0))
            for member in jar.namelist():
                if member.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")) and member.endswith(".jar"):
                    nested_data = jar.read(member)
                    nested_location = f"{location}!/{member}"
                    nested = _inspect_jar(nested_data, nested_location, "nested-jar-metadata")
                    nested_classes = _classes_in_jar(nested_data)
                    references = sorted(
                        symbol
                        for symbol in application_references
                        if symbol_owner(symbol) in nested_classes
                    )[:500]
                    for observation in nested:
                        observation.referenced_symbols = references
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


def _is_application_class(name: str) -> bool:
    if name.startswith(("BOOT-INF/classes/", "WEB-INF/classes/")):
        return name.endswith(".class")
    return name.endswith(".class") and not name.startswith(
        ("META-INF/", "BOOT-INF/", "WEB-INF/", "org/springframework/boot/loader/")
    )


def _classes_in_jar(data: bytes) -> set[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as jar:
            return class_names_from_jar_entries(jar.namelist())
    except zipfile.BadZipFile:
        return set()


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


def scan_saved_image(tar_path: Path, max_jar_bytes: int = 512 * 1024 * 1024) -> list[Observation]:
    files: dict[str, bytes] = {}
    with tarfile.open(tar_path, "r:*") as image_archive:
        manifest_member = image_archive.getmember("manifest.json")
        manifest_stream = image_archive.extractfile(manifest_member)
        if manifest_stream is None:
            raise TypeError("Saved image has no readable manifest.json")
        manifest = json.load(manifest_stream)
        if not isinstance(manifest, list) or not manifest or not isinstance(manifest[0], dict):
            raise TypeError("Saved image manifest.json has an unexpected format")
        layers = manifest[0].get("Layers")
        if not isinstance(layers, list) or not all(isinstance(layer, str) for layer in layers):
            raise TypeError("Saved image manifest has no layer list")
        for layer_name in layers:
            layer_member = image_archive.getmember(layer_name)
            layer_stream = image_archive.extractfile(layer_member)
            if layer_stream is None:
                raise TypeError(f"Saved image layer is not readable: {layer_name}")
            _apply_layer(layer_stream, files, max_jar_bytes)
    return _inspect_files(files)


def _apply_layer(stream: BinaryIO, files: dict[str, bytes], max_jar_bytes: int) -> None:
    with tarfile.open(fileobj=stream, mode="r|*") as layer:
        for member in layer:
            path = _safe_image_path(member.name)
            if path is None:
                continue
            basename = PurePosixPath(path).name
            parent = str(PurePosixPath(path).parent)
            if basename == ".wh..wh..opq":
                prefix = parent.rstrip("/") + "/"
                for existing in [name for name in files if name.startswith(prefix)]:
                    del files[existing]
                continue
            if basename.startswith(".wh."):
                target = str(PurePosixPath(parent) / basename.removeprefix(".wh."))
                files.pop(target, None)
                continue
            if not member.isfile():
                files.pop(path, None)
                continue
            if not path.lower().endswith((".jar", ".war")):
                files.pop(path, None)
                continue
            if member.size > max_jar_bytes:
                files.pop(path, None)
                continue
            member_stream = layer.extractfile(member)
            if member_stream is None:
                continue
            data = member_stream.read(max_jar_bytes + 1)
            if len(data) <= max_jar_bytes:
                files[path] = data


def _safe_image_path(value: str) -> str | None:
    raw = PurePosixPath(value.lstrip("./"))
    if not raw.parts or ".." in raw.parts:
        return None
    return "/" + str(raw)


def _inspect_files(files: dict[str, bytes]) -> list[Observation]:
    observations: list[Observation] = []
    for location, data in files.items():
        found = _inspect_jar(data, location, "jar-maven-metadata")
        if found:
            observations.extend(found)
            continue
        guessed = identity_from_filename(PurePosixPath(location).name)
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


def inspect_image(image: str, pull: bool = False) -> tuple[str, list[Observation]]:
    if pull:
        pull_image(image)
    digest = inspect_digest(image)
    with tempfile.TemporaryDirectory(prefix="sca-accuracy-") as directory:
        archive = Path(directory) / "image.tar"
        save_image(image, archive)
        return digest, scan_saved_image(archive)
