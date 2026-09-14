from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import ComponentIdentity

DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree"


def generate_dependency_tree(source: Path, output: Path) -> Path:
    project = source.resolve()
    if not (project / "pom.xml").is_file():
        raise FileNotFoundError(f"Maven pom.xml not found in source directory: {project}")
    runner = _maven_runner(project)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    command = [
        *runner,
        "-B",
        DEPENDENCY_PLUGIN,
        "-DoutputType=json",
        f"-DoutputFile={output}",
        "-DappendOutput=false",
    ]
    process = subprocess.run(command, cwd=project, check=False, capture_output=True, text=True)
    if process.returncode:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"Maven dependency tree generation failed: {detail[-4000:]}")
    if not output.is_file():
        raise RuntimeError("Maven dependency plugin did not create dependency-tree.json")
    load_dependency_tree(output)
    return output


def _maven_runner(project: Path) -> list[str]:
    windows_wrapper = project / "mvnw.cmd"
    unix_wrapper = project / "mvnw"
    if windows_wrapper.is_file():
        return [str(windows_wrapper)]
    if unix_wrapper.is_file():
        return [str(unix_wrapper)]
    executable = shutil.which("mvn")
    if executable:
        return [executable]
    raise RuntimeError("Maven is required to derive dependency scopes from source")


def load_dependency_tree(path: Path) -> dict[str, str]:
    """Return resolved Maven scopes indexed by exact GAV from dependency:tree JSON."""
    with path.open("r", encoding="utf-8") as stream:
        root = json.load(stream)
    if not isinstance(root, dict):
        raise TypeError("Maven dependency tree must be a JSON object")
    scopes: dict[str, str] = {}
    _visit(root, scopes)
    return scopes


def _visit(node: dict[str, Any], scopes: dict[str, str]) -> None:
    group = str(node.get("groupId", ""))
    name = str(node.get("artifactId", ""))
    version = str(node.get("version", ""))
    scope = str(node.get("scope", "")).lower()
    if group and name and version:
        scopes[ComponentIdentity(group, name, version).gav] = scope
    children = node.get("children", [])
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                _visit(child, scopes)
