from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ComponentIdentity


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
