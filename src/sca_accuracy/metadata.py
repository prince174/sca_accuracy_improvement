"""Bounded identity metadata from scanner output; claims are not verified file content."""

import hashlib
import json


def metadata_evidence(artifact):
    metadata = artifact.get("metadata")
    if not isinstance(metadata, dict) or not metadata:
        return {}
    # Project identity-bearing fields only, not arbitrary package configuration or URLs.
    selected = {
        k: metadata[k]
        for k in (
            "name",
            "version",
            "packageName",
            "packageVersion",
            "architecture",
            "originPackage",
            "virtualPath",
            "pomProperties",
            "pomProject",
        )
        if k in metadata
    }
    for name in ("pomProperties", "pomProject"):
        if isinstance(selected.get(name), dict):
            selected[name] = {
                k: v
                for k, v in selected[name].items()
                if k in {"path", "groupId", "artifactId", "version", "name", "parent"}
            }
            if isinstance(selected[name].get("parent"), dict):
                selected[name]["parent"] = {
                    k: v
                    for k, v in selected[name]["parent"].items()
                    if k in {"groupId", "artifactId", "version"}
                }
    manifest = metadata.get("manifest", {})
    if isinstance(manifest, dict) and isinstance(manifest.get("main"), list):
        selected["manifest"] = [
            {"key": entry["key"], "value": entry.get("value")}
            for entry in manifest["main"]
            if isinstance(entry, dict)
            and entry.get("key")
            in {
                "Implementation-Title",
                "Implementation-Version",
                "Implementation-Vendor-Id",
                "Bundle-Name",
                "Bundle-SymbolicName",
                "Bundle-Version",
                "Automatic-Module-Name",
            }
        ]
    raw = json.dumps(metadata, sort_keys=True, ensure_ascii=False).encode()
    preview = json.dumps(selected, sort_keys=True, ensure_ascii=False)
    return {
        "artifact_id": artifact.get("id"),
        "metadata_type": artifact.get("metadataType"),
        "metadata_sha256": hashlib.sha256(raw).hexdigest(),
        "identity_metadata": preview[:4000],
        "projection_truncated": len(preview) > 4000,
        "scope": "selected scanner metadata; unverified package claims, not payload verification",
    }
