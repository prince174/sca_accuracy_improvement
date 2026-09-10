from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .models import ComponentIdentity, Observation, ReconciliationItem

NON_RUNTIME_SCOPES = {"test", "provided", "system", "import"}


def load_sbom(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("Input is not a CycloneDX BOM")
    if not isinstance(data.get("components", []), list):
        raise TypeError("CycloneDX components must be an array")
    return data


def iter_components(components: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for component in components:
        yield component
        children = component.get("components")
        if isinstance(children, list):
            yield from iter_components(children)


def iter_all_components(sbom: dict[str, Any]) -> Iterator[dict[str, Any]]:
    root = sbom.get("metadata", {}).get("component")
    if isinstance(root, dict):
        yield root
    yield from iter_components(sbom.get("components", []))


def identity_from_component(component: dict[str, Any]) -> ComponentIdentity | None:
    purl = component.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:maven/"):
        value = purl.removeprefix("pkg:maven/").split("?", 1)[0].split("#", 1)[0]
        package, separator, version = value.partition("@")
        parts = package.split("/", 1)
        if separator and len(parts) == 2:
            return ComponentIdentity(unquote(parts[0]), unquote(parts[1]), unquote(version))
    group = str(component.get("group", ""))
    name = str(component.get("name", ""))
    version = str(component.get("version", ""))
    if name and version:
        return ComponentIdentity(group, name, version)
    return None


def reconcile(
    sbom: dict[str, Any],
    observations: list[Observation],
    maven_scopes: dict[str, str] | None = None,
) -> list[ReconciliationItem]:
    maven_scopes = maven_scopes or {}
    by_gav: dict[str, list[Observation]] = {}
    by_ga: dict[tuple[str, str], list[Observation]] = {}
    for observation in observations:
        by_gav.setdefault(observation.identity.gav, []).append(observation)
        by_ga.setdefault((observation.identity.group, observation.identity.name), []).append(
            observation
        )

    result: list[ReconciliationItem] = []
    matched_locations: set[tuple[str, str]] = set()
    for component in iter_all_components(sbom):
        identity = identity_from_component(component)
        if identity is None:
            continue
        exact = by_gav.get(identity.gav, [])
        for observation in exact:
            matched_locations.add((observation.identity.gav, observation.location))
        strong = [observation for observation in exact if observation.confidence >= 0.8]
        if exact:
            result.append(
                ReconciliationItem(
                    status="confirmed_present" if strong else "identity_uncertain",
                    identity=identity,
                    bom_ref=component.get("bom-ref"),
                    observations=exact,
                    maven_scope=maven_scopes.get(identity.gav),
                    explanation=(
                        "Exact Maven coordinates were observed in the delivered image."
                        if strong
                        else "Only weak filename evidence supports this component identity."
                    ),
                )
            )
            continue
        conflicts = by_ga.get((identity.group, identity.name), [])
        for observation in conflicts:
            matched_locations.add((observation.identity.gav, observation.location))
        scope = maven_scopes.get(identity.gav)
        if conflicts:
            status = "version_conflict"
            explanation = "The image contains the same Maven package with another version."
        elif scope in NON_RUNTIME_SCOPES:
            status = "expected_absent"
            explanation = f"Maven scope '{scope}' is not expected in the runtime image."
        else:
            status = "unexpected_absent"
            explanation = "A declared runtime component was not identified in the image."
        result.append(
            ReconciliationItem(
                status=status,
                identity=identity,
                bom_ref=component.get("bom-ref"),
                observations=conflicts,
                maven_scope=scope,
                explanation=explanation,
            )
        )

    for observation in observations:
        key = (observation.identity.gav, observation.location)
        if key not in matched_locations:
            result.append(
                ReconciliationItem(
                    status=(
                        "observed_not_declared"
                        if observation.confidence >= 0.8
                        else "identity_uncertain"
                    ),
                    identity=observation.identity,
                    observations=[observation],
                    explanation=(
                        "Maven metadata was observed in the image but has no matching SBOM component."
                        if observation.confidence >= 0.8
                        else "A JAR filename suggests a component that is not declared in the SBOM."
                    ),
                )
            )
    return result


def enrich_sbom(
    sbom: dict[str, Any], items: list[ReconciliationItem], image: str, digest: str
) -> dict[str, Any]:
    enriched = copy.deepcopy(sbom)
    enriched.setdefault("metadata", {}).setdefault("properties", []).extend(
        [
            {"name": "sca-accuracy:image", "value": image},
            {"name": "sca-accuracy:image-digest", "value": digest},
            {"name": "sca-accuracy:analyzer-version", "value": "0.1.0"},
        ]
    )
    by_ref = {item.bom_ref: item for item in items if item.bom_ref}
    for component in iter_all_components(enriched):
        item = by_ref.get(component.get("bom-ref"))
        if item is None:
            continue
        component.setdefault("properties", []).append(
            {"name": "sca-accuracy:reconciliation-status", "value": item.status}
        )
        if item.maven_scope:
            component.setdefault("properties", []).append(
                {"name": "sca-accuracy:maven-scope", "value": item.maven_scope}
            )
        if item.status == "confirmed_present" and item.observations:
            evidence = component.setdefault("evidence", {})
            occurrences = evidence.setdefault("occurrences", [])
            known = {entry.get("location") for entry in occurrences if isinstance(entry, dict)}
            for observation in item.observations:
                if observation.location not in known:
                    occurrences.append({"location": observation.location})
        if item.status == "version_conflict":
            for version in sorted({entry.identity.version for entry in item.observations}):
                component.setdefault("properties", []).append(
                    {"name": "sca-accuracy:observed-conflicting-version", "value": version}
                )

    declared_gavs = {
        identity.gav
        for component in iter_all_components(enriched)
        if (identity := identity_from_component(component)) is not None
    }
    for item in items:
        if item.status != "observed_not_declared" or item.identity.gav in declared_gavs:
            continue
        purl = f"pkg:maven/{item.identity.group}/{item.identity.name}@{item.identity.version}"
        enriched.setdefault("components", []).append(
            {
                "type": "library",
                "bom-ref": purl,
                "group": item.identity.group,
                "name": item.identity.name,
                "version": item.identity.version,
                "purl": purl,
                "scope": "required",
                "properties": [
                    {
                        "name": "sca-accuracy:reconciliation-status",
                        "value": "observed_not_declared",
                    }
                ],
                "evidence": {
                    "occurrences": [
                        {"location": observation.location} for observation in item.observations
                    ]
                },
            }
        )
        declared_gavs.add(item.identity.gav)
    return enriched
