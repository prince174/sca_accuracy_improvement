"""Complete component assessments and deterministic filtering at TP score > 70."""

from __future__ import annotations

import copy
import math
from typing import Any

from .evidence import checksum
from .sbom import identity_from_component

TP_THRESHOLD = 70
POLICY = "tp-score-gt-70-v1"


def component_paths(sbom):
    def walk(items, prefix):
        for index, component in enumerate(items):
            path = f"{prefix}/{index}"
            yield path, component
            yield from walk(component.get("components", []), path + "/components")

    yield from walk(sbom.get("components", []), "components")
    root = sbom.get("metadata", {}).get("component", {})
    yield from walk(root.get("components", []), "metadata/component/components")


def component_catalog(sbom, observations, source_observations=()):
    """Group declared/observed identities; the document subject itself is not a dependency."""
    entries = {}
    for path, component in component_paths(sbom):
        identity = identity_from_component(component)
        key = identity.purl if identity else path
        record = {k: copy.deepcopy(v) for k, v in component.items() if k != "components"}
        entry = entries.setdefault(
            key,
            {
                "id": checksum({"identity": key}),
                "identity": identity.purl if identity else None,
                "component": record,
                "declared_paths": [],
                "evidence": [],
            },
        )
        entry["declared_paths"].append(path)
        data = {
            "origin": "build_sbom",
            "source": "build_sbom",
            "sha256": None,
            "path": path,
            "component": record,
        }
        entry["evidence"].append({"id": checksum(data), **data})
    root_identity = identity_from_component(sbom.get("metadata", {}).get("component", {}))
    for observation in observations:
        identity = observation.identity
        if root_identity == identity and identity.purl not in entries:
            continue
        entry = entries.setdefault(
            identity.purl,
            {
                "id": checksum({"identity": identity.purl}),
                "identity": identity.purl,
                "component": {
                    "type": "library",
                    "name": identity.name,
                    "group": identity.group,
                    "version": identity.version,
                    **({"purl": identity.purl} if identity.ecosystem != "generic" else {}),
                },
                "declared_paths": [],
                "evidence": [],
            },
        )
        data = {"origin": "image", **observation.to_dict()}
        entry["evidence"].append({"id": checksum(data), **data})
    for observation in source_observations:
        entry = entries.get(observation.identity.purl)
        if entry is not None:
            data = {"origin": "source_checkout", **observation.to_dict()}
            entry["evidence"].append({"id": checksum(data), **data})
    for entry in entries.values():
        entry["evidence"] = list({e["id"]: e for e in entry["evidence"]}.values())
    return list(entries.values())


def validate_scores(catalog, assessments):
    if not isinstance(assessments, list) or len(assessments) != len(catalog):
        raise ValueError("Exactly one assessment is required for every component")
    expected = {entry["id"]: entry for entry in catalog}
    if len(expected) != len(catalog):
        raise ValueError("Duplicate component IDs in assessment catalog")
    result = {}
    for assessment in assessments:
        if not isinstance(assessment, dict) or set(assessment) != {
            "component_id",
            "tp_score",
            "reason",
            "evidence_ids",
            "missing_evidence",
        }:
            raise ValueError("Invalid component assessment fields")
        cid, score = assessment["component_id"], assessment["tp_score"]
        if not isinstance(cid, str) or cid not in expected or cid in result:
            raise ValueError("Unknown or duplicate component assessment")
        if type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 100:
            raise ValueError("TP score must be a finite number from 0 to 100")
        reason = assessment["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
            raise ValueError("Assessment requires a bounded nonempty reason")
        evidence_ids = assessment["evidence_ids"]
        if (
            not isinstance(evidence_ids, list)
            or len(evidence_ids) > 100
            or any(not isinstance(e, str) for e in evidence_ids)
            or not set(evidence_ids) <= {e["id"] for e in expected[cid]["evidence"]}
        ):
            raise ValueError("Assessment references unknown evidence")
        missing = assessment["missing_evidence"]
        if (
            not isinstance(missing, list)
            or len(missing) > 20
            or any(not isinstance(m, str) or len(m) > 1000 for m in missing)
        ):
            raise ValueError("Invalid missing-evidence list")
        result[cid] = copy.deepcopy(assessment)
    if result.keys() != expected.keys():
        raise ValueError("Component assessments are incomplete")
    return result


def _refs(document):
    refs = []

    def walk(value):
        if isinstance(value, dict):
            if "bom-ref" in value:
                refs.append(value["bom-ref"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if any(not isinstance(ref, str) or not ref for ref in refs) or len(refs) != len(set(refs)):
        raise ValueError("SBOM bom-ref values must be nonempty and unique")
    return set(refs)


def _clean_references(document, removed):
    counts = {
        "dependency_nodes": 0,
        "dependency_edges": 0,
        "vulnerability_targets": 0,
        "vulnerabilities": 0,
        "signatures": 0,
    }
    deps = []
    for node in document.get("dependencies", []):
        if node.get("ref") in removed:
            counts["dependency_nodes"] += 1
            continue
        for key in ("dependsOn", "provides"):
            if key in node:
                previous = node[key]
                node[key] = [ref for ref in previous if ref not in removed]
                counts["dependency_edges"] += len(previous) - len(node[key])
        deps.append(node)
    if "dependencies" in document:
        document["dependencies"] = deps
    vulnerabilities = []
    for vuln in document.get("vulnerabilities", []):
        affects = vuln.get("affects", [])
        remaining = [a for a in affects if a.get("ref") not in removed]
        counts["vulnerability_targets"] += len(affects) - len(remaining)
        if affects and not remaining:
            counts["vulnerabilities"] += 1
            if vuln.get("bom-ref"):
                removed.add(vuln["bom-ref"])
            continue
        if "affects" in vuln:
            vuln["affects"] = remaining
        vulnerabilities.append(vuln)
    if "vulnerabilities" in document:
        document["vulnerabilities"] = vulnerabilities
    for composition in document.get("compositions", []):
        for key in ("assemblies", "dependencies", "vulnerabilities"):
            if key in composition:
                old = composition[key]
                composition[key] = [ref for ref in old if ref not in removed]
                if old != composition[key]:
                    composition["aggregate"] = "unknown"
    annotations = []
    for annotation in document.get("annotations", []):
        subjects = annotation.get("subjects", [])
        if subjects:
            annotation["subjects"] = [s for s in subjects if s not in removed]
            if not annotation["subjects"]:
                if annotation.get("bom-ref"):
                    removed.add(annotation["bom-ref"])
                continue
        annotations.append(annotation)
    if "annotations" in document:
        document["annotations"] = annotations

    def guard(value, key=""):
        if isinstance(value, dict):
            if "signature" in value:
                value.pop("signature")
                counts["signatures"] += 1
            for k, v in value.items():
                guard(v, k)
        elif isinstance(value, list):
            for child in value:
                guard(child, key)
        elif (
            isinstance(value, str)
            and value in removed
            and key
            in {
                "ref",
                "dependsOn",
                "provides",
                "assemblies",
                "dependencies",
                "subjects",
                "vulnerabilities",
                "components",
                "services",
            }
        ):
            raise ValueError(
                "Unsupported reference to an excluded component; cannot publish filtered SBOM"
            )

    guard(document)
    return counts


def filter_sbom(sbom, observations, assessments, source_observations=()):
    catalog = component_catalog(sbom, observations, source_observations)
    scores = validate_scores(catalog, assessments)
    original_refs = _refs(sbom)
    by_path = {path: entry for entry in catalog for path in entry["declared_paths"]}
    result = copy.deepcopy(sbom)
    audit: dict[str, Any] = {
        "policy_version": POLICY,
        "threshold": TP_THRESHOLD,
        "comparison": ">",
        "score_kind": "uncalibrated_model_estimate",
        "assessments": [],
        "accepted": [],
        "excluded": [],
        "rejected": [],
        "input_sha256": checksum(sbom),
        "subject_policy": "metadata.component describes the document subject and is retained",
    }

    def annotate(component, entry):
        score = scores[entry["id"]]["tp_score"]
        props = component.setdefault("properties", [])
        names = {
            "sca-accuracy:tp-score",
            "sca-accuracy:fp-score",
            "sca-accuracy:score-kind",
            "sca-accuracy:assessment-id",
        }
        props[:] = [p for p in props if p.get("name") not in names]
        props.extend(
            [
                {"name": "sca-accuracy:tp-score", "value": str(score)},
                {"name": "sca-accuracy:fp-score", "value": str(100 - score)},
                {"name": "sca-accuracy:score-kind", "value": audit["score_kind"]},
                {"name": "sca-accuracy:assessment-id", "value": entry["id"]},
            ]
        )

    removed_count = 0

    def prune(items, prefix):
        nonlocal removed_count
        kept = []
        for index, component in enumerate(items):
            path = f"{prefix}/{index}"
            entry = by_path[path]
            children = prune(component.get("components", []), path + "/components")
            if scores[entry["id"]]["tp_score"] > TP_THRESHOLD:
                if "components" in component:
                    component["components"] = children
                annotate(component, entry)
                kept.append(component)
            else:
                removed_count += 1
                kept.extend(children)  # A passing child must survive a rejected parent.
        return kept

    result["components"] = prune(result.get("components", []), "components")
    root = result.get("metadata", {}).get("component")
    if isinstance(root, dict) and "components" in root:
        root["components"] = prune(root["components"], "metadata/component/components")
    added_count = 0
    for entry in catalog:
        score = scores[entry["id"]]["tp_score"]
        included = score > TP_THRESHOLD
        row = {
            **scores[entry["id"]],
            "identity": entry["identity"],
            "name": entry["component"].get("name", "unknown"),
            "fp_score": 100 - score,
            "included": included,
            "label": "TP" if included else "FP" if score < 30 else "uncertain",
            "declared_paths": entry["declared_paths"],
        }
        audit["assessments"].append(row)
        audit["accepted" if included else "excluded"].append(row)
        if included and not entry["declared_paths"]:
            component = copy.deepcopy(entry["component"])
            ref = "sca-scored-" + entry["id"]
            if ref in original_refs:
                raise ValueError("Generated component bom-ref collides with input")
            component["bom-ref"] = ref
            component["evidence"] = {
                "occurrences": [
                    {"location": e["location"]} for e in entry["evidence"] if e["origin"] == "image"
                ]
            }
            annotate(component, entry)
            result["components"].append(component)
            added_count += 1
    removed_refs = original_refs - _refs(result)
    audit["references_pruned"] = _clean_references(result, removed_refs)
    _refs(result)
    audit["removed_bom_refs"] = sorted(removed_refs)
    audit["changes_applied"] = removed_count + added_count
    audit["components_removed"] = removed_count
    audit["components_added"] = added_count
    result["version"] = sbom.get("version", 1) + 1
    properties = result.setdefault("metadata", {}).setdefault("properties", [])
    policy_props = {
        "sca-accuracy:inventory-policy": POLICY,
        "sca-accuracy:tp-threshold": ">70",
        "sca-accuracy:score-kind": audit["score_kind"],
        "sca-accuracy:scope": "model-filtered inventory; not proof of absence or CVE non-applicability",
    }
    properties[:] = [p for p in properties if p.get("name") not in policy_props]
    properties.extend({"name": k, "value": v} for k, v in policy_props.items())
    return result, audit
