from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from .findings import Finding
from .models import ReconciliationItem
from .sbom import iter_all_components
from .vulnerability_rules import VulnerabilityRule

VexMode = Literal["advisory", "safe"]


def build_vex(
    sbom: dict[str, Any],
    findings: list[Finding],
    reconciliation: list[ReconciliationItem],
    image_digest: str,
    mode: VexMode = "advisory",
    rules: dict[str, VulnerabilityRule] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rules = rules or {}
    components_by_ref = {
        str(component["bom-ref"]): component
        for component in iter_all_components(sbom)
        if component.get("bom-ref")
    }
    items_by_ref = {item.bom_ref: item for item in reconciliation if item.bom_ref}
    vex_components: dict[str, dict[str, Any]] = {}
    vulnerabilities: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []

    root = sbom.get("metadata", {}).get("component")
    if not isinstance(root, dict):
        raise TypeError("SBOM metadata.component is required to build product-scoped VEX")

    for finding in findings:
        source_component = components_by_ref.get(finding.affects_ref)
        item = items_by_ref.get(finding.affects_ref)
        decision = _decision(finding, item, image_digest, mode, rules.get(finding.vulnerability_id))
        assessment = {
            "vulnerability_id": finding.vulnerability_id,
            "source": finding.source_name,
            "affects_ref": finding.affects_ref,
            "component": finding.component.gav if finding.component else None,
            **decision,
        }
        assessments.append(assessment)
        if source_component is None:
            assessment["emitted_to_vex"] = False
            assessment["reason"] = "The affects reference cannot be resolved in the supplied SBOM."
            continue

        vex_components[finding.affects_ref] = _identity_component(source_component)
        vulnerability: dict[str, Any] = {
            "id": finding.vulnerability_id,
            "analysis": {
                "state": decision["state"],
                "detail": decision["detail"],
            },
            "affects": [{"ref": finding.affects_ref}],
        }
        if finding.source_name:
            vulnerability["source"] = {"name": finding.source_name}
            if finding.source_url:
                vulnerability["source"]["url"] = finding.source_url
        if decision.get("justification"):
            vulnerability["analysis"]["justification"] = decision["justification"]
        vulnerabilities.append(vulnerability)
        assessment["emitted_to_vex"] = True

    metadata_component = _identity_component(root)
    metadata_component["bom-ref"] = str(root.get("bom-ref", "product"))
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": metadata_component,
            "properties": [{"name": "sca-accuracy:image-digest", "value": image_digest}],
        },
        "components": list(vex_components.values()),
        "vulnerabilities": vulnerabilities,
    }
    return vex, assessments


def _identity_component(component: dict[str, Any]) -> dict[str, Any]:
    allowed = ("bom-ref", "type", "group", "name", "version", "purl", "cpe", "hashes")
    return {key: copy.deepcopy(component[key]) for key in allowed if key in component}


def _decision(
    finding: Finding,
    item: ReconciliationItem | None,
    image_digest: str,
    mode: VexMode,
    rule: VulnerabilityRule | None,
) -> dict[str, str]:
    if item is None:
        return {
            "state": "in_triage",
            "detail": "No reconciliation evidence was found for this component.",
            "automation": "blocked",
        }
    if rule and finding.component and rule.component_gav == finding.component.gav:
        observed_symbols = {
            symbol for observation in item.observations for symbol in observation.referenced_symbols
        }
        matched = sorted(observed_symbols & rule.symbols)
        if matched:
            return {
                "state": "in_triage",
                "detail": (
                    "Static bytecode references a rule-associated symbol; exploitability is unproven in the "
                    f"delivered image {image_digest}: {', '.join(matched)}"
                ),
                "automation": "deterministic_symbol_match",
                "matched_symbols": ",".join(matched),
            }
    return {
        "state": "in_triage",
        "detail": (
            f"Component reconciliation status is {item.status} for image {image_digest}. "
            "Additional vulnerability-specific reachability evidence is required."
        ),
        "automation": "advisory",
    }
