from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .catalog import coverage, inspect_image, observations_from_catalog, scan
from .decisions import apply_plan, candidates
from .expectations import load_expectations, verify_expectations, verify_vex_expectations
from .findings import load_findings
from .llm import LlmConfig, analyze
from .maven import load_dependency_tree
from .report import write_outputs
from .sbom import enrich_sbom, load_sbom, reconcile
from .vex import build_vex
from .vulnerability_rules import load_vulnerability_rules


@dataclass(slots=True, frozen=True)
class AnalysisConfig:
    sbom: Path
    image: str
    output: Path
    pull_image: bool = False
    source: Path | None = None
    dependency_tree: Path | None = None
    expectations: Path | None = None
    with_llm: bool = False
    findings: Path | None = None
    vex_mode: Literal["advisory", "safe"] = "advisory"
    vulnerability_rules: Path | None = None
    vex_expectations: Path | None = None


def run_analysis(config: AnalysisConfig) -> dict[str, Any]:
    sbom = load_sbom(config.sbom)
    dependency_tree = config.dependency_tree
    maven_scopes = load_dependency_tree(dependency_tree) if dependency_tree else {}
    evidence = config.output / "evidence"
    source_catalog = (
        scan(f"dir:{config.source.resolve()}", evidence / "source.syft.json")
        if config.source
        else None
    )
    digest, observations, image_catalog = inspect_image(
        config.image, evidence, pull=config.pull_image
    )
    _write_json(config.output / "coverage.json", coverage(image_catalog, source_catalog))
    items = reconcile(sbom, observations, maven_scopes)
    source_items = []
    if source_catalog is not None:
        source_items = reconcile(sbom, observations_from_catalog(source_catalog))
        for item in source_items:
            item.explanation = item.explanation.replace(
                "delivered image", "source catalog"
            ).replace("the image", "the source catalog")
        _write_json(
            config.output / "source-assessment.json",
            {
                "provenance": "checkout catalog; not original build resolution",
                "items": [item.to_dict() for item in source_items],
            },
        )
    discrepancies = [
        item.to_dict()
        for item in items
        if item.status not in {"confirmed_present", "expected_absent"}
    ]
    findings = load_findings(config.findings) if config.findings else []
    llm_analysis = None
    decision_audit = None
    corrected = sbom
    if config.with_llm:
        llm_analysis = analyze(
            {
                "image": config.image,
                "digest": digest,
                "discrepancies": discrepancies,
                "findings": [finding.to_dict() for finding in findings],
                "coverage": coverage(image_catalog, source_catalog),
                "source_evidence": [item.to_dict() for item in source_items],
                "candidates": candidates(sbom, observations),
            },
            LlmConfig.from_environment(),
        )
        corrected, decision_audit = apply_plan(sbom, observations, llm_analysis["decisions"])
        _write_json(config.output / "decisions.json", decision_audit)
    corrected_items = reconcile(corrected, observations, maven_scopes)
    enriched = enrich_sbom(
        corrected, corrected_items, config.image, digest, add_observed=not config.with_llm
    )
    _write_json(config.output / "sbom.original.json", sbom)
    write_outputs(
        config.output,
        config.image,
        digest,
        observations,
        items,
        enriched,
        llm_analysis,
    )
    vex_result = _write_vex(config, sbom, findings, items, digest)
    expectation_result = _write_reconciliation_expectations(config, items)
    return {
        "output": str(config.output.resolve()),
        "image_digest": digest,
        "components_observed": len(observations),
        "discrepancies": len(discrepancies),
        "expectations": expectation_result,
        "vex": vex_result,
        "dependency_tree": str(dependency_tree) if dependency_tree else None,
        "decision_mode": "model_validated" if config.with_llm else "rules",
        "changes_applied": len(decision_audit["accepted"]) if decision_audit else 0,
    }


def _write_vex(
    config: AnalysisConfig,
    sbom: dict[str, Any],
    findings: list[Any],
    items: list[Any],
    digest: str,
) -> dict[str, Any] | None:
    if not findings:
        return None
    rules = (
        load_vulnerability_rules(config.vulnerability_rules) if config.vulnerability_rules else {}
    )
    vex, vulnerability_assessments = build_vex(
        sbom, findings, items, digest, mode=config.vex_mode, rules=rules
    )
    result: dict[str, Any] = {
        "findings": len(findings),
        "vex_entries": len(vex["vulnerabilities"]),
        "mode": config.vex_mode,
    }
    _write_json(config.output / "vex.json", vex)
    _write_json(
        config.output / "vulnerability-assessment.json",
        {"mode": config.vex_mode, "assessments": vulnerability_assessments},
    )
    if config.vex_expectations:
        expectation_result = verify_vex_expectations(
            vex, load_expectations(config.vex_expectations)
        )
        result["expectations"] = expectation_result
        if not expectation_result["passed"]:
            mismatches = json.dumps(expectation_result["mismatches"], ensure_ascii=False)
            raise RuntimeError(f"VEX expectations failed: {mismatches}")
    return result


def _write_reconciliation_expectations(
    config: AnalysisConfig, items: list[Any]
) -> dict[str, Any] | None:
    if not config.expectations:
        return None
    result = verify_expectations(items, load_expectations(config.expectations))
    _write_json(config.output / "expectation-result.json", result)
    if not result["passed"]:
        mismatches = json.dumps(result["mismatches"], ensure_ascii=False)
        raise RuntimeError(f"Reconciliation expectations failed: {mismatches}")
    return result


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
