from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .expectations import load_expectations, verify_expectations, verify_vex_expectations
from .findings import load_findings
from .image import inspect_image
from .llm import LlmConfig, analyze
from .maven import load_dependency_tree
from .report import write_outputs
from .sbom import enrich_sbom, load_sbom, reconcile
from .vex import build_vex
from .vulnerability_rules import load_vulnerability_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca-accuracy",
        description="Reconcile a CycloneDX SBOM with Java components delivered in a container image.",
    )
    parser.add_argument("--sbom", required=True, type=Path, help="CycloneDX JSON input")
    parser.add_argument(
        "--image", required=True, help="Locally available image reference or digest"
    )
    parser.add_argument("--output", type=Path, default=Path("out"), help="Output directory")
    parser.add_argument(
        "--dependency-tree", type=Path, help="Maven dependency:tree JSON with resolved scopes"
    )
    parser.add_argument(
        "--expectations", type=Path, help="Expected GAV-to-status JSON; fail on any mismatch"
    )
    parser.add_argument(
        "--with-llm", action="store_true", help="Ask the configured LLM to explain discrepancies"
    )
    parser.add_argument(
        "--findings", type=Path, help="CycloneDX VDR/BOM containing vulnerability findings"
    )
    parser.add_argument(
        "--vex-mode",
        choices=("advisory", "safe"),
        default="advisory",
        help="VEX policy: advisory keeps findings in triage; safe enables deterministic rules",
    )
    parser.add_argument(
        "--vulnerability-rules",
        type=Path,
        help="Local vulnerability-to-JVM-symbol rule database",
    )
    parser.add_argument(
        "--vex-expectations", type=Path, help="Expected vulnerability-ID-to-VEX-state JSON"
    )
    return parser


def run(args: argparse.Namespace) -> int:
    sbom = load_sbom(args.sbom)
    maven_scopes = load_dependency_tree(args.dependency_tree) if args.dependency_tree else {}
    digest, observations = inspect_image(args.image)
    items = reconcile(sbom, observations, maven_scopes)
    enriched = enrich_sbom(sbom, items, args.image, digest)
    discrepancies = [
        item.to_dict()
        for item in items
        if item.status not in {"confirmed_present", "expected_absent"}
    ]
    findings = load_findings(args.findings) if args.findings else []
    llm_analysis = None
    if args.with_llm and (discrepancies or findings):
        llm_analysis = analyze(
            {
                "image": args.image,
                "digest": digest,
                "discrepancies": discrepancies,
                "findings": [finding.to_dict() for finding in findings],
            },
            LlmConfig.from_environment(),
        )
    write_outputs(args.output, args.image, digest, observations, items, enriched, llm_analysis)
    vex_result = None
    if findings:
        rules = (
            load_vulnerability_rules(args.vulnerability_rules) if args.vulnerability_rules else {}
        )
        vex, vulnerability_assessments = build_vex(
            sbom, findings, items, digest, mode=args.vex_mode, rules=rules
        )
        vex_result = {
            "findings": len(findings),
            "vex_entries": len(vex["vulnerabilities"]),
            "mode": args.vex_mode,
        }
        for filename, document in (
            ("vex.json", vex),
            (
                "vulnerability-assessment.json",
                {"mode": args.vex_mode, "assessments": vulnerability_assessments},
            ),
        ):
            with (args.output / filename).open("w", encoding="utf-8") as stream:
                json.dump(document, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        if args.vex_expectations:
            vex_expectation_result = verify_vex_expectations(
                vex, load_expectations(args.vex_expectations)
            )
            vex_result["expectations"] = vex_expectation_result
            if not vex_expectation_result["passed"]:
                mismatches = json.dumps(vex_expectation_result["mismatches"], ensure_ascii=False)
                raise RuntimeError(f"VEX expectations failed: {mismatches}")
    expectation_result = None
    if args.expectations:
        expectation_result = verify_expectations(items, load_expectations(args.expectations))
        with (args.output / "expectation-result.json").open("w", encoding="utf-8") as stream:
            json.dump(expectation_result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        if not expectation_result["passed"]:
            mismatches = json.dumps(expectation_result["mismatches"], ensure_ascii=False)
            raise RuntimeError(f"Reconciliation expectations failed: {mismatches}")
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "image_digest": digest,
                "components_observed": len(observations),
                "discrepancies": len(discrepancies),
                "expectations": expectation_result,
                "vex": vex_result,
            },
            ensure_ascii=False,
        )
    )
    return 0


def main() -> None:
    try:
        raise SystemExit(run(build_parser().parse_args()))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
