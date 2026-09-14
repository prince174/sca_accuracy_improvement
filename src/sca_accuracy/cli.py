from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import AnalysisConfig, run_analysis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca-accuracy",
        description="Reconcile a CycloneDX SBOM with Java components delivered in a container image.",
    )
    parser.add_argument("--sbom", required=True, type=Path, help="CycloneDX JSON input")
    parser.add_argument("--image", required=True, help="Container image reference or digest")
    parser.add_argument(
        "--pull", action="store_true", help="Pull the image reference before inspecting its layers"
    )
    parser.add_argument("--output", type=Path, default=Path("out"), help="Output directory")
    parser.add_argument(
        "--source",
        type=Path,
        help="Maven module source directory; used to derive dependency scopes when tree is absent",
    )
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
    import json

    result = run_analysis(
        AnalysisConfig(
            sbom=args.sbom,
            image=args.image,
            output=args.output,
            pull_image=args.pull,
            source=args.source,
            dependency_tree=args.dependency_tree,
            expectations=args.expectations,
            with_llm=args.with_llm,
            findings=args.findings,
            vex_mode=args.vex_mode,
            vulnerability_rules=args.vulnerability_rules,
            vex_expectations=args.vex_expectations,
        )
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


def main() -> None:
    try:
        raise SystemExit(run(build_parser().parse_args()))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
