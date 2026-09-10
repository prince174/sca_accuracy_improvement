from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .image import inspect_image
from .llm import LlmConfig, analyze
from .maven import load_dependency_tree
from .report import write_outputs
from .sbom import enrich_sbom, load_sbom, reconcile


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
        "--with-llm", action="store_true", help="Ask the configured LLM to explain discrepancies"
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
    llm_analysis = None
    if args.with_llm and discrepancies:
        llm_analysis = analyze(
            {"image": args.image, "digest": digest, "discrepancies": discrepancies},
            LlmConfig.from_environment(),
        )
    write_outputs(args.output, args.image, digest, observations, items, enriched, llm_analysis)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "image_digest": digest,
                "components_observed": len(observations),
                "discrepancies": len(discrepancies),
            },
            ensure_ascii=False,
        )
    )
    return 0


def main() -> None:
    try:
        raise SystemExit(run(build_parser().parse_args()))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
