"""Synthetic labeled evaluation; --live calls the configured model, default tests the executor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sca_accuracy.decisions import apply_plan, candidates
from sca_accuracy.llm import LlmConfig, analyze
from sca_accuracy.models import ComponentIdentity, Observation
from sca_accuracy.sbom import enrich_sbom, iter_all_components, reconcile


def metrics(bom, expected):
    actual = {c.get("purl") for c in iter_all_components(bom)}
    return {
        "tp": len(actual & expected),
        "fp": len(actual - expected),
        "fn": len(expected - actual),
    }


def evaluate(live=False):
    rows = []
    for ecosystem in ("maven", "npm", "pypi", "nuget", "golang", "cargo", "gem", "composer", "apk"):
        old = ComponentIdentity("", "demo", "1", ecosystem)
        new = ComponentIdentity("", "demo", "2", ecosystem)
        extra = ComponentIdentity("", "extra", "1", ecosystem)
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": "demo",
                    "name": "demo",
                    "version": "1",
                    "purl": old.purl,
                    "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                }
            ],
        }
        # Only Java currently supplies a byte-level link in the production scanner.
        obs = [
            Observation(
                new, "/demo", "fixture-metadata", "a" * 64 if ecosystem == "maven" else None
            ),
            Observation(extra, "/extra", "fixture-metadata"),
        ]
        expected = {new.purl, extra.purl}
        offered = candidates(bom, obs)
        payload = {
            "candidates": offered,
            "coverage": {"absence_proven": False},
            "discrepancies": [i.to_dict() for i in reconcile(bom, obs)],
        }
        response = (
            analyze(payload, LlmConfig.from_environment())
            if live
            else {
                "decisions": [
                    {"candidate_id": c["id"], "action": "apply", "reason": "scripted test decision"}
                    for c in offered
                ]
            }
        )
        corrected, audit = apply_plan(bom, obs, response["decisions"])
        baseline = enrich_sbom(bom, reconcile(bom, obs), "fixture", "fixture")
        rows.append(
            {
                "ecosystem": ecosystem,
                "input": metrics(bom, expected),
                "rules": metrics(baseline, expected),
                "validated_plan": metrics(corrected, expected),
                "audit": audit,
                "response": response,
            }
        )
    return {
        "dataset": "synthetic-package-identities-v1",
        "live_model": live,
        "scope": "component inventory, not vulnerability applicability or runtime reachability",
        "rows": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("out/model-evaluation.json"))
    args = parser.parse_args()
    result = evaluate(args.live)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "live_model": result["live_model"],
                "cases": len(result["rows"]),
                "output": str(args.output),
            }
        )
    )
