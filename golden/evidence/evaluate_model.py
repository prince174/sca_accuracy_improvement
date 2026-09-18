"""Compare real Syft evidence from controlled packaging images, keeping labels local."""

import hashlib
import json
from pathlib import Path

from sca_accuracy.benchmark import aggregate, evaluate_case, prepare, save_bundle, write_json
from sca_accuracy.evidence import checksum, configured_store
from sca_accuracy.llm import SYSTEM_PROMPT, LlmConfig, analyze


def main():
    store = configured_store()
    if store is None:
        raise RuntimeError("Configure SCA_EVIDENCE_DSN")
    config = LlmConfig.from_environment()
    root = Path(__file__).resolve().parents[2]
    acceptance = json.loads((root / "out/evidence-service-acceptance.json").read_bytes())
    output = root / "out/scanned-model-comparison"
    rows = []
    for entry in acceptance["cases"]:
        original_id = entry["evidence_id"]
        # Labels derive from fixture construction, not from scanner results.
        expected_versions = {
            "exact": ["1.0.0"],
            "conflict": ["2.0.0"],
            "both": ["1.0.0", "2.0.0"],
            "absent": [],
            "extra": ["1.0.0"],
            "nested": ["1.0.0"],
        }
        expected = [f"pkg:npm/sca-evidence-demo@{v}" for v in expected_versions[entry["case"]]]
        if entry["case"] == "extra":
            expected.append("pkg:pypi/sca-extra@3.0.0")
        case = {
            "id": "scanned-" + entry["case"],
            "family": entry["case"],
            "ecosystem": "npm/pypi",
            "sbom": json.loads(store.artifact(original_id, "sbom.original.json").read_bytes()),
            "observations": json.loads(store.artifact(original_id, "inventory.json").read_bytes())[
                "observations"
            ],
            "source_evidence": [],
            "expected_purls": expected,
            "truth_source": "controlled scratch image construction; actual Syft scan, synthetic package metadata",
        }
        _, _, _, payload = prepare(case)
        cache_key = checksum(
            {
                "source_run": original_id,
                "model": config.model,
                "endpoint": config.base_url,
                "prompt": SYSTEM_PROMPT,
                "payload": payload,
            }
        )
        checkpoint = output / (cache_key + ".json")
        if checkpoint.exists():
            response = json.loads(checkpoint.read_bytes())
        elif payload["candidates"]:
            response = analyze(payload, config)
            write_json(checkpoint, response)
        else:
            response = {
                "summary": "No admissible edits; model not called",
                "hypotheses": [],
                "warnings": [],
                "decisions": [],
            }
        row = evaluate_case(case, response)
        row["model_called"] = bool(payload["candidates"])
        context = {
            "model": config.model,
            "source_run": original_id,
            "prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
            "kind": "real_scanner_synthetic_image",
        }
        directory = output / "bundles" / case["id"]
        save_bundle(directory, case, row, response, context)
        row["evidence_id"] = store.ingest(directory, kind="synthetic")
        rows.append(row)
        print(
            json.dumps(
                {"case": case["id"], "model_called": row["model_called"], "model": row["model"]}
            ),
            flush=True,
        )
    report = {
        "all": aggregate(rows, ("legacy_rules", "allowed_rules", "model")),
        "model_called": aggregate(
            [r for r in rows if r["model_called"]], ("legacy_rules", "allowed_rules", "model")
        ),
        "rows": rows,
    }
    write_json(output / "report.json", report)
    print(json.dumps(report["model_called"]), flush=True)


if __name__ == "__main__":
    main()
