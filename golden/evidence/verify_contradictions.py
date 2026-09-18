"""Actual Syft scans of controlled code/metadata mismatches; never start target containers."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path

from sca_accuracy.benchmark import aggregate, evaluate_case, prepare, save_bundle, write_json
from sca_accuracy.evidence import configured_store
from sca_accuracy.experiments import CLARIFIED_PROMPT, cached_call
from sca_accuracy.hard_benchmark import INVENTORY_POLICY, evidence_rules
from sca_accuracy.llm import LlmConfig
from sca_accuracy.pipeline import AnalysisConfig, run_analysis

ROOT = Path(__file__).resolve().parents[2]
SLF4J = ROOT / "golden/image-libs/target/image-libs/slf4j-api-2.0.16.jar"
PURL = "pkg:npm/sca-code-demo@"


def build_fixture(directory, family):
    files = directory / "root"
    files.mkdir()
    (files / "fixture.txt").write_text("Controlled packaging fixture; not a production application")
    expected, audit = set(), []

    def npm(root, metadata_version, code_version):
        path = files / root
        path.mkdir(parents=True)
        if metadata_version:
            (path / "package.json").write_text(
                json.dumps({"name": "sca-code-demo", "version": metadata_version})
            )
        if code_version:
            (path / "index.js").write_text(f"exports.version = '{code_version}';\n")
            expected.add(PURL + code_version)
        audit.append(
            {
                "location": "/" + root,
                "metadata_version": metadata_version,
                "payload_files": ["index.js"] if code_version else [],
                "payload_version_marker": code_version,
                "file_listing_complete_under_package_root": True,
            }
        )

    if family == "installed":
        npm("app/node_modules/demo", "1.0.0", "1.0.0")
    elif family == "orphan":
        npm("app/node_modules/demo", "1.0.0", None)
    elif family == "stale":
        npm("app/node_modules/demo", "1.0.0", "2.0.0")
    elif family == "vendored":
        npm("app/vendor/copied", None, "1.0.0")
    elif family == "multiple":
        npm("app/node_modules/demo", "1.0.0", "1.0.0")
        npm("app/node_modules/other/node_modules/demo", "2.0.0", "2.0.0")
    elif family == "python_orphan":
        path = files / "usr/lib/python3/site-packages/sca_code_demo-1.0.0.dist-info"
        path.mkdir(parents=True)
        (path / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: sca-code-demo\nVersion: 1.0.0\n"
        )
        audit.append(
            {
                "location": "/usr/lib/python3/site-packages",
                "payload_files": [],
                "metadata_present": True,
                "file_listing_complete_under_package_root": True,
            }
        )
    elif family in {"java_original", "java_stripped"}:
        if not SLF4J.is_file():
            raise RuntimeError("Run golden/build.py first to obtain the pinned Java fixture")
        library = files / "app/component.jar"
        library.parent.mkdir()
        if family == "java_original":
            library.write_bytes(SLF4J.read_bytes())
        else:
            with zipfile.ZipFile(SLF4J) as source, zipfile.ZipFile(library, "w") as target:
                for name in source.namelist():
                    if name.endswith(".class"):
                        target.writestr(name, source.read(name))
        expected.add("pkg:maven/org.slf4j/slf4j-api@2.0.16")
        # File hash is a fact; known original identity is deliberately not in model input.
        audit.append(
            {
                "location": "/app/component.jar",
                "sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
                "payload_files": ["JVM class files"],
                "metadata_present": family == "java_original",
            }
        )
    else:
        raise ValueError("Unknown fixture")
    (directory / "Dockerfile").write_text("FROM scratch\nCOPY root/ /\n")
    return sorted(expected), {
        "provenance": "controlled image file inventory from constructor",
        "packages": audit,
        "runtime_execution": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "out/contradictions-real")
    args = parser.parse_args()
    families = (
        "installed",
        "orphan",
        "stale",
        "vendored",
        "multiple",
        "python_orphan",
        "java_original",
        "java_stripped",
    )
    rows = []
    config = (
        replace(
            LlmConfig.from_environment(),
            thinking="disabled",
            reasoning_effort=None,
            max_tokens=4096,
            timeout_seconds=180,
        )
        if args.live
        else None
    )
    for family in families:
        with tempfile.TemporaryDirectory(prefix="sca-contradiction-") as temp:
            directory = Path(temp)
            expected, artifact_evidence = build_fixture(directory, family)
            image = f"sca-contradictions-{family.replace('_', '-')}:fixture"
            subprocess.run(
                ["docker", "build", "--quiet", "--tag", image, str(directory)],
                check=True,
                capture_output=True,
            )
            bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
            path = directory / "bom.json"
            write_json(path, bom)
            output = args.output / family
            result = run_analysis(AnalysisConfig(path, image, output, evidence_kind="synthetic"))
        inventory = json.loads((output / "inventory.json").read_bytes())
        case = {
            "id": family,
            "family": family,
            "ecosystem": "mixed",
            "sbom": bom,
            "observations": inventory["observations"],
            "source_evidence": [],
            "expected_purls": expected,
            "artifact_evidence": artifact_evidence,
            "truth_source": "controlled image construction, code-bearing package identity",
            "inventory_policy": INVENTORY_POLICY,
        }
        write_json(
            output / "ground-truth.json",
            {"expected_purls": expected, "source": case["truth_source"]},
        )
        write_json(output / "case.json", case)
        response = None
        if config:
            payload = prepare(case)[3]
            response = (
                cached_call(args.output, payload, config, CLARIFIED_PROMPT)
                if payload["candidates"]
                else {"decisions": []}
            )
        row = evaluate_case(case, response)
        row["evidence_rules"] = evidence_rules(case)
        row["evidence_id"] = result["evidence_id"]
        row["transport"] = response.get("_transport") if response else None
        comparison = output / "comparison"
        save_bundle(
            comparison,
            case,
            row,
            response,
            {
                "origin": "actual Syft scan of controlled image",
                "image_id": result["image_digest"],
                "original_evidence_id": result["evidence_id"],
            },
        )
        (comparison / "evidence").mkdir(exist_ok=True)
        shutil.copyfile(
            output / "evidence/image.syft.json", comparison / "evidence/image.syft.json"
        )
        write_json(
            comparison / "provenance.json",
            {
                "generator": "real-contradictions-v1",
                "case_id": family,
                "image_id": result["image_digest"],
                "original_evidence_id": result["evidence_id"],
            },
        )
        store = configured_store()
        row["comparison_evidence_id"] = (
            store.ingest(comparison, kind="synthetic") if store else None
        )
        rows.append(row)
        # These fixture properties must stay observable as the pinned scanner evolves.
        if family in {"orphan", "stale", "python_orphan"}:
            assert row["allowed_rules"]["fp"] >= 1, (family, row)
        if family in {"installed", "multiple", "java_original"}:
            assert row["allowed_rules"]["fn"] == 0, (family, row)
        if family == "vendored":
            assert row["allowed_rules"]["fn"] == 1, row
    report = {
        "rows": rows,
        "totals": aggregate(rows, ("allowed_rules", "evidence_rules", "model")),
        "limitations": [
            "Controlled code-bearing inventory policy, not vulnerability applicability.",
            "File listing evidence is supplied by constructor, not the production scanner adapter.",
        ],
    }
    write_json(args.output / "report.json", report)
    print(json.dumps(report["totals"]), flush=True)


if __name__ == "__main__":
    main()
