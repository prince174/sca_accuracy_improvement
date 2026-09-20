"""Exercise live model scoring through HTTP against three controlled images.

Requires a running service, its API token, and model credentials on that service.
Images contain a pinned Java library or synthetic npm code; targets are never run.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from verify_contradictions import build_fixture

from sca_accuracy.scoring import component_paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Authorize configured model API calls")
    parser.add_argument("--output", type=Path, default=Path("out/scoring-service-live"))
    args = parser.parse_args()
    if not args.live:
        parser.error("Pass --live to run the model-backed acceptance")
    root = Path(__file__).resolve().parents[2]
    url = os.getenv("SCA_SERVICE_URL", "http://127.0.0.1:18087")
    token = os.environ["SCA_API_TOKEN"]
    args.output.mkdir(parents=True, exist_ok=True)

    def fetch(path, data=None):
        request = urllib.request.Request(
            url + path,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            data=json.dumps(data).encode() if data is not None else None,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    def api(path, data=None):
        return json.loads(fetch(path, data))

    api("/ready")
    results = []
    for family in ("java_original", "installed", "multiple"):
        with tempfile.TemporaryDirectory(prefix="sca-score-fixture-") as directory:
            expected, _ = build_fixture(Path(directory), family)
            image = f"sca-scoring-{family.replace('_', '-')}:fixture"
            subprocess.run(
                ["docker", "build", "--quiet", "--tag", image, directory],
                capture_output=True,
                check=True,
            )
        # Deliberately declare a wrong version and a package not in the constructed image.
        declared = (
            ("org.slf4j", "slf4j-api", "2.0.13", "maven")
            if family == "java_original"
            else ("", "sca-code-demo", "0.9.0", "npm")
        )
        group, name, version, ecosystem = declared
        purl = f"pkg:{ecosystem}/{group + '/' if group else ''}{name}@{version}"
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": "wrong-version",
                    "group": group,
                    "name": name,
                    "version": version,
                    "purl": purl,
                },
                {
                    "type": "library",
                    "bom-ref": "missing-package",
                    "name": "sca-score-absent",
                    "version": "1.0.0",
                    "purl": "pkg:npm/sca-score-absent@1.0.0",
                },
            ],
            "dependencies": [{"ref": "wrong-version", "dependsOn": ["missing-package"]}],
        }
        input_path = root / "workspace/scoring-acceptance" / family / "bom.json"
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text(json.dumps(bom), encoding="utf-8")
        job = api(
            "/v1/analyses",
            {
                "sbom_path": input_path.relative_to(root / "workspace").as_posix(),
                "image": image,
                "pull_image": False,
                "with_llm": True,
                "evidence_kind": "synthetic",
            },
        )
        print(json.dumps({"case": family, "job": job["id"], "status": "submitted"}), flush=True)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = api(f"/v1/analyses/{job['id']}")
            if status["status"] in {"failed", "succeeded"}:
                break
            time.sleep(1)
        if status["status"] != "succeeded":
            raise RuntimeError(f"Score acceptance {family}: {status['status']}")
        target = args.output / family
        target.mkdir(exist_ok=True)
        artifacts = {}
        for filename in (
            "sbom.original.json",
            "sbom.enriched.json",
            "component-scores.json",
            "model-request.json",
            "model-response.json",
            "assessment.json",
            "report.html",
        ):
            content = fetch(f"/v1/analyses/{job['id']}/artifacts/{filename}")
            (target / filename).write_bytes(content)
            artifacts[filename] = content
        assert json.loads(artifacts["sbom.original.json"]) == bom
        scores = json.loads(artifacts["component-scores.json"])
        output = json.loads(artifacts["sbom.enriched.json"])
        expected_ids = {a["component_id"] for a in scores["assessments"] if a["tp_score"] > 70}
        actual_ids = set()
        for _, component in component_paths(output):
            props = {p["name"]: p["value"] for p in component["properties"]}
            assert float(props["sca-accuracy:tp-score"]) > 70
            actual_ids.add(props["sca-accuracy:assessment-id"])
        assert actual_ids == expected_ids
        assert all(a["included"] == (a["tp_score"] > 70) for a in scores["assessments"])
        requested = json.loads(artifacts["model-request.json"])
        assert {c["id"] for b in requested["batches"] for c in b["components"]} == {
            a["component_id"] for a in scores["assessments"]
        }
        stored = api(f"/v2/evidence/runs/{status['result']['evidence_id']}")
        assert stored["kind"] == "synthetic"
        stored_scores = next(a for a in stored["artifacts"] if a["name"] == "component-scores.json")
        assert (
            stored_scores["sha256"]
            == hashlib.sha256(artifacts["component-scores.json"]).hexdigest()
        )
        actual = {c.get("purl") for _, c in component_paths(output)}
        gold = set(expected)
        row = {
            "case": family,
            "job_id": job["id"],
            "evidence_id": status["result"]["evidence_id"],
            "contract_passed": True,
            "image_digest": status["result"]["image_digest"],
            "input_components": len(bom["components"]),
            "assessed": len(scores["assessments"]),
            "included": len(actual_ids),
            "excluded": len(scores["assessments"]) - len(actual_ids),
            "expected_purls": sorted(gold),
            "output_purls": sorted(actual, key=str),
            "false_positive_purls": sorted(actual - gold, key=str),
            "false_negative_purls": sorted(gold - actual),
            "model_transport": json.loads(artifacts["model-response.json"])["_transport"],
        }
        results.append(row)
        (args.output / "acceptance.json").write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(json.dumps({k: v for k, v in row.items() if k != "model_transport"}), flush=True)


if __name__ == "__main__":
    main()
