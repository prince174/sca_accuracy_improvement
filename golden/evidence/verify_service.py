"""Build six packaging images; scan through live HTTP service and check stored bytes."""

import hashlib
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    target = root / "workspace/evidence-acceptance"
    url = os.getenv("SCA_SERVICE_URL", "http://127.0.0.1:18087")
    token = os.environ["SCA_API_TOKEN"]

    def api(path, data=None):
        request = urllib.request.Request(
            url + path,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            data=json.dumps(data).encode() if data is not None else None,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    api("/ready")
    results = []
    cases = {
        "exact": ["1.0.0"],
        "conflict": ["2.0.0"],
        "both": ["1.0.0", "2.0.0"],
        "absent": [],
        "extra": ["1.0.0"],
        "nested": ["1.0.0"],
    }
    for name, versions in cases.items():
        directory = target / name
        directory.mkdir(parents=True, exist_ok=True)
        files = directory / "root"
        files.mkdir(exist_ok=True)
        (files / "fixture-marker").write_text(
            "Synthetic package metadata; not third-party binaries"
        )
        for index, version in enumerate(versions):
            package = files / f"app{index}/node_modules/sca-evidence-demo/package.json"
            package.parent.mkdir(parents=True, exist_ok=True)
            package.write_text(json.dumps({"name": "sca-evidence-demo", "version": version}))
        if name == "extra":
            metadata = files / "usr/lib/python3/site-packages/sca_extra-3.0.0.dist-info/METADATA"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text("Metadata-Version: 2.1\nName: sca-extra\nVersion: 3.0.0\n")
        (directory / "Dockerfile").write_text("FROM scratch\nCOPY root/ /\n")
        image = f"sca-evidence-{name}:fixture"
        subprocess.run(
            ["docker", "build", "--quiet", "--tag", image, str(directory)],
            check=True,
            capture_output=True,
        )
        component = {
            "type": "library",
            "name": "sca-evidence-demo",
            "version": "1.0.0",
            "purl": "pkg:npm/sca-evidence-demo@1.0.0",
            "bom-ref": "demo",
        }
        components = [component]
        if name == "nested":
            components = [
                {
                    "type": "application",
                    "name": "wrapper",
                    "bom-ref": "wrapper",
                    "components": components,
                }
            ]
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": components,
        }
        (directory / "bom.json").write_text(json.dumps(bom))
        job = api(
            "/v1/analyses",
            {
                "sbom_path": f"evidence-acceptance/{name}/bom.json",
                "image": image,
                "pull_image": False,
                "with_llm": False,
                "evidence_kind": "synthetic",
            },
        )
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            status = api(f"/v1/analyses/{job['id']}")
            if status["status"] in {"failed", "succeeded"}:
                break
            time.sleep(1)
        if status["status"] != "succeeded":
            raise RuntimeError(f"Service acceptance failed: {name}, status={status['status']}")
        evidence_id = status["result"]["evidence_id"]
        stored = api(f"/v2/evidence/runs/{evidence_id}")
        assert stored["kind"] == "synthetic"
        seen = {o["purl"] for o in stored["observations"] if o["scope"] == "image"}
        expected = {f"pkg:npm/sca-evidence-demo@{version}" for version in versions}
        if name == "extra":
            expected.add("pkg:pypi/sca-extra@3.0.0")
        assert expected == seen, (name, expected, seen)
        assert api(f"/v2/evidence/runs/{evidence_id}/artifacts/sbom.original.json") == bom
        assert any(a["name"] == "evidence/image.syft.json" for a in stored["artifacts"])
        artifact = next(a for a in stored["artifacts"] if a["name"] == "sbom.enriched.json")
        request = urllib.request.Request(
            f"{url}/v2/evidence/runs/{evidence_id}/artifacts/sbom.enriched.json",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            assert hashlib.sha256(response.read()).hexdigest() == artifact["sha256"]
        results.append(
            {"case": name, "evidence_id": evidence_id, "observed": sorted(seen), "passed": True}
        )
        print(json.dumps(results[-1]), flush=True)
    output = root / "out/evidence-service-acceptance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"cases": results, "target_containers_executed": False}, indent=2))


if __name__ == "__main__":
    main()
