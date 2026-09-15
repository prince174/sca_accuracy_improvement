"""Synthetic packaging fixtures, not third-party application code. Never run the image."""

import json
import subprocess
from pathlib import Path

from sca_accuracy.pipeline import AnalysisConfig, run_analysis

ROOT = Path(__file__).resolve().parent
TARGET = ROOT / "target"


def write(path, content):
    path = TARGET / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")


def main():
    write("root/etc/os-release", 'ID=alpine\nVERSION_ID=3.20.0\nNAME="Alpine Linux"\n')
    write("root/app/node_modules/demo/package.json", {"name": "demo", "version": "1.0.0"})
    write(
        "root/usr/lib/python3/site-packages/demo_python-1.0.0.dist-info/METADATA",
        "Metadata-Version: 2.1\nName: demo-python\nVersion: 1.0.0\n",
    )
    write(
        "root/app/demo.deps.json",
        {
            "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0"},
            "targets": {
                ".NETCoreApp,Version=v8.0": {
                    "Demo.Nuget/1.0.0": {"runtime": {"lib/net8.0/Demo.Nuget.dll": {}}}
                }
            },
            "libraries": {"Demo.Nuget/1.0.0": {"type": "package", "path": "demo.nuget/1.0.0"}},
        },
    )
    write(
        "root/app/vendor/composer/installed.json",
        {"packages": [{"name": "example/demo", "version": "1.0.0", "type": "library"}]},
    )
    write(
        "root/usr/lib/ruby/gems/3.0.0/specifications/demo-1.0.0.gemspec",
        'Gem::Specification.new do |s|\n s.name = "demo"\n s.version = "1.0.0"\nend\n',
    )
    write(
        "root/lib/apk/db/installed",
        "P:demo-os\nV:1.0.0-r0\nA:x86_64\nT:Synthetic fixture\nL:MIT\no:demo-os\n\n",
    )
    write(
        "source/package-lock.json",
        {
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {"node_modules/demo": {"version": "1.0.0"}},
        },
    )
    write("source/requirements.txt", "demo-python==1.0.0\n")
    write(
        "source/Cargo.lock",
        'version = 3\n\n[[package]]\nname = "demo-rust"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    )
    write(
        "source/go.mod",
        "module example.com/fixture\n\ngo 1.22\n\nrequire example.com/demo v1.0.0\n",
    )
    write(
        "source/composer.lock",
        {"packages": [{"name": "example/demo", "version": "1.0.0"}], "packages-dev": []},
    )
    write(
        "source/Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  demo\n",
    )
    write("Dockerfile", "FROM scratch\nCOPY root/ /\n")
    purls = [
        "pkg:npm/demo@1.0.0",
        "pkg:pypi/demo-python@1.0.0",
        "pkg:nuget/Demo.Nuget@1.0.0",
        "pkg:composer/example/demo@1.0.0",
        "pkg:gem/demo@1.0.0",
        "pkg:npm/absent@1.0.0",
        "pkg:cargo/demo-rust@1.0.0",
    ]
    write(
        "bom.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {"type": "application", "name": "universal-fixture", "bom-ref": "app"}
            },
            "components": [
                {
                    "type": "library",
                    "name": p.split("/")[-1].split("@")[0],
                    "version": "1.0.0",
                    "purl": p,
                    "bom-ref": p,
                }
                for p in purls
            ],
        },
    )
    subprocess.run(
        ["docker", "build", "-t", "sca-universal-fixture:latest", str(TARGET)], check=True
    )
    run_analysis(
        AnalysisConfig(
            sbom=TARGET / "bom.json",
            image="sca-universal-fixture:latest",
            source=TARGET / "source",
            output=TARGET / "results",
        )
    )
    data = json.loads((TARGET / "results/assessment.json").read_text())
    actual = {i["bom_ref"]: i["status"] for i in data["items"] if i["bom_ref"]}
    for purl in purls[:5]:
        assert actual[purl] == "confirmed_present", (purl, actual)
    assert actual[purls[5]] == "unexpected_absent"
    assert actual[purls[6]] == "unexpected_absent"
    source = json.loads((TARGET / "results/evidence/source.syft.json").read_text())
    types = {a["type"] for a in source["artifacts"]}
    assert {"npm", "python", "rust-crate", "go-module", "php-composer", "gem"} <= types, types
    image = json.loads((TARGET / "results/evidence/image.syft.json").read_text())
    assert "apk" in {a["type"] for a in image["artifacts"]}
    assert any(
        i["identity"]["ecosystem"] == "apk" and i["status"] == "observed_not_declared"
        for i in data["items"]
    )
    print(
        "Universal fixture passed: 6 image ecosystems, 6 source ecosystems; missing and source-only packages remain unproven absent."
    )


if __name__ == "__main__":
    main()
