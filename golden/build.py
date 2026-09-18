"""Build the Java golden fixture using Maven build containers."""

import subprocess
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    for module in ("app", "image-libs"):
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--mount",
                f"type=bind,source={root},target=/workspace",
                "--mount",
                "type=volume,source=sca-accuracy-m2,target=/root/.m2",
                "-w",
                f"/workspace/{module}",
                "maven:3.9.11-eclipse-temurin-21",
                "mvn",
                "-B",
                "clean",
                "package",
            ],
            check=True,
        )
    subprocess.run(
        ["docker", "build", "--tag", "sca-accuracy-golden:latest", str(root)], check=True
    )
    print(f"Built sca-accuracy-golden:latest; SBOM: {root / 'app/target/bom.json'}")


if __name__ == "__main__":
    main()
