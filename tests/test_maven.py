import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sca_accuracy.maven import generate_dependency_tree, load_dependency_tree


def test_generate_dependency_tree_uses_pinned_plugin_and_validates_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "pom.xml").write_text("<project/>", encoding="utf-8")
    output = tmp_path / "evidence" / "dependency-tree.json"

    def run(command: list[str], **_: object) -> MagicMock:
        output.write_text(
            json.dumps(
                {
                    "groupId": "com.example",
                    "artifactId": "app",
                    "version": "1.0",
                    "scope": "compile",
                }
            ),
            encoding="utf-8",
        )
        assert "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree" in command
        assert "-DoutputType=json" in command
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch("sca_accuracy.maven._maven_runner", return_value=["mvn"]),
        patch("sca_accuracy.maven.subprocess.run", side_effect=run),
    ):
        generated = generate_dependency_tree(source, output)

    assert generated == output.resolve()
    assert load_dependency_tree(generated) == {"com.example:app:1.0": "compile"}


def test_generate_dependency_tree_does_not_reuse_stale_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "pom.xml").write_text("<project/>", encoding="utf-8")
    output = tmp_path / "dependency-tree.json"
    output.write_text('{"artifactId":"stale"}', encoding="utf-8")

    with (
        patch("sca_accuracy.maven._maven_runner", return_value=["mvn"]),
        patch(
            "sca_accuracy.maven.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ),
        pytest.raises(RuntimeError, match="did not create"),
    ):
        generate_dependency_tree(source, output)
