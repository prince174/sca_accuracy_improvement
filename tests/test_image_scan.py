import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from sca_accuracy.image import pull_image, scan_exported_image, scan_saved_image


def make_jar(group: str, artifact: str, version: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as jar:
        jar.writestr(
            f"META-INF/maven/{group}/{artifact}/pom.properties",
            f"groupId={group}\nartifactId={artifact}\nversion={version}\n",
        )
    return output.getvalue()


def test_scan_exported_image_reads_spring_boot_nested_jar(tmp_path: Path) -> None:
    dependency = make_jar("org.example", "dependency", "2.1")
    application = io.BytesIO()
    with zipfile.ZipFile(application, "w") as jar:
        jar.writestr("BOOT-INF/lib/dependency-2.1.jar", dependency)

    archive_path = tmp_path / "rootfs.tar"
    with tarfile.open(archive_path, "w") as archive:
        payload = application.getvalue()
        entry = tarfile.TarInfo("app/application.jar")
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))

    result = scan_exported_image(archive_path)

    assert len(result) == 1
    assert result[0].identity.gav == "org.example:dependency:2.1"
    assert result[0].location == "/app/application.jar!/BOOT-INF/lib/dependency-2.1.jar"
    assert result[0].confidence == 1.0


def make_layer(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as layer:
        for name, payload in entries.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(payload)
            layer.addfile(entry, io.BytesIO(payload))
    return output.getvalue()


def test_scan_saved_image_applies_layers_without_creating_container(tmp_path: Path) -> None:
    removed = make_jar("org.example", "removed", "1.0")
    delivered = make_jar("org.example", "delivered", "2.0")
    layers = {
        "layer-1.tar": make_layer({"app/removed-1.0.jar": removed}),
        "layer-2.tar": make_layer(
            {
                "app/.wh.removed-1.0.jar": b"",
                "app/delivered-2.0.jar": delivered,
            }
        ),
    }
    manifest = b'[{"Config":"config.json","RepoTags":["test:latest"],"Layers":["layer-1.tar","layer-2.tar"]}]'
    image_path = tmp_path / "image.tar"
    with tarfile.open(image_path, "w") as image:
        for name, payload in {"manifest.json": manifest, **layers}.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(payload)
            image.addfile(entry, io.BytesIO(payload))

    result = scan_saved_image(image_path)

    assert [item.identity.gav for item in result] == ["org.example:delivered:2.0"]
    assert result[0].location == "/app/delivered-2.0.jar"


def test_pull_image_uses_registry_reference_without_shell() -> None:
    with patch("sca_accuracy.image._run") as run:
        pull_image("registry.example/team/app:42")

    run.assert_called_once_with(["docker", "pull", "registry.example/team/app:42"])
