import io
import tarfile
import zipfile
from pathlib import Path

from sca_accuracy.image import scan_exported_image


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
