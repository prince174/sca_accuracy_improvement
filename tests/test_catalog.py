import json
from unittest.mock import patch

import pytest

from sca_accuracy.catalog import observations_from_catalog, scan
from sca_accuracy.models import ComponentIdentity, Observation
from sca_accuracy.sbom import enrich_sbom, identity_from_component, reconcile
from sca_accuracy.service import JobManager


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:maven/org.example/demo@1.0",
        "pkg:npm/%40example/demo@1.0",
        "pkg:pypi/demo@1.0",
        "pkg:nuget/Demo@1.0",
        "pkg:golang/example.com/demo@1.0",
        "pkg:cargo/demo@1.0",
        "pkg:gem/demo@1.0",
        "pkg:composer/example/demo@1.0",
        "pkg:deb/debian/demo@1.0?arch=amd64",
        "pkg:rpm/fedora/demo@1.0?arch=x86_64",
        "pkg:apk/alpine/demo@1.0?arch=x86_64",
        "pkg:hex/demo@1.0",
    ],
)
def test_ecosystems_preserve_identity_and_enrichment(purl):
    artifact = {
        "name": "demo",
        "version": "1.0",
        "purl": purl,
        "foundBy": "fixture",
        "locations": [{"path": "/app/demo"}],
    }
    observations = observations_from_catalog({"artifacts": [artifact]})
    bom = {"components": [{**artifact, "bom-ref": "demo"}]}
    assert reconcile(bom, observations)[0].status == "confirmed_present"
    enriched = enrich_sbom(
        {"components": []}, reconcile({"components": []}, observations), "image", "digest"
    )
    assert identity_from_component(enriched["components"][0]) == observations[0].identity


def test_cross_ecosystem_and_qualifier_collisions_do_not_match():
    bom = {"components": [{"purl": "pkg:npm/demo@1", "bom-ref": "npm"}]}
    observations = [Observation(ComponentIdentity("", "demo", "1", "pypi"), "/lib", "test")]
    assert reconcile(bom, observations)[0].status == "unexpected_absent"
    assert identity_from_component(
        {"purl": "pkg:deb/debian/demo@1?arch=amd64"}
    ) != identity_from_component({"purl": "pkg:deb/debian/demo@1?arch=arm64"})


def test_maven_default_jar_qualifier_matches_plain_purl():
    assert identity_from_component({"purl": "pkg:maven/org/a@1?type=jar"}) == ComponentIdentity(
        "org", "a", "1"
    )
    assert identity_from_component(
        {"purl": "pkg:maven/org/a@1?classifier=tests"}
    ) != ComponentIdentity("org", "a", "1")


def test_invalid_or_unidentified_components_are_not_silently_dropped():
    bom = {"components": [{"name": "demo", "version": "1"}, {"name": "bad", "purl": "invalid"}]}
    assert [i.status for i in reconcile(bom, [])] == ["identity_uncertain", "identity_uncertain"]


def test_non_maven_source_directory_is_accepted(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    assert JobManager(tmp_path).resolve_source(".") == tmp_path


def test_scanner_never_runs_build_and_disables_network(tmp_path):
    class Result:
        returncode = 0
        stdout = json.dumps({"artifacts": []})

    with patch("sca_accuracy.catalog.subprocess.run", return_value=Result()) as run:
        scan(f"dir:{tmp_path}", tmp_path / "result.json")
    command = run.call_args.args[0]
    assert command[1] == "scan"
    assert command[command.index("--scope") + 1] == "squashed"
    assert run.call_args.kwargs["timeout"] == 900
    assert run.call_args.kwargs["env"]["SYFT_CHECK_FOR_APP_UPDATE"] == "false"


def test_version_conflict_stays_within_ecosystem():
    bom = {"components": [{"purl": "pkg:npm/demo@1", "bom-ref": "demo"}]}
    observation = Observation(ComponentIdentity("", "demo", "2", "npm"), "/demo", "test")
    assert reconcile(bom, [observation])[0].status == "version_conflict"


@pytest.mark.parametrize("purl", ["", "invalid", None])
def test_scanner_unidentified_artifact_is_preserved(purl):
    observations = observations_from_catalog(
        {"artifacts": [{"name": "unknown-package", "version": "1", "purl": purl}]}
    )
    assert len(observations) == 1
    assert observations[0].confidence < 0.8
    assert reconcile({"components": []}, observations)[0].status == "identity_uncertain"
