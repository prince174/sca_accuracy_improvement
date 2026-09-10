from sca_accuracy.models import ComponentIdentity, Observation
from sca_accuracy.sbom import enrich_sbom, reconcile


def component(group: str, name: str, version: str, ref: str) -> dict:
    return {
        "type": "library",
        "group": group,
        "name": name,
        "version": version,
        "purl": f"pkg:maven/{group}/{name}@{version}",
        "bom-ref": ref,
    }


def test_reconcile_reports_exact_conflict_absence_and_observed_component() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            component("org.example", "exact", "1.0", "exact-ref"),
            component("org.example", "wrong", "1.0", "wrong-ref"),
            component("org.example", "missing", "1.0", "missing-ref"),
        ],
    }
    observations = [
        Observation(ComponentIdentity("org.example", "exact", "1.0"), "/app/exact.jar", "test"),
        Observation(ComponentIdentity("org.example", "wrong", "2.0"), "/app/wrong.jar", "test"),
        Observation(ComponentIdentity("org.example", "extra", "3.0"), "/app/extra.jar", "test"),
    ]

    items = reconcile(bom, observations, {"org.example:missing:1.0": "test"})

    assert [(item.identity.name, item.status) for item in items] == [
        ("exact", "confirmed_present"),
        ("wrong", "version_conflict"),
        ("missing", "expected_absent"),
        ("extra", "observed_not_declared"),
    ]


def test_compile_component_missing_from_image_is_unexpected_absence() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [component("org.example", "runtime", "1.0", "runtime-ref")],
    }

    items = reconcile(bom, [], {"org.example:runtime:1.0": "compile"})

    assert items[0].status == "unexpected_absent"
    assert items[0].maven_scope == "compile"


def test_enrich_sbom_adds_digest_status_and_occurrence() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [component("org.example", "lib", "1.0", "lib-ref")],
    }
    observations = [
        Observation(ComponentIdentity("org.example", "lib", "1.0"), "/app/lib.jar", "test")
    ]
    items = reconcile(bom, observations)

    enriched = enrich_sbom(bom, items, "example:latest", "sha256:abc")

    properties = {item["name"]: item["value"] for item in enriched["metadata"]["properties"]}
    assert properties["sca-accuracy:image-digest"] == "sha256:abc"
    assert enriched["components"][0]["evidence"]["occurrences"] == [{"location": "/app/lib.jar"}]
