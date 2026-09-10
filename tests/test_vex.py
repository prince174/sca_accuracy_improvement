from sca_accuracy.findings import Finding
from sca_accuracy.models import ComponentIdentity, Observation, ReconciliationItem
from sca_accuracy.vex import build_vex
from sca_accuracy.vulnerability_rules import VulnerabilityRule

REF = "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.10.3?type=jar"


def test_safe_vex_closes_only_absent_test_dependency() -> None:
    identity = ComponentIdentity("org.junit.jupiter", "junit-jupiter-api", "5.10.3")
    sbom = {
        "metadata": {
            "component": {
                "bom-ref": "app",
                "type": "application",
                "name": "app",
                "version": "1",
            }
        },
        "components": [
            {
                "bom-ref": REF,
                "type": "library",
                "group": identity.group,
                "name": identity.name,
                "version": identity.version,
                "purl": REF,
            }
        ],
    }
    finding = Finding("TEST-1", "INTERNAL", None, REF, identity)
    item = ReconciliationItem(
        status="expected_absent",
        identity=identity,
        bom_ref=REF,
        maven_scope="test",
    )

    advisory, _ = build_vex(sbom, [finding], [item], "sha256:test", mode="advisory")
    safe, assessments = build_vex(sbom, [finding], [item], "sha256:test", mode="safe")

    assert advisory["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
    assert safe["vulnerabilities"][0]["analysis"] == {
        "state": "not_affected",
        "detail": (
            "The Maven dependency has test scope and was not observed in the delivered image "
            "identified by sha256:test."
        ),
        "justification": "code_not_present",
    }
    assert assessments[0]["automation"] == "deterministic_safe_rule"


def test_unresolved_component_is_not_emitted_to_vex() -> None:
    sbom = {
        "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "app"}},
        "components": [],
    }
    finding = Finding("TEST-2", "INTERNAL", None, "missing-ref", None)

    vex, assessments = build_vex(sbom, [finding], [], "sha256:test")

    assert vex["vulnerabilities"] == []
    assert assessments[0]["emitted_to_vex"] is False


def test_safe_vex_marks_exact_referenced_vulnerable_symbol_exploitable() -> None:
    identity = ComponentIdentity("org.example", "library", "1.0")
    component_ref = "pkg:maven/org.example/library@1.0"
    symbol = "org.example.Library#vulnerable()V"
    sbom = {
        "metadata": {
            "component": {
                "bom-ref": "app",
                "type": "application",
                "name": "app",
                "version": "1",
            }
        },
        "components": [
            {
                "bom-ref": component_ref,
                "type": "library",
                "group": identity.group,
                "name": identity.name,
                "version": identity.version,
                "purl": component_ref,
            }
        ],
    }
    finding = Finding("CVE-TEST", "NVD", None, component_ref, identity)
    observation = Observation(
        identity,
        "/app/app.jar!/library.jar",
        "pom.properties",
        referenced_symbols=[symbol],
    )
    item = ReconciliationItem(
        status="confirmed_present",
        identity=identity,
        bom_ref=component_ref,
        observations=[observation],
    )
    rule = VulnerabilityRule(
        vulnerability_id="CVE-TEST",
        component_gav=identity.gav,
        symbols=frozenset({symbol}),
        source="test-rule",
    )

    vex, assessments = build_vex(
        sbom,
        [finding],
        [item],
        "sha256:test",
        mode="safe",
        rules={"CVE-TEST": rule},
    )

    assert vex["vulnerabilities"][0]["analysis"]["state"] == "exploitable"
    assert assessments[0]["automation"] == "deterministic_symbol_match"
    assert assessments[0]["matched_symbols"] == symbol
