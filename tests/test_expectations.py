from sca_accuracy.expectations import verify_expectations
from sca_accuracy.models import ComponentIdentity, ReconciliationItem


def test_verify_expectations_reports_missing_and_wrong_statuses() -> None:
    items = [
        ReconciliationItem(
            status="confirmed_present",
            identity=ComponentIdentity("org.example", "present", "1.0"),
        ),
        ReconciliationItem(
            status="unexpected_absent",
            identity=ComponentIdentity("org.example", "absent", "1.0"),
        ),
    ]

    result = verify_expectations(
        items,
        {
            "org.example:present:1.0": "confirmed_present",
            "org.example:absent:1.0": "expected_absent",
            "org.example:unknown:1.0": "observed_not_declared",
        },
    )

    assert result["passed"] is False
    assert result["checked"] == 3
    assert result["mismatches"] == [
        {
            "gav": "org.example:absent:1.0",
            "expected": "expected_absent",
            "actual": "unexpected_absent",
        },
        {
            "gav": "org.example:unknown:1.0",
            "expected": "observed_not_declared",
            "actual": "missing",
        },
    ]
