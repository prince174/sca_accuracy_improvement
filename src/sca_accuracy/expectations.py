from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ReconciliationItem


def load_expectations(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(status, str) for key, status in value.items()
    ):
        raise TypeError("Expectations must be a JSON object mapping GAV to status")
    return value


def verify_expectations(
    items: list[ReconciliationItem], expectations: dict[str, str]
) -> dict[str, Any]:
    actual = {item.identity.gav: item.status for item in items}
    mismatches = [
        {"gav": gav, "expected": expected, "actual": actual.get(gav, "missing")}
        for gav, expected in expectations.items()
        if actual.get(gav) != expected
    ]
    return {
        "passed": not mismatches,
        "checked": len(expectations),
        "mismatches": mismatches,
    }


def verify_vex_expectations(vex: dict[str, Any], expectations: dict[str, str]) -> dict[str, Any]:
    actual = {
        str(vulnerability.get("id")): str(vulnerability.get("analysis", {}).get("state", "missing"))
        for vulnerability in vex.get("vulnerabilities", [])
    }
    mismatches = [
        {
            "vulnerability_id": identifier,
            "expected": expected,
            "actual": actual.get(identifier, "missing"),
        }
        for identifier, expected in expectations.items()
        if actual.get(identifier) != expected
    ]
    return {"passed": not mismatches, "checked": len(expectations), "mismatches": mismatches}
