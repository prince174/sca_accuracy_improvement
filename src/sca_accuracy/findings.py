from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import ComponentIdentity
from .sbom import identity_from_component, iter_all_components


@dataclass(slots=True, frozen=True)
class Finding:
    vulnerability_id: str
    source_name: str
    source_url: str | None
    affects_ref: str
    component: ComponentIdentity | None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        if self.component:
            value["component"]["gav"] = self.component.gav
        return value


def load_findings(path: Path) -> list[Finding]:
    """Load component-scoped findings from a CycloneDX BOM, VDR, or VEX document."""
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("Findings input is not a CycloneDX document")

    identities = {
        str(component["bom-ref"]): identity_from_component(component)
        for component in iter_all_components(document)
        if component.get("bom-ref")
    }
    findings: list[Finding] = []
    for vulnerability in document.get("vulnerabilities", []):
        if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
            continue
        source = vulnerability.get("source") or {}
        source_name = str(source.get("name", ""))
        for affected in vulnerability.get("affects", []):
            if not isinstance(affected, dict) or not affected.get("ref"):
                continue
            ref = str(affected["ref"])
            findings.append(
                Finding(
                    vulnerability_id=str(vulnerability["id"]),
                    source_name=source_name,
                    source_url=source.get("url"),
                    affects_ref=ref,
                    component=identities.get(ref),
                    description=vulnerability.get("description"),
                )
            )
    return findings
