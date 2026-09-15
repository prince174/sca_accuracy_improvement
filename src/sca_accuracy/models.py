from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from packageurl import PackageURL

MatchStatus = Literal[
    "confirmed_present",
    "expected_absent",
    "unexpected_absent",
    "observed_not_declared",
    "version_conflict",
    "identity_uncertain",
]


@dataclass(slots=True, frozen=True)
class ComponentIdentity:
    group: str
    name: str
    version: str
    ecosystem: str = "maven"
    qualifiers: tuple[tuple[str, str], ...] = ()

    @property
    def purl(self) -> str:
        return PackageURL(
            self.ecosystem,
            self.group or None,
            self.name,
            self.version or None,
            dict(self.qualifiers) or None,
        ).to_string()

    @property
    def package_key(self) -> tuple[str, str, str, tuple[tuple[str, str], ...]]:
        return self.ecosystem, self.group, self.name, self.qualifiers

    @property
    def gav(self) -> str:
        return (
            f"{self.group}:{self.name}:{self.version}"
            if self.ecosystem == "maven" and not self.qualifiers
            else self.purl
        )


@dataclass(slots=True)
class Observation:
    identity: ComponentIdentity
    location: str
    source: str
    sha256: str | None = None
    confidence: float = 1.0
    referenced_symbols: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["gav"] = self.identity.gav
        return result


@dataclass(slots=True)
class ReconciliationItem:
    status: MatchStatus
    identity: ComponentIdentity
    bom_ref: str | None = None
    observations: list[Observation] = field(default_factory=list)
    maven_scope: str | None = None
    explanation: str = ""

    @property
    def usage_status(self) -> str:
        if any(observation.referenced_symbols for observation in self.observations):
            return "bytecode_referenced"
        if self.status == "confirmed_present":
            return "present_no_reference_observed"
        return "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "identity": {**asdict(self.identity), "gav": self.identity.gav},
            "bom_ref": self.bom_ref,
            "observations": [item.to_dict() for item in self.observations],
            "maven_scope": self.maven_scope,
            "usage_status": self.usage_status,
            "explanation": self.explanation,
        }
