from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

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

    @property
    def gav(self) -> str:
        return f"{self.group}:{self.name}:{self.version}"


@dataclass(slots=True)
class Observation:
    identity: ComponentIdentity
    location: str
    source: str
    sha256: str | None = None
    confidence: float = 1.0

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "identity": {**asdict(self.identity), "gav": self.identity.gav},
            "bom_ref": self.bom_ref,
            "observations": [item.to_dict() for item in self.observations],
            "maven_scope": self.maven_scope,
            "explanation": self.explanation,
        }
