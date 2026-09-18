"""Evidence-bound model plans. Model text is never interpreted as executable edits."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

from .models import Observation
from .sbom import identity_from_component, iter_all_components


def candidates(sbom: dict[str, Any], observations: list[Observation]) -> list[dict[str, Any]]:
    components = list(iter_all_components(sbom))
    declared = {identity_from_component(c) for c in components}
    strong = [o for o in observations if o.confidence >= 0.8 and o.identity.ecosystem != "generic"]
    result = []
    for identity in sorted({o.identity for o in strong}, key=lambda i: i.purl):
        if identity in declared:
            continue
        evidence = [o.to_dict() for o in strong if o.identity == identity]
        result.append({"operation": "add", "identity": identity.purl, "evidence": evidence})
    for component in components:
        ref = component.get("bom-ref")
        if not ref or sum(c.get("bom-ref") == ref for c in components) != 1:
            continue
        # Do not change the application root or reinterpret vulnerability references.
        if component is sbom.get("metadata", {}).get("component") or sbom.get("vulnerabilities"):
            continue
        hashes = {
            h.get("content", "").lower()
            for h in component.get("hashes", [])
            if h.get("alg") == "SHA-256" and re.fullmatch(r"[a-fA-F0-9]{64}", h.get("content", ""))
        }
        matches = [o for o in strong if o.sha256 and o.sha256.lower() in hashes]
        identities = {o.identity for o in matches}
        old = identity_from_component(component)
        if len(hashes) != 1 or len(identities) != 1 or any(o.identity == old for o in strong):
            continue
        identity = next(iter(identities))
        if identity == old or identity in declared:
            continue
        result.append(
            {
                "operation": "replace_identity",
                "bom_ref": ref,
                "identity": identity.purl,
                "before": copy.deepcopy(component),
                "evidence": [o.to_dict() for o in matches],
            }
        )
    for entry in result:
        entry["id"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    return result


def apply_plan(
    sbom: dict[str, Any], observations: list[Observation], plan: Any
) -> tuple[dict, dict]:
    """Recompute candidates locally; accept only exact candidate IDs and an explicit reason."""
    if not isinstance(plan, list) or len(plan) > 10000:
        raise ValueError("Model decisions must be an array of at most 10000 entries")
    allowed = {c["id"]: c for c in candidates(sbom, observations)}
    result = copy.deepcopy(sbom)
    audit: dict[str, Any] = {"policy_version": "1", "accepted": [], "rejected": [], "deferred": []}
    seen = set()
    # Apply replacements first, so an add of the same observed identity becomes redundant.
    ordered = sorted(
        plan,
        key=lambda d: (
            0
            if isinstance(d, dict)
            and isinstance(d.get("candidate_id"), str)
            and allowed.get(d["candidate_id"], {}).get("operation") == "replace_identity"
            else 1
        ),
    )
    for decision in ordered:
        if not isinstance(decision, dict):
            audit["rejected"].append({"decision": decision, "reason": "invalid decision"})
            continue
        cid = decision.get("candidate_id")
        candidate = allowed.get(cid) if isinstance(cid, str) else None
        reason = decision.get("reason")
        if (
            set(decision) != {"candidate_id", "action", "reason"}
            or not candidate
            or not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 4000
            or decision.get("action") not in {"apply", "defer"}
            or cid in seen
        ):
            audit["rejected"].append(
                {"decision": decision, "reason": "unsupported, duplicate or ungrounded decision"}
            )
            continue
        seen.add(cid)
        if decision["action"] == "defer":
            audit["deferred"].append(decision)
            continue
        from packageurl import PackageURL

        purl = PackageURL.from_string(candidate["identity"])
        fields = {
            "group": purl.namespace or "",
            "name": purl.name,
            "version": purl.version,
            "purl": candidate["identity"],
        }
        if candidate["operation"] == "replace_identity":
            component = next(
                c for c in iter_all_components(result) if c.get("bom-ref") == candidate["bom_ref"]
            )
            for key in ("cpe", "swid", "licenses", "externalReferences", "pedigree"):
                component.pop(key, None)
            component.update(fields)
        else:
            if any(c.get("purl") == candidate["identity"] for c in iter_all_components(result)):
                audit["deferred"].append({**decision, "reason": "identity already represented"})
                continue
            refs = {c.get("bom-ref") for c in iter_all_components(result)}
            ref = "sca-added-" + cid
            if ref in refs:
                audit["rejected"].append({"decision": decision, "reason": "bom-ref collision"})
                continue
            component = {"type": "library", "bom-ref": ref, **fields}
            result.setdefault("components", []).append(component)
        component.setdefault("properties", []).append(
            {"name": "sca-accuracy:decision-id", "value": cid}
        )
        audit["accepted"].append({**candidate, "reason": reason})
    audit["unreviewed"] = sorted(set(allowed) - seen)
    audit["input_sha256"] = hashlib.sha256(json.dumps(sbom, sort_keys=True).encode()).hexdigest()
    return result, audit
