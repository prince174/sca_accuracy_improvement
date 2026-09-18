"""Bounded retrieval of reviewed image observations, never model-generated conclusions."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from .evidence import configured_store


def reviewed_examples(
    store,
    offered,
    *,
    reviewers,
    kind="build",
    excluded_runs=(),
    excluded_groups=(),
    image_id=None,
    cutoff=None,
    limit=6,
):
    if not reviewers or kind not in {"build", "synthetic"} or not 1 <= limit <= 20:
        raise ValueError("Retrieval requires trusted reviewers, evidence kind and bounded limit")
    cutoff = cutoff or datetime.now(UTC)
    purls = sorted({c["identity"] for c in offered})
    hashes = sorted({o["sha256"] for c in offered for o in c["evidence"] if o.get("sha256")})
    sources = sorted({o["source"] for c in offered for o in c["evidence"]})
    # Latest statement per trusted reviewer; disagreement or insufficient evidence excludes it.
    with store.connection() as conn:
        rows = conn.execute(
            """
            WITH latest AS (
              SELECT DISTINCT ON (run_id, observation_id, reviewer)
                run_id, observation_id, reviewer, verdict, rationale, id, created_at
              FROM evidence_labels WHERE reviewer=ANY(%s) AND created_at < %s
              ORDER BY run_id, observation_id, reviewer, created_at DESC, id DESC
            ), agreed AS (
              SELECT run_id, observation_id FROM latest GROUP BY run_id, observation_id
              HAVING count(DISTINCT verdict)=1 AND min(verdict) IN ('confirmed','refuted')
            )
            SELECT o.run_id, o.id AS observation_id, o.purl, o.sha256, o.data,
                   r.kind, r.provenance, l.id AS label_id, l.verdict, l.rationale, l.reviewer,
                   a.sha256 AS inventory_sha256,
                   CASE WHEN o.sha256=ANY(%s) THEN 0 WHEN o.purl=ANY(%s) THEN 1 ELSE 2 END AS rank
            FROM evidence_observations o
            JOIN evidence_runs r ON r.id=o.run_id
            JOIN agreed g ON g.run_id=o.run_id AND g.observation_id=o.id
            JOIN latest l ON l.run_id=o.run_id AND l.observation_id=o.id
            JOIN evidence_artifacts a ON a.run_id=o.run_id AND a.name='inventory.json'
            WHERE o.scope='image' AND r.kind=%s AND r.created_at < %s
              AND NOT (r.id=ANY(%s))
              AND NOT (COALESCE(r.provenance->>'evaluation_group','')=ANY(%s))
              AND (%s::text IS NULL OR r.provenance->>'image_id' IS DISTINCT FROM %s)
              AND (o.purl=ANY(%s) OR o.sha256=ANY(%s) OR o.data->>'source'=ANY(%s))
            ORDER BY rank, r.created_at DESC, o.run_id, o.id, l.id LIMIT 100
        """,
            (
                list(reviewers),
                cutoff,
                hashes,
                purls,
                kind,
                cutoff,
                list(excluded_runs),
                list(excluded_groups),
                image_id,
                image_id,
                purls,
                hashes,
                sources,
            ),
        ).fetchall()
    examples, seen = [], set()
    # Prefer a mix of confirmed/refuted examples; avoid repeated labels consuming context.
    rows.sort(key=lambda r: (r["rank"], r["verdict"], r["run_id"], r["observation_id"]))
    buckets = {v: [r for r in rows if r["verdict"] == v] for v in ("confirmed", "refuted")}
    while any(buckets.values()) and len(examples) < limit:
        for bucket in buckets.values():
            if not bucket:
                continue
            row = bucket.pop(0)
            key = (row["run_id"], row["observation_id"])
            if key in seen:
                continue
            seen.add(key)
            # Verify the referenced immutable artifact before exposing its evidence.
            store.artifact(row["run_id"], "inventory.json")
            data = row["data"]
            examples.append(
                {
                    "run_id": row["run_id"],
                    "observation_id": row["observation_id"],
                    "label_id": row["label_id"],
                    "reviewer": row["reviewer"],
                    "kind": row["kind"],
                    "purl": row["purl"],
                    "sha256": row["sha256"],
                    "source": str(data.get("source", ""))[:256],
                    "location": str(data.get("location", ""))[:1024],
                    "verdict": row["verdict"],
                    "rationale": row["rationale"][:2000],
                    "inventory_sha256": row["inventory_sha256"],
                    "match": ("sha256", "purl", "scanner_source")[row["rank"]],
                }
            )
            if len(examples) == limit:
                break
    return {
        "policy": "reviewed-image-observations-v1",
        "cutoff": cutoff.isoformat(),
        "kind": kind,
        "trusted_reviewers": sorted(reviewers),
        "excluded_runs": sorted(excluded_runs),
        "excluded_groups": sorted(excluded_groups),
        "excluded_image_id": image_id,
        "examples": examples,
        "meaning": "Historical analogies only; no proof of presence, absence or CVE applicability in this build.",
    }


def configured_history(offered, image_id):
    enabled = os.getenv("SCA_EVIDENCE_RETRIEVAL", "false").lower()
    if enabled not in {"true", "false"}:
        raise ValueError("SCA_EVIDENCE_RETRIEVAL must be true or false")
    if enabled == "false":
        return None
    reviewers = [r.strip() for r in os.getenv("SCA_EVIDENCE_REVIEWERS", "").split(",") if r.strip()]
    store = configured_store()
    if store is None or not reviewers:
        raise ValueError("Reviewed evidence retrieval requires a database and trusted reviewers")
    store.migrate()
    return reviewed_examples(store, offered, reviewers=reviewers, image_id=image_id)
