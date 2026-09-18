"""Immutable evidence ledger in PostgreSQL with content-addressed artifact storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .models import ComponentIdentity
from .sbom import identity_from_component, iter_all_components

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_schema (version integer PRIMARY KEY);
INSERT INTO evidence_schema VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS evidence_runs (
 id text PRIMARY KEY, kind text NOT NULL CHECK (kind IN ('build','synthetic')),
 provenance jsonb NOT NULL, summary jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evidence_artifacts (
 run_id text REFERENCES evidence_runs(id), name text NOT NULL,
 sha256 text NOT NULL, size bigint NOT NULL, PRIMARY KEY(run_id,name)
);
CREATE TABLE IF NOT EXISTS evidence_observations (
 run_id text REFERENCES evidence_runs(id), id text NOT NULL,
 scope text NOT NULL, purl text, sha256 text, data jsonb NOT NULL,
 PRIMARY KEY(run_id,id)
);
CREATE INDEX IF NOT EXISTS evidence_purl ON evidence_observations(purl);
CREATE INDEX IF NOT EXISTS evidence_hash ON evidence_observations(sha256);
CREATE INDEX IF NOT EXISTS evidence_commit ON evidence_runs((provenance->>'commit'));
CREATE INDEX IF NOT EXISTS evidence_image ON evidence_runs((provenance->>'image_id'));
CREATE TABLE IF NOT EXISTS evidence_labels (
 id text PRIMARY KEY, run_id text NOT NULL, observation_id text NOT NULL,
 verdict text NOT NULL CHECK (verdict IN ('confirmed','refuted','insufficient')),
 rationale text NOT NULL, reviewer text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(run_id,observation_id) REFERENCES evidence_observations(run_id,id)
);
"""

FILES = {
    "retrieved-evidence.json",
    "model-request.json",
    "model-response.json",
    "sbom.original.json",
    "sbom.enriched.json",
    "inventory.json",
    "assessment.json",
    "coverage.json",
    "source-assessment.json",
    "decisions.json",
    "provenance.json",
    "analysis-context.json",
    "evidence/image.syft.json",
    "evidence/source.syft.json",
    "vex.json",
    "vulnerability-assessment.json",
    "ground-truth.json",
    "comparison.json",
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def checksum(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class EvidenceStore:
    def __init__(self, dsn: str, blobs: Path):
        self.dsn = dsn
        self.blobs = blobs.resolve()

    @contextmanager
    def connection(self):
        try:
            with psycopg.connect(self.dsn, connect_timeout=10, row_factory=dict_row) as conn:
                yield conn
        except psycopg.Error:
            # Driver errors can contain DSN credentials or private record contents.
            raise RuntimeError("Evidence database operation failed") from None

    def migrate(self):
        with self.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(73190425)")
            conn.execute(SCHEMA)
            versions = conn.execute("SELECT version FROM evidence_schema").fetchall()
            if versions != [{"version": 1}]:
                raise RuntimeError("Unsupported evidence schema version")

    def ingest(
        self, directory: Path, *, kind: str = "build", provenance: dict | None = None
    ) -> str:
        if kind not in {"build", "synthetic"}:
            raise ValueError("Unknown evidence kind")
        directory = directory.resolve()
        raw, documents, stable = {}, {}, {}
        for name in sorted(FILES):
            path = directory / name
            if not path.exists():
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(directory):
                raise ValueError("Evidence artifacts must remain inside the result directory")
            raw[name] = path.read_bytes()
            documents[name] = json.loads(raw[name])
            value = documents[name]
            # These fields only timestamp serialization, not observations or decisions.
            if name in {"inventory.json", "assessment.json"}:
                value = {k: v for k, v in value.items() if k != "generated_at"}
            stable[name] = value
        required = {"sbom.original.json", "sbom.enriched.json", "inventory.json", "assessment.json"}
        if not required <= documents.keys():
            raise ValueError("Evidence bundle is incomplete")
        provenance = {**documents.get("provenance.json", {}), **(provenance or {})}
        run_id = checksum({"kind": kind, "provenance": provenance, "documents": stable})
        observations = self._observations(documents)
        with self.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (int(run_id[:15], 16),))
            if conn.execute("SELECT id FROM evidence_runs WHERE id=%s", (run_id,)).fetchone():
                return run_id
            conn.execute(
                "INSERT INTO evidence_runs(id,kind,provenance,summary) VALUES (%s,%s,%s,%s)",
                (run_id, kind, Jsonb(provenance), Jsonb(documents["assessment.json"])),
            )
            for name, content in raw.items():
                digest = hashlib.sha256(content).hexdigest()
                path = self.blob_path(digest)
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                        raise RuntimeError("Evidence artifact integrity check failed")
                else:
                    temporary = path.with_name(f".{digest}.{uuid.uuid4().hex}.tmp")
                    try:
                        temporary.write_bytes(content)
                        os.replace(temporary, path)
                    finally:
                        temporary.unlink(missing_ok=True)
                conn.execute(
                    "INSERT INTO evidence_artifacts VALUES (%s,%s,%s,%s)",
                    (run_id, name, digest, len(content)),
                )
            for observation in observations:
                conn.execute(
                    "INSERT INTO evidence_observations VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                    (
                        run_id,
                        checksum(observation),
                        observation["scope"],
                        observation["purl"],
                        observation["sha256"],
                        Jsonb(observation["data"]),
                    ),
                )
        return run_id

    @staticmethod
    def _observations(documents):
        result = []
        for name, scope in (("sbom.original.json", "declared"), ("sbom.enriched.json", "result")):
            for c in iter_all_components(documents[name]):
                identity = identity_from_component(c)
                result.append(
                    {
                        "scope": scope,
                        "purl": identity.purl if identity else None,
                        "sha256": None,
                        "data": c,
                    }
                )
        for o in documents["inventory.json"].get("observations", []):
            i = o["identity"]
            identity = ComponentIdentity(
                i["group"],
                i["name"],
                i["version"],
                i.get("ecosystem", "maven"),
                tuple(tuple(q) for q in i.get("qualifiers", [])),
            )
            result.append(
                {"scope": "image", "purl": identity.purl, "sha256": o.get("sha256"), "data": o}
            )
        for item in documents.get("source-assessment.json", {}).get("items", []):
            result.append(
                {"scope": "source_assessment", "purl": None, "sha256": None, "data": item}
            )
        return result

    def blob_path(self, digest: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid artifact hash")
        path = self.blobs / digest[:2] / digest
        if not path.resolve().is_relative_to(self.blobs):
            raise ValueError("Invalid artifact path")
        return path

    def search(
        self,
        *,
        kind=None,
        purl=None,
        sha256=None,
        commit=None,
        image_id=None,
        repository=None,
        limit=50,
        offset=0,
    ):
        if not 1 <= limit <= 100 or not 0 <= offset <= 1000000:
            raise ValueError("Invalid pagination")
        clauses, args = [], []
        for value, expr in (
            (kind, "r.kind"),
            (commit, "r.provenance->>'commit'"),
            (image_id, "r.provenance->>'image_id'"),
            (repository, "r.provenance->>'repository_url'"),
        ):
            if value is not None:
                clauses.append(expr + "=%s")
                args.append(value)
        if purl is not None or sha256 is not None:
            inner = ["o.run_id=r.id"]
            for value, column in ((purl, "purl"), (sha256, "sha256")):
                if value is not None:
                    inner.append(f"o.{column}=%s")
                    args.append(value)
            clauses.append(
                "EXISTS (SELECT 1 FROM evidence_observations o WHERE " + " AND ".join(inner) + ")"
            )
        sql = "SELECT r.id,r.kind,r.provenance,r.created_at FROM evidence_runs r"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        with self.connection() as conn:
            return conn.execute(
                sql + " ORDER BY r.created_at DESC,r.id LIMIT %s OFFSET %s", (*args, limit, offset)
            ).fetchall()

    def get(self, run_id):
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM evidence_runs WHERE id=%s", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            row["artifacts"] = conn.execute(
                "SELECT name,sha256,size FROM evidence_artifacts WHERE run_id=%s ORDER BY name",
                (run_id,),
            ).fetchall()
            row["observations"] = conn.execute(
                "SELECT id,scope,purl,sha256,data FROM evidence_observations WHERE run_id=%s ORDER BY scope,id",
                (run_id,),
            ).fetchall()
            row["labels"] = conn.execute(
                "SELECT * FROM evidence_labels WHERE run_id=%s ORDER BY created_at,id", (run_id,)
            ).fetchall()
            return row

    def artifact(self, run_id, name):
        with self.connection() as conn:
            row = conn.execute(
                "SELECT sha256 FROM evidence_artifacts WHERE run_id=%s AND name=%s", (run_id, name)
            ).fetchone()
            if row is None:
                raise KeyError(name)
        path = self.blob_path(row["sha256"])
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            raise RuntimeError("Evidence artifact integrity check failed")
        return path

    def label(self, run_id, observation_id, verdict, rationale, reviewer):
        if (
            verdict not in {"confirmed", "refuted", "insufficient"}
            or not rationale.strip()
            or not reviewer.strip()
        ):
            raise ValueError("A verdict, rationale and reviewer are required")
        identity = uuid.uuid4().hex
        with self.connection() as conn:
            if not conn.execute(
                "SELECT 1 FROM evidence_observations WHERE run_id=%s AND id=%s",
                (run_id, observation_id),
            ).fetchone():
                raise KeyError(observation_id)
            conn.execute(
                "INSERT INTO evidence_labels(id,run_id,observation_id,verdict,rationale,reviewer) VALUES (%s,%s,%s,%s,%s,%s)",
                (identity, run_id, observation_id, verdict, rationale, reviewer),
            )
        return identity


def configured_store() -> EvidenceStore | None:
    dsn = os.getenv("SCA_EVIDENCE_DSN", "")
    if not dsn:
        return None
    return EvidenceStore(dsn, Path(os.getenv("SCA_EVIDENCE_BLOBS", "workspace/evidence-blobs")))


def persist_bundle(directory: Path, **kwargs) -> str | None:
    store = configured_store()
    if store is None:
        return None
    store.migrate()
    return store.ingest(directory, **kwargs)
