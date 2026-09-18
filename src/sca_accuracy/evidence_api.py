"""Authenticated read access and append-only review labels."""

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from .evidence import configured_store


class ReviewLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observation_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    verdict: Literal["confirmed", "refuted", "insufficient"]
    rationale: str = Field(min_length=1, max_length=10000)
    reviewer: str = Field(min_length=1, max_length=256)


def evidence_router(authorize):
    router = APIRouter(prefix="/v2/evidence", dependencies=[Depends(authorize)])

    def store():
        value = configured_store()
        if value is None:
            raise HTTPException(503, "Evidence database is not configured")
        try:
            value.migrate()
        except RuntimeError:
            raise HTTPException(503, "Evidence database unavailable") from None
        return value

    @router.get("/runs")
    def search(
        kind: Literal["build", "synthetic"] | None = None,
        purl: str | None = None,
        sha256: str | None = None,
        commit: str | None = None,
        image_id: str | None = None,
        repository: str | None = None,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0, le=1000000),
    ):
        try:
            return {
                "runs": store().search(
                    kind=kind,
                    purl=purl,
                    sha256=sha256,
                    commit=commit,
                    image_id=image_id,
                    repository=repository,
                    limit=limit,
                    offset=offset,
                )
            }
        except RuntimeError:
            raise HTTPException(503, "Evidence database unavailable") from None

    @router.get("/runs/{run_id}")
    def get(run_id: str):
        try:
            return store().get(run_id)
        except KeyError:
            raise HTTPException(404, "Evidence run not found") from None
        except RuntimeError:
            raise HTTPException(503, "Evidence database unavailable") from None

    @router.get("/runs/{run_id}/artifacts/{name:path}")
    def artifact(run_id: str, name: str):
        try:
            return FileResponse(
                store().artifact(run_id, name),
                filename=Path(name).name,
                media_type="application/json",
            )
        except KeyError:
            raise HTTPException(404, "Evidence artifact not found") from None
        except RuntimeError:
            raise HTTPException(503, "Evidence artifact unavailable or corrupt") from None

    @router.post("/runs/{run_id}/labels", status_code=201)
    def label(run_id: str, request: ReviewLabel):
        try:
            return {"id": store().label(run_id, **request.model_dump())}
        except KeyError:
            raise HTTPException(404, "Evidence observation not found") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError:
            raise HTTPException(503, "Evidence database unavailable") from None

    return router
