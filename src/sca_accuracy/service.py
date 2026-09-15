from __future__ import annotations

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .pipeline import AnalysisConfig, run_analysis
from .version import __version__

ARTIFACTS = {
    "assessment.json",
    "coverage.json",
    "source-assessment.json",
    "expectation-result.json",
    "inventory.json",
    "report.html",
    "sbom.enriched.json",
    "vex.json",
    "vulnerability-assessment.json",
}


class AnalysisRequest(BaseModel):
    sbom_path: str
    image: str = Field(min_length=1, max_length=512)
    pull_image: bool = True
    source_path: str | None = None
    dependency_tree_path: str | None = None
    findings_path: str | None = None
    vulnerability_rules_path: str | None = None
    with_llm: bool = False
    vex_mode: Literal["advisory", "safe"] = "advisory"


@dataclass(slots=True)
class Job:
    id: str
    status: Literal["queued", "running", "succeeded", "failed"] = "queued"
    result: dict[str, object] | None = None
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class JobManager:
    def __init__(self, workspace: Path, workers: int = 2) -> None:
        self.workspace = workspace.resolve()
        self.results = self.workspace / "results"
        self.results.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="analysis")
        self._restore()

    def submit(self, request: AnalysisRequest) -> Job:
        job = Job(str(uuid.uuid4()))
        config = AnalysisConfig(
            sbom=self.resolve_input(request.sbom_path),
            image=request.image,
            output=self.results / job.id,
            pull_image=request.pull_image,
            source=self.resolve_source(request.source_path),
            dependency_tree=self.resolve_optional(request.dependency_tree_path),
            findings=self.resolve_optional(request.findings_path),
            vulnerability_rules=self.resolve_optional(request.vulnerability_rules_path),
            with_llm=request.with_llm,
            vex_mode=request.vex_mode,
        )
        with self._lock:
            self._jobs[job.id] = job
            self._save(job)
        self._executor.submit(self._execute, job.id, config)
        return job

    def get(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            return Job(**asdict(job))

    def artifact(self, job_id: str, filename: str) -> Path:
        if filename not in ARTIFACTS:
            raise ValueError(filename)
        job = self.get(job_id)
        if job.status != "succeeded":
            raise RuntimeError(job.status)
        path = self.results / job_id / filename
        if not path.is_file():
            raise FileNotFoundError(filename)
        return path

    def resolve_input(self, value: str) -> Path:
        candidate = (self.workspace / value).resolve()
        if not candidate.is_relative_to(self.workspace):
            raise ValueError("Input path must stay inside SCA_WORKSPACE")
        if not candidate.is_file():
            raise FileNotFoundError(value)
        return candidate

    def resolve_optional(self, value: str | None) -> Path | None:
        return self.resolve_input(value) if value else None

    def resolve_source(self, value: str | None) -> Path | None:
        if not value:
            return None
        candidate = (self.workspace / value).resolve()
        if not candidate.is_relative_to(self.workspace):
            raise ValueError("Source path must stay inside SCA_WORKSPACE")
        if not candidate.is_dir():
            raise FileNotFoundError(f"Source directory not found: {value}")
        return candidate

    def _execute(self, job_id: str, config: AnalysisConfig) -> None:
        self._update(job_id, status="running")
        try:
            result = run_analysis(config)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._update(job_id, status="failed", error=f"{type(exc).__name__}: {exc}")
        else:
            self._update(job_id, status="succeeded", result=result)

    def _update(self, job_id: str, **values: object) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in values.items():
                setattr(job, key, value)
            job.updated_at = datetime.now(UTC).isoformat()
            self._save(job)

    def _restore(self) -> None:
        for path in self.results.glob("*/job.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                job = Job(**data)
            except (OSError, TypeError, ValueError):
                continue
            if job.status in {"queued", "running"}:
                job.status = "failed"
                job.error = "Service restarted before the analysis completed."
                job.updated_at = datetime.now(UTC).isoformat()
                self._save(job)
            self._jobs[job.id] = job

    def _save(self, job: Job) -> None:
        directory = self.results / job.id
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "job.json"
        temporary = directory / ".job.json.tmp"
        temporary.write_text(
            json.dumps(asdict(job), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporary.replace(target)


def create_app(workspace: Path | None = None) -> FastAPI:
    root = workspace or Path(os.getenv("SCA_WORKSPACE", "workspace"))
    manager = JobManager(root, int(os.getenv("SCA_WORKERS", "2")))
    api_token = os.getenv("SCA_API_TOKEN", "")
    app = FastAPI(title="SCA Accuracy Improvement", version=__version__)

    def authorize(authorization: Annotated[str | None, Header()] = None) -> None:
        if api_token and authorization != f"Bearer {api_token}":
            raise HTTPException(status_code=401, detail="Invalid bearer token")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready(_: None = Depends(authorize)) -> dict[str, str]:
        return {"status": "ready", "workspace": str(manager.workspace)}

    @app.post("/v1/analyses", status_code=202)
    def submit(request: AnalysisRequest, _: None = Depends(authorize)) -> dict[str, str]:
        try:
            job = manager.submit(request)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": job.id, "status": job.status}

    @app.get("/v1/analyses/{job_id}")
    def status(job_id: str, _: None = Depends(authorize)) -> dict[str, object]:
        try:
            return asdict(manager.get(job_id))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Analysis not found") from exc

    @app.get("/v1/analyses/{job_id}/artifacts/{filename}")
    def artifact(job_id: str, filename: str, _: None = Depends(authorize)) -> FileResponse:
        try:
            path = manager.artifact(job_id, filename)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Analysis not found") from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Artifact not available") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=f"Analysis is {exc}") from exc
        return FileResponse(path)

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        "sca_accuracy.service:app",
        host=os.getenv("SCA_HOST", "0.0.0.0"),
        port=int(os.getenv("SCA_PORT", "8080")),
    )
