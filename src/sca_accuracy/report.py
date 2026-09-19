from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

from .models import Observation, ReconciliationItem


def write_outputs(
    output_dir: Path,
    image: str,
    digest: str,
    observations: list[Observation],
    items: list[ReconciliationItem],
    enriched_sbom: dict[str, Any],
    llm_analysis: dict[str, Any] | None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(UTC).isoformat()
    inventory = {
        "schema_version": "1",
        "generated_at": generated_at,
        "image": image,
        "digest": digest,
        "observations": [item.to_dict() for item in observations],
    }
    coverage_path = output_dir / "coverage.json"
    coverage = (
        json.loads(coverage_path.read_text(encoding="utf-8")) if coverage_path.exists() else None
    )
    decisions = (
        json.loads((output_dir / "decisions.json").read_text(encoding="utf-8"))
        if llm_analysis
        else None
    )
    assessment = {
        "coverage": coverage,
        "schema_version": "2",
        "generated_at": generated_at,
        "image": image,
        "digest": digest,
        "summary": _summary(items),
        "items": [item.to_dict() for item in items],
        "llm_analysis": llm_analysis,
        "decision_policy": "Include components only when TP score > 70; scores are uncalibrated model estimates."
        if decisions
        else "Rules enrichment; model scoring and score filtering are disabled.",
        "component_assessments": decisions.get("assessments", []) if decisions else [],
        "decisions": decisions,
    }
    _write_json(output_dir / "inventory.json", inventory)
    _write_json(output_dir / "assessment.json", assessment)
    _write_json(output_dir / "sbom.enriched.json", enriched_sbom)
    _write_html(output_dir / "report.html", assessment)


def _summary(items: list[ReconciliationItem]) -> dict[str, int]:
    result = {
        "confirmed_present": 0,
        "expected_absent": 0,
        "unexpected_absent": 0,
        "observed_not_declared": 0,
        "version_conflict": 0,
        "identity_uncertain": 0,
    }
    for item in items:
        result[item.status] += 1
    return result


def _write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _write_html(path: Path, assessment: dict[str, Any]) -> None:
    summary = assessment["summary"]
    cards = "".join(
        f'<div class="card {escape(status)}"><strong>{count}</strong><span>{escape(status)}</span></div>'
        for status, count in summary.items()
    )
    rows = []
    for item in assessment["items"]:
        identity = item["identity"]
        locations = (
            "<br>".join(escape(observation["location"]) for observation in item["observations"])
            or "—"
        )
        rows.append(
            "<tr>"
            f'<td><span class="badge {escape(item["status"])}">{escape(item["status"])}</span></td>'
            f"<td><code>{escape(identity['gav'])}</code></td>"
            f"<td>{locations}</td>"
            f"<td>{escape(item['usage_status'])}</td>"
            f"<td>{escape(item['explanation'])}</td>"
            "</tr>"
        )
    llm = assessment.get("llm_analysis")
    llm_section = (
        f"<section><h2>LLM analysis</h2><p>{escape(llm['summary'])}</p></section>" if llm else ""
    )
    decision_section = (
        '<section><h2>Filtering audit</h2><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'
        + escape(json.dumps(assessment["decisions"], ensure_ascii=False, indent=2))
        + "</pre></section>"
        if assessment.get("decisions") is not None
        else ""
    )
    score_section = ""
    if assessment.get("decisions"):
        score_rows = []
        scored = assessment.get("component_assessments", [])
        for row in scored:
            missing = "; ".join(row["missing_evidence"]) or "None specified"
            evidence_ids = ", ".join(row["evidence_ids"]) or "No evidence cited"
            score_rows.append(
                "<tr>"
                f"<td><code>{escape(row['identity'] or row['name'])}</code></td>"
                f"<td>{escape(str(row['tp_score']))}%</td><td>{escape(str(row['fp_score']))}%</td>"
                f"<td>{escape(row['label'])}</td>"
                f"<td>{'Included' if row['included'] else 'Excluded'}</td>"
                f"<td>{escape(row['reason'])}<details><summary>Evidence and gaps</summary>"
                f"<p>{escape(evidence_ids)}</p><p>Missing: {escape(missing)}</p></details></td></tr>"
            )
        included = sum(row["included"] for row in scored)
        score_section = (
            "<section><h2>Component scores · TP &gt; 70%</h2>"
            f"<p>Assessed identities: {len(scored)} · Included: {included} · Excluded: {len(scored) - included}</p>"
            "<p>Scores are uncalibrated model estimates. Exactly 70% is excluded. "
            "TP: above 70%; FP: below 30%; otherwise uncertain. All excluded identities remain in this report. "
            "The document subject is retained. Exclusion is not proof of absence or a VEX verdict.</p>"
            '<div style="overflow-x:auto"><table><thead><tr><th>Component</th><th>TP score</th>'
            "<th>FP score</th><th>Assessment</th><th>Output SBOM</th><th>Reason</th></tr></thead><tbody>"
            + "".join(score_rows)
            + "</tbody></table></div></section>"
        )
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SCA accuracy report</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, system-ui, sans-serif; }}
    body {{ margin: 0; background: #f5f7fb; color: #172033; }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 32px; }}
    h1 {{ margin-bottom: 8px; }} h2 {{ margin-top: 32px; }}
    .meta {{ color: #5c667a; overflow-wrap: anywhere; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px 0; }}
    .card {{ background: white; border: 1px solid #e2e6ee; border-radius: 10px; padding: 18px; }}
    .card strong {{ display: block; font-size: 28px; }} .card span {{ color: #5c667a; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e8ebf1; text-align: left; vertical-align: top; }}
    th {{ background: #edf1f7; }} code {{ overflow-wrap: anywhere; }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 4px 8px; font-size: 12px; }}
    .confirmed_present, .expected_absent {{ background: #d9f5e5; color: #126138; }}
    .identity_uncertain {{ background: #fff0c2; color: #765500; }}
    .unexpected_absent, .observed_not_declared, .version_conflict {{ background: #ffe0df; color: #82211d; }}
    section {{ background: white; border: 1px solid #e2e6ee; border-radius: 10px; padding: 0 20px 12px; }}
    @media (max-width: 760px) {{ .cards {{ grid-template-columns: repeat(2, 1fr); }} main {{ padding: 16px; }} }}
  </style>
</head>
<body><main>
  <h1>SCA accuracy report</h1>
  <div class="meta">Image: {escape(assessment["image"])}<br>Digest: {escape(assessment["digest"])}<br>Generated: {escape(assessment["generated_at"])}</div>
  <div class="cards">{cards}</div>
  {score_section}
  <h2>Component reconciliation</h2>
  <table><thead><tr><th>Status</th><th>Component</th><th>Observed at</th><th>Usage</th><th>Explanation</th></tr></thead>
  <tbody>{"".join(rows)}</tbody></table>
  <section><h2>Coverage and limitations</h2><pre>{escape(json.dumps(assessment.get("coverage"), ensure_ascii=False, indent=2))}</pre></section>{llm_section}{decision_section}
</main></body></html>
"""
    path.write_text(document, encoding="utf-8")
