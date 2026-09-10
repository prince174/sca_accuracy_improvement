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
    assessment = {
        "schema_version": "1",
        "generated_at": generated_at,
        "image": image,
        "digest": digest,
        "summary": _summary(items),
        "items": [item.to_dict() for item in items],
        "llm_analysis": llm_analysis,
        "decision_policy": "LLM output is advisory and cannot suppress vulnerability findings.",
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
            f"<td>{escape(item['explanation'])}</td>"
            "</tr>"
        )
    llm = assessment.get("llm_analysis")
    llm_section = (
        f"<section><h2>LLM analysis</h2><p>{escape(llm['summary'])}</p></section>" if llm else ""
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
  <h2>Component reconciliation</h2>
  <table><thead><tr><th>Status</th><th>Component</th><th>Observed at</th><th>Explanation</th></tr></thead>
  <tbody>{"".join(rows)}</tbody></table>
  {llm_section}
</main></body></html>
"""
    path.write_text(document, encoding="utf-8")
