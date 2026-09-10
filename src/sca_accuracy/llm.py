from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

SYSTEM_PROMPT = """You are an SCA evidence analyst. Analyze only the supplied structured facts.
Never infer that a vulnerability is not affected merely because a component or call was not observed.
Return strict JSON with keys summary (string), hypotheses (array of objects with subject, assessment,
evidence_needed), and warnings (array of strings). Treat filename-only identities as weak evidence.
Do not return markdown."""


@dataclass(slots=True)
class LlmConfig:
    api_key: str
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-v4-flash"
    timeout_seconds: int = 120

    @classmethod
    def from_environment(cls) -> LlmConfig:
        key = os.getenv("DEEPSEEK_API_KEY", "")
        if not key:
            raise RuntimeError("DEEPSEEK_API_KEY is not configured")
        return cls(
            api_key=key,
            base_url=os.getenv("SCA_LLM_BASE_URL", "https://api.deepseek.com/v1").rstrip("/"),
            model=os.getenv("SCA_LLM_MODEL", "deepseek-v4-flash"),
            timeout_seconds=int(os.getenv("SCA_LLM_TIMEOUT_SECONDS", "120")),
        )


def _extract_json(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    result = json.loads(text)
    if not isinstance(result, dict):
        raise TypeError("Model response must be a JSON object")
    if not isinstance(result.get("summary"), str):
        raise TypeError("Model response has no string summary")
    for key in ("hypotheses", "warnings"):
        if not isinstance(result.get(key), list):
            raise TypeError(f"Model response has no {key} array")
    return result


def analyze(payload: dict[str, Any], config: LlmConfig) -> dict[str, Any]:
    request_body = {
        "model": config.model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
    }
    request = urllib.request.Request(
        f"{config.base_url}/chat/completions",
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            envelope = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", errors="replace")
        raise RuntimeError(f"LLM API returned HTTP {exc.code}: {detail}") from exc
    content = envelope["choices"][0]["message"]["content"]
    return _extract_json(content)
