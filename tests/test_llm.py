import io
import json
import urllib.request
from typing import Self
from unittest.mock import patch

import pytest

from sca_accuracy.llm import LlmConfig, analyze


class JsonResponse(io.BytesIO):
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_analyze_sends_structured_request_and_parses_json() -> None:
    envelope = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {"summary": "ok", "hypotheses": [], "warnings": [], "decisions": []}
                    )
                }
            }
        ]
    }
    response = JsonResponse(json.dumps(envelope).encode())

    with patch.object(urllib.request, "urlopen", return_value=response) as urlopen:
        result = analyze(
            {"discrepancies": []},
            LlmConfig("secret", "https://model.example/v1", "model", 10),
        )

    request = urlopen.call_args.args[0]
    body = json.loads(request.data)
    assert result["summary"] == "ok"
    assert request.full_url == "https://model.example/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer secret"
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0


def test_local_endpoint_does_not_require_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCA_LLM_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("SCA_LLM_BASE_URL", "http://127.0.0.1:11434/v1/")
    monkeypatch.setenv("SCA_LLM_MODEL", "local-model")

    config = LlmConfig.from_environment()

    assert config.api_key == ""
    assert config.base_url == "http://127.0.0.1:11434/v1"
    assert config.model == "local-model"


def test_remote_endpoint_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCA_LLM_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("SCA_LLM_BASE_URL", "https://model.example/v1")

    with pytest.raises(RuntimeError, match="API_KEY"):
        LlmConfig.from_environment()
