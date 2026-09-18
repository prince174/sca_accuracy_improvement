import copy

from sca_accuracy.benchmark import make_case, prepare
from sca_accuracy.experiments import cached_call, neutral_label, omission_audit
from sca_accuracy.llm import LlmConfig


def test_neutral_label_changes_only_source_not_candidate_identity():
    payload = prepare(make_case("npm", "undeclared", 0))[3]
    original = copy.deepcopy(payload)
    changed = neutral_label(payload)
    assert payload == original
    assert changed["candidates"][0]["id"] == original["candidates"][0]["id"]
    assert changed["candidates"][0]["evidence"][0]["source"] == "package-metadata"

    def strip_sources(value):
        if isinstance(value, dict):
            return {k: strip_sources(v) for k, v in value.items() if k != "source"}
        if isinstance(value, list):
            return [strip_sources(v) for v in value]
        return value

    assert strip_sources(changed) == strip_sources(original)


def test_cache_separates_prompt_model_and_reasoning(tmp_path, monkeypatch):
    calls = []

    def fake(payload, config, *, prompt):
        calls.append(1)
        return {"decisions": []}

    monkeypatch.setattr("sca_accuracy.experiments.analyze", fake)
    for config, prompt in [
        (LlmConfig("a"), "p"),
        (LlmConfig("b"), "p"),
        (LlmConfig("a", thinking="enabled"), "p"),
        (LlmConfig("a", model="other"), "p"),
        (LlmConfig("a"), "other"),
    ]:
        cached_call(tmp_path, {}, config, prompt)
    assert len(calls) == 4


def test_omission_audit_counts_delta_not_all_deferrals():
    report = {
        "rows": [
            {
                "case_id": "x",
                "family": "f",
                "ecosystem": "npm",
                "model": {"fn": 2},
                "allowed_rules": {"fn": 1},
                "model_audit": {"deferred": [{"reason": "a"}, {"reason": "b"}]},
            }
        ]
    }
    assert omission_audit(report)["extra_fn"] == 1


def test_checkpoint_compares_json_values_not_python_tuple_representation(tmp_path, monkeypatch):
    calls = []

    def fake(payload, config, *, prompt):
        calls.append(1)
        return {"decisions": []}

    monkeypatch.setattr("sca_accuracy.experiments.analyze", fake)
    cached_call(tmp_path, {"qualifiers": (("arch", "x64"),)}, LlmConfig("key"))
    cached_call(tmp_path, {"qualifiers": [["arch", "x64"]]}, LlmConfig("key"))
    assert len(calls) == 1
