import sys
import types as pytypes

import config
import llm_agent
from schemas import BehavioralVerdict, RiskLevel

SCAM_TEXT = (
    "I'm Anne from Globex. We want to hire you right away with no experience "
    "required. Message me on Telegram at @GlobexHR immediately. We will mail "
    "you a check for $2,000 to buy a MacBook."
)


def test_deterministic_flags_detect_scam_patterns():
    flags = llm_agent.deterministic_behavior_flags(SCAM_TEXT)
    joined = " ".join(flags).lower()
    assert "chat app" in joined
    assert any("check" in f.lower() or "payment" in f.lower() for f in flags)
    assert len(flags) >= 3


def test_evaluate_without_llm_returns_high_for_scam():
    verdict = llm_agent.evaluate_email_behavior(SCAM_TEXT, use_llm=False)
    assert isinstance(verdict, BehavioralVerdict)
    assert verdict.risk_level == RiskLevel.HIGH


def test_evaluate_without_llm_clean_text_low():
    verdict = llm_agent.evaluate_email_behavior(
        "Thanks for applying, let's find a time to chat next week.",
        use_llm=False,
    )
    assert verdict.risk_level == RiskLevel.LOW


def test_llm_failure_falls_back_to_deterministic(monkeypatch):
    def boom(_text):
        raise RuntimeError("permanent failure")

    monkeypatch.setattr(llm_agent, "_llm_verdict", boom)
    verdict = llm_agent.evaluate_email_behavior(SCAM_TEXT, use_llm=True)
    assert verdict.risk_level == RiskLevel.HIGH  # deterministic still flags it


def _install_fake_genai(monkeypatch, behavior):
    """Inject a fake google.genai SDK whose call runs ``behavior()``."""
    google_mod = pytypes.ModuleType("google")
    genai_mod = pytypes.ModuleType("google.genai")
    types_mod = pytypes.ModuleType("google.genai.types")

    class FakeResponse:
        def __init__(self, text):
            self.text = text

    class FakeModels:
        def generate_content(self, **_kwargs):
            return FakeResponse(behavior())

    class FakeClient:
        def __init__(self, **_kwargs):
            self.models = FakeModels()

    class GenerateContentConfig:
        def __init__(self, **_kwargs):
            pass

    genai_mod.Client = FakeClient
    types_mod.GenerateContentConfig = GenerateContentConfig
    genai_mod.types = types_mod
    google_mod.genai = genai_mod

    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.genai", genai_mod)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_mod)


def test_llm_retries_transient_then_succeeds(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_API_KEY", "test-key")
    monkeypatch.setattr(config, "LLM_MAX_RETRIES", 4)
    monkeypatch.setattr(config, "LLM_BACKOFF_BASE_SECONDS", 0.0)

    calls = {"n": 0}
    good_json = '{"risk_level": "HIGH", "flags_detected": ["x"], "summary": "s"}'

    def behavior():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("429 rate limit exceeded")
        return good_json

    _install_fake_genai(monkeypatch, behavior)
    verdict = llm_agent._llm_verdict(SCAM_TEXT)
    assert calls["n"] == 3  # retried twice before succeeding
    assert verdict.risk_level == RiskLevel.HIGH


def test_llm_strict_schema_validation(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_API_KEY", "test-key")
    monkeypatch.setattr(config, "LLM_BACKOFF_BASE_SECONDS", 0.0)
    # Extra/unknown keys are ignored; required shape is enforced.
    payload = '{"risk_level": "MEDIUM", "flags_detected": [], "summary": "ok", "junk": 1}'
    _install_fake_genai(monkeypatch, lambda: payload)
    verdict = llm_agent._llm_verdict(SCAM_TEXT)
    assert verdict.risk_level == RiskLevel.MEDIUM
    assert verdict.summary == "ok"
