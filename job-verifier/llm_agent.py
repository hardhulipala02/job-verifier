"""Behavioral analysis of recruiter emails.

Two layers, deterministic-first:

  1. ``deterministic_behavior_flags`` — cheap, offline regex/keyword detection of
     well-known scam patterns (forced chat-app migration, fake payment/check,
     upfront fees, urgency, credential harvesting). These run *before* and
     *without* any paid AI call.

  2. ``evaluate_email_behavior`` — optionally enriches the deterministic verdict
     with a Gemini call. The LLM call:
        * retries transient errors with exponential backoff (tenacity), and
        * is forced into the strict :class:`BehavioralVerdict` JSON schema.

If no ``GOOGLE_API_KEY`` is configured the function transparently returns the
deterministic-only verdict, so the pipeline always produces a result.
"""
from __future__ import annotations

import json
import logging
import re

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

import config
from schemas import BehavioralVerdict, RiskLevel

logger = logging.getLogger(__name__)

# --- deterministic scam-pattern signatures ---------------------------------
_PATTERN_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "Forced migration to an external chat app",
        re.compile(
            r"\b(telegram|whatsapp|signal|wechat|skype|wire)\b", re.IGNORECASE
        ),
    ),
    (
        "Promise of an upfront check / payment before work",
        re.compile(
            r"\b(mail(ed)?\s+you\s+a?\s*check|send\s+you\s+a?\s*check|"
            r"cashier'?s?\s+check|wire\s+you|advance\s+payment|"
            r"we will (?:mail|send) you)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Request to buy equipment / pay a fee",
        re.compile(
            r"\b(buy (?:a )?(?:macbook|laptop|equipment|software)|"
            r"purchase (?:the )?equipment|processing fee|registration fee|"
            r"training fee|reimburse)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Request for sensitive personal/financial info",
        re.compile(
            r"\b(ssn|social security|bank account|routing number|"
            r"credit card|date of birth|driver'?s? licen[sc]e)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "High-pressure urgency",
        re.compile(
            r"\b(immediately|right away|urgent|asap|act now|within \d+ "
            r"(?:hours|minutes))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Unrealistic compensation for minimal effort",
        re.compile(
            r"\b(\$\d{2,}(?:[/ ]?(?:hour|hr|day))|easy money|"
            r"no experience (?:needed|required)|work from home)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Hire without an interview",
        re.compile(
            r"\b(hire you right away|no interview|instant(?:ly)? hired|"
            r"text-based interview|interview over (?:telegram|whatsapp|chat))\b",
            re.IGNORECASE,
        ),
    ),
]


def deterministic_behavior_flags(email_body_text: str) -> list[str]:
    """Return scam-pattern flags found via deterministic matching."""
    flags: list[str] = []
    for label, pattern in _PATTERN_SIGNATURES:
        if pattern.search(email_body_text or ""):
            flags.append(label)
    return flags


def _risk_from_flag_count(count: int) -> RiskLevel:
    if count >= 3:
        return RiskLevel.HIGH
    if count >= 1:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
    return a if order[a] >= order[b] else b


_PROMPT_TEMPLATE = """\
You are an expert recruitment-security agent screening a recruiter's email for
job-scam behavior. Look for behavioral traps such as forced migration to chat
apps (Telegram/WhatsApp), fake check/payment offers, requests to buy equipment
or pay fees, requests for sensitive personal data, and pressure tactics.

Respond ONLY with a JSON object matching this exact schema:
{{
    "risk_level": "LOW" | "MEDIUM" | "HIGH",
    "flags_detected": ["short red-flag descriptions"],
    "summary": "one-sentence explanation of the verdict"
}}

EMAIL TEXT TO ANALYZE:
\"\"\"
{email_body_text}
\"\"\"
"""


class TransientLLMError(Exception):
    """Raised for retryable LLM failures (rate limits / 5xx / timeouts)."""


def _is_transient(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    markers = (
        "rate limit",
        "resource_exhausted",
        "429",
        "500",
        "502",
        "503",
        "504",
        "timeout",
        "timed out",
        "temporarily",
        "unavailable",
        "deadline",
    )
    return any(m in text for m in markers)


def _llm_verdict(email_body_text: str) -> BehavioralVerdict:
    """Call Gemini with retries and coerce the reply into the strict schema."""
    from google import genai  # imported lazily so tests need no SDK creds
    from google.genai import types

    client = genai.Client(api_key=config.GOOGLE_API_KEY)
    prompt = _PROMPT_TEMPLATE.format(email_body_text=email_body_text)

    @retry(
        retry=retry_if_exception_type(TransientLLMError),
        stop=stop_after_attempt(config.LLM_MAX_RETRIES),
        wait=wait_exponential(multiplier=config.LLM_BACKOFF_BASE_SECONDS),
        reraise=True,
    )
    def _do_call() -> str:
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                ),
            )
            return response.text
        except Exception as exc:  # noqa: BLE001 - classify then re-raise
            if _is_transient(exc):
                logger.warning("Transient LLM error, will retry: %s", exc)
                raise TransientLLMError(str(exc)) from exc
            raise

    raw = _do_call()
    data = json.loads(raw)
    # Pydantic enforces the strict schema; unknown keys are ignored.
    return BehavioralVerdict.model_validate(data)


def evaluate_email_behavior(
    email_body_text: str, *, use_llm: bool | None = None
) -> BehavioralVerdict:
    """Produce a behavioral verdict, combining deterministic + LLM signals."""
    det_flags = deterministic_behavior_flags(email_body_text)
    det_verdict = BehavioralVerdict(
        risk_level=_risk_from_flag_count(len(det_flags)),
        flags_detected=det_flags,
        summary=(
            f"Deterministic screening found {len(det_flags)} scam pattern(s)."
            if det_flags
            else "No deterministic scam patterns detected."
        ),
    )

    should_use_llm = config.llm_enabled() if use_llm is None else use_llm
    if not should_use_llm:
        return det_verdict

    try:
        llm = _llm_verdict(email_body_text)
    except Exception as exc:  # noqa: BLE001 - never let the LLM crash the pipeline
        logger.error("LLM analysis failed, using deterministic verdict: %s", exc)
        det_verdict.summary += " (LLM enrichment unavailable.)"
        return det_verdict

    merged_flags = list(dict.fromkeys([*det_flags, *llm.flags_detected]))
    return BehavioralVerdict(
        risk_level=_max_risk(det_verdict.risk_level, llm.risk_level),
        flags_detected=merged_flags,
        summary=llm.summary or det_verdict.summary,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample = (
        "Hi there! I'm Anne from XXXX. We loved your resume and want to hire "
        "you right away for a W-2 role. Please message me on Telegram at "
        "@ScottHR for a text-based interview. If hired, we will mail you a "
        "check for $2,000 to buy a MacBook."
    )
    print(evaluate_email_behavior(sample, use_llm=False).model_dump_json(indent=2))
