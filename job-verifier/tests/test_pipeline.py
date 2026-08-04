import os

import main_graph
from schemas import RiskLevel

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_emails")


def _analyze(name):
    return main_graph.analyze_email(
        os.path.join(SAMPLES, name),
        use_llm=False,
        persist=False,
        resolve_dns=False,
    )


def test_telegram_scam_is_high_risk():
    report = _analyze("telegram_scam.eml")
    assert report.verdict.risk_level == RiskLevel.HIGH
    assert "globexhr" in report.entities.telegram_handles
    assert report.impersonation.is_impersonation is True
    assert report.persisted is False


def test_spoofed_email_short_circuits_to_high():
    report = _analyze("spoofed.eml")
    assert report.security.spoof_detected is True
    assert report.verdict.risk_level == RiskLevel.HIGH
    assert any("Authentication failure" in f for f in report.verdict.flags_detected)


def test_legit_email_is_low_risk():
    report = _analyze("legit.eml")
    assert report.security.spoof_detected is False
    assert report.impersonation.is_impersonation is False
    assert report.verdict.risk_level == RiskLevel.LOW
