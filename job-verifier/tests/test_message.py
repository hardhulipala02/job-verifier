import main_graph
import parser
from schemas import RiskLevel

LINKEDIN_SCAM = (
    "Hi! I'm Anne from Globex. We'd love to hire you right away, no interview "
    "needed. Please continue on Telegram at @GlobexHR. We'll send you a check "
    "to buy a MacBook. Reply ASAP!"
)

CLEAN_MESSAGE = (
    "Hi, thanks for connecting! I'm a recruiter at Acme and wanted to see if "
    "you'd be open to chatting about a backend role next week."
)


def test_text_entity_extraction():
    entities = parser.extract_entities_from_text(
        "Reach me on Telegram @ScamHR or WhatsApp +1 415 555 0100. "
        "See https://fake.example/jobs"
    )
    assert "scamhr" in entities.telegram_handles
    assert entities.whatsapp_numbers
    assert any(u.startswith("https://fake") for u in entities.urls)


def test_digits_in_urls_are_not_phone_numbers():
    # Long digit runs embedded in tracking URLs/tokens must not be read as phones.
    entities = parser.extract_entities_from_text(
        "Unsubscribe: https://list.example.com/opt-out/a284150952b21de94c47 "
        "Questions? email us at jobs1234@example.com"
    )
    assert entities.phone_numbers == []


def test_real_phone_still_extracted():
    entities = parser.extract_entities_from_text("Call me at +1 (415) 555-0100.")
    assert entities.phone_numbers


def test_analyze_message_scam_high():
    report = main_graph.analyze_message(
        LINKEDIN_SCAM, sender_name="Anne", platform="linkedin",
        use_llm=False, persist=False,
    )
    assert report.verdict.risk_level == RiskLevel.HIGH
    assert "globexhr" in report.entities.telegram_handles
    # No email headers on a platform message.
    assert report.security.spoof_detected is False
    assert report.persisted is False


def test_analyze_message_clean_low():
    report = main_graph.analyze_message(
        CLEAN_MESSAGE, use_llm=False, persist=False
    )
    assert report.verdict.risk_level == RiskLevel.LOW
