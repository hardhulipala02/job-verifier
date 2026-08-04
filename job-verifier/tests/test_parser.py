import parser
from schemas import AuthStatus

PLAIN_EML = """\
From: Anne <anne.hr@gmail.com>
To: me@example.com
Subject: hi
Authentication-Results: mx; spf=pass; dkim=fail; dmarc=fail
Content-Type: text/plain; charset="utf-8"

Message me on Telegram at @ScottHR or call +1 (415) 555-2671.
Visit https://scam-jobs.example for details. Domain corp-careers.io.
"""

MULTIPART_EML = """\
From: Jordan <jordan@stripe.com>
To: me@example.com
Subject: multipart
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b"

--b
Content-Type: text/plain; charset="utf-8"

plain body here
--b
Content-Type: text/html; charset="utf-8"

<html><body><p>html body</p></body></html>
--b--
"""


def test_security_headers_parsed():
    msg = parser.parse_email(PLAIN_EML)
    sec = parser.extract_security_headers(msg)
    assert sec.spf == AuthStatus.PASS
    assert sec.dkim == AuthStatus.FAIL
    assert sec.dmarc == AuthStatus.FAIL
    assert sec.spoof_detected is True


def test_missing_headers_default_missing():
    msg = parser.parse_email("From: a@b.com\nSubject: x\n\nbody")
    sec = parser.extract_security_headers(msg)
    assert sec.dmarc == AuthStatus.MISSING
    assert sec.spoof_detected is False


def test_entity_extraction():
    msg = parser.parse_email(PLAIN_EML)
    entities = parser.extract_entities(msg)
    assert "scotthr" in entities.telegram_handles
    assert any("415" in p for p in entities.phone_numbers)
    assert "gmail.com" in entities.domains
    assert "corp-careers.io" in entities.domains
    assert any(u.startswith("https://scam-jobs") for u in entities.urls)


def test_sender_helpers():
    msg = parser.parse_email(PLAIN_EML)
    assert parser.get_sender_address(msg) == "anne.hr@gmail.com"
    assert parser.get_sender_domain(msg) == "gmail.com"
    assert parser.is_free_email_provider("gmail.com") is True
    assert parser.is_free_email_provider("stripe.com") is False


def test_build_reference_captures_identity():
    eml = (
        "From: Anne <anne.hr@gmail.com>\n"
        "Subject: Exciting opportunity\n"
        "Date: Mon, 1 Jan 2024 10:00:00 +0000\n"
        "Message-ID: <abc123@mail>\n\nbody"
    )
    ref = parser.build_reference(parser.parse_email(eml))
    assert ref.from_address == "anne.hr@gmail.com"
    assert ref.subject == "Exciting opportunity"
    assert ref.message_id == "<abc123@mail>"
    assert ref.analysis_id.startswith("JSC-")


def test_build_reference_is_stable_for_same_email():
    eml = "From: a@b.com\nSubject: x\nMessage-ID: <id@h>\n\nbody"
    a = parser.build_reference(parser.parse_email(eml))
    b = parser.build_reference(parser.parse_email(eml))
    assert a.analysis_id == b.analysis_id


def test_multipart_prefers_plain_text():
    msg = parser.parse_email(MULTIPART_EML)
    body = parser.extract_body_text(msg)
    assert "plain body here" in body
