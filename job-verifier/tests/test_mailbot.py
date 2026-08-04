import email
import os
from email.message import EmailMessage
from email.policy import default

import config
import mailbot
import report_format
from schemas import RiskLevel

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_emails")


def _read(name):
    with open(os.path.join(SAMPLES, name), "rb") as fh:
        return fh.read()


def _forwarded_with_attachment(original_bytes):
    """Build an email that forwards `original_bytes` as a message/rfc822 part."""
    wrapper = EmailMessage()
    wrapper["From"] = "victim@example.com"
    wrapper["To"] = config.BOT_EMAIL or "bot@example.com"
    wrapper["Subject"] = "Fwd: is this a scam?"
    wrapper["Message-ID"] = "<wrap-123@example.com>"
    wrapper.set_content("Hi, can you check this email?")
    original_msg = email.message_from_bytes(original_bytes, policy=default)
    wrapper.add_attachment(original_msg, filename="original.eml")
    return wrapper.as_bytes()


def test_get_forwarded_payload_extracts_attachment():
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    msg = email.message_from_bytes(raw, policy=default)
    payload = mailbot.get_forwarded_payload(msg)
    assert payload is not None
    assert b"Telegram" in payload


def test_reply_target_is_forwarder():
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    assert mailbot.reply_target(raw) == "victim@example.com"


def test_analyze_received_uses_attached_original():
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    report = mailbot.analyze_received(raw, persist=False)
    assert report.verdict.risk_level == RiskLevel.HIGH
    assert "globexhr" in report.entities.telegram_handles


def test_analyze_received_falls_back_to_body():
    wrapper = EmailMessage()
    wrapper["From"] = "victim@example.com"
    wrapper["Subject"] = "Fwd"
    wrapper.set_content(
        "I'm Anne from Globex, message me on Telegram @GlobexHR right away, "
        "we'll mail you a check to buy a MacBook."
    )
    report = mailbot.analyze_received(wrapper.as_bytes(), persist=False)
    assert report.verdict.risk_level == RiskLevel.HIGH


def test_build_reply_contents():
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    report = mailbot.analyze_received(raw, persist=False)
    reply = mailbot.build_reply("victim@example.com", report, in_reply_to="<x@y>")
    assert reply["To"] == "victim@example.com"
    assert "HIGH RISK" in reply["Subject"]
    assert reply["In-Reply-To"] == "<x@y>"
    # multipart: text + html alternative
    body = reply.get_body(preferencelist=("plain",)).get_content()
    assert "RISK LEVEL: HIGH" in body


def test_process_raw_end_to_end():
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    reply = mailbot.process_raw(raw, persist=False)
    assert reply is not None
    assert reply["To"] == "victim@example.com"


def test_poll_once_with_fake_imap(monkeypatch):
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    sent = []

    monkeypatch.setattr(mailbot, "_send", lambda reply: sent.append(reply))

    class FakeIMAP:
        def __init__(self):
            self.stored = []

        def select(self, mailbox):
            return ("OK", [b"1"])

        def search(self, charset, *criteria):
            return ("OK", [b"1"])

        def fetch(self, num, spec):
            return ("OK", [(b"1 (RFC822 {123}", raw)])

        def store(self, num, flag, value):
            self.stored.append((num, flag, value))
            return ("OK", [b"1"])

    imap = FakeIMAP()
    handled = mailbot.poll_once(imap)
    assert handled == 1
    assert len(sent) == 1
    assert sent[0]["To"] == "victim@example.com"
    assert imap.stored  # message marked seen


GMAIL_INLINE_FORWARD = """\
Hi, is this a scam? Please check.

---------- Forwarded message ---------
From: Anne Recruiter <anne.hr2024@gmail.com>
Date: Mon, 1 Jan 2024 at 10:00
Subject: Exciting opportunity at Globex Corporation
To: <victim@example.com>

Hi! I'm Anne from Globex Corporation. We'd love to hire you right away, no
interview needed. Please continue on Telegram @GlobexHR. We'll send you a
check to buy a MacBook. Reply ASAP!
"""


def test_parse_inline_forward():
    sender, subject, inner = mailbot.parse_inline_forward(GMAIL_INLINE_FORWARD)
    assert sender == "anne.hr2024@gmail.com"
    assert "Globex" in subject
    assert "Telegram @GlobexHR" in inner
    assert "is this a scam" not in inner  # the forwarder's note is stripped


def test_analyze_received_inline_forward():
    wrapper = EmailMessage()
    wrapper["From"] = "victim@example.com"
    wrapper["Subject"] = "Fwd: Exciting opportunity"
    wrapper.set_content(GMAIL_INLINE_FORWARD)
    report = mailbot.analyze_received(wrapper.as_bytes(), persist=False)
    assert report.verdict.risk_level == RiskLevel.HIGH
    assert report.sender_domain == "gmail.com"
    assert report.impersonation.is_impersonation is True
    assert "globexhr" in report.entities.telegram_handles


def test_report_format_text_and_html():
    raw = _forwarded_with_attachment(_read("telegram_scam.eml"))
    report = mailbot.analyze_received(raw, persist=False)
    text = report_format.render_text(report)
    html = report_format.render_html(report)
    assert "RISK LEVEL: HIGH" in text
    assert "HIGH RISK" in html
    assert "Telegram" in html
    # The report references the analyzed email so users can map it back.
    assert report.source is not None
    assert report.source.analysis_id in text
    assert "Analyzed email" in text
    assert report.source.analysis_id in html
