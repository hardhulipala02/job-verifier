"""One-off helper: email the test .eml pack to a recipient as rfc822 attachments.

Each sample is sent as its own message with the original email attached as a
``message/rfc822`` part. When the recipient forwards one of these to the bot,
Gmail keeps the attachment, so the bot analyzes the ORIGINAL with full fidelity
(forged SPF/DKIM/DMARC headers, typosquat domains, etc. all survive).
"""
from __future__ import annotations

import email
import smtplib
import sys
from email.message import EmailMessage
from email.policy import default as default_policy

import config

PACK = [
    ("typosquat_lookalike.eml", "Look-alike domain (linkedln.com) test"),
    ("misaligned_spoof.eml", "Auth-misaligned spoof (google.com via .ru) test"),
    ("fake_check_webmail.eml", "Fake-check + WhatsApp + free webmail test"),
    ("telegram_scam.eml", "Telegram trap + check scam test"),
    ("spoofed.eml", "SPF/DKIM/DMARC all-fail test"),
    ("legit.eml", "Legit recruiter control (should be LOW)"),
]


def build(to_addr: str, fname: str, label: str) -> EmailMessage:
    with open(f"sample_emails/{fname}", "rb") as fh:
        inner = email.message_from_bytes(fh.read(), policy=default_policy)

    outer = EmailMessage()
    outer["From"] = config.BOT_EMAIL
    outer["To"] = to_addr
    outer["Subject"] = f"[TEST] {label}"
    outer.set_content(
        "This is a Job Scam Checker test email.\n\n"
        "To test the bot: Forward this message to "
        f"{config.BOT_EMAIL}.\n"
        "The original scam email is attached, so forwarding preserves its real "
        "headers (sender domain, SPF/DKIM/DMARC, look-alike domains).\n\n"
        f"Scenario: {label}\n"
    )
    outer.add_attachment(inner, filename=fname)
    return outer


def main(to_addr: str) -> None:
    msgs = [build(to_addr, f, label) for f, label in PACK]
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(config.BOT_EMAIL, config.BOT_PASSWORD)
        for m in msgs:
            smtp.send_message(m)
            print("sent:", m["Subject"])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "harshitha.dhulipala2@gmail.com")
