"""Forward-to-address email bot.

Users forward a suspicious recruiter email to the bot's mailbox; the bot analyzes
it and replies with a readable report.

Flow:
  1. Poll the mailbox over IMAP for unseen messages.
  2. For each, find the *original* forwarded email — preferring a
     ``message/rfc822`` attachment (full headers, so SPF/DKIM/DMARC still work);
     otherwise fall back to analyzing the forwarded body text.
  3. Reply to the forwarder over SMTP with the report.

Run with ``python mailbot.py`` (requires JOBVERIFIER_BOT_EMAIL / _PASSWORD).
The IMAP/SMTP plumbing is isolated from the pure logic (``analyze_received``,
``build_reply``) so the logic is unit-tested without a network.
"""
from __future__ import annotations

import base64
import email
import imaplib
import logging
import quopri
import re
import smtplib
import time
from email.message import EmailMessage, Message
from email.policy import default as default_policy
from email.utils import parseaddr

import config
import report_format
from main_graph import analyze_email, analyze_message
from schemas import ScamReport

logger = logging.getLogger(__name__)


def get_forwarded_payload(msg: Message) -> bytes | None:
    """Return the raw bytes of an attached original email, if present."""
    if not msg.is_multipart():
        return None
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            # Properly-formed forwards expose the nested message as a sub-part.
            if isinstance(payload, list) and payload:
                return payload[0].as_bytes()
            # Some clients (wrongly) transfer-encode the nested message; decode
            # it ourselves so SPF/DKIM headers survive.
            if isinstance(payload, str):
                cte = (part.get("Content-Transfer-Encoding") or "").lower()
                if cte == "base64":
                    return base64.b64decode(payload)
                if cte == "quoted-printable":
                    return quopri.decodestring(payload.encode())
                return payload.encode("utf-8", errors="replace")
    return None


def _plain_body(msg: Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                raw = part.get_payload(decode=True)
                if isinstance(raw, bytes):
                    return raw.decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
    raw = msg.get_payload(decode=True)
    if isinstance(raw, bytes):
        return raw.decode(msg.get_content_charset() or "utf-8", errors="replace")
    payload = msg.get_payload()
    return payload if isinstance(payload, str) else ""


_FWD_HEADER_RE = re.compile(
    r"^\s*[>\s]*(From|Sender|Subject|Date|To|Reply-To|Cc)\s*:\s*(.*)$",
    re.IGNORECASE,
)
_FWD_MARKER_RE = re.compile(
    r"(-{2,}\s*Forwarded message\s*-{2,}|Begin forwarded message:|"
    r"-{2,}\s*Original Message\s*-{2,})",
    re.IGNORECASE,
)


def parse_inline_forward(body_text: str) -> tuple[str | None, str | None, str]:
    """Parse a Gmail/Outlook/Apple inline-forwarded email.

    Returns ``(sender, subject, inner_body)``. A normal "Forward" inlines the
    original as quoted text (no headers like SPF/DKIM survive), so we recover at
    least the original sender and subject to keep impersonation checks working.
    """
    lines = body_text.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if _FWD_MARKER_RE.search(line):
            start = i + 1
            break

    sender: str | None = None
    subject: str | None = None
    body_start = start
    seen_header = False
    for i in range(start, min(start + 25, len(lines))):
        m = _FWD_HEADER_RE.match(lines[i])
        if m:
            seen_header = True
            field, value = m.group(1).lower(), m.group(2).strip()
            if field in ("from", "sender") and not sender:
                _, addr = parseaddr(value)
                sender = addr or value or None
            elif field == "subject" and not subject:
                subject = value
            body_start = i + 1
        elif seen_header and not lines[i].strip():
            body_start = i + 1
            break
        elif seen_header:
            break

    inner_body = "\n".join(lines[body_start:]).strip() if seen_header else body_text
    return sender, subject, inner_body


def _reconstruct_email(sender: str, subject: str | None, body: str) -> bytes:
    rebuilt = EmailMessage()
    rebuilt["From"] = sender
    if subject:
        rebuilt["Subject"] = subject
    rebuilt.set_content(body)
    return rebuilt.as_bytes()


def analyze_received(raw_message: bytes, *, persist: bool = True) -> ScamReport:
    """Analyze a forwarded email (bytes of the message received by the bot)."""
    msg = email.message_from_bytes(raw_message, policy=default_policy)
    forwarded = get_forwarded_payload(msg)
    if forwarded is not None:
        logger.info("Analyzing attached original email")
        return analyze_email(forwarded, persist=persist)

    body = _plain_body(msg)
    sender, subject, inner = parse_inline_forward(body)
    if sender:
        logger.info("No attachment; reconstructing inline-forwarded email")
        return analyze_email(
            _reconstruct_email(sender, subject, inner), persist=persist
        )

    logger.info("No attached original; analyzing forwarded body text")
    return analyze_message(body, platform="email-forward", persist=persist)


def reply_target(raw_message: bytes) -> str | None:
    """Who forwarded the email (so we know whom to reply to)."""
    msg = email.message_from_bytes(raw_message, policy=default_policy)
    _, addr = parseaddr(msg.get("Reply-To") or msg.get("From") or "")
    return addr or None


def build_reply(to_addr: str, report: ScamReport, in_reply_to: str | None = None) -> EmailMessage:
    """Build the report reply email."""
    reply = EmailMessage()
    reply["From"] = config.BOT_EMAIL or "job-scam-checker@localhost"
    reply["To"] = to_addr
    reply["Subject"] = report_format.subject_line(report)
    if in_reply_to:
        reply["In-Reply-To"] = in_reply_to
        reply["References"] = in_reply_to
    reply.set_content(report_format.render_text(report))
    reply.add_alternative(report_format.render_html(report), subtype="html")
    return reply


def process_raw(raw_message: bytes, *, persist: bool = True) -> EmailMessage | None:
    """Pure pipeline: bytes in -> reply email out (or None if no reply target)."""
    to_addr = reply_target(raw_message)
    if not to_addr:
        logger.warning("Could not determine a reply address; skipping message")
        return None
    report = analyze_received(raw_message, persist=persist)
    in_reply_to = email.message_from_bytes(
        raw_message, policy=default_policy
    ).get("Message-ID")
    return build_reply(to_addr, report, in_reply_to=in_reply_to)


# --- IMAP / SMTP plumbing --------------------------------------------------
def _send(reply: EmailMessage) -> None:
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(config.BOT_EMAIL, config.BOT_PASSWORD)
        smtp.send_message(reply)
    logger.info("Replied to %s", reply["To"])


def poll_once(imap: imaplib.IMAP4) -> int:
    """Process all unseen messages once. Returns the number handled."""
    imap.select(config.MAILBOX)
    status, data = imap.search(None, "UNSEEN")
    if status != "OK" or not data or not data[0]:
        return 0
    handled = 0
    for num in data[0].split():
        status, fetched = imap.fetch(num, "(RFC822)")
        if status != "OK" or not fetched:
            continue
        raw = fetched[0][1]
        try:
            reply = process_raw(raw)
            if reply is not None:
                _send(reply)
                handled += 1
        except Exception as exc:  # noqa: BLE001 - one bad email shouldn't kill the loop
            logger.error("Failed to process a message: %s", exc)
        imap.store(num, "+FLAGS", "\\Seen")
    return handled


def run() -> None:
    if not config.mailbot_enabled():
        raise SystemExit(
            "Mailbox not configured. Set JOBVERIFIER_BOT_EMAIL and "
            "JOBVERIFIER_BOT_PASSWORD."
        )
    logging.basicConfig(level=logging.INFO)
    logger.info("Job Scam Checker mail bot starting for %s", config.BOT_EMAIL)
    while True:
        try:
            with imaplib.IMAP4_SSL(config.IMAP_HOST, config.IMAP_PORT) as imap:
                imap.login(config.BOT_EMAIL, config.BOT_PASSWORD)
                n = poll_once(imap)
                if n:
                    logger.info("Handled %d message(s)", n)
        except Exception as exc:  # noqa: BLE001 - keep the daemon alive
            logger.error("Poll cycle failed: %s", exc)
        time.sleep(config.POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
