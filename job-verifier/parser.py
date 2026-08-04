"""Email parsing and deterministic feature extraction.

Responsibilities:
  * Read raw ``.eml`` files (or raw bytes/strings) robustly.
  * Extract the plain-text body from arbitrarily nested MIME structures.
  * Deterministically read SPF / DKIM / DMARC authentication results.
  * Pull out entities (domains, phone numbers, Telegram/WhatsApp handles, URLs)
    used to map scam syndicates in the graph.

Everything here is deterministic so it can gate (and run before) expensive AI
calls.
"""
from __future__ import annotations

import email
import hashlib
import re
from email.message import Message
from email.policy import default as default_policy
from email.utils import parseaddr

from schemas import AuthStatus, EmailReference, ExtractedEntities, SecurityHeaders

# --- regexes ---------------------------------------------------------------
_AUTH_RE = {
    "dmarc": re.compile(r"dmarc=(\w+)", re.IGNORECASE),
    "spf": re.compile(r"spf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"dkim=(\w+)", re.IGNORECASE),
}

# Authenticated identifiers used for DMARC alignment.
_MAILFROM_RE = re.compile(r"smtp\.mailfrom=([^;\s]+)", re.IGNORECASE)
_HEADER_FROM_RE = re.compile(r"header\.from=([^;\s]+)", re.IGNORECASE)
_DKIM_D_RE = re.compile(r"header\.d=([^;\s]+)", re.IGNORECASE)
_DKIM_I_RE = re.compile(r"header\.i=@?([^;\s]+)", re.IGNORECASE)

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
# Match Telegram handles after "telegram"/"t.me/" cues, or a bare "@handle"
# that is NOT part of an email address (negative lookbehind on word chars/dot).
_TELEGRAM_RE = re.compile(
    r"(?:(?:telegram|t\.me/)\s*[:/@]*\s*@?|(?<![\w.])@)"
    r"([A-Za-z][A-Za-z0-9_]{3,31})",
    re.IGNORECASE,
)
_WHATSAPP_RE = re.compile(
    r"whats\s*app[^0-9+]{0,15}(\+?\d[\d\s().-]{7,}\d)", re.IGNORECASE
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# A phone-like run that is not glued to surrounding letters/digits (which would
# indicate it's part of a token, not a real number).
_PHONE_RE = re.compile(r"(?<![A-Za-z0-9])\+?\d[\d\s().-]{7,}\d(?![A-Za-z0-9])")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b"
)

_FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "gmx.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
    "live.com",
    "msn.com",
}


def parse_email(source: str | bytes) -> Message:
    """Parse an email from a file path, raw string, or raw bytes."""
    if isinstance(source, bytes):
        return email.message_from_bytes(source, policy=default_policy)
    # A short single-line string that exists on disk is treated as a path.
    if "\n" not in source and len(source) < 4096:
        try:
            with open(source, "rb") as fh:
                return email.message_from_bytes(fh.read(), policy=default_policy)
        except (OSError, ValueError):
            pass
    return email.message_from_string(source, policy=default_policy)


def parse_email_basics(file_path: str | bytes) -> tuple[Message, str]:
    """Backward-compatible helper returning ``(message, sender_header)``."""
    msg = parse_email(file_path)
    return msg, msg.get("From", "") or ""


def get_sender_address(msg: Message) -> str | None:
    """Return the bare ``local@domain`` from the ``From`` header."""
    _, addr = parseaddr(msg.get("From", "") or "")
    return addr or None


def build_reference(msg: Message) -> EmailReference:
    """Build a stable, human-readable handle for the analyzed email.

    The ``analysis_id`` is derived from the message's identity (Message-ID, or
    sender+subject+date as a fallback) so the same email always maps to the same
    id and can be cross-referenced with the persisted Recruiter node.
    """
    subject = (msg.get("Subject", "") or "").strip() or None
    from_address = get_sender_address(msg)
    date = (msg.get("Date", "") or "").strip() or None
    message_id = (msg.get("Message-ID", "") or "").strip() or None
    seed = message_id or "|".join(
        x for x in (from_address, subject, date) if x
    ) or "unknown"
    digest = hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()[:10].upper()
    return EmailReference(
        analysis_id=f"JSC-{digest}",
        subject=subject,
        from_address=from_address,
        date=date,
        message_id=message_id,
    )


def get_sender_domain(msg: Message) -> str | None:
    addr = get_sender_address(msg)
    if addr and "@" in addr:
        return addr.split("@", 1)[1].lower()
    return None


def extract_body_text(msg: Message) -> str:
    """Extract the best-effort plain-text body from any MIME structure."""
    if msg.is_multipart():
        # Prefer the first text/plain part; fall back to text/html stripped.
        html_fallback = ""
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                return _decode_part(part)
            if ctype == "text/html" and not html_fallback:
                html_fallback = _strip_html(_decode_part(part))
        return html_fallback
    content = _decode_part(msg)
    if msg.get_content_type() == "text/html":
        return _strip_html(content)
    return content


def _decode_part(part: Message) -> str:
    try:
        payload = part.get_content()
        if isinstance(payload, str):
            return payload
    except (LookupError, ValueError, KeyError):
        pass
    raw = part.get_payload(decode=True)
    if isinstance(raw, bytes):
        charset = part.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")
    payload = part.get_payload()
    return payload if isinstance(payload, str) else ""


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _registrable(domain: str) -> str:
    """Best-effort registrable domain (last two labels), lowercased."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def extract_security_headers(msg: Message) -> SecurityHeaders:
    """Read SPF/DKIM/DMARC and check identifier alignment from headers.

    Beyond the raw pass/fail, this verifies *alignment*: the domains that
    actually authenticated (SMTP MAIL FROM / DKIM ``d=``) must match the visible
    ``From:`` domain. A passing SPF/DKIM for an unrelated domain is a classic
    way spoofed mail sneaks through, so misalignment is treated as a failure.
    """
    auth_results = " ".join(msg.get_all("Authentication-Results", []))
    results: dict[str, AuthStatus] = {}
    for key, pattern in _AUTH_RE.items():
        match = pattern.search(auth_results)
        results[key] = _to_auth_status(match.group(1)) if match else AuthStatus.MISSING

    headers = SecurityHeaders(**results)

    from_domain = get_sender_domain(msg)
    headers.from_domain = from_domain

    authed: list[str] = []
    if headers.spf == AuthStatus.PASS:
        authed += [m.split("@")[-1] for m in _MAILFROM_RE.findall(auth_results)]
    if headers.dkim == AuthStatus.PASS:
        authed += _DKIM_D_RE.findall(auth_results)
        authed += [m.split("@")[-1] for m in _DKIM_I_RE.findall(auth_results)]
    authed = list(dict.fromkeys(a.lower() for a in authed if a))
    headers.authenticated_domains = authed

    # Alignment is only determinable when something actually authenticated.
    if from_domain and authed:
        reg_from = _registrable(from_domain)
        headers.aligned = any(_registrable(a) == reg_from for a in authed)
    elif headers.dmarc == AuthStatus.PASS:
        # A DMARC pass implies alignment by definition.
        headers.aligned = True

    return headers


def _to_auth_status(raw: str) -> AuthStatus:
    value = raw.strip().lower()
    try:
        return AuthStatus(value)
    except ValueError:
        return AuthStatus.MISSING


def extract_entities_from_text(
    text: str, priority_domain: str | None = None
) -> ExtractedEntities:
    """Pull domains, phone numbers and chat handles out of arbitrary text.

    Works for both email bodies and platform messages (LinkedIn DMs, etc.).
    ``priority_domain`` (e.g. an email sender domain) is surfaced first.
    """
    blob = text or ""

    urls = _unique(_URL_RE.findall(blob))
    telegram = _unique(m.lower() for m in _TELEGRAM_RE.findall(blob))
    whatsapp = _unique(_normalize_phone(m) for m in _WHATSAPP_RE.findall(blob))

    # Phone numbers are easily faked by digit runs inside URLs / tracking tokens,
    # so search a cleaned copy with URLs and emails removed.
    phone_blob = _URL_RE.sub(" ", blob)
    phone_blob = _EMAIL_RE.sub(" ", phone_blob)
    phones = _unique(
        _normalize_phone(m)
        for m in _PHONE_RE.findall(phone_blob)
        if _looks_like_phone(m)
    )
    # Don't double-count WhatsApp numbers as generic phones.
    phones = [p for p in phones if p not in set(whatsapp)]

    domains = _unique(d.lower() for d in _DOMAIN_RE.findall(blob))
    if priority_domain and priority_domain not in domains:
        domains.insert(0, priority_domain)
    # URLs already capture link domains; keep domains list to real hostnames.
    domains = [d for d in domains if "." in d and not d.endswith(".")]

    return ExtractedEntities(
        domains=domains,
        phone_numbers=phones,
        telegram_handles=telegram,
        whatsapp_numbers=whatsapp,
        urls=urls,
    )


def extract_entities(msg: Message, body_text: str | None = None) -> ExtractedEntities:
    """Pull domains, phone numbers and chat handles out of the email."""
    if body_text is None:
        body_text = extract_body_text(msg)

    header_blob = " ".join(
        filter(None, [msg.get("From"), msg.get("Reply-To"), msg.get("Return-Path")])
    )
    blob = f"{header_blob}\n{body_text}"
    return extract_entities_from_text(blob, priority_domain=get_sender_domain(msg))


def is_free_email_provider(domain: str | None) -> bool:
    return bool(domain) and domain.lower() in _FREE_EMAIL_PROVIDERS


def _looks_like_phone(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    return 7 <= len(digits) <= 15


def _normalize_phone(raw: str) -> str:
    raw = raw.strip()
    plus = raw.startswith("+")
    digits = re.sub(r"\D", "", raw)
    return f"+{digits}" if plus else digits


def _unique(items) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
