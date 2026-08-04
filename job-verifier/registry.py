"""Corporate-registry cross-referencing for impersonation detection.

A common scam pattern is a recruiter *claiming* to represent a real company
(e.g. "I'm Anne from Stripe") while emailing from an unrelated free mailbox
(``anne.recruiter93@gmail.com``) or a look-alike domain.

This module deterministically compares the *claimed* company against the
*actual* sending domain:

  * Does the sending domain resolve at all? (DNS)
  * Is it a free webmail provider rather than a corporate domain?
  * Does the domain plausibly match the claimed company name?

DNS resolution is best-effort and can be disabled (``resolve_dns=False``) so the
checks stay fully deterministic and offline-friendly for tests/CI.
"""
from __future__ import annotations

import logging
import re
import socket
from datetime import datetime, timezone

from parser import is_free_email_provider
from schemas import ExtractedEntities, ImpersonationCheck

logger = logging.getLogger(__name__)

# Well-known brands frequently impersonated by recruitment scams. Sender domains
# that are a *near miss* of one of these (small edit distance) are typosquats.
_KNOWN_BRAND_DOMAINS = (
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "facebook.com", "linkedin.com", "netflix.com", "stripe.com", "oracle.com",
    "salesforce.com", "ibm.com", "intel.com", "nvidia.com", "adobe.com",
    "paypal.com", "uber.com", "airbnb.com", "spotify.com", "tesla.com",
    "deloitte.com", "accenture.com", "kpmg.com", "ey.com", "pwc.com",
)

# A domain younger than this is a strong scam signal.
NEW_DOMAIN_THRESHOLD_DAYS = 60

# "I'm Anne from Acme Corp", "on behalf of Globex", "here at Initech"
_COMPANY_PATTERNS = [
    re.compile(r"\bfrom\s+([A-Z][\w&.\- ]{1,40}?)(?:[.,!\n]|\s+(?:and|we|to)\b)"),
    re.compile(r"\bon behalf of\s+([A-Z][\w&.\- ]{1,40}?)(?:[.,!\n]|$)"),
    re.compile(r"\bhere at\s+([A-Z][\w&.\- ]{1,40}?)(?:[.,!\n]|$)"),
    re.compile(r"\bwork(?:ing)? (?:at|for)\s+([A-Z][\w&.\- ]{1,40}?)(?:[.,!\n]|$)"),
]

_COMPANY_SUFFIXES = {
    "inc",
    "incorporated",
    "llc",
    "ltd",
    "limited",
    "corp",
    "corporation",
    "co",
    "company",
    "group",
    "holdings",
    "technologies",
    "technology",
    "labs",
    "software",
    "solutions",
}

_PUBLIC_SUFFIX_HINTS = ("co.uk", "com.au", "co.in", "co.jp", "com.br")


def guess_claimed_company(
    display_name: str | None, body_text: str
) -> str | None:
    """Best-effort extraction of the company the sender claims to represent."""
    for pattern in _COMPANY_PATTERNS:
        match = pattern.search(body_text)
        if match:
            candidate = match.group(1).strip()
            if candidate:
                return candidate
    # Fall back to a display name that looks like "Anne | Acme Corp".
    if display_name:
        for sep in ("|", "-", "@", ",", "·"):
            if sep in display_name:
                tail = display_name.split(sep)[-1].strip()
                if tail and not _looks_like_person(tail):
                    return tail
    return None


def _looks_like_person(text: str) -> bool:
    words = text.split()
    return 1 <= len(words) <= 2 and all(w[:1].isupper() for w in words if w)


def _company_tokens(company: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", company.lower())
    return [t for t in tokens if t and t not in _COMPANY_SUFFIXES]


def registrable_domain(domain: str) -> str:
    """Strip subdomains to the registrable part (best-effort, no PSL dep)."""
    domain = domain.lower().strip(".")
    for hint in _PUBLIC_SUFFIX_HINTS:
        if domain.endswith("." + hint) or domain == hint:
            parts = domain.split(".")
            return ".".join(parts[-3:]) if len(parts) >= 3 else domain
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance between two strings (insert/delete/substitute)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(
                min(
                    prev[j] + 1,       # deletion
                    cur[j - 1] + 1,    # insertion
                    prev[j - 1] + (ca != cb),  # substitution
                )
            )
        prev = cur
    return prev[-1]


def detect_typosquatting(
    domain: str, extra_targets: list[str] | None = None
) -> tuple[str | None, int | None]:
    """Return the closest legitimate brand a domain is squatting on, if any.

    Compares the registrable form of ``domain`` against known brand domains (and
    any ``extra_targets``, e.g. a domain derived from the claimed company). A
    small but non-zero edit distance indicates a look-alike (``str1pe.com``).
    """
    reg = registrable_domain(domain)
    targets = list(_KNOWN_BRAND_DOMAINS) + [
        registrable_domain(t) for t in (extra_targets or []) if t
    ]
    best: tuple[str | None, int | None] = (None, None)
    for target in targets:
        if not target or reg == target:
            continue
        dist = levenshtein(reg, target)
        # Only flag genuinely close look-alikes, scaled to the brand length.
        max_dist = 2 if len(target) <= 10 else 3
        if dist <= max_dist and (best[1] is None or dist < best[1]):
            best = (target, dist)
    return best


def domain_age_days(domain: str, timeout: float = 4.0) -> int | None:
    """Best-effort domain age via RDAP (free, no API key). None on failure."""
    import httpx

    reg = registrable_domain(domain)
    try:
        resp = httpx.get(
            f"https://rdap.org/domain/{reg}",
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "JobScamChecker"},
        )
        if resp.status_code != 200:
            return None
        events = resp.json().get("events", [])
    except Exception as exc:  # noqa: BLE001 - never crash the pipeline
        logger.warning("RDAP lookup failed for %s: %s", reg, exc)
        return None

    for event in events:
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate", "")
            try:
                when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
            now = datetime.now(timezone.utc)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max((now - when).days, 0)
    return None


def domain_resolves(domain: str, timeout: float = 3.0) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(None)


def domain_matches_company(domain: str, company: str | None) -> bool:
    if not company:
        return False
    tokens = _company_tokens(company)
    if not tokens:
        return False
    label = registrable_domain(domain).split(".")[0]
    collapsed = "".join(tokens)
    if collapsed and collapsed in label:
        return True
    # Match the longest meaningful token (avoid trivial 2-char matches).
    return any(len(tok) >= 4 and tok in label for tok in tokens)


def check_impersonation(
    sender_domain: str | None,
    display_name: str | None,
    body_text: str,
    entities: ExtractedEntities | None = None,
    *,
    resolve_dns: bool = True,
    check_age: bool | None = None,
) -> ImpersonationCheck:
    """Cross-reference the claimed company against the actual sending domain."""
    claimed = guess_claimed_company(display_name, body_text)
    result = ImpersonationCheck(
        claimed_company=claimed,
        sender_domain=sender_domain,
    )
    notes: list[str] = []

    if not sender_domain:
        notes.append("No sender domain could be determined.")
        result.notes = notes
        return result

    result.is_free_email_provider = is_free_email_provider(sender_domain)
    result.domain_resolves = (
        domain_resolves(sender_domain) if resolve_dns else True
    )
    result.domain_matches_company = domain_matches_company(
        sender_domain, claimed
    )

    if not result.domain_resolves:
        notes.append(f"Sender domain '{sender_domain}' does not resolve (DNS).")

    # Typosquatting: a look-alike of a known brand (or the claimed company).
    if not result.is_free_email_provider:
        target, dist = detect_typosquatting(
            sender_domain, [claimed] if claimed else None
        )
        if target:
            result.typosquatting_target = target
            result.typosquatting_distance = dist
            result.is_impersonation = True
            notes.append(
                f"Sender domain '{sender_domain}' is a look-alike of "
                f"'{target}' (edit distance {dist}) — likely typosquatting."
            )

    # Domain age via RDAP: newly registered domains are a strong scam signal.
    should_check_age = (
        (resolve_dns and not result.is_free_email_provider)
        if check_age is None
        else check_age
    )
    if should_check_age:
        age = domain_age_days(sender_domain)
        if age is not None:
            result.domain_age_days = age
            if age < NEW_DOMAIN_THRESHOLD_DAYS:
                result.is_newly_registered = True
                result.is_impersonation = True
                notes.append(
                    f"Sender domain '{sender_domain}' was registered only "
                    f"{age} day(s) ago (< {NEW_DOMAIN_THRESHOLD_DAYS}) — "
                    "freshly created domains are a common scam signal."
                )

    if claimed:
        if result.is_free_email_provider:
            notes.append(
                f"Claims to represent '{claimed}' but emails from a free "
                f"webmail provider ('{sender_domain}')."
            )
            result.is_impersonation = True
        elif not result.domain_matches_company:
            notes.append(
                f"Sender domain '{sender_domain}' does not match claimed "
                f"company '{claimed}'."
            )
            result.is_impersonation = True
    elif result.is_free_email_provider:
        notes.append(
            "Recruiter outreach from a free webmail provider rather than a "
            "corporate domain."
        )

    result.notes = notes
    return result
