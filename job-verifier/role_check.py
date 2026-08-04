"""Best-effort verification that an advertised role actually exists.

Scammers frequently dangle a vague or fabricated job ("remote data-entry, $40/hr,
no interview") that does not map to any real opening. This module:

  1. Extracts the *claimed* role/title from the message text (cheap, offline), and
  2. Optionally checks whether that role plausibly exists at the claimed company.

Verification queries public Applicant Tracking System (ATS) job-board APIs
(Greenhouse and Lever) which expose every open posting as JSON with no API key.
This is far more reliable than scraping a search engine. Coverage is partial
(many large companies use other systems), so a "not found" result is treated as
*inconclusive*, not proof of a scam: the report then points the user to a direct
careers/LinkedIn search to confirm for themselves.

Verification is disabled by default and only runs when
:func:`config.role_check_enabled` is true, so tests/CI stay offline.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import quote_plus

import config
from schemas import OpenRole, RoleCheck

# How many of a company's live openings to surface in the report.
_MAX_OPEN_ROLES = 10

logger = logging.getLogger(__name__)

# Words that commonly end a job title; used to bound title extraction.
_TITLE_KEYWORDS = (
    "engineer", "developer", "manager", "analyst", "designer", "scientist",
    "specialist", "coordinator", "assistant", "representative", "consultant",
    "intern", "associate", "director", "lead", "administrator", "recruiter",
    "accountant", "nurse", "technician", "architect", "strategist", "officer",
    "agent", "clerk", "operator", "supervisor", "executive", "writer",
    "marketer", "bookkeeper", "cashier", "receptionist", "tester",
)
_TITLE_WORD = (
    r"(?:[A-Z][A-Za-z+/.]+|of|the|and|&|Sr\.?|Jr\.?|I{1,3}|Senior|Junior|"
    r"Lead|Staff|Principal|Remote|Entry[- ]?Level)"
)
# "for the Senior Data Analyst role/position/opening/opportunity/job"
_ROLE_AROUND = re.compile(
    rf"\b(?:for|the|a|an|our|this)\s+((?:{_TITLE_WORD}\s+){{0,5}}{_TITLE_WORD})\s+"
    r"(?:role|position|opening|opportunity|vacancy|job)\b",
    re.IGNORECASE,
)
# "position/role/opening: Senior Data Analyst"  or  "hiring a Data Entry Clerk"
_ROLE_LABELLED = re.compile(
    rf"\b(?:role|position|title|opening|job)\s*[:\-]\s*"
    rf"((?:{_TITLE_WORD}\s*){{1,6}})",
)
_ROLE_HIRING = re.compile(
    rf"\b(?:hiring|seeking|recruiting|looking for)\s+(?:a|an|our)?\s*"
    rf"((?:{_TITLE_WORD}\s+){{0,5}}(?:{'|'.join(_TITLE_KEYWORDS)}))\b",
    re.IGNORECASE,
)

_STOPWORDS = {"of", "the", "and", "a", "an", "for", "to", "remote", "senior",
              "junior", "lead", "staff", "principal", "entry", "level"}


def _clean_title(raw: str) -> str | None:
    title = re.sub(r"\s+", " ", raw or "").strip(" .,-:")
    title = re.sub(r"^(?:the|a|an|our|this|of)\s+", "", title, flags=re.IGNORECASE)
    if len(title) < 3 or len(title.split()) > 6:
        return None
    return title


def extract_claimed_role(text: str) -> str | None:
    """Pull the advertised job title out of the message, best-effort."""
    blob = text or ""
    for pattern in (_ROLE_AROUND, _ROLE_LABELLED, _ROLE_HIRING):
        match = pattern.search(blob)
        if match:
            title = _clean_title(match.group(1))
            if title:
                return title
    return None


def _role_tokens(role: str) -> list[str]:
    return [
        t for t in re.findall(r"[a-z0-9]+", role.lower())
        if len(t) > 2 and t not in _STOPWORDS
    ]


def _slug_candidates(company: str) -> list[str]:
    """Derive plausible ATS board slugs from a company name."""
    words = re.findall(r"[a-z0-9]+", company.lower())
    drop = {"inc", "llc", "ltd", "limited", "corp", "corporation", "co",
            "company", "companies", "group", "holdings", "the"}
    core = [w for w in words if w not in drop] or words
    candidates = ["".join(core)]
    if len(core) > 1:
        candidates.append("".join(core[:2]))
    # A single generic first token (e.g. "career") risks matching an unrelated
    # board, so only use the lone first word when it's the whole core name.
    if len(core) == 1:
        candidates.append(core[0])
    seen: list[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.append(c)
    return seen


def _greenhouse_jobs(slug: str, timeout: float) -> list[tuple[str, str]] | None:
    """Return [(title, url)] for a Greenhouse board, or None if it doesn't exist."""
    import httpx

    url = f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs"
    resp = httpx.get(url, timeout=timeout, headers={"User-Agent": "JobScamChecker"})
    if resp.status_code != 200:
        return None
    jobs = resp.json().get("jobs", [])
    return [(j.get("title", ""), j.get("absolute_url", "")) for j in jobs]


def _lever_jobs(slug: str, timeout: float) -> list[tuple[str, str]] | None:
    """Return [(title, url)] for a Lever board, or None if it doesn't exist."""
    import httpx

    url = f"https://api.lever.co/v0/postings/{slug}?mode=json"
    resp = httpx.get(url, timeout=timeout, headers={"User-Agent": "JobScamChecker"})
    if resp.status_code != 200:
        return None
    data = resp.json()
    if not isinstance(data, list):
        return None
    return [(p.get("text", ""), p.get("hostedUrl", "")) for p in data]


def fetch_company_postings(
    company: str, timeout: float
) -> tuple[list[tuple[str, str]], bool]:
    """Look up a company's open postings across known ATS boards.

    Returns ``(postings, board_found)``. ``board_found`` is True if any ATS board
    existed for the company (even with zero matching titles).
    """
    board_found = False
    postings: list[tuple[str, str]] = []
    for slug in _slug_candidates(company):
        for fetch in (_greenhouse_jobs, _lever_jobs):
            try:
                jobs = fetch(slug, timeout)
            except Exception as exc:  # noqa: BLE001 - never crash the pipeline
                logger.warning("ATS lookup failed (%s/%s): %s", fetch.__name__, slug, exc)
                continue
            if jobs is not None:
                board_found = True
                postings.extend(jobs)
        if board_found:
            break
    return postings, board_found


def _title_matches(role_tokens: list[str], title: str) -> bool:
    low = title.lower()
    present = [t for t in role_tokens if t in low]
    if not role_tokens:
        return False
    if len(role_tokens) == 1:
        return bool(present)
    # Require the head noun plus at least one more token, or full overlap.
    head = role_tokens[-1]
    return (head in low and len(present) >= 2) or len(present) == len(role_tokens)


def _linkedin_search_url(role: str, company: str | None) -> str:
    terms = role + (f" {company}" if company else "")
    return f"https://www.linkedin.com/jobs/search/?keywords={quote_plus(terms)}"


def verify_role(
    role: str, company: str | None, *, timeout: float | None = None
) -> RoleCheck:
    """Check whether the advertised role plausibly exists at the company."""
    timeout = config.ROLE_CHECK_TIMEOUT if timeout is None else timeout
    result = RoleCheck(claimed_role=role, claimed_company=company, checked=True)
    tokens = _role_tokens(role)

    if not company:
        result.summary = (
            "No company was named, so the role could not be verified against a "
            "specific employer. Search for it directly:"
        )
        result.sources = [_linkedin_search_url(role, None)]
        return result

    postings, board_found = fetch_company_postings(company, timeout)
    result.board_found = board_found
    match_titles = {t for (t, _) in postings if _title_matches(tokens, t)}

    # Surface the company's actual live openings, matches first, so the user can
    # see what really is being hired for -- not just a yes/no.
    ordered = sorted(
        postings, key=lambda p: p[0] not in match_titles
    )
    seen: set[str] = set()
    for title, url in ordered:
        if not title or title in seen:
            continue
        seen.add(title)
        result.open_roles.append(
            OpenRole(title=title, url=url, matches_claim=title in match_titles)
        )
        if len(result.open_roles) >= _MAX_OPEN_ROLES:
            break

    if match_titles:
        result.verified = True
        result.summary = (
            f"Confirmed: '{role}' matches an open posting on {company}'s "
            f"official job board ({len(postings)} live roles listed)."
        )
        result.sources = [
            u for (t, u) in postings if t in match_titles and u
        ][:3]
        return result

    if board_found and postings:
        result.summary = (
            f"{company} has {len(postings)} live role(s) on its official job "
            f"board, but none clearly match '{role}'. That isn't necessarily a "
            "scam -- the title may differ -- but do more research before "
            "engaging."
        )
    elif board_found:
        result.summary = (
            f"{company}'s official job board shows no live roles right now. "
            "A company with no current openings isn't inherently suspicious, "
            "but an unsolicited offer warrants more research."
        )
    else:
        result.summary = (
            f"Could not find an official job board for {company} to map open "
            f"roles. This is inconclusive, not a red flag -- verify directly:"
        )
    result.sources = [_linkedin_search_url(role, company)]
    return result


def analyze_role(
    text: str, company: str | None = None, *, enabled: bool | None = None
) -> RoleCheck:
    """Extract the claimed role and optionally verify it against ATS boards."""
    role = extract_claimed_role(text)
    if not role:
        return RoleCheck(claimed_company=company, summary="No specific role named.")

    should_verify = config.role_check_enabled() if enabled is None else enabled
    if not should_verify:
        return RoleCheck(
            claimed_role=role,
            claimed_company=company,
            summary="Role named but not web-verified (verification disabled).",
        )
    return verify_role(role, company)
