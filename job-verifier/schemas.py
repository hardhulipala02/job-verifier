"""Strict Pydantic schemas shared across the pipeline.

These models enforce type-safe contracts for:
  * the LLM behavioral verdict (so downstream DB writes never see junk),
  * the security/auth header summary,
  * the extracted entities (domains, phones, chat handles), and
  * the final aggregated report returned by the API and graph layer.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    MISSING = "missing"
    NEUTRAL = "neutral"
    SOFTFAIL = "softfail"
    NONE = "none"


class SecurityHeaders(BaseModel):
    """Deterministic SPF/DKIM/DMARC results parsed from the raw email."""

    dmarc: AuthStatus = AuthStatus.MISSING
    spf: AuthStatus = AuthStatus.MISSING
    dkim: AuthStatus = AuthStatus.MISSING
    # Identifier alignment: do the authenticated domains match the From domain?
    from_domain: str | None = None
    authenticated_domains: list[str] = Field(default_factory=list)
    # True/False when determinable; None when there is nothing to align.
    aligned: bool | None = None

    @property
    def spoof_detected(self) -> bool:
        """A hard authentication failure means the sender domain is spoofed."""
        return AuthStatus.FAIL in (self.dmarc, self.spf, self.dkim)

    @property
    def gateway_failed(self) -> bool:
        """Gateway validation failed: hard auth failure or broken alignment."""
        return self.spoof_detected or self.aligned is False


class ExtractedEntities(BaseModel):
    """Entities pulled out of the email for graphing scam syndicates."""

    domains: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    telegram_handles: list[str] = Field(default_factory=list)
    whatsapp_numbers: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class ImpersonationCheck(BaseModel):
    """Result of cross-referencing the sender against corporate registries."""

    claimed_company: str | None = None
    sender_domain: str | None = None
    domain_resolves: bool = False
    domain_matches_company: bool = False
    is_free_email_provider: bool = False
    is_impersonation: bool = False
    # Typosquatting: a near-miss of a legitimate brand domain.
    typosquatting_target: str | None = None
    typosquatting_distance: int | None = None
    # WHOIS / RDAP domain age.
    domain_age_days: int | None = None
    is_newly_registered: bool = False
    notes: list[str] = Field(default_factory=list)


class URLVerdict(BaseModel):
    """Reputation result for a single URL from threat-intel providers."""

    url: str
    defanged: str
    malicious: bool = False
    sources: list[str] = Field(default_factory=list)
    detail: str = ""


class ThreatIntel(BaseModel):
    """Aggregated URL reputation across VirusTotal / URLScan."""

    checked: bool = False
    any_malicious: bool = False
    urls: list[URLVerdict] = Field(default_factory=list)
    summary: str = ""


class DomainDNS(BaseModel):
    """Resolved DNS records for a domain (infrastructure mapping)."""

    domain: str
    a_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)


class OpenRole(BaseModel):
    """A single live posting found on a company's official job board."""

    title: str
    url: str = ""
    matches_claim: bool = False


class RoleCheck(BaseModel):
    """Best-effort verification that the advertised role actually exists."""

    claimed_role: str | None = None
    claimed_company: str | None = None
    checked: bool = False
    verified: bool = False
    # Whether an official ATS board was located for the company at all.
    board_found: bool = False
    # The company's actual live openings (capped), with the ones matching the
    # claimed role flagged. Empty list with board_found=True means the board
    # exists but currently lists no roles -- inconclusive, not a red flag.
    open_roles: list[OpenRole] = Field(default_factory=list)
    summary: str = ""
    sources: list[str] = Field(default_factory=list)


class BehavioralVerdict(BaseModel):
    """Strict schema the LLM (and the deterministic fallback) must conform to."""

    risk_level: RiskLevel = RiskLevel.LOW
    flags_detected: list[str] = Field(default_factory=list)
    summary: str = ""


class EmailReference(BaseModel):
    """Identifies the original message a report was generated from.

    Gives every report a stable, human-readable handle so a user can tell which
    forwarded email a verdict maps to, and so it can be cross-referenced with the
    Recruiter node persisted in Neo4j.
    """

    analysis_id: str
    subject: str | None = None
    from_address: str | None = None
    date: str | None = None
    message_id: str | None = None


class ScamReport(BaseModel):
    """Final aggregated report returned to callers and persisted to Neo4j."""

    source: EmailReference | None = None
    sender: str | None = None
    sender_domain: str | None = None
    security: SecurityHeaders = Field(default_factory=SecurityHeaders)
    entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    impersonation: ImpersonationCheck = Field(default_factory=ImpersonationCheck)
    role: RoleCheck = Field(default_factory=RoleCheck)
    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    dns: list[DomainDNS] = Field(default_factory=list)
    verdict: BehavioralVerdict = Field(default_factory=BehavioralVerdict)
    persisted: bool = False
