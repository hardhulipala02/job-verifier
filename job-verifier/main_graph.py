"""LangGraph orchestration of the Job Scam Intelligence Network.

Stateful multi-agent flow::

    parse ──► [auth gate] ──spoofed──► persist
                  │
                  └──authenticated──► registry ──► behavior(LLM) ──► persist

The auth gate enforces the "validate SPF/DKIM/DMARC *before* expensive AI"
requirement: a hard authentication failure short-circuits straight to a HIGH
verdict without ever paying for an LLM call.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TypedDict

from langgraph.graph import END, StateGraph

import config
import dns_intel
import graph_db
import llm_agent
import parser
import registry
import role_check
import threat_intel
from schemas import (
    BehavioralVerdict,
    DomainDNS,
    EmailReference,
    ExtractedEntities,
    ImpersonationCheck,
    RiskLevel,
    RoleCheck,
    ScamReport,
    SecurityHeaders,
    ThreatIntel,
)

logger = logging.getLogger(__name__)


class AgentState(TypedDict, total=False):
    # inputs
    email_source: str | bytes
    use_llm: bool | None
    persist: bool
    resolve_dns: bool
    verify_role: bool | None
    # working fields
    reference: EmailReference | None
    sender: str | None
    sender_domain: str | None
    display_name: str | None
    email_text: str
    security: SecurityHeaders
    entities: ExtractedEntities
    impersonation: ImpersonationCheck
    role: RoleCheck
    threat_intel: ThreatIntel
    dns: list[DomainDNS]
    verdict: BehavioralVerdict
    persisted: bool


def parser_node(state: AgentState) -> AgentState:
    logger.info("NODE: parser")
    msg = parser.parse_email(state["email_source"])
    body = parser.extract_body_text(msg)
    return {
        "reference": parser.build_reference(msg),
        "sender": parser.get_sender_address(msg),
        "sender_domain": parser.get_sender_domain(msg),
        "display_name": _display_name(msg),
        "email_text": body,
        "security": parser.extract_security_headers(msg),
        "entities": parser.extract_entities(msg, body),
    }


def _display_name(msg) -> str | None:
    from email.utils import parseaddr

    name, _ = parseaddr(msg.get("From", "") or "")
    return name or None


def registry_node(state: AgentState) -> AgentState:
    logger.info("NODE: registry / impersonation")
    impersonation = registry.check_impersonation(
        sender_domain=state.get("sender_domain"),
        display_name=state.get("display_name"),
        body_text=state.get("email_text", ""),
        entities=state.get("entities"),
        resolve_dns=state.get("resolve_dns", True),
    )
    return {"impersonation": impersonation}


def behavior_node(state: AgentState) -> AgentState:
    logger.info("NODE: behavioral analysis")
    verdict = llm_agent.evaluate_email_behavior(
        state.get("email_text", ""), use_llm=state.get("use_llm")
    )
    verdict = _apply_sender_trust(verdict, state.get("impersonation"))
    return {"verdict": verdict}


def role_node(state: AgentState) -> AgentState:
    logger.info("NODE: role verification")
    impersonation = state.get("impersonation")
    company = impersonation.claimed_company if impersonation else None
    role = role_check.analyze_role(
        state.get("email_text", ""),
        company=company,
        enabled=state.get("verify_role"),
    )
    return {"role": role}


async def threat_node(state: AgentState) -> AgentState:
    """Async URL reputation node: defang every link and (with keys) check it."""
    logger.info("NODE: URL threat intelligence")
    entities = state.get("entities")
    urls = list(entities.urls) if entities else []
    intel = await threat_intel.scan_urls(urls)
    verdict = state.get("verdict")
    if intel.any_malicious and verdict is not None:
        verdict.flags_detected = list(
            dict.fromkeys(
                [*verdict.flags_detected, "Known-malicious link (quarantined)"]
            )
        )
        verdict.risk_level = RiskLevel.HIGH
        return {"threat_intel": intel, "verdict": verdict}
    return {"threat_intel": intel}


async def dns_node(state: AgentState) -> AgentState:
    """Async DNS node: resolve A/NS records to map shared infrastructure."""
    logger.info("NODE: DNS infrastructure mapping")
    if not config.dns_resolve_enabled():
        return {"dns": []}
    entities = state.get("entities")
    domains = [d for d in [state.get("sender_domain")] if d]
    if entities:
        domains += entities.domains
    records = await dns_intel.resolve_domains(domains, config.DNS_TIMEOUT)
    return {"dns": records}


def _apply_sender_trust(
    verdict: BehavioralVerdict, impersonation: ImpersonationCheck | None
) -> BehavioralVerdict:
    """Escalate risk based on who the sender appears to be.

    * Outright impersonation -> HIGH.
    * Recruiter using a free webmail address (gmail/yahoo/outlook) instead of a
      corporate domain -> at least MEDIUM, since legitimate companies recruit
      from their own domain.
    """
    if not impersonation:
        return verdict
    if impersonation.is_impersonation:
        verdict.flags_detected = list(
            dict.fromkeys([*verdict.flags_detected, "Corporate impersonation"])
        )
        verdict.risk_level = RiskLevel.HIGH
    elif impersonation.is_free_email_provider:
        verdict.flags_detected = list(
            dict.fromkeys(
                [
                    *verdict.flags_detected,
                    "Recruiter using a free webmail address, not a company domain",
                ]
            )
        )
        verdict.risk_level = llm_agent._max_risk(
            verdict.risk_level, RiskLevel.MEDIUM
        )
    return verdict


def spoofed_node(state: AgentState) -> AgentState:
    logger.info("NODE: spoof short-circuit (skipping LLM)")
    security = state["security"]
    failed = [
        name
        for name, status in (
            ("DMARC", security.dmarc),
            ("SPF", security.spf),
            ("DKIM", security.dkim),
        )
        if status.value == "fail"
    ]
    if failed:
        flag = f"Authentication failure: {', '.join(failed)}"
        summary = (
            "Sender domain is spoofed (" + ", ".join(failed) + " failed); "
            "no AI analysis needed."
        )
    else:
        # No hard fail, but the authenticated domains don't match the From domain.
        authed = ", ".join(security.authenticated_domains) or "another domain"
        flag = "Authentication misaligned (From domain not authenticated)"
        summary = (
            f"Gateway validation failed: mail authenticated as '{authed}' but "
            f"claims to be from '{security.from_domain}'. Likely spoofed."
        )
    verdict = BehavioralVerdict(
        risk_level=RiskLevel.HIGH,
        flags_detected=[flag],
        summary=summary,
    )
    return {
        "verdict": verdict,
        "impersonation": ImpersonationCheck(
            sender_domain=state.get("sender_domain"),
            is_impersonation=True,
            notes=["Email failed cryptographic authentication."],
        ),
    }


def persist_node(state: AgentState) -> AgentState:
    logger.info("NODE: persist")
    report = _build_report(state)
    persisted = False
    if state.get("persist", True):
        persisted = graph_db.persist_report(report)
    return {"persisted": persisted}


def route_security(state: AgentState) -> str:
    logger.info("ROUTING: auth gate")
    if state["security"].gateway_failed:
        return "spoofed"
    return "authenticated"


def _build_report(state: AgentState) -> ScamReport:
    return ScamReport(
        source=state.get("reference"),
        sender=state.get("sender"),
        sender_domain=state.get("sender_domain"),
        security=state.get("security", SecurityHeaders()),
        entities=state.get("entities", ExtractedEntities()),
        impersonation=state.get("impersonation", ImpersonationCheck()),
        role=state.get("role", RoleCheck()),
        threat_intel=state.get("threat_intel", ThreatIntel()),
        dns=state.get("dns", []),
        verdict=state.get("verdict", BehavioralVerdict()),
        persisted=state.get("persisted", False),
    )


def build_app():
    """Compile and return the LangGraph application."""
    workflow = StateGraph(AgentState)

    workflow.add_node("parser", parser_node)
    workflow.add_node("registry", registry_node)
    workflow.add_node("behavior", behavior_node)
    workflow.add_node("role", role_node)
    workflow.add_node("threat", threat_node)
    workflow.add_node("dns", dns_node)
    workflow.add_node("spoofed", spoofed_node)
    workflow.add_node("persist", persist_node)

    workflow.set_entry_point("parser")
    workflow.add_conditional_edges(
        "parser",
        route_security,
        {"spoofed": "spoofed", "authenticated": "registry"},
    )
    workflow.add_edge("registry", "behavior")
    workflow.add_edge("behavior", "role")
    workflow.add_edge("role", "threat")
    workflow.add_edge("threat", "dns")
    workflow.add_edge("dns", "persist")
    workflow.add_edge("spoofed", "persist")
    workflow.add_edge("persist", END)

    return workflow.compile()


app = build_app()


def analyze_email(
    email_source: str | bytes,
    *,
    use_llm: bool | None = None,
    persist: bool = True,
    resolve_dns: bool = True,
    verify_role: bool | None = None,
) -> ScamReport:
    """Run the full pipeline on an email and return a structured report."""
    final_state = asyncio.run(
        app.ainvoke(
            {
                "email_source": email_source,
                "use_llm": use_llm,
                "persist": persist,
                "resolve_dns": resolve_dns,
                "verify_role": verify_role,
            }
        )
    )
    return _build_report(final_state)


def analyze_message(
    text: str,
    *,
    sender_name: str | None = None,
    platform: str | None = None,
    use_llm: bool | None = None,
    persist: bool = True,
    verify_role: bool | None = None,
) -> ScamReport:
    """Analyze a platform message (LinkedIn DM, etc.) that has no email headers.

    SPF/DKIM/DMARC do not apply here, so this path focuses on scam-language
    patterns, extracted entities, and impersonation cues from the text itself.
    """
    logger.info("Analyzing %s message", platform or "platform")
    entities = parser.extract_entities_from_text(text)
    digest = hashlib.sha1(
        (text or "").encode("utf-8", "replace")
    ).hexdigest()[:10].upper()
    reference = EmailReference(
        analysis_id=f"JSC-{digest}",
        from_address=sender_name,
        subject=f"{platform or 'platform'} message",
    )

    # No verified sending domain on a platform message; use the first linked
    # domain (if any) as a weak signal for impersonation checks.
    candidate_domain = entities.domains[0] if entities.domains else None
    impersonation = registry.check_impersonation(
        sender_domain=candidate_domain,
        display_name=sender_name,
        body_text=text,
        entities=entities,
        resolve_dns=False,
    )

    verdict = llm_agent.evaluate_email_behavior(text, use_llm=use_llm)
    verdict = _apply_sender_trust(verdict, impersonation)
    role = role_check.analyze_role(
        text, company=impersonation.claimed_company, enabled=verify_role
    )

    intel = asyncio.run(threat_intel.scan_urls(entities.urls))
    if intel.any_malicious:
        verdict.flags_detected = list(
            dict.fromkeys(
                [*verdict.flags_detected, "Known-malicious link (quarantined)"]
            )
        )
        verdict.risk_level = RiskLevel.HIGH

    dns_records: list[DomainDNS] = []
    if config.dns_resolve_enabled():
        dns_records = asyncio.run(
            dns_intel.resolve_domains(entities.domains, config.DNS_TIMEOUT)
        )

    report = ScamReport(
        source=reference,
        sender=sender_name,
        sender_domain=candidate_domain,
        security=SecurityHeaders(),  # N/A for platform messages
        entities=entities,
        impersonation=impersonation,
        role=role,
        threat_intel=intel,
        dns=dns_records,
        verdict=verdict,
    )
    if persist:
        report.persisted = graph_db.persist_report(report)
    return report


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_emails/telegram_scam.eml"
    print(f"\nAnalyzing {path} ...\n")
    report = analyze_email(path, persist=False, resolve_dns=False)
    print(report.model_dump_json(indent=2))
