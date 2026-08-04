"""Neo4j persistence for the scam-intelligence graph.

Each analyzed email becomes a ``Recruiter`` node linked to the entities it used
(Domain, PhoneNumber, TelegramHandle, WhatsApp number, URL). Because scam
syndicates reuse infrastructure, shared entities naturally connect separate
recruiter reports — letting you query coordinated networks later, e.g.::

    MATCH (r1:Recruiter)-[:USES_TELEGRAM]->(t)<-[:USES_TELEGRAM]-(r2:Recruiter)
    RETURN r1, t, r2

Connecting is optional: when Neo4j credentials are absent, :func:`persist_report`
is a graceful no-op so the rest of the pipeline keeps working.
"""
from __future__ import annotations

import logging

import config
from schemas import ScamReport

logger = logging.getLogger(__name__)

_WRITE_QUERY = """
MERGE (r:Recruiter {address: $sender})
SET r.risk = $risk,
    r.summary = $summary,
    r.last_seen = datetime(),
    r.impersonation = $impersonation,
    r.analysis_id = $analysis_id,
    r.subject = $subject
WITH r
// Record each analyzed message as its own node so a recruiter seen multiple
// times keeps a traceable history, each tagged with the report id shown to the
// user.
FOREACH (_ IN CASE WHEN $analysis_id IS NULL THEN [] ELSE [1] END |
    MERGE (a:Analysis {analysis_id: $analysis_id})
    SET a.subject = $subject,
        a.risk = $risk,
        a.from_address = $sender,
        a.analyzed_at = datetime()
    MERGE (r)-[:ANALYZED_AS]->(a)
)
WITH r
FOREACH (dom IN $domains |
    MERGE (d:Domain {name: dom})
    MERGE (r)-[:USES_DOMAIN]->(d)
)
FOREACH (ph IN $phones |
    MERGE (p:PhoneNumber {number: ph})
    MERGE (r)-[:USES_PHONE]->(p)
)
FOREACH (tg IN $telegram |
    MERGE (t:TelegramHandle {handle: tg})
    MERGE (r)-[:USES_TELEGRAM]->(t)
)
FOREACH (wa IN $whatsapp |
    MERGE (w:WhatsAppNumber {number: wa})
    MERGE (r)-[:USES_WHATSAPP]->(w)
)
FOREACH (u IN $urls |
    MERGE (link:Url {value: u})
    MERGE (r)-[:LINKS_TO]->(link)
)
WITH r
// Infrastructure mapping: link sending domains to the IPs and nameservers they
// resolve to, so distinct recruiters that share infrastructure connect up.
FOREACH (rec IN $dns |
    MERGE (d:Domain {name: rec.domain})
    MERGE (r)-[:USES_DOMAIN]->(d)
    FOREACH (ip IN rec.a_records |
        MERGE (a:IPAddress {address: ip})
        MERGE (d)-[:RESOLVES_TO]->(a)
    )
    FOREACH (ns IN rec.ns_records |
        MERGE (n:NameServer {host: ns})
        MERGE (d)-[:USES_NAMESERVER]->(n)
    )
)
"""


class Neo4jAgent:
    """Thin wrapper around the Neo4j driver for writing scam reports."""

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ):
        from neo4j import GraphDatabase  # lazy import; optional dependency at runtime

        self.driver = GraphDatabase.driver(
            uri or config.NEO4J_URI,
            auth=(user or config.NEO4J_USER, password or config.NEO4J_PASSWORD),
        )

    def close(self) -> None:
        self.driver.close()

    def __enter__(self) -> "Neo4jAgent":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def add_report(self, report: ScamReport) -> None:
        params = {
            "sender": report.sender or "unknown",
            "risk": report.verdict.risk_level.value,
            "summary": report.verdict.summary,
            "impersonation": report.impersonation.is_impersonation,
            "analysis_id": report.source.analysis_id if report.source else None,
            "subject": report.source.subject if report.source else None,
            "domains": report.entities.domains,
            "phones": report.entities.phone_numbers,
            "telegram": report.entities.telegram_handles,
            "whatsapp": report.entities.whatsapp_numbers,
            "urls": report.entities.urls,
            "dns": [
                {
                    "domain": rec.domain,
                    "a_records": rec.a_records,
                    "ns_records": rec.ns_records,
                }
                for rec in report.dns
            ],
        }
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(_WRITE_QUERY, **params))
        logger.info("Persisted scam report for %s to Neo4j", report.sender)


def persist_report(report: ScamReport) -> bool:
    """Persist a report if Neo4j is configured; otherwise no-op.

    Returns ``True`` when the report was written, ``False`` otherwise.
    """
    if not config.neo4j_enabled():
        logger.info("Neo4j not configured; skipping persistence.")
        return False
    try:
        with Neo4jAgent() as agent:
            agent.add_report(report)
        return True
    except Exception as exc:  # noqa: BLE001 - persistence must not crash pipeline
        logger.error("Failed to persist report to Neo4j: %s", exc)
        return False


if __name__ == "__main__":
    from schemas import (
        BehavioralVerdict,
        ExtractedEntities,
        ImpersonationCheck,
        RiskLevel,
    )

    logging.basicConfig(level=logging.INFO)
    demo = ScamReport(
        sender="anne@scam-example.com",
        sender_domain="scam-example.com",
        entities=ExtractedEntities(
            domains=["scam-example.com"],
            telegram_handles=["scotthr"],
        ),
        impersonation=ImpersonationCheck(is_impersonation=True),
        verdict=BehavioralVerdict(
            risk_level=RiskLevel.HIGH, summary="Detected Telegram trap"
        ),
    )
    print("persisted:", persist_report(demo))
