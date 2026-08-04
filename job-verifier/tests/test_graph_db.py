import config
import graph_db
from schemas import (
    BehavioralVerdict,
    ExtractedEntities,
    ImpersonationCheck,
    RiskLevel,
    ScamReport,
)


def _report():
    return ScamReport(
        sender="anne@gmail.com",
        sender_domain="gmail.com",
        entities=ExtractedEntities(
            domains=["gmail.com"], telegram_handles=["globexhr"]
        ),
        impersonation=ImpersonationCheck(is_impersonation=True),
        verdict=BehavioralVerdict(risk_level=RiskLevel.HIGH, summary="bad"),
    )


def test_persist_noop_when_neo4j_disabled(monkeypatch):
    monkeypatch.setattr(config, "NEO4J_URI", None)
    monkeypatch.setattr(config, "NEO4J_USER", None)
    monkeypatch.setattr(config, "NEO4J_PASSWORD", None)
    assert graph_db.persist_report(_report()) is False


def test_persist_writes_when_configured(monkeypatch):
    monkeypatch.setattr(config, "NEO4J_URI", "bolt://localhost:7687")
    monkeypatch.setattr(config, "NEO4J_USER", "neo4j")
    monkeypatch.setattr(config, "NEO4J_PASSWORD", "pw")

    captured = {}

    class FakeAgent:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def add_report(self, report):
            captured["report"] = report

    monkeypatch.setattr(graph_db, "Neo4jAgent", lambda *a, **k: FakeAgent())
    assert graph_db.persist_report(_report()) is True
    assert captured["report"].verdict.risk_level == RiskLevel.HIGH
