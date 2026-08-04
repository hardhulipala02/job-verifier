"""Tests for typosquatting, domain age, defang, threat-intel, DNS, alignment."""
import asyncio

import config
import defang
import dns_intel
import main_graph
import registry
import threat_intel
from schemas import AuthStatus, DomainDNS, ImpersonationCheck, RiskLevel


# --- defang ----------------------------------------------------------------
def test_defang_url():
    assert (
        defang.defang_url("https://evil.example.com/login")
        == "hxxps[://]evil[.]example[.]com/login"
    )
    assert defang.defang_url("http://a.co").startswith("hxxp[://]")


def test_defang_domain():
    assert defang.defang_domain("bad.example.com") == "bad[.]example[.]com"


# --- Levenshtein + typosquatting ------------------------------------------
def test_levenshtein():
    assert registry.levenshtein("stripe", "str1pe") == 1
    assert registry.levenshtein("abc", "abc") == 0
    assert registry.levenshtein("", "abc") == 3


def test_detect_typosquatting_brand():
    target, dist = registry.detect_typosquatting("str1pe.com")
    assert target == "stripe.com"
    assert dist == 1


def test_detect_typosquatting_clean_domain():
    target, _ = registry.detect_typosquatting("totally-unrelated-name.com")
    assert target is None


# --- RDAP domain age -------------------------------------------------------
def test_domain_age_newly_registered(monkeypatch):
    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {
                "events": [
                    {"eventAction": "registration", "eventDate": "2026-06-01T00:00:00Z"}
                ]
            }

    monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResp())
    age = registry.domain_age_days("brand-new-scam.com")
    assert age is not None and age < registry.NEW_DOMAIN_THRESHOLD_DAYS


def test_check_impersonation_escalates_new_domain(monkeypatch):
    monkeypatch.setattr(registry, "domain_age_days", lambda d, timeout=4.0: 5)
    result = registry.check_impersonation(
        sender_domain="freshcorp.com",
        display_name="Jane",
        body_text="Hello from FreshCorp",
        resolve_dns=False,
        check_age=True,
    )
    assert result.is_newly_registered is True
    assert result.is_impersonation is True
    assert result.domain_age_days == 5


# --- Authentication-Results alignment -------------------------------------
def _eml(headers: str, body: str = "hello") -> str:
    return headers + "\n\n" + body


def test_alignment_pass():
    import parser

    raw = _eml(
        "From: HR <hr@acme.com>\n"
        "Subject: Hi\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=acme.com; "
        "dkim=pass header.d=acme.com; dmarc=pass header.from=acme.com"
    )
    sec = parser.extract_security_headers(parser.parse_email(raw))
    assert sec.aligned is True
    assert sec.gateway_failed is False


def test_alignment_broken_short_circuits():
    raw = _eml(
        "From: CEO <ceo@bank.com>\n"
        "Subject: urgent\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=evil.ru; "
        "dkim=pass header.d=evil.ru"
    )
    report = main_graph.analyze_email(raw, persist=False, resolve_dns=False)
    assert report.security.aligned is False
    assert report.security.gateway_failed is True
    assert report.verdict.risk_level == RiskLevel.HIGH
    assert any("misalign" in f.lower() for f in report.verdict.flags_detected)


# --- threat intel ----------------------------------------------------------
def test_scan_urls_no_key_defangs_only(monkeypatch):
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", None)
    monkeypatch.setattr(config, "URLSCAN_API_KEY", None)
    intel = asyncio.run(threat_intel.scan_urls(["https://x.com/a"]))
    assert intel.checked is False
    assert intel.urls[0].defanged == "hxxps[://]x[.]com/a"
    assert "skipped" in intel.summary.lower()


def test_scan_urls_flags_malicious(monkeypatch):
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "fake")

    async def _mal(client, url):
        return (True, "VirusTotal: 5 engine(s) flagged it")

    async def _none(client, url):
        return None

    monkeypatch.setattr(threat_intel, "_check_virustotal", _mal)
    monkeypatch.setattr(threat_intel, "_check_urlscan", _none)
    intel = asyncio.run(threat_intel.scan_urls(["https://bad.com"]))
    assert intel.any_malicious is True
    assert intel.urls[0].malicious is True


# --- async DNS -------------------------------------------------------------
def test_resolve_domains_dedup_and_aggregate(monkeypatch):
    async def fake_resolve(domain, timeout=4.0):
        return DomainDNS(domain=domain, a_records=["1.2.3.4"], ns_records=["ns1.x"])

    monkeypatch.setattr(dns_intel, "resolve_domain", fake_resolve)
    out = asyncio.run(dns_intel.resolve_domains(["A.com", "a.com", "b.com"]))
    assert {r.domain for r in out} == {"a.com", "b.com"}
    assert out[0].a_records == ["1.2.3.4"]


def test_resolve_domains_graceful(monkeypatch):
    async def boom(domain, timeout=4.0):
        raise RuntimeError("dns down")

    monkeypatch.setattr(dns_intel, "resolve_domain", boom)
    out = asyncio.run(dns_intel.resolve_domains(["a.com"]))
    assert out[0].domain == "a.com"
    assert out[0].a_records == []


# --- threat node escalates verdict ----------------------------------------
def test_threat_node_escalates(monkeypatch):
    from schemas import BehavioralVerdict, ExtractedEntities, ThreatIntel, URLVerdict

    async def fake_scan(urls, timeout=None):
        return ThreatIntel(
            checked=True,
            any_malicious=True,
            urls=[URLVerdict(url=urls[0], defanged="x", malicious=True)],
        )

    monkeypatch.setattr(threat_intel, "scan_urls", fake_scan)
    state = {
        "entities": ExtractedEntities(urls=["https://bad.com"]),
        "verdict": BehavioralVerdict(risk_level=RiskLevel.LOW),
    }
    out = asyncio.run(main_graph.threat_node(state))
    assert out["verdict"].risk_level == RiskLevel.HIGH


def test_auth_status_unchanged_for_plain_message():
    # A platform message has no headers; security stays MISSING/None-aligned.
    report = main_graph.analyze_message("hi there", persist=False)
    assert report.security.spf == AuthStatus.MISSING
    assert report.security.aligned is None
    assert isinstance(report.impersonation, ImpersonationCheck)
