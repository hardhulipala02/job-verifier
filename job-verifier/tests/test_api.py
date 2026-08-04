from fastapi.testclient import TestClient

from api import app

client = TestClient(app)

SCAM = (
    "From: Anne <anne.hr@gmail.com>\n"
    "Subject: hire\n"
    "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
    "I'm Anne from Globex. Message me on Telegram at @GlobexHR right away. "
    "We will mail you a check for $2,000 to buy a MacBook."
)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "llm_enabled" in body
    assert "neo4j_enabled" in body


def test_analyze_endpoint():
    resp = client.post(
        "/analyze",
        json={
            "raw_email": SCAM,
            "persist": False,
            "use_llm": False,
            "resolve_dns": False,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"]["risk_level"] == "HIGH"
    assert "globexhr" in body["entities"]["telegram_handles"]


def test_analyze_empty_rejected():
    resp = client.post("/analyze", json={"raw_email": "   "})
    assert resp.status_code == 400


def test_analyze_upload(tmp_path):
    eml = tmp_path / "scam.eml"
    eml.write_text(SCAM)
    with open(eml, "rb") as fh:
        resp = client.post(
            "/analyze/upload?persist=false&use_llm=false&resolve_dns=false",
            files={"file": ("scam.eml", fh, "message/rfc822")},
        )
    assert resp.status_code == 200
    assert resp.json()["verdict"]["risk_level"] == "HIGH"
