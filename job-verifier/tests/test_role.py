import main_graph
import role_check
from schemas import ImpersonationCheck, RiskLevel


def test_extract_role_around_keyword():
    assert (
        role_check.extract_claimed_role(
            "We are excited about you for the Senior Data Analyst role."
        )
        == "Senior Data Analyst"
    )


def test_extract_role_hiring_phrase():
    assert (
        role_check.extract_claimed_role("We are hiring a Backend Engineer to join us.")
        == "Backend Engineer"
    )


def test_extract_role_none():
    assert role_check.extract_claimed_role("Hi, are you available to chat?") is None


def test_slug_candidates_strip_suffixes():
    cands = role_check._slug_candidates("Career Group Companies")
    assert "career" in cands


def test_title_matching():
    tokens = role_check._role_tokens("Senior Data Analyst")
    assert role_check._title_matches(tokens, "Data Analyst, Risk")
    assert not role_check._title_matches(tokens, "Warehouse Forklift Operator")


def test_analyze_role_disabled_does_not_hit_network(monkeypatch):
    def _boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("network must not be touched when disabled")

    monkeypatch.setattr(role_check, "fetch_company_postings", _boom)
    rc = role_check.analyze_role(
        "Hiring a Backend Engineer", company="Acme", enabled=False
    )
    assert rc.claimed_role == "Backend Engineer"
    assert rc.checked is False


def test_verify_role_found(monkeypatch):
    monkeypatch.setattr(
        role_check,
        "fetch_company_postings",
        lambda company, timeout: (
            [("Backend Engineer", "https://boards.greenhouse.io/acme/jobs/1")],
            True,
        ),
    )
    rc = role_check.analyze_role(
        "We are hiring a Backend Engineer", company="Acme", enabled=True
    )
    assert rc.checked is True
    assert rc.verified is True
    assert rc.sources


def test_verify_role_board_found_but_no_match(monkeypatch):
    monkeypatch.setattr(
        role_check,
        "fetch_company_postings",
        lambda company, timeout: ([("Sales Director", "u")], True),
    )
    rc = role_check.analyze_role(
        "We are hiring a Backend Engineer", company="Acme", enabled=True
    )
    assert rc.checked is True
    assert rc.verified is False
    assert "job board" in rc.summary.lower()


def test_verify_role_no_board(monkeypatch):
    monkeypatch.setattr(
        role_check, "fetch_company_postings", lambda company, timeout: ([], False)
    )
    rc = role_check.analyze_role(
        "We are hiring a Backend Engineer", company="Acme", enabled=True
    )
    assert rc.verified is False
    assert any("linkedin.com/jobs" in s for s in rc.sources)


def test_verify_role_no_company():
    rc = role_check.verify_role("Backend Engineer", None)
    assert rc.checked is True
    assert rc.verified is False
    assert rc.sources


def test_fetch_postings_network_failure_is_graceful(monkeypatch):
    def _raise(slug, timeout):
        raise RuntimeError("network down")

    monkeypatch.setattr(role_check, "_greenhouse_jobs", _raise)
    monkeypatch.setattr(role_check, "_lever_jobs", _raise)
    postings, found = role_check.fetch_company_postings("Acme", 1.0)
    assert postings == []
    assert found is False


def test_verify_role_lists_open_roles_with_match_flag(monkeypatch):
    monkeypatch.setattr(
        role_check,
        "fetch_company_postings",
        lambda company, timeout: (
            [
                ("Sales Director", "https://b/1"),
                ("Backend Engineer", "https://b/2"),
                ("Office Manager", "https://b/3"),
            ],
            True,
        ),
    )
    rc = role_check.analyze_role(
        "We are hiring a Backend Engineer", company="Acme", enabled=True
    )
    assert rc.verified is True
    assert rc.board_found is True
    titles = [o.title for o in rc.open_roles]
    assert {"Sales Director", "Backend Engineer", "Office Manager"} <= set(titles)
    # The matching role is flagged and surfaced first.
    assert rc.open_roles[0].title == "Backend Engineer"
    assert rc.open_roles[0].matches_claim is True


def test_no_live_roles_is_inconclusive_not_a_red_flag(monkeypatch):
    monkeypatch.setattr(
        role_check, "fetch_company_postings", lambda company, timeout: ([], True)
    )
    rc = role_check.analyze_role(
        "We are hiring a Backend Engineer", company="Acme", enabled=True
    )
    assert rc.board_found is True
    assert rc.open_roles == []
    assert "no live roles" in rc.summary.lower()
    assert "isn't inherently suspicious" in rc.summary.lower()


def test_no_board_is_inconclusive(monkeypatch):
    monkeypatch.setattr(
        role_check, "fetch_company_postings", lambda company, timeout: ([], False)
    )
    rc = role_check.analyze_role(
        "We are hiring a Backend Engineer", company="Acme", enabled=True
    )
    assert "inconclusive" in rc.summary.lower()


def test_free_webmail_sender_escalates_to_medium():
    verdict = main_graph.BehavioralVerdict(risk_level=RiskLevel.LOW)
    imp = ImpersonationCheck(is_free_email_provider=True)
    out = main_graph._apply_sender_trust(verdict, imp)
    assert out.risk_level == RiskLevel.MEDIUM
    assert any("free webmail" in f.lower() for f in out.flags_detected)
