import registry


def test_free_provider_with_claimed_company_is_impersonation():
    result = registry.check_impersonation(
        sender_domain="gmail.com",
        display_name="Anne",
        body_text="I'm Anne from Globex Corporation. We loved your resume.",
        resolve_dns=False,
    )
    assert result.claimed_company is not None
    assert result.is_free_email_provider is True
    assert result.is_impersonation is True


def test_matching_corporate_domain_not_impersonation():
    result = registry.check_impersonation(
        sender_domain="stripe.com",
        display_name="Jordan Lee",
        body_text="I'm Jordan from Stripe and would like to schedule a call.",
        resolve_dns=False,
    )
    assert result.domain_matches_company is True
    assert result.is_impersonation is False


def test_mismatched_corporate_domain_is_impersonation():
    result = registry.check_impersonation(
        sender_domain="totally-unrelated.xyz",
        display_name="Jordan",
        body_text="I'm Jordan from Stripe.",
        resolve_dns=False,
    )
    assert result.is_impersonation is True


def test_domain_matches_company_helper():
    assert registry.domain_matches_company("careers.stripe.com", "Stripe") is True
    assert registry.domain_matches_company("globex.io", "Globex Corp") is True
    assert registry.domain_matches_company("evil.xyz", "Stripe") is False


def test_registrable_domain():
    assert registry.registrable_domain("careers.stripe.com") == "stripe.com"
    assert registry.registrable_domain("foo.bar.co.uk") == "bar.co.uk"
