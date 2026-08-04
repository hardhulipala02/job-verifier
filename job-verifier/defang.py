"""Defang URLs and domains so they are inert in reports and replies.

Defanging rewrites a live link into a non-clickable, non-resolving form, e.g.::

    https://evil.example.com/login  ->  hxxps[://]evil[.]example[.]com/login

This is standard practice in security tooling so an analyst (or an email client)
never accidentally navigates to a hostile URL embedded in a report.
"""
from __future__ import annotations

import re

_HTTPS_RE = re.compile(r"https://", re.IGNORECASE)
_HTTP_RE = re.compile(r"http://", re.IGNORECASE)
_DOT_RE = re.compile(r"\.")


def defang_url(url: str) -> str:
    """Return a non-clickable, non-resolving version of ``url``."""
    if not url:
        return url
    out = _HTTPS_RE.sub("hxxps[://]", url)
    out = _HTTP_RE.sub("hxxp[://]", out)
    return _DOT_RE.sub("[.]", out)


def defang_domain(domain: str) -> str:
    """Return a non-resolving version of a bare domain/host."""
    if not domain:
        return domain
    return _DOT_RE.sub("[.]", domain)
