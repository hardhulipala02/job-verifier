"""Asynchronous URL reputation lookups (VirusTotal + URLScan).

For every URL found in a message this module:

  * defangs it (so it is inert in any report), and
  * if API keys are configured, queries VirusTotal and URLScan for an existing
    reputation verdict and flags known-malicious links for "quarantine".

The whole node is graceful: with no keys it still returns defanged URLs and a
"reputation check skipped" note, so the pipeline never depends on these APIs.
"""
from __future__ import annotations

import asyncio
import base64
import logging

import config
from defang import defang_url
from schemas import ThreatIntel, URLVerdict

logger = logging.getLogger(__name__)

_VT_URL = "https://www.virustotal.com/api/v3/urls/{vid}"
_URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"


def _vt_url_id(url: str) -> str:
    """VirusTotal addresses a URL by its unpadded base64url id."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def _check_virustotal(client, url: str) -> tuple[bool, str] | None:
    if not config.VIRUSTOTAL_API_KEY:
        return None
    try:
        resp = await client.get(
            _VT_URL.format(vid=_vt_url_id(url)),
            headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
        )
        if resp.status_code == 404:
            return (False, "VirusTotal: no record")
        resp.raise_for_status()
        stats = (
            resp.json().get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
        )
        malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        if malicious:
            return (True, f"VirusTotal: {malicious} engine(s) flagged it")
        return (False, "VirusTotal: clean")
    except Exception as exc:  # noqa: BLE001 - never crash the pipeline
        logger.warning("VirusTotal lookup failed: %s", exc)
        return None


async def _check_urlscan(client, url: str) -> tuple[bool, str] | None:
    if not config.URLSCAN_API_KEY:
        return None
    try:
        resp = await client.get(
            _URLSCAN_SEARCH,
            params={"q": f'page.url:"{url}"'},
            headers={"API-Key": config.URLSCAN_API_KEY},
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
        for r in results:
            verdict = r.get("verdicts", {}).get("overall", {})
            if verdict.get("malicious"):
                return (True, "URLScan: flagged malicious")
        return (False, "URLScan: no malicious verdict")
    except Exception as exc:  # noqa: BLE001 - never crash the pipeline
        logger.warning("URLScan lookup failed: %s", exc)
        return None


async def _scan_one(client, url: str) -> URLVerdict:
    verdict = URLVerdict(url=url, defanged=defang_url(url))
    checks = await asyncio.gather(
        _check_virustotal(client, url), _check_urlscan(client, url)
    )
    for result in checks:
        if result is None:
            continue
        malicious, detail = result
        verdict.sources.append(detail)
        if malicious:
            verdict.malicious = True
    verdict.detail = "; ".join(verdict.sources)
    return verdict


async def scan_urls(
    urls: list[str], timeout: float | None = None
) -> ThreatIntel:
    """Defang and (if keys present) reputation-check every URL."""
    import httpx

    timeout = config.THREAT_INTEL_TIMEOUT if timeout is None else timeout
    unique = list(dict.fromkeys(urls))
    enabled = config.threat_intel_enabled()

    if not unique:
        return ThreatIntel(checked=enabled, summary="No URLs to scan.")

    if not enabled:
        return ThreatIntel(
            checked=False,
            urls=[URLVerdict(url=u, defanged=defang_url(u)) for u in unique],
            summary="URLs defanged; reputation check skipped (no API key).",
        )

    async with httpx.AsyncClient(timeout=timeout) as client:
        verdicts = await asyncio.gather(*(_scan_one(client, u) for u in unique))

    any_mal = any(v.malicious for v in verdicts)
    return ThreatIntel(
        checked=True,
        any_malicious=any_mal,
        urls=list(verdicts),
        summary=(
            "Malicious link(s) detected — quarantine recommended."
            if any_mal
            else "No malicious links found by reputation providers."
        ),
    )
