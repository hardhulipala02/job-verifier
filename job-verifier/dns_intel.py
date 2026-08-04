"""Asynchronous DNS resolution for infrastructure mapping.

Scam syndicates reuse infrastructure: many throwaway sending domains often share
the same hosting IP (A-record) or the same nameservers (NS-records). Resolving
these and storing them as nodes in Neo4j lets the graph link otherwise unrelated
domains that point at the same attacker infrastructure.

Resolution is async (all domains resolved concurrently) and fully graceful: any
lookup failure simply yields empty record lists.
"""
from __future__ import annotations

import asyncio
import logging

from schemas import DomainDNS

logger = logging.getLogger(__name__)


async def _resolve_record(resolver, domain: str, rdtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(domain, rdtype)
        return sorted(r.to_text().rstrip(".") for r in answer)
    except Exception as exc:  # noqa: BLE001 - missing records are expected
        logger.debug("DNS %s lookup failed for %s: %s", rdtype, domain, exc)
        return []


async def resolve_domain(domain: str, timeout: float = 4.0) -> DomainDNS:
    """Resolve A and NS records for a single domain."""
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    a_records, ns_records = await asyncio.gather(
        _resolve_record(resolver, domain, "A"),
        _resolve_record(resolver, domain, "NS"),
    )
    return DomainDNS(domain=domain, a_records=a_records, ns_records=ns_records)


async def resolve_domains(
    domains: list[str], timeout: float = 4.0
) -> list[DomainDNS]:
    """Resolve A/NS records for many domains concurrently."""
    unique = list(dict.fromkeys(d.lower() for d in domains if d))
    if not unique:
        return []
    results = await asyncio.gather(
        *(resolve_domain(d, timeout) for d in unique), return_exceptions=True
    )
    out: list[DomainDNS] = []
    for domain, res in zip(unique, results):
        if isinstance(res, DomainDNS):
            out.append(res)
        else:  # pragma: no cover - defensive; resolve_domain already guards
            logger.warning("DNS resolution errored for %s: %s", domain, res)
            out.append(DomainDNS(domain=domain))
    return out
