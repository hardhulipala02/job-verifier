"""Render a :class:`ScamReport` into human-readable text / HTML for emails."""
from __future__ import annotations

from defang import defang_url
from schemas import RiskLevel, ScamReport

_EMOJI = {RiskLevel.LOW: "[OK]", RiskLevel.MEDIUM: "[CAUTION]", RiskLevel.HIGH: "[DANGER]"}
_ADVICE = {
    RiskLevel.LOW: "This looks legitimate. Still use normal caution.",
    RiskLevel.MEDIUM: "Some red flags found. Verify before sharing anything.",
    RiskLevel.HIGH: (
        "This is likely a scam. Do not share personal info or money, and do "
        "not move the conversation to external chat apps like Telegram."
    ),
}
_COLOR = {RiskLevel.LOW: "#22c55e", RiskLevel.MEDIUM: "#f59e0b", RiskLevel.HIGH: "#ef4444"}


def subject_line(report: ScamReport) -> str:
    return f"[{report.verdict.risk_level.value} RISK] Job Scam Checker report"


def render_text(report: ScamReport) -> str:
    v = report.verdict
    lines = [
        f"{_EMOJI[v.risk_level]} RISK LEVEL: {v.risk_level.value}",
        "",
        _ADVICE[v.risk_level],
        "",
    ]

    src = report.source
    if src:
        lines.append("Analyzed email:")
        lines.append(f"  Report ID: {src.analysis_id}")
        if src.from_address:
            lines.append(f"  From:    {src.from_address}")
        if src.subject:
            lines.append(f"  Subject: {src.subject}")
        if src.date:
            lines.append(f"  Date:    {src.date}")
        lines.append("")

    if report.sender:
        lines += [f"Sender: {report.sender}", ""]

    s = report.security
    if s.spf.value != "missing" or s.dkim.value != "missing" or s.dmarc.value != "missing":
        lines += [
            "Email authentication:",
            f"  SPF:   {s.spf.value}",
            f"  DKIM:  {s.dkim.value}",
            f"  DMARC: {s.dmarc.value}",
            "",
        ]

    lines.append(f"Red flags ({len(v.flags_detected)}):")
    if v.flags_detected:
        lines += [f"  - {f}" for f in v.flags_detected]
    else:
        lines.append("  None detected.")
    lines.append("")

    if report.impersonation and report.impersonation.notes:
        lines.append("Impersonation:")
        lines += [f"  - {n}" for n in report.impersonation.notes]
        lines.append("")

    r = report.role
    if r and (r.claimed_role or r.summary):
        lines.append("Advertised role:")
        if r.claimed_role:
            mark = "verified" if r.verified else ("not found" if r.checked else "")
            suffix = f" ({mark})" if mark else ""
            lines.append(f"  - {r.claimed_role}{suffix}")
        if r.summary:
            lines.append(f"  - {r.summary}")
        if r.open_roles:
            lines.append(f"  Open roles at {r.claimed_company or 'this company'}:")
            for role in r.open_roles:
                star = " <- matches" if role.matches_claim else ""
                lines.append(f"    - {role.title}{star}")
                if role.url:
                    lines.append(f"        {role.url}")
        lines += [f"  - search: {u}" for u in r.sources]
        lines.append("")

    ti = report.threat_intel
    if ti and (ti.summary or ti.urls):
        lines.append("URL reputation:")
        if ti.summary:
            lines.append(f"  - {ti.summary}")
        for u in ti.urls:
            tag = " [MALICIOUS]" if u.malicious else ""
            lines.append(f"  - {u.defanged}{tag}")
        lines.append("")

    if report.dns:
        lines.append("Resolved infrastructure:")
        for rec in report.dns:
            lines.append(f"  - {rec.domain}")
            if rec.a_records:
                lines.append(f"      A:  {', '.join(rec.a_records)}")
            if rec.ns_records:
                lines.append(f"      NS: {', '.join(rec.ns_records)}")
        lines.append("")

    e = report.entities
    contacts = (
        [f"Telegram: @{h}" for h in e.telegram_handles]
        + [f"WhatsApp: {n}" for n in e.whatsapp_numbers]
        + [f"Phone: {n}" for n in e.phone_numbers]
        + [f"Link (defanged): {defang_url(u)}" for u in e.urls]
    )
    if contacts:
        lines.append("Extracted contacts & links:")
        lines += [f"  - {c}" for c in contacts]
        lines.append("")

    lines += ["--", "Analyzed by Job Scam Checker."]
    return "\n".join(lines)


def render_html(report: ScamReport) -> str:
    v = report.verdict
    color = _COLOR[v.risk_level]
    flags = (
        "".join(f"<li>{_esc(f)}</li>" for f in v.flags_detected)
        or "<li>None detected.</li>"
    )
    sections = [
        f'<div style="border-left:6px solid {color};padding:12px 16px;'
        f'background:#f8fafc;border-radius:8px;">'
        f'<div style="font-size:20px;font-weight:700;color:{color};">'
        f"{v.risk_level.value} RISK</div>"
        f'<div style="color:#334155;">{_esc(_ADVICE[v.risk_level])}</div></div>',
    ]
    src = report.source
    if src:
        meta = [f"<li><strong>Report ID:</strong> {_esc(src.analysis_id)}</li>"]
        if src.from_address:
            meta.append(f"<li><strong>From:</strong> {_esc(src.from_address)}</li>")
        if src.subject:
            meta.append(f"<li><strong>Subject:</strong> {_esc(src.subject)}</li>")
        if src.date:
            meta.append(f"<li><strong>Date:</strong> {_esc(src.date)}</li>")
        sections.append(
            "<p><strong>Analyzed email:</strong></p>"
            f'<ul style="color:#475569;">{"".join(meta)}</ul>'
        )

    if report.sender:
        sections.append(f"<p><strong>Sender:</strong> {_esc(report.sender)}</p>")

    s = report.security
    if any(x.value != "missing" for x in (s.spf, s.dkim, s.dmarc)):
        sections.append(
            "<p><strong>Email authentication:</strong> "
            f"SPF={s.spf.value}, DKIM={s.dkim.value}, DMARC={s.dmarc.value}</p>"
        )

    sections.append(
        f"<p><strong>Red flags ({len(v.flags_detected)}):</strong></p><ul>{flags}</ul>"
    )

    if report.impersonation and report.impersonation.notes:
        notes = "".join(f"<li>{_esc(n)}</li>" for n in report.impersonation.notes)
        sections.append(f"<p><strong>Impersonation:</strong></p><ul>{notes}</ul>")

    r = report.role
    if r and (r.claimed_role or r.summary):
        items = []
        if r.claimed_role:
            mark = "verified" if r.verified else ("not found" if r.checked else "")
            suffix = f" ({mark})" if mark else ""
            items.append(f"<li>{_esc(r.claimed_role)}{_esc(suffix)}</li>")
        if r.summary:
            items.append(f"<li>{_esc(r.summary)}</li>")
        if r.open_roles:
            rows = []
            for role in r.open_roles:
                label = _esc(role.title)
                if role.url:
                    label = f'<a href="{_esc(role.url)}">{label}</a>'
                if role.matches_claim:
                    label += " <strong>(matches)</strong>"
                rows.append(f"<li>{label}</li>")
            company = _esc(r.claimed_company or "this company")
            items.append(
                f"<li>Open roles at {company}:<ul>{''.join(rows)}</ul></li>"
            )
        items += [
            f'<li>search: <a href="{_esc(u)}">{_esc(u)}</a></li>' for u in r.sources
        ]
        sections.append(
            f"<p><strong>Advertised role:</strong></p><ul>{''.join(items)}</ul>"
        )

    ti = report.threat_intel
    if ti and (ti.summary or ti.urls):
        items = []
        if ti.summary:
            items.append(f"<li>{_esc(ti.summary)}</li>")
        for u in ti.urls:
            tag = " <strong>[MALICIOUS]</strong>" if u.malicious else ""
            items.append(f"<li>{_esc(u.defanged)}{tag}</li>")
        sections.append(
            f"<p><strong>URL reputation:</strong></p><ul>{''.join(items)}</ul>"
        )

    if report.dns:
        items = []
        for rec in report.dns:
            detail = []
            if rec.a_records:
                detail.append("A: " + ", ".join(rec.a_records))
            if rec.ns_records:
                detail.append("NS: " + ", ".join(rec.ns_records))
            extra = f" ({_esc('; '.join(detail))})" if detail else ""
            items.append(f"<li>{_esc(rec.domain)}{extra}</li>")
        sections.append(
            f"<p><strong>Resolved infrastructure:</strong></p><ul>{''.join(items)}</ul>"
        )

    e = report.entities
    contacts = (
        [f"Telegram: @{h}" for h in e.telegram_handles]
        + [f"WhatsApp: {n}" for n in e.whatsapp_numbers]
        + [f"Phone: {n}" for n in e.phone_numbers]
        + [f"Link (defanged): {defang_url(u)}" for u in e.urls]
    )
    if contacts:
        items = "".join(f"<li>{_esc(c)}</li>" for c in contacts)
        sections.append(f"<p><strong>Contacts &amp; links:</strong></p><ul>{items}</ul>")

    body = "".join(sections)
    return (
        '<div style="font-family:system-ui,Arial,sans-serif;max-width:600px;'
        f'color:#0f172a;">{body}'
        '<hr/><p style="color:#94a3b8;font-size:12px;">Analyzed by Job Scam '
        "Checker.</p></div>"
    )


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
