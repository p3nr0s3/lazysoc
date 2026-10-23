"""
Microsoft Teams delivery for LazySOC digests via Workflows ("Post to a channel when a webhook request is
received"). The webhook takes an Adaptive Card message and cannot carry files, so the card holds the brief
and a button to the PDF on this LazySOC instance (LAZYSOC_PUBLIC_URL).

Webhook URLs are secrets and come only from the environment, never from requests.
"""

from typing import Any, Dict, List

import requests

from core.config import PUBLIC_BASE_URL, TEAMS_WEBHOOK_URL, TEAMS_WEBHOOKS

URGENCY_LABEL = {"critical": "KRITIS", "high": "TINGGI", "medium": "SEDANG", "low": "RENDAH"}
URGENCY_COLOR = {"critical": "Attention", "high": "Warning", "medium": "Accent", "low": "Default"}
EXPLOIT_LABEL = {
    "exploited_in_the_wild": "Dieksploitasi aktif",
    "public_poc": "PoC publik",
    "not_reported": "Eksploitasi belum dilaporkan",
    "not_applicable": "Bukan kerentanan",
}
MAX_ISSUES_IN_CARD = 6
MAX_TEXT = 600


class TeamsError(Exception):
    pass


def _channels() -> Dict[str, str]:
    channels: Dict[str, str] = {}
    if TEAMS_WEBHOOK_URL:
        channels["default"] = TEAMS_WEBHOOK_URL
    for part in TEAMS_WEBHOOKS.split(";"):
        name, sep, url = part.strip().partition("=")
        if sep and name.strip() and url.strip().startswith("https://"):
            channels[name.strip()] = url.strip()
    return channels


def channel_names() -> List[str]:
    return list(_channels())


def _short(text: Any, limit: int = MAX_TEXT) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _message(body: List[Dict[str, Any]], actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
    }
    if actions:
        card["actions"] = actions
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def _period(digest: Dict[str, Any]) -> str:
    start, end = digest.get("period_start", ""), digest.get("period_end", "")
    return start if start == end else f"{start} s/d {end}"


def digest_card(digest: Dict[str, Any], schedule_name: str = "") -> Dict[str, Any]:
    kpis = digest.get("kpis", {})
    issues = digest.get("issues", [])
    mode = "Critical Tools" if digest.get("mode") == "critical" else "General"

    body: List[Dict[str, Any]] = [
        {"type": "TextBlock", "text": "LAZYSOC THREAT DIGEST · RAHASIA - INTERNAL", "size": "Small", "weight": "Bolder", "color": "Accent", "isSubtle": True},
        {"type": "TextBlock", "text": f"Laporan Ancaman Siber — {_period(digest)}", "size": "Large", "weight": "Bolder", "wrap": True},
        {"type": "FactSet", "facts": [
            {"title": "Jadwal", "value": schedule_name or "-"},
            {"title": "Cakupan", "value": f"{mode} · {digest.get('owner') or 'Semua owner'}"},
            {"title": "Berita", "value": f"{digest.get('article_count', 0)} berita → {kpis.get('issues', len(issues))} isu"},
            {"title": "Model AI", "value": f"{digest.get('provider', '')} · {digest.get('model', '')}"},
        ]},
        {"type": "ColumnSet", "columns": [
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": str(value), "size": "ExtraLarge", "weight": "Bolder", "color": color, "horizontalAlignment": "Center"},
                {"type": "TextBlock", "text": label, "size": "Small", "isSubtle": True, "horizontalAlignment": "Center", "wrap": True},
            ]}
            for value, label, color in (
                (kpis.get("critical", 0), "Kritis", "Attention"),
                (kpis.get("high", 0), "Tinggi", "Warning"),
                (kpis.get("exploited", 0), "Dieksploitasi", "Attention"),
                (kpis.get("kev", 0), "CVE di KEV", "Accent"),
                (kpis.get("owners", 0), "Owner terdampak", "Default"),
            )
        ]},
        {"type": "TextBlock", "text": "Ringkasan Eksekutif", "weight": "Bolder", "spacing": "Medium"},
        {"type": "TextBlock", "text": _short(digest.get("overview"), 900), "wrap": True},
    ]

    if digest.get("priority_actions"):
        body.append({"type": "TextBlock", "text": "Tindakan Prioritas", "weight": "Bolder", "spacing": "Medium"})
        body.append({"type": "TextBlock", "wrap": True,
                     "text": "\n".join(f"{n}. {_short(a, 200)}" for n, a in enumerate(digest["priority_actions"][:5], start=1))})

    if issues:
        body.append({"type": "TextBlock", "text": f"Isu Teratas ({min(len(issues), MAX_ISSUES_IN_CARD)} dari {len(issues)})",
                     "weight": "Bolder", "spacing": "Medium"})
    for n, issue in enumerate(issues[:MAX_ISSUES_IN_CARD], start=1):
        products = "; ".join(f"{p['product']} ({', '.join(p.get('owners', []))})" for p in issue.get("products", []))
        if not products and issue.get("vendor_only"):
            products = "Vendor " + ", ".join(sorted({v.get("vendor", "") for v in issue["vendor_only"]})) + " (produk tidak ada di list)"
        kev = set(issue.get("kev_cves", []))
        cves = ", ".join(f"{c} (KEV)" if c in kev else c for c in issue.get("cves", [])[:6])
        facts = [{"title": "Status", "value": EXPLOIT_LABEL.get(issue.get("exploitation"), "-")}]
        if products:
            facts.append({"title": "Watchlist", "value": _short(products, 300)})
        if cves:
            facts.append({"title": "CVE", "value": cves})
        facts.append({"title": "Sumber", "value": f"{len(issue.get('sources', []))} berita"})
        body.append({
            "type": "Container", "style": "emphasis", "spacing": "Small", "items": [
                {"type": "TextBlock", "wrap": True, "weight": "Bolder", "color": URGENCY_COLOR.get(issue.get("urgency"), "Default"),
                 "text": f"#{n} [{URGENCY_LABEL.get(issue.get('urgency'), '-')}] {_short(issue.get('title'), 200)}"},
                {"type": "TextBlock", "wrap": True, "size": "Small", "text": _short(issue.get("summary"), 350)},
                {"type": "FactSet", "facts": facts},
            ],
        })

    body.append({"type": "TextBlock", "size": "Small", "isSubtle": True, "wrap": True, "spacing": "Medium",
                 "text": "Dibuat otomatis oleh LazySOC dari berita publik. Verifikasi ke sumber asli sebelum bertindak."})

    actions = []
    if PUBLIC_BASE_URL and digest.get("id"):
        actions.append({"type": "Action.OpenUrl", "title": "Buka PDF", "url": f"{PUBLIC_BASE_URL}/api/digest/{digest['id']}/pdf"})
        actions.append({"type": "Action.OpenUrl", "title": "Buka LazySOC", "url": f"{PUBLIC_BASE_URL}/"})
    return _message(body, actions)


def empty_card(schedule: Dict[str, Any], start_date: str, end_date: str) -> Dict[str, Any]:
    period = start_date if start_date == end_date else f"{start_date} s/d {end_date}"
    return _message([
        {"type": "TextBlock", "text": "LAZYSOC THREAT DIGEST", "size": "Small", "weight": "Bolder", "color": "Accent"},
        {"type": "TextBlock", "text": f"{schedule.get('name', '')}: tidak ada berita yang cocok untuk {period}.", "wrap": True},
    ], [])


def test_card() -> Dict[str, Any]:
    return _message([
        {"type": "TextBlock", "text": "LAZYSOC", "size": "Small", "weight": "Bolder", "color": "Accent"},
        {"type": "TextBlock", "text": "Tes koneksi webhook Teams berhasil. Ringkasan terjadwal akan dikirim ke channel ini.", "wrap": True},
    ], [])


def post_card(channel: str, payload: Dict[str, Any]) -> None:
    url = _channels().get(channel)
    if not url:
        raise TeamsError(f"Channel Teams '{channel}' tidak dikonfigurasi (TEAMS_WEBHOOK_URL / TEAMS_WEBHOOKS).")
    try:
        resp = requests.post(url, json=payload, timeout=20)
    except requests.RequestException as e:
        raise TeamsError(f"Tidak dapat terhubung ke webhook Teams: {e.__class__.__name__}")
    if resp.status_code not in (200, 201, 202):
        raise TeamsError(f"Webhook Teams membalas HTTP {resp.status_code}: {resp.text[:200]}")
