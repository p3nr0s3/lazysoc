"""Tests for period digests, the local LLM provider and PDF export."""

import json
from datetime import date

import pytest

import core.digest as dg
import core.llm as llm
import core.watchlist as wl
from core.database import get_digest
from core.pdf_export import digest_pdf

WATCHLIST = {
    "assets": [{
        "id": "fortinet-fortios", "vendor": "Fortinet", "product": "FortiOS / FortiGate", "criticality": "critical",
        "aliases": ["FortiOS", "FortiGate"], "cpe": ["fortinet:fortios"],
        "deployments": [{"owner": "Internal", "version": "7.4.8", "note": "fw-01"}, {"owner": "Customer A"}],
    }]
}

ARTICLES = [
    {"link": "https://example.test/forti", "title": "FortiGate zero-day exploited", "source": "News", "summary": "s",
     "content": "Attackers exploit CVE-2099-0001 in FortiOS.", "published_at": "2026-10-21 08:00:00"},
    {"link": "https://example.test/other", "title": "Unrelated ransomware news", "source": "News", "summary": "s",
     "content": "Nothing about the stack.", "published_at": "2026-10-20 08:00:00"},
]


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps(WATCHLIST), encoding="utf-8")
    monkeypatch.setattr(wl, "WATCHLIST_FILE", path)
    monkeypatch.setattr(wl, "_state", {"mtime": None, "assets": [], "error": None})
    monkeypatch.setattr(dg, "refresh_feed_store", lambda: 0)
    monkeypatch.setattr(dg, "get_feed_articles_between", lambda start, end: [dict(a) for a in ARTICLES])
    monkeypatch.setattr(dg, "_kev_ids", lambda: {"CVE-2099-0001"})


def _art(title, urgency="high", cves=(), products=(("PHP", ["Internal"]),), exploitation="not_reported", actions=("Patch",)):
    return {
        "title": title, "headline": title, "urgency": urgency, "exploitation": exploitation, "cves": list(cves),
        "kev_cves": [], "summary": f"Ringkasan {title}", "recommended_actions": list(actions), "source": "News",
        "link": f"https://example.test/{abs(hash(title))}", "published_at": "2026-10-21 08:00:00",
        "watchlist_matches": [{"level": "product", "product": p, "vendor": "", "criticality": "high", "owners": o} for p, o in products],
    }


def test_group_issues_merges_same_story():
    articles = [
        _art("PHP2Shell: Two Critical PHP RCE Flaws", urgency="critical", cves=["CVE-2026-1"], exploitation="exploited_in_the_wild"),
        _art("PHP ships emergency patches", cves=["CVE-2026-1"]),                       # shared CVE
        _art("PHP warns admins of two critical flaws, emergency patches coming"),     # same product + title words
        _art("LiteLLM Compromised in Supply Chain Attack", products=(("Docker", ["Customer C"]),)),
        _art("LiteLLM Suspects GitHub Token Leak", products=(("Docker", ["Customer C"]),)),  # shared distinctive token
        _art("Unrelated Chrome scam detection", products=(("Google Chrome", ["LK"]),)),
    ]
    issues = dg.group_issues(articles)
    sizes = sorted(len(i["sources"]) for i in issues)
    assert sizes == [1, 2, 3]
    top = issues[0]
    assert top["urgency"] == "critical" and top["exploitation"] == "exploited_in_the_wild"
    assert top["title"].startswith("PHP2Shell") and top["recommended_actions"] == ["Patch"]


def test_owner_impact_ignores_vendor_only_matches():
    vendor_only = _art("Critical FortiSIEM flaw", urgency="critical", products=())
    vendor_only["watchlist_matches"] = [{"level": "vendor", "vendor": "Fortinet", "product": "Fortinet", "criticality": "critical", "owners": ["Customer D"]}]
    issues = dg.group_issues([vendor_only, _art("GitLab RCE", urgency="critical", products=(("GitLab", ["Internal"]),))])
    impact = dg.owner_impact(issues)
    assert [r["owner"] for r in impact] == ["Internal"]
    assert impact[0]["critical"] == 1
    assert next(i for i in issues if i["vendor_only"])["owners"] == []


def test_enrich_and_pdf_for_digest_without_issues():
    old = {"period_start": "2026-10-20", "period_end": "2026-10-22", "mode": "critical", "provider": "local", "model": "m",
           "article_count": 2, "overview": "x", "key_themes": [], "priority_actions": [],
           "articles": [_art("A one", cves=["CVE-2026-9"]), _art("A two", cves=["CVE-2026-9"])]}
    enriched = dg.enrich_digest(old)
    assert enriched["kpis"]["issues"] == 1 and enriched["kpis"]["articles"] == 2
    assert digest_pdf(old).startswith(b"%PDF")


def test_period_bounds_presets_and_custom():
    _, _, today = dg.period_bounds(days=1, today=date(2026, 10, 22))
    assert today == {"from": "2026-10-22", "to": "2026-10-22"}
    _, _, week = dg.period_bounds(days=7, today=date(2026, 10, 22))
    assert week == {"from": "2026-10-16", "to": "2026-10-22"}
    start, end, custom = dg.period_bounds(start_date="2026-10-20", end_date="2026-10-01")
    assert custom == {"from": "2026-10-01", "to": "2026-10-20"}
    assert start < end
    with pytest.raises(dg.DigestError):
        dg.period_bounds(start_date="2026-01-01", end_date="2026-12-31")
    with pytest.raises(dg.DigestError):
        dg.period_bounds(start_date="22-10-2026")


def test_collect_filters_by_mode_owner_and_query():
    assert [a["link"] for a in dg.collect_articles("a", "b", mode="critical")] == ["https://example.test/forti"]
    assert len(dg.collect_articles("a", "b", mode="general")) == 2
    assert dg.collect_articles("a", "b", owner="Nobody", mode="critical") == []
    assert len(dg.collect_articles("a", "b", mode="general", query="ransomware")) == 1
    assert len(dg.collect_articles("a", "b", mode="critical", query="fortios")) == 1


def test_generate_digest_merges_local_correlation_and_saves(monkeypatch):
    sent = {}

    def fake_complete(system, user, schema, provider):
        sent["prompt"] = system + user
        return {
            "overview": "Ringkas.", "key_themes": ["Fortinet"], "priority_actions": ["Patch"],
            "articles": [{"ref": 1, "headline": "Zero-day FortiGate", "summary": "Isi", "urgency": "critical",
                          "exploitation": "exploited_in_the_wild", "recommended_actions": ["Upgrade"]}],
        }, "fake-model", provider

    monkeypatch.setattr(dg, "complete_json", fake_complete)
    digest = dg.generate_digest(days=7, mode="critical", provider="claude")

    assert digest["article_count"] == 1
    article = digest["articles"][0]
    assert article["headline"] == "Zero-day FortiGate"
    assert article["watchlist_matches"][0]["owners"] == ["Customer A", "Internal"]
    assert article["cves"] == ["CVE-2099-0001"]
    assert article["kev_cves"] == ["CVE-2099-0001"]
    assert digest["kpis"]["kev"] == 1 and digest["issues"][0]["owners"] == ["Customer A", "Internal"]
    # The model never sees owners or deployment details.
    for private in ("Internal", "Customer A", "fw-01", "7.4.8"):
        assert private not in sent["prompt"]
    assert get_digest(digest["id"])["overview"] == "Ringkas."


def test_generate_digest_without_articles(monkeypatch):
    monkeypatch.setattr(dg, "get_feed_articles_between", lambda start, end: [])
    with pytest.raises(dg.DigestError) as exc:
        dg.generate_digest(days=1, provider="claude")
    assert exc.value.error_type == "NO_ARTICLES"


def test_local_provider_parses_fenced_json(monkeypatch):
    calls = []

    class Resp:
        def __init__(self, status, payload, text=""):
            self.status_code, self._payload, self.text = status, payload, text

        def json(self):
            return self._payload

    def fake_post(url, headers, json, timeout):
        calls.append(json)
        if "response_format" in json:
            return Resp(400, {}, "unknown field response_format")
        return Resp(200, {"model": "llama3", "choices": [{"finish_reason": "stop", "message": {"content": 'Here:\n```json\n{"ok": true}\n```'}}]})

    monkeypatch.setattr(llm, "LOCAL_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setattr(llm, "LOCAL_LLM_MODEL", "llama3")
    monkeypatch.setattr(llm, "AI_SUMMARY_ENABLED", True)
    monkeypatch.setattr(llm.requests, "post", fake_post)

    data, model, provider = llm.complete_json("sys", "user", {"type": "object"}, provider="local")
    assert data == {"ok": True} and model == "llama3" and provider == "local"
    assert len(calls) == 2 and "response_format" not in calls[1]


def test_local_provider_requires_configuration(monkeypatch):
    monkeypatch.setattr(llm, "LOCAL_LLM_BASE_URL", "")
    monkeypatch.setattr(llm, "AI_SUMMARY_ENABLED", True)
    with pytest.raises(llm.LLMError) as exc:
        llm.complete_json("sys", "user", {}, provider="local")
    assert exc.value.error_type == "NOT_CONFIGURED"
    with pytest.raises(llm.LLMError):
        llm.resolve_provider("openai")


def test_pdf_export_handles_unicode_and_markup():
    pdf = digest_pdf({
        "period_start": "2026-10-16", "period_end": "2026-10-22", "mode": "critical", "provider": "local",
        "model": "m", "article_count": 1, "overview": "Ringkasan → “kutip” ≥ <b>tag</b> & Ünicode ✓",
        "key_themes": ["A"], "priority_actions": ["B"],
        "articles": [{"headline": "H <script>", "summary": "S", "urgency": "high", "exploitation": "public_poc",
                      "watchlist_matches": [{"level": "product", "product": "FortiOS", "vendor": "Fortinet", "owners": ["Internal"]}],
                      "cves": ["CVE-2099-0001"], "recommended_actions": ["X"], "link": "https://example.test/?a=1&b=2", "title": "T"}],
    })
    assert pdf.startswith(b"%PDF")
