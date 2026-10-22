"""Tests for Claude-powered feed article summaries (core.ai_summary)."""

import json
from types import SimpleNamespace

import pytest

import core.ai_summary as ai
import core.llm as llm

ARTICLE = {
    "title": "FortiGate zero-day exploited",
    "link": "https://example.test/fortigate",
    "source": "Example News",
    "pub_date": "Wed, 21 Oct 2026",
    "summary": "short",
    "content": "Fortinet disclosed CVE-2099-0001 in FortiOS 7.4.0 through 7.4.8.",
}

SUMMARY = {
    "summary": "Ringkasan.",
    "affected_products": [{"vendor": "Fortinet", "product": "FortiOS", "affected_versions": "7.4.0-7.4.8", "fixed_versions": "7.4.9"}],
    "cves": ["CVE-2099-0001"],
    "exploitation": "exploited_in_the_wild",
    "urgency": "critical",
    "recommended_actions": ["Upgrade ke 7.4.9"],
}


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def _fake_client(monkeypatch, stop_reason="end_turn", text=None):
    response = SimpleNamespace(
        stop_reason=stop_reason,
        model="claude-opus-5-5",
        content=[SimpleNamespace(type="text", text=json.dumps(SUMMARY) if text is None else text)],
    )
    messages = FakeMessages(response)
    monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=messages)))
    return messages


@pytest.fixture(autouse=True)
def in_memory_store(monkeypatch):
    store = {}
    monkeypatch.setattr(llm, "AI_SUMMARY_ENABLED", True)
    monkeypatch.setattr(ai, "get_ai_summary", lambda key: store.get(key))
    monkeypatch.setattr(ai, "save_ai_summary", lambda key, link, model, summary: store.__setitem__(
        key, {"model": model, "summary": summary, "created_at": "now"}))
    return store


def test_summary_is_generated_then_cached(monkeypatch):
    messages = _fake_client(monkeypatch)

    first = ai.summarize_article(ARTICLE)
    assert first["success"] is True
    assert first["cached"] is False
    assert first["summary"]["urgency"] == "critical"

    second = ai.summarize_article(ARTICLE)
    assert second["cached"] is True
    assert len(messages.calls) == 1


def test_request_sends_only_article_text(monkeypatch):
    messages = _fake_client(monkeypatch)
    ai.summarize_article(ARTICLE)

    call = messages.calls[0]
    assert call["fallbacks"] == "default"
    assert call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["output_config"]["format"]["type"] == "json_schema"
    sent = json.dumps(call["messages"]) + call["system"]
    assert ARTICLE["content"] in sent
    # Nothing from the watchlist (owners, hostnames) is part of the request.
    for private in ("Internal", "Customer", "watchlist", "fw-01"):
        assert private not in sent


def test_refusal_is_reported(monkeypatch):
    _fake_client(monkeypatch, stop_reason="refusal", text="")
    result = ai.summarize_article(ARTICLE, force=True)
    assert result["success"] is False
    assert result["error_type"] == "REFUSAL"


def test_invalid_json_is_reported(monkeypatch):
    _fake_client(monkeypatch, text="not json")
    result = ai.summarize_article(ARTICLE, force=True)
    assert result["error_type"] == "PARSE_ERROR"


def test_disabled_by_config(monkeypatch):
    monkeypatch.setattr(llm, "AI_SUMMARY_ENABLED", False)
    assert ai.summarize_article(ARTICLE)["error_type"] == "DISABLED"
