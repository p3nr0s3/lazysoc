"""Tests for the critical tools watchlist correlation (core.watchlist) and feed tagging."""

import json

import pytest

import core.watchlist as wl
import core.feed as feed

SAMPLE_WATCHLIST = {
    "assets": [
        {
            "id": "fortinet-fortios",
            "vendor": "Fortinet",
            "product": "FortiOS / FortiGate",
            "criticality": "critical",
            "aliases": ["FortiOS", "FortiGate"],
            "vendor_aliases": ["Fortinet"],
            "kev": [{"vendor": "Fortinet", "product": "FortiOS"}],
            "cpe": ["fortinet:fortios"],
            "deployments": [
                {"owner": "Internal", "version": "7.4.8", "note": "fw-01"},
                {"owner": "Internal", "version": "6.4.5", "note": "fw-legacy"},
                {"owner": "Customer A", "note": "FortiGate 100F"},
            ],
        },
        {
            "id": "fortinet-fortiweb",
            "vendor": "Fortinet",
            "product": "FortiWeb",
            "criticality": "critical",
            "aliases": ["FortiWeb"],
            "vendor_aliases": ["Fortinet"],
            "cpe": ["fortinet:fortiweb"],
            "deployments": [{"owner": "Customer B"}],
        },
        {
            "id": "react",
            "vendor": "Meta",
            "product": "React",
            "criticality": "high",
            "strict_aliases": ["React"],
            "cpe": ["facebook:react"],
            "deployments": [{"owner": "Customer B", "version": "19.0.0"}],
        },
    ]
}


def _fortios_cve(entries):
    return {
        "id": "CVE-2099-0001",
        "descriptions": [{"lang": "en", "value": "Test vuln"}],
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": entries}]}],
    }


@pytest.fixture(autouse=True)
def sample_watchlist(tmp_path, monkeypatch):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps(SAMPLE_WATCHLIST), encoding="utf-8")
    monkeypatch.setattr(wl, "WATCHLIST_FILE", path)
    monkeypatch.setattr(wl, "_state", {"mtime": None, "assets": [], "error": None})
    return path


def test_missing_watchlist_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(wl, "WATCHLIST_FILE", tmp_path / "nope.json")
    summary = wl.get_watchlist_summary()
    assert summary["loaded"] is False
    assert "not found" in summary["error"]


def test_summary_lists_owners_with_internal_first():
    summary = wl.get_watchlist_summary()
    assert summary["total_assets"] == 3
    assert summary["owners"][0] == "Internal"
    assert set(summary["owners"]) == {"Internal", "Customer A", "Customer B"}


def test_product_alias_match_case_insensitive():
    matches = wl.match_text("Critical fortigate SSL-VPN flaw exploited")
    assert len(matches) == 1
    assert matches[0]["asset_id"] == "fortinet-fortios"
    assert matches[0]["level"] == "product"
    assert matches[0]["owners"] == ["Customer A", "Internal"]


def test_alias_requires_word_boundary():
    assert wl.match_text("FortiOSX is not a product") == []


def test_strict_alias_is_case_sensitive():
    assert wl.match_text("Attackers react quickly to new patches") == []
    assert wl.match_text("React Server Components RCE")[0]["asset_id"] == "react"


def test_vendor_only_match_when_no_product_named():
    matches = wl.match_text("Fortinet warns customers about a new campaign")
    assert len(matches) == 1
    assert matches[0]["level"] == "vendor"
    assert set(matches[0]["owners"]) == {"Internal", "Customer A", "Customer B"}


def test_vendor_match_suppressed_when_product_matched():
    matches = wl.match_text("Fortinet patches FortiWeb bug")
    assert [m["asset_id"] for m in matches] == ["fortinet-fortiweb"]


def test_owner_filter_limits_matches_and_deployments():
    assert wl.match_text("FortiWeb flaw", owner="Internal") == []
    matches = wl.match_text("FortiGate flaw", owner="Customer A")
    assert matches[0]["owners"] == ["Customer A"]
    assert [d["owner"] for d in matches[0]["deployments"]] == ["Customer A"]


def test_priority_score_prefers_product_level():
    product = wl.match_text("FortiGate flaw")
    vendor = wl.match_text("Fortinet news")
    assert wl.priority_score(product) > wl.priority_score(vendor) > 0


@pytest.mark.parametrize("raw, expected", [
    ("7.4.8", (7, 4, 8)),
    ("v7.4.8 build2795 (Mature)", (7, 4, 8)),
    ("E4.5", (4, 5)),
    ("11.9.000047", (11, 9, 47)),
    ("", None),
    ("unknown", None),
])
def test_parse_version(raw, expected):
    assert wl.parse_version(raw) == expected


def test_version_range_marks_affected_and_not_affected():
    cve = _fortios_cve([{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "7.4.0",
        "versionEndExcluding": "7.4.9",
    }])
    asset = next(a for a in wl.load_watchlist() if a["id"] == "fortinet-fortios")
    results = {d["note"]: d["status"] for d in wl.evaluate_deployments(asset, cve)}
    assert results == {"fw-01": "affected", "fw-legacy": "not_affected", "FortiGate 100F": "unknown"}


def test_exact_version_cpe_and_non_vulnerable_entries():
    cve = _fortios_cve([
        {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:6.4.5:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:fortinet:fortios:7.4.8:*:*:*:*:*:*:*"},
    ])
    asset = next(a for a in wl.load_watchlist() if a["id"] == "fortinet-fortios")
    results = {d["note"]: d["status"] for d in wl.evaluate_deployments(asset, cve, owner="Internal")}
    assert results == {"fw-01": "not_affected", "fw-legacy": "affected"}


def test_pending_when_nvd_data_missing():
    asset = next(a for a in wl.load_watchlist() if a["id"] == "fortinet-fortios")
    assert {d["status"] for d in wl.evaluate_deployments(asset, None)} == {"pending"}


def test_check_cve_impact_rejects_bad_id():
    result = wl.check_cve_impact("not-a-cve")
    assert result["found"] is False
    assert result["error_type"] == "INVALID_ID"


def test_check_cve_impact_uses_cpe(monkeypatch):
    cve = _fortios_cve([{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "7.0.0",
    }])
    monkeypatch.setattr(wl, "_get_nvd_cve", lambda cve_id, allow_fetch: cve)
    result = wl.check_cve_impact("CVE-2099-0001", owner="Internal")
    assert result["overall_status"] == "affected"
    assert [a["asset_id"] for a in result["assets"]] == ["fortinet-fortios"]


def test_kev_exposure_matches_vendor_and_product(monkeypatch):
    catalog = [
        {"cveID": "CVE-2099-0001", "vendorProject": "Fortinet", "product": "FortiOS and FortiProxy",
         "dateAdded": "2099-01-02", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2099-0002", "vendorProject": "Ivanti", "product": "Connect Secure", "dateAdded": "2099-01-03"},
    ]
    monkeypatch.setattr(wl, "fetch_kev_catalog", lambda: catalog)
    monkeypatch.setattr(wl, "_get_nvd_cve", lambda cve_id, allow_fetch: None)
    result = wl.get_kev_exposure(since_days=0, max_lookups=0)
    assert result["total"] == 1
    item = result["items"][0]
    assert item["cve_id"] == "CVE-2099-0001"
    assert item["ransomware"] is True
    assert item["overall_status"] == "pending"
    assert result["pending_version_checks"] == 1


def test_extract_cve_ids_dedupes_and_uppercases():
    assert wl.extract_cve_ids("cve-2024-3400 and CVE-2024-3400, CVE-2025-61882") == ["CVE-2024-3400", "CVE-2025-61882"]


def test_feed_articles_are_tagged_and_content_is_not_returned(monkeypatch):
    articles = [
        {"title": "FortiGate zero-day", "link": "https://example.test/a", "source": "X", "source_key": "x",
         "summary": "short", "content": "Full text mentions CVE-2099-0001", "category": "Vulnerability"},
        {"title": "Unrelated news", "link": "https://example.test/b", "source": "X", "source_key": "x",
         "summary": "nothing", "content": "nothing here", "category": "Cyber News"},
    ]
    monkeypatch.setattr(feed, "_get_all_articles", lambda: articles)

    data = feed.get_cyber_news(limit=10)
    assert data["watchlist_matched"] == 1
    tagged = data["items"][0]
    assert tagged["watchlist_matches"][0]["asset_id"] == "fortinet-fortios"
    assert tagged["cves"] == ["CVE-2099-0001"]
    assert "content" not in tagged

    only = feed.get_cyber_news(limit=10, watchlist_only=True)
    assert [a["link"] for a in only["items"]] == ["https://example.test/a"]
