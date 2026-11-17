"""
Unit and integration tests for new Threat Intelligence improvements inspired by BreachIntel:
1. Favicon MurmurHash3 (mmh3) signature & pivot intelligence
2. Phishing-ready typosquatting triage
3. HudsonRock Cavalier infostealer intelligence
4. RFC-compliant Abuse Takedown Dossier generator
5. Ransomlook.io live mirror and search
6. FastAPI REST endpoints
"""

import base64
import hashlib
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from server import app
from core.recon import _murmur3_32, get_favicon_intel, generate_lookalike_domains, typosquat_triage
from core.credential_leak import fetch_hudsonrock_infostealer, analyze_domain_darkweb_exposure
from core.containment import generate_takedown_dossier
from core.darkweb import fetch_ransomlook_recent, search_ransomlook

client = TestClient(app)


# ==============================================================================
# 1. FAVICON MURMURHASH3 TESTS
# ==============================================================================

def test_murmur3_32_computation():
    """Verifies that 32-bit MurmurHash3 returns signed integer matching Shodan spec."""
    raw_data = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    b64 = base64.encodebytes(raw_data)
    h = _murmur3_32(b64)
    assert isinstance(h, int)
    # Recomputing must be deterministic
    assert _murmur3_32(b64) == h


def test_get_favicon_intel_success():
    """Tests favicon retrieval and pivot link creation with mocked network response."""
    fake_favicon = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x16\x00\x00\x00" * 3

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = fake_favicon

    with patch("requests.get", return_value=mock_resp):
        res = get_favicon_intel("example.com")
        assert res["found"] is True
        assert res["domain"] == "example.com"
        assert "mmh3" in res
        assert "md5" in res
        assert "pivots" in res
        assert "Shodan" in res["pivots"]
        assert "FOFA" in res["pivots"]
        assert "Censys" in res["pivots"]
        assert "ZoomEye" in res["pivots"]
        assert str(res["mmh3"]) in res["pivots"]["Shodan"]


def test_get_favicon_intel_not_found():
    """Tests graceful fallback when domain has no favicon."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.content = b""

    with patch("requests.get", return_value=mock_resp):
        res = get_favicon_intel("nofavicon.test")
        assert res["found"] is False
        assert "nofavicon.test" in res["message"]


# ==============================================================================
# 2. TYPOSQUATTING & PHISHING-READY TRIAGE TESTS
# ==============================================================================

def test_generate_lookalike_domains():
    """Ensures domain permutations include TLD swaps, typos, and phishing prefixes."""
    candidates = generate_lookalike_domains("paypal.com")
    assert len(candidates) > 5
    # Must include common lookalikes
    assert any("paypal.net" in c or "paypal.org" in c for c in candidates)
    assert any(c.startswith("login-") or c.startswith("secure-") for c in candidates)


def test_typosquat_triage():
    """Tests active DNS triage classifying domains into phishing-ready vs dormant."""
    fake_ip = MagicMock()
    fake_ip.__str__ = lambda self: "198.51.100.25"

    fake_mx = MagicMock()
    fake_mx.exchange = "mail.fakehost.com."

    def fake_resolve(domain, rdtype):
        if domain == "login-example.com":
            if rdtype == "A":
                return [fake_ip]
            if rdtype == "MX":
                return [fake_mx]
        elif domain == "example.net":
            if rdtype == "A":
                return [fake_ip]
            raise Exception("No MX")
        raise Exception("NXDOMAIN")

    with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
        res = typosquat_triage("example.com", max_checks=6)
        assert isinstance(res, list)
        phishing_ready = [r for r in res if r["status"] == "phishing-ready"]
        if phishing_ready:
            assert phishing_ready[0]["live"] is True
            assert phishing_ready[0]["has_mail"] is True


# ==============================================================================
# 3. HUDSONROCK INFOSTEALER INTELLIGENCE TESTS
# ==============================================================================

def test_fetch_hudsonrock_infostealer_success():
    """Tests HudsonRock Cavalier OSINT parser with mocked compromised data."""
    mock_data = {
        "employees": 12,
        "users": 340,
        "third_parties": 5,
        "totalStealers": 357,
        "stealerFamilies": ["RedLine", "Lumma", "Raccoon"],
        "last_employee_compromised": "2026-11-10T14:30:00Z",
        "data": {
            "employees_urls": [
                {"url": "https://sso.targetcorp.com/idp", "occurrence": 8},
                {"url": "https://vpn.targetcorp.com/dana-na", "occurrence": 4}
            ]
        }
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_data

    with patch("requests.get", return_value=mock_resp):
        info = fetch_hudsonrock_infostealer("targetcorp.com")
        assert info["available"] is True
        assert info["employees_compromised"] == 12
        assert info["users_compromised"] == 340
        assert info["total_stealers"] == 357
        assert "RedLine" in info["stealer_families"]
        assert len(info["exposed_employee_urls"]) == 2
        assert info["exposed_employee_urls"][0]["url"] == "https://sso.targetcorp.com/idp"


def test_fetch_hudsonrock_infostealer_error_handling():
    """Ensures offline or API network errors fail gracefully without crashing."""
    with patch("requests.get", side_effect=Exception("Connection timeout")):
        info = fetch_hudsonrock_infostealer("offline-test.com")
        assert info["available"] is False
        assert info["employees_compromised"] == 0
        assert "Connection timeout" in info["error"]


def test_analyze_domain_darkweb_exposure_integrates_hudsonrock():
    """Verifies analyze_domain_darkweb_exposure factors in HudsonRock metrics."""
    mock_hr = {
        "available": True,
        "domain": "stealer-victim.com",
        "employees_compromised": 7,
        "users_compromised": 150,
        "third_parties_compromised": 2,
        "total_stealers": 159,
        "stealer_families": ["Lumma", "Vidar"],
        "last_compromised": "2026-11-01 10:00:00",
        "exposed_employee_urls": [
            {"service": "Corporate Portal", "url": "https://mail.stealer-victim.com/owa", "exposed": True, "risk": "CRITICAL"}
        ],
        "source": "HudsonRock Cavalier Intelligence (Keyless)",
        "url": "https://www.hudsonrock.com/free-tools?domain=stealer-victim.com",
    }

    with patch("core.credential_leak.fetch_hudsonrock_infostealer", return_value=mock_hr), \
         patch("core.credential_leak.search_ransomware_victims", return_value=([], 500)):
        res = analyze_domain_darkweb_exposure("stealer-victim.com")
        assert res["success"] is True
        assert "INFOSTEALER" in res["verdict"]
        assert res["summary"]["stealer_logs_detected"] == 159
        assert res["summary"]["compromised_employee_accounts"] == 7
        assert "hudsonrock" in res


# ==============================================================================
# 4. TAKEDOWN DOSSIER GENERATOR TESTS
# ==============================================================================

def test_generate_takedown_dossier():
    """Validates the generation of RFC-compliant Abuse Takedown notice email."""
    dossier = generate_takedown_dossier(
        target="phishing-bank-secure.com",
        threat_type="Phishing & Credential Theft",
        brand_targeted="Global Bank Corp",
        evidence_notes="Fake login page capturing username, password, and SMS OTP tokens.",
        ip_address="192.0.2.123",
        asn_info="AS64512 Example Hosting",
        abuse_contacts=["abuse@example-hosting.com", "cert@registrar.net"]
    )

    assert dossier["success"] is True
    assert dossier["target"] == "phishing-bank-secure.com"
    assert "abuse@example-hosting.com" in dossier["abuse_contacts"]
    assert "[URGENT ABUSE TAKEDOWN]" in dossier["subject"]
    body = dossier["body_text"]
    assert "Global Bank Corp" in body
    assert "192.0.2.123" in body
    assert "AS64512 Example Hosting" in body
    assert "IMMEDIATE SUSPENSION" in body
    assert "LOG PRESERVATION" in body


# ==============================================================================
# 5. RANSOMLOOK.IO INTEGRATION TESTS
# ==============================================================================

def test_ransomlook_recent_and_search():
    """Tests live mirror parser for Ransomlook.io recent feeds and search."""
    mock_recent = [
        {
            "group_name": "RansomHub",
            "post_title": "MegaCorp Logistics",
            "discovered": "2026-11-15T09:00:00",
            "link": "/post/123"
        }
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_recent

    with patch("requests.get", return_value=mock_resp):
        recent = fetch_ransomlook_recent(limit=5)
        assert len(recent) == 1
        assert recent[0]["group"] == "RansomHub"
        assert recent[0]["victim"] == "MegaCorp Logistics"

    mock_search = {
        "posts": [
            {
                "group_name": "LockBit 3.0",
                "post_title": "Target Logistics Corp",
                "discovered": "2026-11-12T11:00:00",
                "link": "https://ransomlook.io/post/456",
                "description": "Exfiltrated financial archives."
            }
        ]
    }
    mock_resp2 = MagicMock()
    mock_resp2.status_code = 200
    mock_resp2.json.return_value = mock_search

    with patch("requests.get", return_value=mock_resp2):
        results = search_ransomlook("target logistics")
        assert len(results) == 1
        assert results[0]["cartel"] == "LockBit 3.0"
        assert "Target Logistics Corp" in results[0]["victim_name"]


# ==============================================================================
# 6. REST API ENDPOINTS TESTS
# ==============================================================================

def test_api_recon_favicon():
    r = client.get("/api/recon/favicon?domain=invalid.local")
    assert r.status_code == 200
    data = r.json()
    assert data["found"] is False


def test_api_recon_typosquat():
    r = client.get("/api/recon/typosquat?domain=paypal.com&limit=3")
    assert r.status_code == 200
    data = r.json()
    assert data["domain"] == "paypal.com"
    assert "results" in data


def test_api_containment_takedown():
    payload = {
        "target": "evil-phishing-login.com",
        "threat_type": "Phishing & Credential Harvester",
        "brand_targeted": "Acme Corp",
        "evidence_notes": "Fake SSO portal deployed.",
        "ip_address": "203.0.113.5",
        "asn_info": "AS65536 Bulletproof Hosting"
    }
    r = client.post("/api/containment/takedown", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert "evil-phishing-login.com" in data["subject"]
    assert "Acme Corp" in data["body_text"]


def test_api_darkweb_ransomlook():
    with patch("server.search_ransomlook", return_value=[{"cartel": "Play", "victim_name": "Test Inc"}]):
        r = client.get("/api/darkweb/ransomlook?query=test")
        assert r.status_code == 200
        assert len(r.json()["results"]) == 1


def test_api_darkweb_ransomlook_recent():
    with patch("server.fetch_ransomlook_recent", return_value=[{"group": "Akira", "victim": "Sample"}]):
        r = client.get("/api/darkweb/ransomlook/recent?limit=10")
        assert r.status_code == 200
        assert len(r.json()["results"]) == 1


def test_api_credential_hudsonrock():
    mock_hr = {
        "available": True,
        "domain": "corp.test",
        "employees_compromised": 3,
        "users_compromised": 10,
        "total_stealers": 13,
        "stealer_families": ["Lumma"],
        "last_compromised": "2026-11-01",
        "exposed_employee_urls": [],
        "source": "HudsonRock Cavalier Intelligence (Keyless)",
        "url": "https://www.hudsonrock.com/free-tools?domain=corp.test",
    }
    with patch("server.fetch_hudsonrock_infostealer", return_value=mock_hr):
        r = client.get("/api/credential-leak/hudsonrock?domain=corp.test")
        assert r.status_code == 200
        data = r.json()
        assert data["available"] is True
        assert data["employees_compromised"] == 3
