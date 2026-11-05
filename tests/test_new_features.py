"""Tests for new features: Darkweb monitoring, Script scanner, and Watchlist item CRUD."""

import pytest
from starlette.testclient import TestClient
from server import app

client = TestClient(app)


def test_darkweb_overview_endpoint():
    resp = client.get("/api/darkweb/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_active_groups" in data
    assert "threat_condition" in data
    assert data["total_active_groups"] >= 5


def test_darkweb_victims_endpoint():
    resp = client.get("/api/darkweb/victims?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert "victims" in data
    assert len(data["victims"]) > 0
    victim = data["victims"][0]
    assert "post_title" in victim
    assert "group_name" in victim
    assert "total" in data
    assert "total_pages" in data
    assert "page" in data


def test_darkweb_victims_pagination_and_query():
    # Page 1
    resp1 = client.get("/api/darkweb/victims?page=1&limit=10")
    assert resp1.status_code == 200
    d1 = resp1.json()
    assert d1["page"] == 1
    assert len(d1["victims"]) == 10
    assert d1["total"] > 1000
    assert d1["total_pages"] > 100

    # Page 2 has distinct victims
    resp2 = client.get("/api/darkweb/victims?page=2&limit=10")
    assert resp2.status_code == 200
    d2 = resp2.json()
    assert d2["page"] == 2
    assert len(d2["victims"]) == 10
    titles1 = {v["post_title"] for v in d1["victims"]}
    titles2 = {v["post_title"] for v in d2["victims"]}
    assert titles1 != titles2

    # Query search
    resp_q = client.get("/api/darkweb/victims?page=1&limit=5&q=health")
    assert resp_q.status_code == 200
    dq = resp_q.json()
    assert dq["total"] > 0
    assert len(dq["victims"]) <= 5


def test_darkweb_groups_endpoint():
    resp = client.get("/api/darkweb/groups")
    assert resp.status_code == 200
    data = resp.json()
    assert "groups" in data
    assert len(data["groups"]) >= 8
    group_names = [g["name"] for g in data["groups"]]
    assert "LockBit 3.0" in group_names
    assert "RansomHub" in group_names


def test_darkweb_iocs_endpoint():
    resp = client.get("/api/darkweb/iocs")
    assert resp.status_code == 200
    data = resp.json()
    assert "iocs" in data
    assert len(data["iocs"]) >= 5


def test_script_scanner_webshell():
    payload = "<?php eval(gzinflate(base64_decode($_POST['cmd']))); ?>"
    resp = client.post("/api/investigate/script-scan", json={"payload": payload})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    assert data["threat_score"] > 20
    assert "T1027" in data["mitre_ttps"]


def test_script_scanner_clean():
    payload = "console.log('Hello world SOC Analyst');"
    resp = client.post("/api/investigate/script-scan", json={"payload": payload})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "CLEAN"
    assert data["threat_score"] == 0


def test_watchlist_catalog_endpoint():
    resp = client.get("/api/watchlist/catalog")
    assert resp.status_code == 200
    data = resp.json()
    assert "catalog" in data
    assert len(data["catalog"]) > 10


def test_watchlist_item_crud_and_seed(tmp_path, monkeypatch):
    import core.config as config
    test_wl = tmp_path / "test_watchlist.json"
    monkeypatch.setattr(config, "WATCHLIST_FILE", test_wl)

    # 1. Seed defaults
    seed_resp = client.post("/api/watchlist/defaults")
    assert seed_resp.status_code == 200
    assert seed_resp.json()["seeded_count"] >= 5

    # 2. Add custom item
    add_resp = client.post("/api/watchlist/item", json={
        "product": "Fortinet FortiOS",
        "vendor": "Fortinet",
        "version": "7.4.9",
        "owner": "Unit Alpha",
        "criticality": "critical",
        "note": "Perimeter FW"
    })
    assert add_resp.status_code == 200
    assert add_resp.json()["success"] is True

    # 3. Delete item
    del_resp = client.request("DELETE", "/api/watchlist/item", json={
        "asset_id": "fortinet-fortios",
        "owner": "Unit Alpha"
    })
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True


def test_index_page_contains_new_menus_and_views():
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    # Capitalized navigation menus
    assert "IOC TRIAGE" in html
    assert "CASE TIMELINE" in html
    assert "SCRIPT & WEBSHELL" in html
    assert "DARKWEB MONITORING" in html
    assert "WATCHLIST MANAGER" in html
    assert "INVESTIGATION & TRIAGE" in html
    assert "ANALYSIS & REVERSE" in html
    assert "THREAT INTELLIGENCE" in html
    # Standard website menus
    assert "DASHBOARD" in html
    assert "INVESTIGATE" in html
    assert "INTELLIGENCE" in html
    assert "DOCUMENTATION" in html
    assert "STATUS" in html
    assert "API" in html
    # View containers
    assert 'id="view-casecanvas"' in html
    assert 'id="view-scriptscan"' in html
    assert 'id="view-darkweb"' in html
    assert 'id="view-watchlist"' in html
    # Modals & footer
    assert 'id="modal-docs"' in html
    assert 'id="modal-health"' in html
    assert 'id="modal-add-watchlist"' in html
    assert 'id="set-tab-users"' in html
    assert 'id="set-view-users"' in html
    assert "LazySOC v3.0.0" in html


def test_security_headers_present():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "strict-origin" in resp.headers.get("Referrer-Policy", "")


def test_web_login_flow():
    # 1. Invalid login
    bad_resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert bad_resp.status_code == 401

    # 2. Valid login
    good_resp = client.post("/api/auth/login", json={"username": "admin", "password": "lazysoc2026", "role": "SOC Lead / Admin"})
    assert good_resp.status_code == 200
    data = good_resp.json()
    assert data["success"] is True
    assert "token" in data
    token = data["token"]

    # 3. Check session
    sess_resp = client.get("/api/auth/session", headers={"Authorization": f"Bearer {token}"})
    assert sess_resp.status_code == 200
    assert sess_resp.json()["authenticated"] is True
    assert sess_resp.json()["analyst"]["username"] == "admin"

    # 4. Logout
    logout_resp = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200
    assert logout_resp.json()["success"] is True


def test_settings_and_audit_endpoints():
    # 1. Settings get
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "settings" in data
    assert "security_headers" in data

    # 2. Settings update
    update_resp = client.post("/api/settings", json={"air_gap_mode": True, "session_timeout_minutes": 45})
    assert update_resp.status_code == 200
    assert update_resp.json()["settings"]["air_gap_mode"] is True
    assert update_resp.json()["settings"]["session_timeout_minutes"] == 45

    # 3. Audit logs
    audit_resp = client.get("/api/audit-logs")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()["logs"]
    assert len(logs) > 0
    assert any("SETTINGS_UPDATED" in log.get("event", "") for log in logs)


def test_darkweb_domain_query():
    resp = client.post("/api/darkweb/domain", json={"domain": "cdkglobal.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["threat_score"] >= 75
    assert "CRITICAL" in data["verdict"]
    assert "compromised_accounts" in data
    assert "exposed_portals" in data
    assert len(data["ransomware_exposures"]) > 0


def test_darkweb_domain_query_clean():
    resp = client.post("/api/darkweb/domain", json={"domain": "uncompromised-secure-corp.id"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["threat_score"] == 0
    assert "CLEAN" in data["verdict"]
    assert len(data["ransomware_exposures"]) == 0
    assert len(data["compromised_accounts"]) == 0
    assert len(data["underground_iab_listings"]) == 0


def test_password_pwned_check():
    resp = client.post("/api/darkweb/password-pwned", json={"password": "password"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["pwned"] is True
    assert data["count"] > 1000
    assert "sha1_hash" in data


def test_user_management_crud():
    # 1. List users - root admin must exist
    resp = client.get("/api/users")
    assert resp.status_code == 200
    users = resp.json()["users"]
    assert any(u["username"] == "admin" for u in users)

    # 2. Create new analyst
    create_resp = client.post("/api/users", json={
        "username": "analyst_sarah",
        "password": "SarahPass2026!",
        "role": "Tier-2 SOC",
        "full_name": "Sarah Connor"
    })
    assert create_resp.status_code == 200
    assert create_resp.json()["success"] is True

    # 3. Login with newly created analyst
    login_resp = client.post("/api/auth/login", json={
        "username": "analyst_sarah",
        "password": "SarahPass2026!"
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]

    # 4. Update password
    update_pw_resp = client.put("/api/users/analyst_sarah/password", json={"password": "NewSarahPass2026#"}, headers={"Authorization": f"Bearer {token}"})
    assert update_pw_resp.status_code == 200

    # 5. Verify new password works
    login_new_pw = client.post("/api/auth/login", json={
        "username": "analyst_sarah",
        "password": "NewSarahPass2026#"
    })
    assert login_new_pw.status_code == 200

    # 6. Self-deletion of own account must fail
    bad_self_del = client.delete("/api/users/analyst_sarah", headers={"Authorization": f"Bearer {token}"})
    assert bad_self_del.status_code == 400
    assert "Self-deletion prohibited" in bad_self_del.json()["detail"]

    # 7. Admin deletes analyst_sarah successfully
    del_resp = client.delete("/api/users/analyst_sarah")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # 8. Self-deletion / deletion of root admin must fail
    bad_del = client.delete("/api/users/admin")
    assert bad_del.status_code == 400
