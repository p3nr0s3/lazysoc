"""Tests for the optional HTTP Basic Auth login (core.auth)."""

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

import core.config as config
from core.auth import auth_enabled, check_credentials, parse_basic_header
from server import app

client = TestClient(app)


def _basic(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def login_on(monkeypatch):
    monkeypatch.setattr(config, "AUTH_USER", "analyst")
    monkeypatch.setattr(config, "AUTH_PASSWORD", "s3cret-Pass")
    monkeypatch.setattr(config, "AUTH_PASSWORD_SHA256", "")


@pytest.fixture(autouse=True)
def login_off_by_default(monkeypatch):
    monkeypatch.setattr(config, "AUTH_USER", "")
    monkeypatch.setattr(config, "AUTH_PASSWORD", "")
    monkeypatch.setattr(config, "AUTH_PASSWORD_SHA256", "")


def test_disabled_by_default_everything_open():
    assert auth_enabled() is False
    assert client.get("/").status_code == 200
    assert client.get("/api/status").status_code == 200


def test_user_without_password_does_not_enable_login(monkeypatch):
    monkeypatch.setattr(config, "AUTH_USER", "analyst")
    assert auth_enabled() is False
    assert client.get("/api/status").status_code == 200


def test_requires_login_when_enabled(login_on):
    for path in ("/", "/api/status", "/api/watchlist", "/api/digests"):
        res = client.get(path)
        assert res.status_code == 401, path
        assert res.headers["www-authenticate"].startswith("Basic realm=")


def test_wrong_credentials_rejected(login_on):
    assert client.get("/api/status", headers=_basic("analyst", "wrong")).status_code == 401
    assert client.get("/api/status", headers=_basic("someone", "s3cret-Pass")).status_code == 401
    assert client.get("/api/status", headers={"Authorization": "Basic not-base64!!"}).status_code == 401
    assert client.get("/api/status", headers={"Authorization": "Bearer token"}).status_code == 401


def test_correct_credentials_accepted(login_on):
    assert client.get("/api/status", headers=_basic("analyst", "s3cret-Pass")).status_code == 200
    assert client.post("/api/parse", json={"raw_text": "1.1.1.1"}, headers=_basic("analyst", "s3cret-Pass")).status_code == 200


def test_healthz_is_public_and_minimal(login_on):
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_sha256_password_mode(monkeypatch):
    monkeypatch.setattr(config, "AUTH_USER", "analyst")
    monkeypatch.setattr(config, "AUTH_PASSWORD_SHA256", hashlib.sha256(b"hashed-pass").hexdigest())
    assert auth_enabled() is True
    assert check_credentials("analyst", "hashed-pass") is True
    assert check_credentials("analyst", hashlib.sha256(b"hashed-pass").hexdigest()) is False
    assert client.get("/api/status", headers=_basic("analyst", "hashed-pass")).status_code == 200


def test_password_may_contain_colon(monkeypatch):
    monkeypatch.setattr(config, "AUTH_USER", "analyst")
    monkeypatch.setattr(config, "AUTH_PASSWORD", "a:b:c")
    assert parse_basic_header(_basic("analyst", "a:b:c")["Authorization"]) == ("analyst", "a:b:c")
    assert client.get("/api/status", headers=_basic("analyst", "a:b:c")).status_code == 200
