"""Shared fixtures: every test runs against a throwaway SQLite file, never data/lazysoc_cache.db."""

import pytest

import core.database as db


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "CACHE_DB_FILE", tmp_path / "test_cache.db")
    db.init_db()
    yield
