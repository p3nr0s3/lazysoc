"""Tests for scheduled digests (core.scheduler) and Microsoft Teams delivery (core.teams)."""

import json
from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import core.config as config
import core.scheduler as sch
import core.teams as teams
import server
from core.database import get_schedule
from core.digest import DigestError

client = TestClient(server.app)


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def channels(monkeypatch):
    monkeypatch.setattr(teams, "TEAMS_WEBHOOK_URL", "https://example.test/webhook/default")
    monkeypatch.setattr(teams, "TEAMS_WEBHOOKS", "soc=https://example.test/webhook/soc;bad=http://insecure.test")
    monkeypatch.setattr(teams, "PUBLIC_BASE_URL", "https://lazysoc.example.test")


@pytest.fixture
def fake_run(monkeypatch):
    """Replaces digest generation and Teams posting; records what happened."""
    calls = {"digests": [], "posts": []}

    def fake_generate(**kwargs):
        calls["digests"].append(kwargs)
        return {"id": 42, "article_count": 3, "period_start": kwargs["start_date"], "period_end": kwargs["end_date"],
                "mode": kwargs["mode"], "owner": kwargs.get("owner") or "", "provider": "claude", "model": "m",
                "overview": "Ringkasan.", "priority_actions": ["Patch"], "kpis": {"issues": 1, "critical": 1},
                "issues": [{"title": "Isu", "urgency": "critical", "exploitation": "exploited_in_the_wild", "summary": "S",
                            "products": [{"product": "FortiOS", "owners": ["Internal"]}], "cves": ["CVE-2099-1"],
                            "kev_cves": ["CVE-2099-1"], "sources": [{}]}]}

    monkeypatch.setattr(sch, "generate_digest", fake_generate)
    monkeypatch.setattr(teams, "post_card", lambda channel, payload: calls["posts"].append((channel, payload)))
    return calls


BASE = {"name": "Daily", "frequency": "daily", "time": "07:00", "period": "yesterday", "mode": "critical", "teams_channel": "soc"}


# ---- clock math ------------------------------------------------------------------

def test_daily_next_run_uses_app_timezone():
    _, _, cfg = sch.validate_schedule(BASE)
    # 22 Oct 2026 23:30 UTC = 23 Oct 06:30 WIB -> today 07:00 WIB = 00:00 UTC
    assert sch.next_run_after(cfg, utc(2026, 10, 22, 23, 30)) == utc(2026, 10, 23, 0, 0)
    # exactly at the slot -> next day
    assert sch.next_run_after(cfg, utc(2026, 10, 23, 0, 0)) == utc(2026, 10, 24, 0, 0)


def test_weekly_and_monthly_next_run():
    _, _, weekly = sch.validate_schedule({**BASE, "frequency": "weekly", "weekdays": [0, 4]})  # Mon, Fri
    # Fri 23 Oct 2026 08:00 WIB -> next Monday 26 Oct 07:00 WIB
    assert sch.next_run_after(weekly, utc(2026, 10, 23, 1, 0)) == utc(2026, 10, 26, 0, 0)
    _, _, monthly = sch.validate_schedule({**BASE, "frequency": "monthly", "month_day": 31})
    # day 31 falls back to the last day of shorter months: 30 Nov 2026
    assert sch.next_run_after(monthly, utc(2026, 11, 1, 0, 0)) == utc(2026, 11, 30, 0, 0)


@pytest.mark.parametrize("period, expected", [
    ("today", ("2026-10-23", "2026-10-23")),
    ("yesterday", ("2026-10-22", "2026-10-22")),
    ("last_7_days", ("2026-10-16", "2026-10-22")),
    ("previous_week", ("2026-10-12", "2026-10-18")),  # 23 Oct 2026 is a Friday
    ("previous_month", ("2026-09-01", "2026-09-30")),
])
def test_period_dates(period, expected):
    assert sch.period_dates(period, date(2026, 10, 23)) == expected


@pytest.mark.parametrize("bad", [
    {"name": ""}, {"time": "25:00"}, {"frequency": "hourly"}, {"period": "forever"},
    {"frequency": "weekly", "weekdays": []}, {"teams_channel": "unknown"}, {"teams_channel": "bad"}, {"provider": "openai"},
])
def test_validation_errors(bad):
    with pytest.raises(sch.ScheduleError):
        sch.validate_schedule({**BASE, **bad})


# ---- running -----------------------------------------------------------------------

def test_create_sets_next_run_only_when_enabled():
    assert sch.create(BASE)["next_run_at"]
    assert sch.create({**BASE, "enabled": False})["next_run_at"] is None


def test_run_due_runs_each_slot_once(fake_run):
    created = sch.create(BASE)
    due_time = datetime.strptime(created["next_run_at"], sch.UTC_FMT).replace(tzinfo=timezone.utc)

    assert sch.run_due(due_time - timedelta(minutes=1)) == []  # not due yet
    first = sch.run_due(due_time)
    assert [r["status"] for r in first] == ["ok"]
    assert len(fake_run["digests"]) == 1
    assert fake_run["digests"][0]["start_date"] == fake_run["digests"][0]["end_date"]  # "yesterday"
    assert sch.run_due(due_time) == []  # same slot is not run again
    stored = get_schedule(created["id"])
    assert stored["last_status"] == "ok" and stored["last_digest_id"] == 42
    assert stored["next_run_at"] > created["next_run_at"]
    channel, payload = fake_run["posts"][0]
    assert channel == "soc" and payload["type"] == "message"


def test_missed_slot_runs_once_then_moves_on(fake_run):
    created = sch.create(BASE)
    due = datetime.strptime(created["next_run_at"], sch.UTC_FMT).replace(tzinfo=timezone.utc)
    three_days_late = due + timedelta(days=3)
    assert len(sch.run_due(three_days_late)) == 1
    assert sch.run_due(three_days_late) == []
    assert get_schedule(created["id"])["next_run_at"] > three_days_late.strftime(sch.UTC_FMT)


def test_empty_period_skips_teams_by_default(monkeypatch, fake_run):
    def no_articles(**kwargs):
        raise DigestError("NO_ARTICLES", "none")

    monkeypatch.setattr(sch, "generate_digest", no_articles)
    quiet = sch.create(BASE)
    assert sch.run_now(quiet["id"])["status"] == "empty"
    assert fake_run["posts"] == []
    loud = sch.create({**BASE, "skip_empty": False})
    sch.run_now(loud["id"])
    assert len(fake_run["posts"]) == 1


def test_teams_failure_is_recorded(monkeypatch, fake_run):
    def broken(channel, payload):
        raise teams.TeamsError("HTTP 400")

    monkeypatch.setattr(teams, "post_card", broken)
    created = sch.create(BASE)
    result = sch.run_now(created["id"])
    assert result["status"] == "error" and result["digest_id"] == 42
    assert "Gagal kirim ke Teams" in get_schedule(created["id"])["last_message"]


# ---- Teams card ---------------------------------------------------------------------

def test_channels_from_environment_only_https():
    assert teams.channel_names() == ["default", "soc"]


def test_digest_card_shape_and_size():
    issue = {"title": "T" * 300, "urgency": "critical", "exploitation": "public_poc", "summary": "S" * 2000,
             "products": [{"product": "FortiOS", "owners": ["Internal"]}], "cves": ["CVE-2099-1"], "kev_cves": [], "sources": [{}]}
    digest = {"id": 7, "period_start": "2026-10-16", "period_end": "2026-10-22", "mode": "critical", "overview": "O" * 5000,
              "priority_actions": ["A" * 500] * 8, "issues": [issue] * 20, "kpis": {"issues": 20}}
    payload = teams.digest_card(digest, schedule_name="Weekly")
    card = payload["attachments"][0]["content"]
    assert payload["type"] == "message" and card["type"] == "AdaptiveCard"
    assert card["actions"][0]["url"] == "https://lazysoc.example.test/api/digest/7/pdf"
    assert len(json.dumps(payload)) < 28_000  # Teams message size limit
    assert sum(1 for b in card["body"] if b["type"] == "Container") == teams.MAX_ISSUES_IN_CARD


def test_post_card_errors(monkeypatch):
    class Resp:
        status_code, text = 400, "bad card"

    monkeypatch.setattr(teams.requests, "post", lambda url, json, timeout: Resp())
    with pytest.raises(teams.TeamsError, match="HTTP 400"):
        teams.post_card("soc", teams.test_card())
    with pytest.raises(teams.TeamsError, match="tidak dikonfigurasi"):
        teams.post_card("nope", teams.test_card())


# ---- API -----------------------------------------------------------------------------

def test_schedule_crud_endpoints():
    res = client.post("/api/schedules", json=BASE)
    assert res.status_code == 200
    sid = res.json()["id"]
    listing = client.get("/api/schedules").json()
    assert listing["teams_channels"] == ["default", "soc"] and listing["timezone"] == config.APP_TIMEZONE
    assert client.put(f"/api/schedules/{sid}", json={**BASE, "time": "99:99"}).status_code == 400
    assert client.put(f"/api/schedules/{sid}", json={**BASE, "enabled": False}).json()["next_run_at"] is None
    assert client.delete(f"/api/schedules/{sid}").status_code == 200
    assert client.delete(f"/api/schedules/{sid}").status_code == 404


def test_tick_requires_token(monkeypatch, fake_run):
    monkeypatch.setattr(server, "SCHEDULER_TRIGGER_TOKEN", "")
    assert client.post("/api/schedules/tick", headers={"X-Scheduler-Token": "x"}).status_code == 403
    monkeypatch.setattr(server, "SCHEDULER_TRIGGER_TOKEN", "cron-secret")
    assert client.post("/api/schedules/tick").status_code == 403
    assert client.post("/api/schedules/tick", headers={"X-Scheduler-Token": "wrong"}).status_code == 403
    assert client.post("/api/schedules/tick", headers={"X-Scheduler-Token": "cron-secret"}).status_code == 200


def test_tick_bypasses_login_but_other_routes_do_not(monkeypatch, fake_run):
    monkeypatch.setattr(config, "AUTH_USER", "analyst")
    monkeypatch.setattr(config, "AUTH_PASSWORD", "pw")
    monkeypatch.setattr(server, "SCHEDULER_TRIGGER_TOKEN", "cron-secret")
    assert client.post("/api/schedules/tick", headers={"X-Scheduler-Token": "cron-secret"}).status_code == 200
    assert client.get("/api/schedules").status_code == 401
