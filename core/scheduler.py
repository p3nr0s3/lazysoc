"""
Digest scheduler for LazySOC: runs saved "Ringkasan Periode" configurations on a daily / weekly / monthly
clock (in APP_TIMEZONE) and optionally posts the result to a Microsoft Teams channel.

A background thread checks for due schedules every minute. Each run is claimed in SQLite first, so two
processes (or the thread and an external /api/schedules/tick) never run the same slot twice. A slot that
was missed while the server was down runs once when it comes back, then the schedule moves on.
"""

import calendar
import re
import threading
from datetime import date, datetime, time as dtime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from core import teams
from core.database import (
    claim_schedule_run,
    delete_schedule,
    get_schedule,
    insert_schedule,
    list_schedules,
    record_schedule_result,
    update_schedule,
)
from core.digest import DigestError, MODE_CRITICAL, MODE_GENERAL, _local_tz, generate_digest

FREQUENCIES = ("daily", "weekly", "monthly")
PERIODS = {
    "today": "Hari ini",
    "yesterday": "Kemarin",
    "last_7_days": "7 hari terakhir (s/d kemarin)",
    "last_30_days": "30 hari terakhir (s/d kemarin)",
    "previous_week": "Minggu lalu (Senin-Minggu)",
    "previous_month": "Bulan lalu",
}
RE_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
TICK_SECONDS = 60
UTC_FMT = "%Y-%m-%d %H:%M:%S"


class ScheduleError(ValueError):
    pass


# ------------------------------------------------------------------------------
# Validation and clock math
# ------------------------------------------------------------------------------

def validate_schedule(raw: Dict[str, Any]) -> Tuple[str, bool, Dict[str, Any]]:
    name = str(raw.get("name", "")).strip()[:80]
    if not name:
        raise ScheduleError("Nama jadwal wajib diisi.")
    frequency = raw.get("frequency", "daily")
    if frequency not in FREQUENCIES:
        raise ScheduleError("Frekuensi harus daily, weekly, atau monthly.")
    time_of_day = str(raw.get("time", "07:00")).strip()
    if not RE_TIME.match(time_of_day):
        raise ScheduleError("Jam harus berformat HH:MM (24 jam).")
    weekdays = sorted({int(d) for d in raw.get("weekdays", [0]) if str(d).isdigit() and 0 <= int(d) <= 6})
    if frequency == "weekly" and not weekdays:
        raise ScheduleError("Pilih minimal satu hari untuk jadwal mingguan.")
    try:
        month_day = int(raw.get("month_day", 1))
    except (TypeError, ValueError):
        month_day = 0
    if frequency == "monthly" and not 1 <= month_day <= 31:
        raise ScheduleError("Tanggal bulanan harus 1-31.")
    period = raw.get("period", "yesterday")
    if period not in PERIODS:
        raise ScheduleError("Periode berita tidak dikenal.")
    mode = raw.get("mode", MODE_CRITICAL)
    if mode not in (MODE_CRITICAL, MODE_GENERAL):
        raise ScheduleError("Mode harus critical atau general.")
    provider = raw.get("provider") or None
    if provider not in (None, "claude", "local"):
        raise ScheduleError("Provider harus claude atau local.")
    channel = str(raw.get("teams_channel") or "").strip()
    if channel and channel not in teams.channel_names():
        raise ScheduleError(f"Channel Teams '{channel}' tidak ada di konfigurasi server.")

    config = {
        "frequency": frequency,
        "time": time_of_day,
        "weekdays": weekdays or [0],
        "month_day": month_day if 1 <= month_day <= 31 else 1,
        "period": period,
        "mode": mode,
        "owner": str(raw.get("owner") or "").strip(),
        "query": str(raw.get("query") or "").strip()[:100],
        "provider": provider,
        "teams_channel": channel,
        "skip_empty": bool(raw.get("skip_empty", True)),
    }
    return name, bool(raw.get("enabled", True)), config


def next_run_after(config: Dict[str, Any], after_utc: datetime) -> datetime:
    """First scheduled moment strictly after `after_utc`, returned in UTC."""
    tz = _local_tz()
    local = after_utc.astimezone(tz)
    hour, minute = (int(p) for p in config["time"].split(":"))
    for offset in range(0, 400):
        day = local.date() + timedelta(days=offset)
        if config["frequency"] == "weekly" and day.weekday() not in config["weekdays"]:
            continue
        if config["frequency"] == "monthly":
            last_day = calendar.monthrange(day.year, day.month)[1]
            if day.day != min(config["month_day"], last_day):  # day 31 -> last day of shorter months
                continue
        candidate = datetime.combine(day, dtime(hour, minute), tzinfo=tz)
        if candidate > local:
            return candidate.astimezone(timezone.utc)
    raise ScheduleError("Tidak bisa menghitung jadwal berikutnya.")


def period_dates(period: str, run_day: date) -> Tuple[str, str]:
    """Inclusive local start/end dates of the news period for a run on `run_day`."""
    yesterday = run_day - timedelta(days=1)
    if period == "today":
        first, last = run_day, run_day
    elif period == "yesterday":
        first, last = yesterday, yesterday
    elif period == "last_7_days":
        first, last = run_day - timedelta(days=7), yesterday
    elif period == "last_30_days":
        first, last = run_day - timedelta(days=30), yesterday
    elif period == "previous_week":
        this_monday = run_day - timedelta(days=run_day.weekday())
        first, last = this_monday - timedelta(days=7), this_monday - timedelta(days=1)
    elif period == "previous_month":
        last = run_day.replace(day=1) - timedelta(days=1)
        first = last.replace(day=1)
    else:
        raise ScheduleError("Periode berita tidak dikenal.")
    return first.isoformat(), last.isoformat()


def _utc_str(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).strftime(UTC_FMT) if dt else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------------------
# CRUD
# ------------------------------------------------------------------------------

def describe(schedule: Dict[str, Any]) -> Dict[str, Any]:
    tz = _local_tz()
    out = dict(schedule)
    out["period_label"] = PERIODS.get(schedule.get("period"), schedule.get("period"))
    if schedule.get("next_run_at"):
        nxt = datetime.strptime(schedule["next_run_at"], UTC_FMT).replace(tzinfo=timezone.utc).astimezone(tz)
        out["next_run_local"] = nxt.strftime("%Y-%m-%d %H:%M")
    else:
        out["next_run_local"] = None
    return out


def all_schedules() -> List[Dict[str, Any]]:
    return [describe(s) for s in list_schedules()]


def create(raw: Dict[str, Any]) -> Dict[str, Any]:
    name, enabled, config = validate_schedule(raw)
    next_run = _utc_str(next_run_after(config, _now())) if enabled else None
    return describe(get_schedule(insert_schedule(name, enabled, config, next_run)))


def update(schedule_id: int, raw: Dict[str, Any]) -> Dict[str, Any]:
    if not get_schedule(schedule_id):
        raise ScheduleError("Jadwal tidak ditemukan.")
    name, enabled, config = validate_schedule(raw)
    next_run = _utc_str(next_run_after(config, _now())) if enabled else None
    update_schedule(schedule_id, name, enabled, config, next_run)
    return describe(get_schedule(schedule_id))


def remove(schedule_id: int) -> bool:
    return delete_schedule(schedule_id)


# ------------------------------------------------------------------------------
# Running
# ------------------------------------------------------------------------------

def run_schedule(schedule: Dict[str, Any], run_at_utc: Optional[datetime] = None) -> Dict[str, Any]:
    """Generates the digest for one schedule and posts it to Teams if a channel is set."""
    run_at = run_at_utc or _now()
    start_date, end_date = period_dates(schedule["period"], run_at.astimezone(_local_tz()).date())
    digest_id = None
    try:
        digest = generate_digest(start_date=start_date, end_date=end_date, owner=schedule.get("owner") or None,
                                 mode=schedule["mode"], provider=schedule.get("provider"), query=schedule.get("query", ""))
        digest_id = digest["id"]
    except DigestError as e:
        if e.error_type == "NO_ARTICLES":
            message = f"Tidak ada berita untuk {start_date} s/d {end_date}."
            if schedule.get("teams_channel") and not schedule.get("skip_empty", True):
                teams.post_card(schedule["teams_channel"], teams.empty_card(schedule, start_date, end_date))
                message += " Pemberitahuan dikirim ke Teams."
            record_schedule_result(schedule["id"], "empty", message, None)
            return {"status": "empty", "message": message}
        record_schedule_result(schedule["id"], "error", e.message, None)
        return {"status": "error", "message": e.message}
    except Exception as e:  # keep the scheduler thread alive whatever happens
        record_schedule_result(schedule["id"], "error", f"Gagal membuat ringkasan: {e}", None)
        return {"status": "error", "message": str(e)}

    message = f"Digest #{digest_id} dibuat ({digest['article_count']} berita, {start_date} s/d {end_date})."
    status = "ok"
    if schedule.get("teams_channel"):
        try:
            teams.post_card(schedule["teams_channel"], teams.digest_card(digest, schedule_name=schedule["name"]))
            message += f" Terkirim ke Teams ({schedule['teams_channel']})."
        except teams.TeamsError as e:
            status = "error"
            message += f" Gagal kirim ke Teams: {e}"
    record_schedule_result(schedule["id"], status, message, digest_id)
    return {"status": status, "message": message, "digest_id": digest_id}


def run_now(schedule_id: int) -> Dict[str, Any]:
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise ScheduleError("Jadwal tidak ditemukan.")
    return run_schedule(schedule)


def run_due(now_utc: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Runs every enabled schedule whose next_run_at has passed. Safe to call from several places."""
    now = now_utc or _now()
    results = []
    for schedule in list_schedules():
        due = schedule.get("next_run_at")
        if not schedule["enabled"] or not due or due > _utc_str(now):
            continue
        new_next = _utc_str(next_run_after(schedule, now))
        if not claim_schedule_run(schedule["id"], due, new_next):
            continue  # another worker took this slot
        results.append({"id": schedule["id"], "name": schedule["name"], **run_schedule(schedule, now)})
    return results


_thread: Optional[threading.Thread] = None
_stop = threading.Event()


def _loop():
    while not _stop.is_set():
        try:
            run_due()
        except Exception:
            pass  # a broken schedule must not stop the others; errors are recorded per schedule
        _stop.wait(TICK_SECONDS)


def start_background() -> bool:
    global _thread
    if _thread and _thread.is_alive():
        return False
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="lazysoc-digest-scheduler", daemon=True)
    _thread.start()
    return True


def stop_background():
    _stop.set()
