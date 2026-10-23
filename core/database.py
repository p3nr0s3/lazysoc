"""SQLite caching and history layer for LazySOC."""

import sqlite3
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from core.config import CACHE_DB_FILE, CACHE_TTL_HOURS


def utc_now() -> datetime:
    """Helper to return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(CACHE_DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Initializes tables in the SQLite database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc_value TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                overall_verdict TEXT NOT NULL,
                vt_data TEXT,
                abuse_data TEXT,
                hit_count INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_iocs INTEGER NOT NULL,
                malicious INTEGER NOT NULL,
                suspicious INTEGER NOT NULL,
                clean INTEGER NOT NULL,
                unknown INTEGER NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nvd_cve_cache (
                cve_id TEXT PRIMARY KEY,
                cve_json TEXT NOT NULL,
                fetched_at TIMESTAMP NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_articles (
                link TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source TEXT,
                source_key TEXT,
                category TEXT,
                summary TEXT,
                content TEXT,
                pub_date TEXT,
                published_at TIMESTAMP NOT NULL,
                fetched_at TIMESTAMP NOT NULL
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_feed_articles_published ON feed_articles (published_at)")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS digest_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL,
                next_run_at TEXT,
                last_run_at TEXT,
                last_status TEXT,
                last_message TEXT,
                last_digest_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS digests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                period_start TEXT NOT NULL,
                period_end TEXT NOT NULL,
                owner TEXT,
                mode TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT,
                article_count INTEGER NOT NULL,
                digest_json TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_summaries (
                article_key TEXT PRIMARY KEY,
                link TEXT,
                model TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


# Initialize on import
init_db()


def get_cached_ioc(ioc_value: str) -> Optional[Dict[str, Any]]:
    """Fetches valid, non-expired cache record for an IoC."""
    val = ioc_value.lower().strip()
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM ioc_cache 
            WHERE ioc_value = ? AND expires_at > ?
            """,
            (val, now_str),
        )
        row = cursor.fetchone()
        if not row:
            return None

        # Safely increment hit counter without failing cache retrieval
        try:
            cursor.execute(
                "UPDATE ioc_cache SET hit_count = hit_count + 1 WHERE ioc_value = ?",
                (val,),
            )
            conn.commit()
        except Exception:
            pass

        vt_parsed = json.loads(row["vt_data"]) if row["vt_data"] else None
        abuse_parsed = json.loads(row["abuse_data"]) if row["abuse_data"] else None

        return {
            "ioc_value": row["ioc_value"],
            "ioc_type": row["ioc_type"],
            "verdict": row["overall_verdict"],
            "vt_data": vt_parsed,
            "abuse_data": abuse_parsed,
            "hit_count": row["hit_count"],
            "updated_at": row["updated_at"],
            "expires_at": row["expires_at"],
            "is_cached": True,
        }


def save_cached_ioc(
    ioc_value: str,
    ioc_type: str,
    verdict: str,
    vt_data: Optional[Dict],
    abuse_data: Optional[Dict],
    ttl_hours: int = CACHE_TTL_HOURS,
):
    """Saves or updates an IoC result in the cache."""
    val = ioc_value.lower().strip()
    now = utc_now()
    expires = now + timedelta(hours=ttl_hours)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

    vt_json = json.dumps(vt_data) if vt_data else None
    abuse_json = json.dumps(abuse_data) if abuse_data else None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO ioc_cache (ioc_value, ioc_type, overall_verdict, vt_data, abuse_data, hit_count, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(ioc_value) DO UPDATE SET
                overall_verdict = excluded.overall_verdict,
                vt_data = excluded.vt_data,
                abuse_data = excluded.abuse_data,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
            """,
            (val, ioc_type, verdict, vt_json, abuse_json, now_str, expires_str),
        )
        conn.commit()


def get_all_cached_iocs(limit: int = 500) -> List[Dict[str, Any]]:
    """Returns list of cached IoCs for management view."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ioc_value, ioc_type, overall_verdict, hit_count, updated_at, expires_at
            FROM ioc_cache
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def clear_cache() -> int:
    """Purges all cached IoCs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ioc_cache")
        count = cursor.rowcount
        conn.commit()
        return count


def delete_cache_entry(ioc_value: str) -> bool:
    """Deletes a specific entry from the cache."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ioc_cache WHERE ioc_value = ?", (ioc_value.lower().strip(),))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted


def get_cache_stats() -> Dict[str, int]:
    """Returns count of active and expired entries."""
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ioc_cache WHERE expires_at > ?", (now_str,))
        active_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ioc_cache WHERE expires_at <= ?", (now_str,))
        expired_count = cursor.fetchone()[0]

        return {"active": active_count, "expired": expired_count, "total": active_count + expired_count}


def log_scan(total: int, mal: int, susp: int, clean: int, unk: int):
    """Logs a completed batch scan to the audit history."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_history (total_iocs, malicious, suspicious, clean, unknown)
            VALUES (?, ?, ?, ?, ?)
            """,
            (total, mal, susp, clean, unk),
        )
        conn.commit()


def get_cached_nvd_cve(cve_id: str, max_age_hours: int = 72) -> Optional[Dict[str, Any]]:
    """Returns the raw NVD CVE object if it was fetched within max_age_hours."""
    cutoff = (utc_now() - timedelta(hours=max_age_hours)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cve_json FROM nvd_cve_cache WHERE cve_id = ? AND fetched_at > ?",
            (cve_id.upper(), cutoff),
        )
        row = cursor.fetchone()
        return json.loads(row["cve_json"]) if row else None


def save_cached_nvd_cve(cve_id: str, cve_obj: Dict[str, Any]):
    """Stores a raw NVD CVE object (including its CPE configurations)."""
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO nvd_cve_cache (cve_id, cve_json, fetched_at) VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET cve_json = excluded.cve_json, fetched_at = excluded.fetched_at
            """,
            (cve_id.upper(), json.dumps(cve_obj), now_str),
        )
        conn.commit()


def get_ai_summary(article_key: str) -> Optional[Dict[str, Any]]:
    """Returns a stored AI summary for an article, if any."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT model, summary_json, created_at FROM ai_summaries WHERE article_key = ?",
            (article_key,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "model": row["model"],
            "summary": json.loads(row["summary_json"]),
            "created_at": row["created_at"],
        }


def save_ai_summary(article_key: str, link: str, model: str, summary: Dict[str, Any]):
    """Stores an AI summary so each article is only summarized once."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO ai_summaries (article_key, link, model, summary_json) VALUES (?, ?, ?, ?)
            ON CONFLICT(article_key) DO UPDATE SET
                model = excluded.model,
                summary_json = excluded.summary_json,
                created_at = CURRENT_TIMESTAMP
            """,
            (article_key, link, model, json.dumps(summary)),
        )
        conn.commit()


def save_feed_articles(articles: List[Dict[str, Any]]):
    """Upserts fetched RSS articles so digests can cover days the live feed no longer shows."""
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.executemany(
            """
            INSERT INTO feed_articles (link, title, source, source_key, category, summary, content, pub_date, published_at, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(link) DO UPDATE SET
                title = excluded.title,
                category = excluded.category,
                summary = excluded.summary,
                content = excluded.content
            """,
            [
                (
                    a["link"], a["title"], a.get("source"), a.get("source_key"), a.get("category"),
                    a.get("summary"), a.get("content"), a.get("pub_date"), a.get("published_at") or now_str, now_str,
                )
                for a in articles if a.get("link")
            ],
        )
        conn.commit()


def get_feed_articles_between(start: str, end: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """Returns stored articles published in [start, end) (UTC 'YYYY-MM-DD HH:MM:SS'), newest first."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT link, title, source, source_key, category, summary, content, pub_date, published_at
            FROM feed_articles
            WHERE published_at >= ? AND published_at < ?
            ORDER BY published_at DESC
            LIMIT ?
            """,
            (start, end, limit),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_feed_article(link: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM feed_articles WHERE link = ?", (link,))
        row = cursor.fetchone()
        return dict(row) if row else None


def _schedule_row(row) -> Dict[str, Any]:
    data = dict(row)
    data.update(json.loads(data.pop("config_json")))
    data["enabled"] = bool(data["enabled"])
    return data


def list_schedules() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM digest_schedules ORDER BY id")
        return [_schedule_row(r) for r in cursor.fetchall()]


def get_schedule(schedule_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM digest_schedules WHERE id = ?", (schedule_id,))
        row = cursor.fetchone()
        return _schedule_row(row) if row else None


def insert_schedule(name: str, enabled: bool, config: Dict[str, Any], next_run_at: Optional[str]) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO digest_schedules (name, enabled, config_json, next_run_at) VALUES (?, ?, ?, ?)",
            (name, 1 if enabled else 0, json.dumps(config), next_run_at),
        )
        conn.commit()
        return cursor.lastrowid


def update_schedule(schedule_id: int, name: str, enabled: bool, config: Dict[str, Any], next_run_at: Optional[str]) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE digest_schedules SET name = ?, enabled = ?, config_json = ?, next_run_at = ? WHERE id = ?",
            (name, 1 if enabled else 0, json.dumps(config), next_run_at, schedule_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_schedule(schedule_id: int) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM digest_schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        return cursor.rowcount > 0


def claim_schedule_run(schedule_id: int, expected_next_run: str, new_next_run: Optional[str]) -> bool:
    """Atomically moves next_run_at forward; only the caller that succeeds runs the schedule."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE digest_schedules SET next_run_at = ? WHERE id = ? AND next_run_at = ? AND enabled = 1",
            (new_next_run, schedule_id, expected_next_run),
        )
        conn.commit()
        return cursor.rowcount == 1


def record_schedule_result(schedule_id: int, status: str, message: str, digest_id: Optional[int]):
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE digest_schedules SET last_run_at = ?, last_status = ?, last_message = ?, last_digest_id = COALESCE(?, last_digest_id) WHERE id = ?",
            (now_str, status, message[:500], digest_id, schedule_id),
        )
        conn.commit()


def save_digest(digest: Dict[str, Any]) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO digests (period_start, period_end, owner, mode, provider, model, article_count, digest_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                digest["period_start"], digest["period_end"], digest.get("owner"), digest["mode"],
                digest["provider"], digest.get("model"), digest["article_count"], json.dumps(digest),
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_digest(digest_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, created_at, digest_json FROM digests WHERE id = ?", (digest_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {**json.loads(row["digest_json"]), "id": row["id"], "created_at": row["created_at"]}


def list_digests(limit: int = 20) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, created_at, period_start, period_end, owner, mode, provider, model, article_count
            FROM digests ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_scan_history(limit: int = 20) -> List[Dict[str, Any]]:
    """Returns recent scan history logs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scan_history
            ORDER BY scan_timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
