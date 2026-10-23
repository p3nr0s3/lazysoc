"""Configuration and environment settings for LazySOC."""

import os
import shutil
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
KEYS_FILE = DATA_DIR / "keys.json"
CACHE_DB_FILE = DATA_DIR / "lazysoc_cache.db"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Auto-migrate legacy slothery_cache.db if present
legacy_cache = DATA_DIR / "slothery_cache.db"
if legacy_cache.exists() and not CACHE_DB_FILE.exists():
    try:
        shutil.move(str(legacy_cache), str(CACHE_DB_FILE))
    except Exception:
        pass

# Load .env if present
load_dotenv(BASE_DIR / ".env")

# Settings
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))
RATE_LIMIT_COOLDOWN_SECONDS = int(os.getenv("RATE_LIMIT_COOLDOWN_SECONDS", "65"))

# API Base URLs
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"

# NIST NVD Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")

# Optional login (HTTP Basic Auth) for every page and API call except /healthz.
# Enabled when a user and a password (or its SHA-256 hex digest) are set.
AUTH_USER = os.getenv("LAZYSOC_AUTH_USER", "")
AUTH_PASSWORD = os.getenv("LAZYSOC_AUTH_PASSWORD", "")
AUTH_PASSWORD_SHA256 = os.getenv("LAZYSOC_AUTH_PASSWORD_SHA256", "").strip().lower()

# Calendar timezone for digest periods and schedules (servers such as Render run in UTC).
APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Asia/Jakarta")

# Digest scheduler. Runs inside the server; on hosts that sleep when idle, call POST /api/schedules/tick
# from an external cron with the X-Scheduler-Token header instead.
SCHEDULER_ENABLED = os.getenv("SCHEDULER_ENABLED", "true").lower() in ("true", "1", "yes")
SCHEDULER_TRIGGER_TOKEN = os.getenv("SCHEDULER_TRIGGER_TOKEN", "")

# Microsoft Teams delivery via Workflows webhooks. Secret URLs live only in the environment:
# TEAMS_WEBHOOK_URL (channel "default") and/or TEAMS_WEBHOOKS="soc=https://...;customer-a=https://..."
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")
TEAMS_WEBHOOKS = os.getenv("TEAMS_WEBHOOKS", "")
# Public base URL of this LazySOC instance, used for the "Buka PDF" button in Teams cards.
PUBLIC_BASE_URL = os.getenv("LAZYSOC_PUBLIC_URL", "").rstrip("/")

# Critical tools watchlist (internal + customer inventory). Kept under data/ so it is never committed.
WATCHLIST_FILE = Path(os.getenv("WATCHLIST_FILE", str(DATA_DIR / "watchlist.json")))

# AI article summaries (Claude). Credentials are resolved by the Anthropic SDK (ANTHROPIC_API_KEY, etc.).
AI_SUMMARY_ENABLED = os.getenv("AI_SUMMARY_ENABLED", "true").lower() in ("true", "1", "yes")
AI_SUMMARY_MODEL = os.getenv("AI_SUMMARY_MODEL", "claude-opus-5-5")
AI_SUMMARY_EFFORT = os.getenv("AI_SUMMARY_EFFORT", "low")
AI_DEFAULT_PROVIDER = os.getenv("AI_DEFAULT_PROVIDER", "claude").lower()  # "claude" or "local"

# Local LLM via an OpenAI-compatible server (Ollama, LM Studio, vLLM, llama.cpp). Configured here only,
# never taken from requests, so the summarize endpoints cannot be pointed at arbitrary hosts.
LOCAL_LLM_BASE_URL = os.getenv("LOCAL_LLM_BASE_URL", "").rstrip("/")  # e.g. http://localhost:11434/v1
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "")
LOCAL_LLM_API_KEY = os.getenv("LOCAL_LLM_API_KEY", "")
LOCAL_LLM_TIMEOUT_SECONDS = int(os.getenv("LOCAL_LLM_TIMEOUT_SECONDS", "300"))

# Watchlist upload from the web UI (the app has no authentication; disable on shared instances).
ALLOW_WATCHLIST_UPLOAD = os.getenv("ALLOW_WATCHLIST_UPLOAD", "true").lower() in ("true", "1", "yes")

# Free tier limits (reference)
# VirusTotal: 4 requests / minute, 500 requests / day
# AbuseIPDB: 1000 requests / day
VT_MINUTE_RATE_LIMIT = 4
VT_MINUTE_WINDOW_SECONDS = 60

# CORS Configuration (Restricted by default for security)
raw_cors = os.getenv("CORS_ALLOWED_ORIGINS", "")
if raw_cors:
    CORS_ALLOWED_ORIGINS = [o.strip() for o in raw_cors.split(",") if o.strip()]
else:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

