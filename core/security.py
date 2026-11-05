"""
Security, Web Authentication, User Management, and Settings Manager for LazySOC.
Provides PBKDF2-HMAC-SHA256 password hashing with per-user salt, SQLite persistent
user store (create/delete/update user), session management, brute-force lockout defense,
audit logging, and runtime security settings.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import core.config as config
from core.database import get_db_connection

logger = logging.getLogger("lazysoc.security")

# In-memory storage for active sessions, failed attempts, and audit logs
_active_sessions: Dict[str, Dict[str, Any]] = {}
_failed_attempts: Dict[str, List[float]] = {}  # ip -> list of timestamps
_audit_trail: deque = deque(maxlen=200)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60

SETTINGS_FILE = config.DATA_DIR / "security_settings.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ==============================================================================
# CRYPTOGRAPHIC PASSWORD HASHING (PBKDF2-HMAC-SHA256 with 100,000 iterations)
# ==============================================================================

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generates cryptographic PBKDF2-HMAC-SHA256 hash with unique salt."""
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return pw_hash, salt


def verify_password(password: str, pw_hash: str, salt: str) -> bool:
    """Constant-time verification of password against stored PBKDF2 hash."""
    check_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(check_hash, pw_hash)


# ==============================================================================
# USER MANAGEMENT & REPOSITORY
# ==============================================================================

def bootstrap_initial_users():
    """Initializes user store and bootstraps primary admin if no users exist."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            if count == 0:
                init_pass = config.AUTH_PASSWORD or "lazysoc2026"
                p_hash, salt = hash_password(init_pass)
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, role, full_name, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, datetime('now'), 1)
                    """,
                    ("admin", p_hash, salt, "SOC Lead / Admin", "Primary SOC Administrator")
                )
                conn.commit()
                logger.info("Bootstrapped initial root administrator account 'admin'")
    except Exception as e:
        logger.error("Error bootstrapping initial users: %s", e)


# Run bootstrap on module import
bootstrap_initial_users()


def list_analyst_users() -> List[Dict[str, Any]]:
    """Returns all registered analyst accounts (hashes and salts omitted)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT username, role, full_name, created_at, last_login, is_active
            FROM users
            ORDER BY created_at ASC
            """
        )
        rows = cursor.fetchall()
        return [
            {
                "username": r["username"],
                "role": r["role"],
                "full_name": r["full_name"] or r["username"],
                "created_at": str(r["created_at"]) if r["created_at"] else "-",
                "last_login": str(r["last_login"]) if r["last_login"] else "Never",
                "is_active": bool(r["is_active"]),
            }
            for r in rows
        ]


def get_analyst_user(username: str) -> Optional[Dict[str, Any]]:
    """Fetches user details by username."""
    u = username.strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (u,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)


def create_analyst_user(
    username: str,
    password: str,
    role: str = "Tier-2 SOC",
    full_name: Optional[str] = None,
    requester: str = "admin"
) -> Tuple[bool, str]:
    """Creates a new analyst account with PBKDF2 encrypted password."""
    u = username.strip().lower()
    if not re.match(r"^[a-zA-Z0-9_\.\-]{3,32}$", u):
        return False, "Username must be 3-32 characters long and contain only letters, numbers, hyphens, dots, or underscores."

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    valid_roles = ("Tier-1 Analyst", "Tier-2 SOC", "SOC Lead / Admin")
    if role not in valid_roles:
        return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = ?", (u,))
        if cursor.fetchone()[0] > 0:
            return False, f"Analyst user '{u}' already exists."

        p_hash, salt = hash_password(password)
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, salt, role, full_name, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, datetime('now'), 1)
            """,
            (u, p_hash, salt, role, full_name or u)
        )
        conn.commit()

    record_audit_log("USER_CREATED", requester, f"Created new analyst account '{u}' with role {role}")
    return True, f"Analyst account '{u}' created successfully."


def delete_analyst_user(username: str, requester: str = "admin") -> Tuple[bool, str]:
    """Deletes an analyst user account with safety checks."""
    u = username.strip().lower()
    req = requester.strip().lower()

    if u == req:
        return False, "Self-deletion prohibited: You cannot delete your currently authenticated administrator account."

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE LOWER(username) = ?", (u,))
        row = cursor.fetchone()
        if not row:
            return False, f"Analyst user '{u}' not found."

        # If deleting an admin, ensure there is at least one other admin remaining
        if row["role"] == "SOC Lead / Admin":
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'SOC Lead / Admin'")
            admin_count = cursor.fetchone()[0]
            if admin_count <= 1:
                return False, "Cannot delete the last remaining SOC Lead / Admin account."

        cursor.execute("DELETE FROM users WHERE LOWER(username) = ?", (u,))
        conn.commit()

    record_audit_log("USER_DELETED", requester, f"Deleted analyst user account '{u}'")
    return True, f"Analyst account '{u}' deleted successfully."


def update_analyst_password(username: str, new_password: str, requester: str = "admin") -> Tuple[bool, str]:
    """Updates password for a user with newly generated salt and PBKDF2 hash."""
    u = username.strip().lower()
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters long."

    p_hash, salt = hash_password(new_password)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = ?", (u,))
        if cursor.fetchone()[0] == 0:
            return False, f"Analyst user '{u}' not found."

        cursor.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE LOWER(username) = ?",
            (p_hash, salt, u)
        )
        conn.commit()

    record_audit_log("PASSWORD_UPDATED", requester, f"Updated password for analyst '{u}'")
    return True, f"Password for '{u}' updated successfully."


def update_analyst_role(username: str, new_role: str, requester: str = "admin") -> Tuple[bool, str]:
    """Updates role permissions for an analyst."""
    u = username.strip().lower()
    valid_roles = ("Tier-1 Analyst", "Tier-2 SOC", "SOC Lead / Admin")
    if new_role not in valid_roles:
        return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = ?", (u,))
        if cursor.fetchone()[0] == 0:
            return False, f"Analyst user '{u}' not found."

        cursor.execute("UPDATE users SET role = ? WHERE LOWER(username) = ?", (new_role, u))
        conn.commit()

    record_audit_log("USER_ROLE_UPDATED", requester, f"Changed role of '{u}' to {new_role}")
    return True, f"Role for '{u}' updated to {new_role}."


# ==============================================================================
# SETTINGS & AUDIT LOGS
# ==============================================================================

def load_security_settings() -> Dict[str, Any]:
    """Loads security settings with safe defaults."""
    defaults = {
        "require_web_login": False,
        "air_gap_mode": False,
        "session_timeout_minutes": 60,
        "enforce_security_headers": True,
        "max_login_attempts": MAX_FAILED_ATTEMPTS,
        "lockout_seconds": LOCKOUT_DURATION_SECONDS,
        "allowed_roles": ["Tier-1 Analyst", "Tier-2 SOC", "SOC Lead / Admin"],
    }
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                defaults.update(saved)
        except Exception as e:
            logger.warning("Failed to read security settings: %s", e)
    return defaults


def save_security_settings(settings: Dict[str, Any]) -> bool:
    """Persists security settings to disk."""
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        current = load_security_settings()
        current.update(settings)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
        return True
    except Exception as e:
        logger.error("Failed to save security settings: %s", e)
        return False


def record_audit_log(event_type: str, username: str, details: str, ip: str = "127.0.0.1"):
    """Appends an event to the security audit trail."""
    entry = {
        "id": secrets.token_hex(4),
        "timestamp": _now_iso(),
        "event": event_type,
        "username": username,
        "ip": ip,
        "details": details,
    }
    _audit_trail.appendleft(entry)


def get_audit_trail(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns the most recent security audit log entries."""
    return list(_audit_trail)[:limit]


# ==============================================================================
# RATE-LIMITING & AUTHENTICATION
# ==============================================================================

def is_rate_limited(ip: str) -> Tuple[bool, int]:
    """Checks whether the client IP is temporarily locked out due to failed attempts."""
    now = time.time()
    history = _failed_attempts.get(ip, [])
    recent = [t for t in history if now - t < LOCKOUT_DURATION_SECONDS]
    _failed_attempts[ip] = recent
    if len(recent) >= MAX_FAILED_ATTEMPTS:
        remaining = int(LOCKOUT_DURATION_SECONDS - (now - recent[0]))
        return True, max(remaining, 1)
    return False, 0


def record_failed_attempt(ip: str):
    """Registers a failed authentication attempt."""
    now = time.time()
    if ip not in _failed_attempts:
        _failed_attempts[ip] = []
    _failed_attempts[ip].append(now)


def clear_failed_attempts(ip: str):
    """Clears failed attempts on successful authentication."""
    if ip in _failed_attempts:
        del _failed_attempts[ip]


def verify_analyst_password(username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validates username and password against:
    1. SQLite persistent users table (PBKDF2-HMAC-SHA256)
    2. Environment config.AUTH_USER & config.AUTH_PASSWORD (for Basic Auth compatibility)
    """
    u_lower = username.strip().lower()

    # 1. Check persistent SQLite database users
    user_record = get_analyst_user(u_lower)
    if user_record and user_record.get("is_active"):
        if verify_password(password, user_record["password_hash"], user_record["salt"]):
            # Update last_login
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET last_login = datetime('now') WHERE LOWER(username) = ?", (u_lower,))
                    conn.commit()
            except Exception:
                pass
            return True, {
                "username": user_record["username"],
                "role": user_record["role"],
                "full_name": user_record["full_name"],
                "permissions": ["all"] if user_record["role"] == "SOC Lead / Admin" else ["triage", "recon", "darkweb"],
            }

    # 2. Check if configured in environment variables
    if config.AUTH_USER and hmac.compare_digest(u_lower, config.AUTH_USER.lower()):
        pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if config.AUTH_PASSWORD_SHA256:
            if hmac.compare_digest(pw_hash, config.AUTH_PASSWORD_SHA256):
                return True, {
                    "username": config.AUTH_USER,
                    "role": "SOC Lead / Admin",
                    "permissions": ["all"],
                }
        elif config.AUTH_PASSWORD:
            if hmac.compare_digest(password, config.AUTH_PASSWORD):
                return True, {
                    "username": config.AUTH_USER,
                    "role": "SOC Lead / Admin",
                    "permissions": ["all"],
                }

    return False, None


def authenticate_web_user(
    username: str, password: str, role_requested: Optional[str] = None, ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Handles web analyst login with rate-limiting, session token issuance,
    and audit trail logging.
    """
    limited, wait_sec = is_rate_limited(ip)
    if limited:
        record_audit_log("LOGIN_BLOCKED", username, f"Rate limited lockout ({wait_sec}s remaining)", ip)
        return {
            "success": False,
            "error": f"Too many failed login attempts. Terminal locked for {wait_sec} seconds.",
            "locked": True,
            "retry_after": wait_sec,
        }

    ok, user_data = verify_analyst_password(username, password)
    if not ok:
        record_failed_attempt(ip)
        record_audit_log("LOGIN_FAILED", username, "Invalid credentials provided", ip)
        return {"success": False, "error": "Invalid analyst handle or security passphrase.", "locked": False}

    clear_failed_attempts(ip)

    role = user_data["role"]
    token = secrets.token_urlsafe(32)
    settings = load_security_settings()
    timeout_mins = int(settings.get("session_timeout_minutes", 60))
    expires_at = time.time() + (timeout_mins * 60)

    session_info = {
        "token": token,
        "username": user_data["username"],
        "role": role,
        "full_name": user_data.get("full_name") or user_data["username"],
        "permissions": user_data.get("permissions", []),
        "created_at": _now_iso(),
        "expires_at": expires_at,
        "ip": ip,
    }

    _active_sessions[token] = session_info
    record_audit_log("LOGIN_SUCCESS", user_data["username"], f"Authenticated as {role}", ip)

    return {
        "success": True,
        "token": token,
        "analyst": {
            "username": user_data["username"],
            "role": role,
            "full_name": session_info["full_name"],
            "created_at": session_info["created_at"],
            "expires_in_minutes": timeout_mins,
        },
    }


def validate_web_session(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Checks if a session token is active and has not expired."""
    if not token or token not in _active_sessions:
        return None
    session = _active_sessions[token]
    if time.time() > session.get("expires_at", 0):
        del _active_sessions[token]
        record_audit_log("SESSION_EXPIRED", session.get("username", "unknown"), "Session timed out", session.get("ip", ""))
        return None
    return session


def terminate_web_session(token: Optional[str]) -> bool:
    """Logs out and deletes the session."""
    if token and token in _active_sessions:
        session = _active_sessions.pop(token)
        record_audit_log("LOGOUT", session.get("username", "unknown"), "Analyst signed out", session.get("ip", ""))
        return True
    return False


record_audit_log("SYSTEM_STARTUP", "system", "LazySOC Security and User Management initialized")
