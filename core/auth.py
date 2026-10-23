"""
Optional login for LazySOC (HTTP Basic Auth).

Set LAZYSOC_AUTH_USER plus LAZYSOC_AUTH_PASSWORD (or LAZYSOC_AUTH_PASSWORD_SHA256) to require a login for
every page and API call. /healthz stays public so container and platform health checks keep working.
Use HTTPS in front of LazySOC (Render does this) - Basic Auth sends credentials with every request.
"""

import base64
import hashlib
import hmac
from typing import Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

import core.config as config

# /api/schedules/tick is checked against its own SCHEDULER_TRIGGER_TOKEN, so external cron jobs can call it.
PUBLIC_PATHS = {"/healthz", "/api/schedules/tick"}


def auth_enabled() -> bool:
    return bool(config.AUTH_USER and (config.AUTH_PASSWORD or config.AUTH_PASSWORD_SHA256))


def check_credentials(user: str, password: str) -> bool:
    if not auth_enabled():
        return False
    # Compare everything in constant time so a wrong user and a wrong password look the same.
    user_ok = hmac.compare_digest(user.encode("utf-8"), config.AUTH_USER.encode("utf-8"))
    if config.AUTH_PASSWORD_SHA256:
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        pass_ok = hmac.compare_digest(digest, config.AUTH_PASSWORD_SHA256)
    else:
        pass_ok = hmac.compare_digest(password.encode("utf-8"), config.AUTH_PASSWORD.encode("utf-8"))
    return user_ok and pass_ok


def parse_basic_header(header: Optional[str]) -> Optional[Tuple[str, str]]:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1].strip(), validate=True).decode("utf-8")
    except Exception:
        return None
    user, sep, password = decoded.partition(":")
    return (user, password) if sep else None


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not auth_enabled() or request.url.path in PUBLIC_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        creds = parse_basic_header(request.headers.get("authorization"))
        if creds and check_credentials(*creds):
            return await call_next(request)
        return Response(
            "Login diperlukan.",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="LazySOC", charset="UTF-8"'},
        )
