"""Protection for a dashboard that has no login and must only ever be local.

* Bound to loopback only (enforced by the CLI).
* Host-header allowlist: stops DNS-rebinding, where a web page on evil.com resolves its
  own name to 127.0.0.1 and then reads the dashboard in the victim's browser.
* CSRF token on every form, plus an Origin check: stops another site from making the
  browser submit "approve upload" or "rescan" to localhost.
* Strict Content-Security-Policy and no-sniff headers. Report pages get an even stricter
  policy (no scripts at all), because their content derives from attacker-controlled
  email.
"""

from __future__ import annotations

import ipaddress
import secrets
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}

APP_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)
REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)


def is_loopback(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def host_of(value: str) -> str:
    """'127.0.0.1:8000' -> '127.0.0.1', '[::1]:8000' -> '::1'."""
    if value.startswith("["):
        return value[1 : value.index("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_ok(expected: str, submitted: str | None) -> bool:
    return bool(submitted) and secrets.compare_digest(expected, submitted or "")


class LocalOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if not is_loopback(host_of(request.headers.get("host", ""))):
            return PlainTextResponse("Invalid Host header", status_code=400)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            # Our own forms always send a real loopback Origin. "null" comes from sandboxed
            # iframes and file:// pages, which are exactly what an attacker would use.
            origin = request.headers.get("origin")
            if origin and not is_loopback(urlsplit(origin).hostname or ""):
                return PlainTextResponse("Cross-origin request refused", status_code=403)
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", APP_CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Not "no-referrer": with it, browsers send `Origin: null` on our own form posts,
        # which the Origin check (rightly) refuses. same-origin leaks nothing to other sites.
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        return response
