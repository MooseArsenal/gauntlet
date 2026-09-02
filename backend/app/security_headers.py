"""Security response headers (M8).

A strict Content-Security-Policy for the app and API; a relaxed one only for the
interactive API docs (Swagger/ReDoc load from a CDN and use inline scripts).
HSTS is sent only in production.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware

from .config import IS_PROD

_APP_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
)

# Swagger UI / ReDoc are served from jsdelivr and use inline scripts/styles.
_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "worker-src 'self' blob:; "
    "connect-src 'self'"
)

_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        path = request.url.path
        response.headers.setdefault(
            "Content-Security-Policy",
            _DOCS_CSP if path.startswith(_DOCS_PATHS) else _APP_CSP,
        )
        if path.startswith("/api/"):
            # Tokens, exports and personal data must never sit in a shared cache (S-11).
            response.headers.setdefault("Cache-Control", "no-store")
        else:
            # Console files: always revalidate. StaticFiles sends an ETag, so an
            # unchanged file costs a 304, and a deploy is visible on the next
            # load instead of after the browser's heuristic cache expires (U-7).
            response.headers.setdefault("Cache-Control", "no-cache, must-revalidate")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if IS_PROD:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response
