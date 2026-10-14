"""Rate limiting and security headers for the API."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from attestra import config


class RateLimiter:
    """In-memory sliding-window limiter keyed by API key prefix or client IP."""

    def __init__(self, limit: int | None = None, window_s: float = 60.0):
        self.limit = limit if limit is not None else config.API_RATE_LIMIT
        self.window_s = window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window_s:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path in ("/docs", "/redoc"):
            # API docs pages load Swagger UI / ReDoc from the jsDelivr CDN.
            csp = (
                "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "worker-src blob:; frame-ancestors 'none'"
            )
        else:
            csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        response.headers.setdefault("Content-Security-Policy", csp)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter | None = None):
        super().__init__(app)
        self.limiter = limiter or RateLimiter()

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith("/api/"):
            auth = request.headers.get("authorization") or ""
            if auth.lower().startswith("bearer "):
                key = f"key:{auth[7:15]}"
            else:
                client = request.client.host if request.client else "unknown"
                key = f"ip:{client}"
            if not self.limiter.allow(key):
                return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        return await call_next(request)


def enforce_scan_rate(limiter: RateLimiter, key: str) -> None:
    if not limiter.allow(f"scan:{key}"):
        from attestra.services import ServiceError

        raise ServiceError("scan rate limit exceeded")
