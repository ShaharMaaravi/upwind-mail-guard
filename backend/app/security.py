"""Bound authenticated requests before JSON parsing, including chunked requests."""

import asyncio
import hmac
import logging
import time
from collections import deque

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings

logger = logging.getLogger(__name__)


class RequestGuard:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self.recent: deque[float] = deque()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def secure_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                message["headers"] = list(message.get("headers", [])) + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ]
            await send(message)

        try:
            await self._guard(scope, receive, secure_send)
        except Exception:
            # Exception text/tracebacks can contain email content or validation inputs.
            # Keep an operational signal without logging the exception, request, or headers.
            logger.error("request_failed")
            if response_started:
                # A response cannot be replaced once sent. Abort with sanitized context.
                raise RuntimeError("response_failed") from None
            await JSONResponse({"error": "internal_error"}, status_code=500)(
                scope, receive, secure_send
            )

    async def _guard(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def reject(status: int, code: str, headers: dict | None = None) -> None:
            await JSONResponse({"error": code}, status_code=status, headers=headers)(
                scope, receive, send
            )

        if scope["path"] not in {"/v1/diagnose", "/v1/analyze"} or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        headers = dict(raw_headers)
        auth_values = [v for k, v in raw_headers if k == b"authorization"]
        expected = b"Bearer " + self.settings.api_token.encode("ascii")
        if len(auth_values) != 1 or not hmac.compare_digest(auth_values[0], expected):
            await reject(401, "unauthorized", {"WWW-Authenticate": "Bearer"})
            return

        now = time.monotonic()
        while self.recent and self.recent[0] <= now - 60:
            self.recent.popleft()
        if len(self.recent) >= self.settings.requests_per_minute:
            await reject(429, "rate_limited", {"Retry-After": "60"})
            return
        self.recent.append(now)

        if headers.get(b"content-type", b"").split(b";")[0].strip().lower() != b"application/json":
            await reject(415, "json_required")
            return
        if headers.get(b"content-encoding", b"identity").lower() != b"identity":
            await reject(415, "content_encoding_not_supported")
            return
        lengths = [v for k, v in raw_headers if k == b"content-length"]
        if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
            await reject(400, "invalid_content_length")
            return
        # Bound the numeric representation too, avoiding giant-integer parsing.
        if lengths and (len(lengths[0]) > 10 or int(lengths[0]) > self.settings.max_body_bytes):
            await reject(413, "request_too_large")
            return

        body = bytearray()
        try:
            async with asyncio.timeout(self.settings.body_timeout_seconds):
                while True:
                    part = await receive()
                    if part["type"] == "http.disconnect":
                        return
                    chunk = part.get("body", b"")
                    if len(body) + len(chunk) > self.settings.max_body_bytes:
                        await reject(413, "request_too_large")
                        return
                    body.extend(chunk)
                    if not part.get("more_body", False):
                        break
        except TimeoutError:
            await reject(408, "request_timeout")
            return
        if lengths and len(body) != int(lengths[0]):
            await reject(400, "content_length_mismatch")
            return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
