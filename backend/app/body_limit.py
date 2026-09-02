"""Request-body size cap that cannot be bypassed with chunked encoding (S-7).

The previous check read ``Content-Length`` only, so a body sent without one was
buffered in full. This ASGI middleware counts the bytes as they arrive and
answers 413 the moment the cap is crossed — before the body reaches JSON
parsing, the PDF renderer, or the database.
"""
from __future__ import annotations

import json


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes) -> None:
        self.app = app
        self._max = max_bytes  # int, or a callable returning the current limit

    @property
    def max_bytes(self) -> int:
        return int(self._max() if callable(self._max) else self._max)

    async def _plain(self, send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for k, v in scope.get("headers") or []:
            if k == b"content-length":
                try:
                    declared = int(v)
                except ValueError:
                    await self._plain(send, 400, "invalid Content-Length")
                    return
                if declared > self.max_bytes:
                    await self._plain(send, 413, f"request body exceeds the {self.max_bytes}-byte limit")
                    return

        state = {"received": 0, "started": False, "closed": False}

        async def limited_receive():
            if state["closed"]:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                state["received"] += len(message.get("body", b""))
                if state["received"] > self.max_bytes:
                    # Answer here: an exception raised from receive() would be
                    # swallowed by the framework's body parser into a 400.
                    if not state["started"]:
                        state["closed"] = True
                        await self._plain(send, 413,
                                          f"request body exceeds the {self.max_bytes}-byte limit")
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            if state["closed"]:
                return
            if message["type"] == "http.response.start":
                state["started"] = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            # The app may raise on the synthetic disconnect; the 413 is already out.
            if not state["closed"]:
                raise
