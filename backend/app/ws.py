"""Real-time updates (M6): a per-session WebSocket fan-out.

Clients (facilitator, evaluators, participants) open a socket for a session and
receive a lightweight ``{"type": "changed"}`` ping whenever anything in that
session moves. On a ping they re-fetch their own (role-appropriate) view — so
the server never pushes privileged data down a participant's socket.

``notify`` is callable from ordinary sync request handlers and from the timer
thread; it hops onto the app's event loop to do the actual async sends.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from .database import SessionLocal
from .ws_ticket import tickets
from . import models

router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:
        self._rooms: dict[int, set[WebSocket]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, session_id: int, ws: WebSocket) -> None:
        await ws.accept()
        self._rooms.setdefault(session_id, set()).add(ws)

    def disconnect(self, session_id: int, ws: WebSocket) -> None:
        room = self._rooms.get(session_id)
        if room:
            room.discard(ws)
            if not room:
                self._rooms.pop(session_id, None)

    async def _broadcast(self, session_id: int, message: dict) -> None:
        dead = []
        for ws in list(self._rooms.get(session_id, ())):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(session_id, ws)

    def notify(self, session_id: int, event: str = "changed") -> None:
        """Thread-safe: schedule a broadcast on the app loop, if one is bound
        and still running. A closed/absent loop is a no-op, never an error."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        msg = {"type": event, "session_id": session_id}
        try:
            loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self._broadcast(session_id, msg))
            )
        except RuntimeError:
            pass


manager = ConnectionManager()


@router.websocket("/ws/sessions/{session_id}")
async def session_socket(websocket: WebSocket, session_id: int, ticket: str = ""):
    """Subscribe to a session's change stream.

    Auth via ``?ticket=<t>`` — a short-lived, single-use ticket minted at
    ``POST /api/sessions/{id}/ws-ticket`` (which requires a bearer token and
    checks org ownership). The ticket keeps the JWT out of the URL and is bound
    to this exact session, so it cannot be replayed against another.
    """
    user_id = tickets.consume(ticket, session_id) if ticket else None
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    db = SessionLocal()
    try:
        user = db.get(models.User, user_id)
        s = db.get(models.Session, session_id)
        if user is None or not user.is_active or s is None or s.org_id != user.org_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    finally:
        db.close()

    await manager.connect(session_id, websocket)
    try:
        while True:
            # We don't expect inbound messages; this keeps the socket open and
            # detects disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)
    except Exception:
        manager.disconnect(session_id, websocket)
