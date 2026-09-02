"""Append-only, hash-chained timeline helper.

Every material moment in a session is written here. Each event is HMAC-signed
(with the server's timeline key) over the previous event's signature together
with its own canonical content, so any later edit breaks the chain and forging
a valid chain requires the key — the property that makes an exercise report
defensible for audit.
"""
from __future__ import annotations

import hmac
import json
from datetime import datetime
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .keys import timeline_sign_key, timeline_verify_keys
from .models import Session as ExerciseSession, TimelineEvent


def _hash(prev_hash: str, canonical: str, key: bytes | None = None) -> str:
    # HMAC (not a bare hash) so recomputing a valid chain requires the server
    # key — the timeline stays tamper-evident even against someone with DB
    # write access but not the key. The signing key is domain-separated from the
    # JWT key (M10) so a leak of one does not compromise the other.
    key = key if key is not None else timeline_sign_key()
    return hmac.new(key, (prev_hash + canonical).encode("utf-8"), sha256).hexdigest()


def append_event(
    db: DbSession,
    session_id: int,
    kind: str,
    payload: dict,
    ref: str = "",
    game_clock: str = "",
) -> TimelineEvent:
    """Create, hash-chain, and persist one timeline event."""
    last = db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.session_id == session_id)
        .order_by(TimelineEvent.seq.desc())
        .limit(1)
    ).scalar_one_or_none()

    seq = (last.seq + 1) if last else 1
    prev_hash = last.hash if last else ""
    # Naive UTC so the value hashed here round-trips byte-identically out of the
    # database when the chain is later re-verified.
    at = datetime.utcnow()

    canonical = json.dumps(
        {
            "seq": seq,
            "kind": kind,
            "ref": ref,
            "game_clock": game_clock,
            "payload": payload,
            "at": at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    event = TimelineEvent(
        session_id=session_id,
        seq=seq,
        at=at,
        game_clock=game_clock,
        kind=kind,
        ref=ref,
        payload=payload,
        prev_hash=prev_hash,
        hash=_hash(prev_hash, canonical),
    )
    db.add(event)
    db.flush()
    _advance_head(db, session_id, seq, event.hash)
    return event


def _head_sig(seq: int, head_hash: str, key: bytes | None = None) -> str:
    return _hash("head", f"{seq}:{head_hash}", key)


def _advance_head(db: DbSession, session_id: int, seq: int, head_hash: str) -> None:
    """Record the chain head on the session (S-6). A chain is only as
    trustworthy as its last link: without a signed head, deleting the final N
    events leaves a shorter chain that still verifies."""
    s = db.get(ExerciseSession, session_id)
    if s is None:
        return
    s.head_seq = seq
    s.head_hash = head_hash
    s.head_sig = _head_sig(seq, head_hash)


def verify_chain(events: list[TimelineEvent], session: ExerciseSession | None = None) -> bool:
    """Return True if the ordered events form an unbroken, complete chain.

    Every link must hash to the next, sequence numbers must run 1..n with no
    gaps, and — when the session carries a signed head — the last event must
    be the one the head names. Truncation, insertion and edits all fail.
    """
    prev_hash = ""
    ordered = sorted(events, key=lambda x: x.seq)
    for i, e in enumerate(ordered, start=1):
        if e.seq != i:
            return False
        canonical = json.dumps(
            {
                "seq": e.seq,
                "kind": e.kind,
                "ref": e.ref,
                "game_clock": e.game_clock,
                "payload": e.payload,
                "at": e.at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if e.prev_hash != prev_hash:
            return False
        # Accept any key in the ring so a chain survives a key rotation and the
        # pre-M10 → domain-separated upgrade.
        if not any(e.hash == _hash(prev_hash, canonical, k) for k in timeline_verify_keys()):
            return False
        prev_hash = e.hash
    return head_valid(ordered, session)


def head_valid(ordered: list[TimelineEvent], session: ExerciseSession | None) -> bool:
    """The session's signed head must name the last event (S-6). Sessions that
    predate the head (head_seq is null) are accepted on the chain alone."""
    if session is None or session.head_seq is None:
        return True
    last_seq = ordered[-1].seq if ordered else 0
    last_hash = ordered[-1].hash if ordered else ""
    if session.head_seq != last_seq or (session.head_hash or "") != last_hash:
        return False
    return any(session.head_sig == _head_sig(last_seq, last_hash, k) for k in timeline_verify_keys())
