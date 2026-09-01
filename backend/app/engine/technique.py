"""ATT&CK technique ids: one place that knows what they look like and when two
of them mean the same thing (F-2).

Matching used to be an exact string compare, so a control covering ``T1003``
never caught an action tagged ``T1003.001`` and a lower-case id matched
nothing. Generators and catalogues tag at sub-technique granularity while
environments (and every real EDR export) list parents; every detection rate
in the product inherited the under-count.
"""
from __future__ import annotations

import re

TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalize(t: str) -> str:
    return str(t or "").strip().upper()


def is_valid(t: str) -> bool:
    return bool(TECH_RE.match(normalize(t)))


def parent(t: str) -> str:
    return normalize(t).split(".")[0]


def covers(control_id: str, action_id: str) -> bool:
    """Does a control listing ``control_id`` catch an action tagged ``action_id``?

    Equal ids match; so does either being the other's parent (``T1003`` covers
    ``T1003.001``; a control that names ``T1003.001`` also covers an action
    tagged only ``T1003``). Sibling sub-techniques do not match each other.
    """
    c, a = normalize(control_id), normalize(action_id)
    if c == "*":
        return True
    if not c or not a:
        return False
    return c == a or c == parent(a) or a == parent(c)


def normalize_list(values) -> list[str]:
    """Normalise well-formed ids in place; leave anything else untouched (used
    on authoring paths, which stay permissive)."""
    out = []
    for v in values or []:
        s = normalize(v)
        out.append(s if TECH_RE.match(s) else v)
    return out


def validate_list(values) -> list[str]:
    """Strict: every entry must be a technique id (used when ruling an action,
    where a typo would otherwise be silently ruled as a detection gap)."""
    out = []
    for v in values or []:
        s = normalize(v)
        if not s:
            continue
        if not TECH_RE.match(s):
            raise ValueError(f"'{v}' is not an ATT&CK technique id (expected Tnnnn or Tnnnn.nnn)")
        out.append(s)
    return out
