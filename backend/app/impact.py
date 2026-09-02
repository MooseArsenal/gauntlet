"""Impact per branch (P4): what the path taken cost.

A branch may carry ``impact`` — money, downtime, records, customers — and a
label. When the proctor (or a timer) takes it, the numbers are added to the
session's running totals and written into the decision event, so the
executive report and the projector can say what this exercise's decisions
would have cost, and the good path can be compared with the bad one.

Branch shape::

    {"when": "timeout", "after": "PT20M", "goto": "INJ-06b",
     "impact": {"cost": 1200000, "downtime_hours": 72, "records": 40000,
                "customers": 300, "label": "Widespread encryption"}}

Numbers are the scenario author's estimates for the modelled organisation,
labelled as such wherever they appear.
"""
from __future__ import annotations

KEYS = ("cost", "downtime_hours", "records", "customers")


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def normalise(impact) -> dict | None:
    if not isinstance(impact, dict):
        return None
    out = {k: _num(impact.get(k)) for k in KEYS if impact.get(k) is not None}
    if not out:
        return None
    out = {k: (int(v) if float(v).is_integer() else round(v, 2)) for k, v in out.items()}
    if impact.get("label"):
        out["label"] = str(impact["label"])[:200]
    return out


def apply(state: dict | None, branch: dict) -> tuple[dict, dict | None]:
    """Return ``(new_state, step)``; the step is what this branch added."""
    step = normalise(branch.get("impact"))
    new_state = dict(state or {})
    if step is None:
        return new_state, None
    totals = dict(new_state.get("impact") or {})
    for k in KEYS:
        if k in step:
            totals[k] = totals.get(k, 0) + step[k]
    new_state["impact"] = totals
    return new_state, step


def summary(events, state: dict | None = None) -> dict:
    """Totals plus the steps that produced them, from the decision events."""
    steps = []
    for e in events:
        if e.kind != "decision":
            continue
        p = e.payload or {}
        if p.get("impact"):
            steps.append({"seq": e.seq, "inject": e.ref, "label": p["impact"].get("label") or p.get("label") or p.get("goto"),
                          **{k: p["impact"].get(k) for k in KEYS if k in p["impact"]}})
    totals = dict((state or {}).get("impact") or {})
    if not totals and steps:
        for s in steps:
            for k in KEYS:
                if s.get(k) is not None:
                    totals[k] = totals.get(k, 0) + s[k]
    return {"totals": totals, "steps": steps}


def money(v) -> str:
    v = _num(v)
    if v >= 1_000_000:
        return f"${v / 1_000_000:.1f}M"
    if v >= 1_000:
        return f"${v / 1_000:.0f}k"
    return f"${v:.0f}"


def lines(summary_: dict) -> list[str]:
    t = summary_["totals"]
    if not t:
        return []
    parts = []
    if "cost" in t:
        parts.append(f"**{money(t['cost'])}** estimated cost")
    if "downtime_hours" in t:
        parts.append(f"**{t['downtime_hours']:g} h** downtime")
    if "records" in t:
        parts.append(f"**{int(t['records']):,}** records exposed")
    if "customers" in t:
        parts.append(f"**{int(t['customers']):,}** customers affected")
    out = ["## Impact of the path taken", "",
           "The decisions made in the room led to " + ", ".join(parts) + " — the scenario author's estimates for the modelled organisation, not a forecast.", ""]
    if summary_["steps"]:
        out += ["| Inject | Branch taken | Cost | Downtime | Records |", "|---|---|---|---|---|"]
        for s in summary_["steps"]:
            out.append(f"| {s['inject']} | {s['label']} | {money(s['cost']) if s.get('cost') is not None else '—'} | "
                       f"{str(s['downtime_hours']) + ' h' if s.get('downtime_hours') is not None else '—'} | "
                       f"{int(s['records']) if s.get('records') is not None else '—'} |")
        out.append("")
    return out
