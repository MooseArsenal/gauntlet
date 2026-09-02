"""Telemetry loop (M4): expected versus observed detections.

Adjudication says what the modelled controls *should* have seen. The SOC's
own tools say what they *did* see. Recording the real alerts that fired during
(or were found after) an exercise against the adjudicated actions closes the
loop: every action becomes one of four outcomes —

- **confirmed** — the model expected a detection and a real alert matched;
- **silent gap** — the model expected a detection but nothing fired (the
  environment model is optimistic, or the control is broken);
- **surprise** — the model expected a miss but an alert fired (better than
  modelled: record it and raise the control's efficacy);
- **missed** — neither the model nor the tools saw it.

Alerts are timeline events (``kind="telemetry"``), so they sit on the same
tamper-evident chain as the rulings they are compared with. Ingest is by hand
in the console, by a JSON/CSV export from the SIEM or EDR, or by any client
that can POST JSON — Gauntlet never reaches out to the tools (air-gap safe).
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import intake, models
from .engine import technique

SOURCES = ("siem", "edr", "ndr", "email", "identity", "cloud", "manual", "other")


def map_alerts(rows: list[dict]) -> list[dict]:
    """Normalise SIEM/EDR export rows into alert dicts. Column names vary by
    product; the usual synonyms are accepted."""
    out = []
    for r in rows:
        techs = technique.normalize_list(intake._as_list(
            intake._first(r, "techniques", "technique", "attack_technique", "attack_techniques",
                          "mitre_technique", "mitre_techniques", "technique_id", "tactic_technique")))
        alert = intake._first(r, "alert", "alert_name", "name", "title", "rule", "rule_name", "signature", "description")
        if not alert and not techs:
            continue
        out.append({
            "alert": alert[:300],
            "techniques": techs,
            "asset": intake._first(r, "asset", "host", "hostname", "device", "computer", "target", "src_host")[:120],
            "source": (intake._first(r, "source", "product", "vendor", "tool", default="siem") or "siem").lower()[:40],
            "severity": (intake._first(r, "severity", "priority", "level", default="") or "")[:20],
            "observed_at": intake._first(r, "observed_at", "time", "timestamp", "@timestamp", "detected_at",
                                         "event_time", "first_seen", "created_at")[:40],
            "external_ref": intake._first(r, "id", "alert_id", "event_id", "incident_id", "ref")[:120],
        })
    return out


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite hands back naive UTC timestamps; compare everything as aware."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _covers(alert_techs: list[str], action_techs: list[str]) -> bool:
    """An alert matches an action when any alert technique covers any action
    technique (parent matches sub-technique in either direction)."""
    if not action_techs:
        return False
    return any(technique.covers(a, b) or technique.covers(b, a) for a in alert_techs for b in action_techs)


def _asset_ok(alert_asset: str, action_asset: str) -> bool:
    return not alert_asset or not action_asset or alert_asset.lower() == action_asset.lower()


def actions_of(session: models.Session) -> list[models.TimelineEvent]:
    return [e for e in session.events if e.kind in ("adjudication", "red_action")]


def alerts_of(session: models.Session) -> list[models.TimelineEvent]:
    return [e for e in session.events if e.kind == "telemetry"]


def compare(session: models.Session) -> dict:
    """Pair every adjudicated action with the alerts that match it, and
    classify. Returns the per-action rows, per-technique rollup and totals."""
    actions = actions_of(session)
    alerts = alerts_of(session)
    matched_alert_seqs: set[int] = set()
    rows = []
    for a in actions:
        p = a.payload or {}
        a_techs = list(p.get("techniques") or [])
        a_asset = str(p.get("target_asset") or p.get("target") or "")
        expected = bool(p.get("detected"))
        hits = []
        for t in alerts:
            q = t.payload or {}
            if _covers(list(q.get("techniques") or []), a_techs) and _asset_ok(str(q.get("asset") or ""), a_asset):
                hits.append(t)
                matched_alert_seqs.add(t.seq)
        observed = bool(hits)
        latency = None
        if hits:
            when = [_parse_dt((h.payload or {}).get("observed_at")) or _aware(h.at) for h in hits]
            first = min(w for w in when if w is not None)
            if a.at is not None:
                latency = round((first - _aware(a.at)).total_seconds() / 60, 1)
        outcome = ("confirmed" if expected and observed else "silent_gap" if expected
                   else "surprise" if observed else "missed")
        rows.append({
            "seq": a.seq, "kind": a.kind, "game_clock": a.game_clock, "techniques": a_techs,
            "target_asset": a_asset, "expected": expected,
            "expected_ttd_min": p.get("time_to_detect_min"),
            "observed": observed, "observed_latency_min": latency,
            "alerts": [{"seq": h.seq, "alert": (h.payload or {}).get("alert", ""),
                        "source": (h.payload or {}).get("source", "")} for h in hits],
            "outcome": outcome,
        })
    unmatched = [{"seq": t.seq, "alert": (t.payload or {}).get("alert", ""),
                  "techniques": (t.payload or {}).get("techniques", []),
                  "source": (t.payload or {}).get("source", "")}
                 for t in alerts if t.seq not in matched_alert_seqs]
    counts = {k: sum(1 for r in rows if r["outcome"] == k) for k in ("confirmed", "silent_gap", "surprise", "missed")}
    total = len(rows)
    agree = counts["confirmed"] + counts["missed"]
    by_tech: dict[str, dict] = {}
    for r in rows:
        for t in r["techniques"] or ["(unspecified)"]:
            b = by_tech.setdefault(t, {"technique": t, "actions": 0, "expected": 0, "observed": 0})
            b["actions"] += 1
            b["expected"] += 1 if r["expected"] else 0
            b["observed"] += 1 if r["observed"] else 0
    return {
        "session_id": session.id,
        "actions": total,
        "alerts": len(alerts),
        "unmatched_alerts": unmatched,
        "counts": counts,
        "expected_rate": round(sum(1 for r in rows if r["expected"]) / total, 3) if total else None,
        "observed_rate": round(sum(1 for r in rows if r["observed"]) / total, 3) if total else None,
        "model_agreement": round(agree / total, 3) if total else None,
        "by_technique": sorted(by_tech.values(), key=lambda b: b["technique"]),
        "rows": rows,
    }


def summary_lines(cmp: dict) -> list[str]:
    """Markdown for the reports: only when telemetry was recorded."""
    if not cmp["alerts"]:
        return []
    c = cmp["counts"]
    pct = lambda v: "n/a" if v is None else f"{round(v * 100)}%"  # noqa: E731
    lines = [
        "## Detections — expected vs observed",
        "",
        f"{cmp['alerts']} real alert(s) were recorded against {cmp['actions']} adjudicated action(s). "
        f"Modelled detection rate **{pct(cmp['expected_rate'])}**, observed **{pct(cmp['observed_rate'])}**; "
        f"the environment model agreed with the tools on **{pct(cmp['model_agreement'])}** of actions.",
        "",
        "| Outcome | Actions |", "|---|---|",
        f"| Confirmed (expected and seen) | {c['confirmed']} |",
        f"| Silent gap (expected, nothing fired) | {c['silent_gap']} |",
        f"| Surprise (not expected, but seen) | {c['surprise']} |",
        f"| Missed (neither) | {c['missed']} |",
        "",
    ]
    gaps = [r for r in cmp["rows"] if r["outcome"] == "silent_gap"]
    if gaps:
        lines.append("Silent gaps to investigate: " + ", ".join(
            f"`{r['game_clock'] or '--:--'}` {', '.join(r['techniques']) or 'action'}"
            + (f" on {r['target_asset']}" if r['target_asset'] else "") for r in gaps) + ".")
        lines.append("")
    if cmp["unmatched_alerts"]:
        lines.append(f"{len(cmp['unmatched_alerts'])} alert(s) matched no adjudicated action (noise, or activity the exercise did not script).")
        lines.append("")
    return lines
