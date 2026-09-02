"""Sector benchmarking (M7): the number, in context.

Two comparisons, both computed locally and both honest about what they are:

- **Reference expectation** — what the bundled library says a sector's modelled
  controls should achieve: every library CTEP pack is adjudicated, module by
  module, against the environment it was written for. It is a model-derived
  yardstick, not survey data.
- **Instance cohort** — the median of completed exercises across organisations
  on this instance that have *opted in*, grouped by the environment's sector,
  and only when at least ``K_ANON`` distinct organisations contribute, so no
  single organisation's figures can be read back out. The caller's own
  organisation is excluded from its own cohort.

Nothing leaves the instance. An organisation that does not opt in sees the
reference expectation only.
"""
from __future__ import annotations

from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .analytics import _session_metrics
from .authoring import ctep
from .authoring.environments import ENVIRONMENT_TEMPLATES, build_from_template
from .engine import adjudication

K_ANON = 3
_reference_cache: dict[str, dict] | None = None


def reference() -> dict[str, dict]:
    """Per-sector model expectation from the library, computed once."""
    global _reference_cache
    if _reference_cache is not None:
        return _reference_cache
    envs = {k: build_from_template(k) for k in ENVIRONMENT_TEMPLATES}
    per: dict[str, dict] = {}
    for key, pack in ctep.CTEP_PACKS.items():
        env_key = pack.get("environment_key")
        if env_key not in envs:
            continue
        env = envs[env_key]
        sector = ENVIRONMENT_TEMPLATES[env_key]["sector"]
        row = per.setdefault(sector, {"sector": sector, "actions": 0, "detected": 0, "ttds": [], "packs": []})
        # Each module's techniques are ruled against every asset in the
        # environment: the expectation is "across the estate", not one lucky
        # target, which is how a real exercise's moves land.
        assets = [a.get("code") for a in (env.assets or []) if a.get("code")] or [""]
        for m in pack.get("modules") or []:
            techs = list(m.get("techniques") or [])
            if not techs:
                continue
            for asset in assets:
                ruling = adjudication.adjudicate(env, techs, asset)
                row["actions"] += 1
                if ruling.get("detected"):
                    row["detected"] += 1
                    if ruling.get("time_to_detect_min") is not None:
                        row["ttds"].append(ruling["time_to_detect_min"])
        row["packs"].append(key)
    out = {}
    for sector, r in per.items():
        out[sector] = {
            "sector": sector,
            "detection_rate": round(r["detected"] / r["actions"], 3) if r["actions"] else None,
            "mean_time_to_detect_min": round(sum(r["ttds"]) / len(r["ttds"]), 1) if r["ttds"] else None,
            "actions": r["actions"], "packs": r["packs"],
        }
    _reference_cache = out
    return out


def _sector_of(db: Session, session: models.Session) -> str:
    scenario = db.get(models.Scenario, session.scenario_id)
    env = db.get(models.Environment, scenario.environment_id) if scenario else None
    return (env.sector if env and env.sector else "") or "Unspecified"


def _completed(db: Session, org_ids: list[int] | None = None) -> list[models.Session]:
    q = select(models.Session).where(models.Session.status == "complete", models.Session.archived_at.is_(None))
    if org_ids is not None:
        q = q.where(models.Session.org_id.in_(org_ids))
    return list(db.execute(q).scalars().all())


def _aggregate(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    def med(key):
        vals = [r[key] for r in rows if r.get(key) is not None]
        return round(median(vals), 3) if vals else None
    return {"exercises": len(rows), "detection_rate": med("detection_rate"),
            "mean_time_to_detect_min": med("mean_time_to_detect_min"),
            "objectives_met_rate": med("objectives_met_rate")}


def own_by_sector(db: Session, org_id: int) -> dict[str, dict]:
    per: dict[str, list[dict]] = {}
    for s in _completed(db, [org_id]):
        m = _session_metrics(s)
        if not m["red_actions"]:
            continue
        per.setdefault(_sector_of(db, s), []).append(m)
    return {sector: _aggregate(rows) for sector, rows in per.items()}


def cohort_by_sector(db: Session, exclude_org: int) -> dict[str, dict]:
    """Opted-in organisations other than the caller's, k-anonymous per sector."""
    opted = [o.id for o in db.execute(
        select(models.Organization).where(models.Organization.benchmark_opt_in.is_(True),
                                          models.Organization.id != exclude_org)).scalars()]
    if not opted:
        return {}
    per: dict[str, dict[int, list[dict]]] = {}
    for s in _completed(db, opted):
        m = _session_metrics(s)
        if not m["red_actions"]:
            continue
        per.setdefault(_sector_of(db, s), {}).setdefault(s.org_id, []).append(m)
    out = {}
    for sector, by_org in per.items():
        if len(by_org) < K_ANON:
            out[sector] = {"suppressed": True, "organisations": len(by_org), "needed": K_ANON}
            continue
        # one row per organisation (its median), so a prolific org cannot dominate
        org_rows = [_aggregate(rows) for rows in by_org.values()]
        agg = _aggregate(org_rows) or {}
        agg["organisations"] = len(by_org)
        agg["exercises"] = sum(len(r) for r in by_org.values())
        out[sector] = agg
    return out


def _rank(own: float | None, cohort_vals: list[float], higher_is_better: bool = True) -> float | None:
    if own is None or not cohort_vals:
        return None
    better = sum(1 for v in cohort_vals if (own > v if higher_is_better else own < v))
    return round(better / len(cohort_vals), 2)


def compare(db: Session, org: models.Organization) -> dict:
    own = own_by_sector(db, org.id)
    cohort = cohort_by_sector(db, org.id) if org.benchmark_opt_in else {}
    ref = reference()
    sectors = sorted(set(own) | set(ref) | set(cohort))
    rows = []
    for sector in sectors:
        o = own.get(sector)
        r = ref.get(sector)
        c = cohort.get(sector)
        if org.benchmark_opt_in and o and c is None:
            # opted in, but nobody else in this sector has: say so rather than show nothing
            c = {"suppressed": True, "organisations": 0, "needed": K_ANON}
        row = {"sector": sector, "own": o, "reference": r, "cohort": c}
        if o and r:
            row["vs_reference"] = {
                "detection_rate": (round(o["detection_rate"] - r["detection_rate"], 3)
                                   if o.get("detection_rate") is not None and r.get("detection_rate") is not None else None),
                "mean_time_to_detect_min": (round(o["mean_time_to_detect_min"] - r["mean_time_to_detect_min"], 1)
                                            if o.get("mean_time_to_detect_min") is not None and r.get("mean_time_to_detect_min") is not None else None),
            }
        if o and c and not c.get("suppressed"):
            row["vs_cohort"] = {
                "detection_rate": (round(o["detection_rate"] - c["detection_rate"], 3)
                                   if o.get("detection_rate") is not None and c.get("detection_rate") is not None else None),
                "mean_time_to_detect_min": (round(o["mean_time_to_detect_min"] - c["mean_time_to_detect_min"], 1)
                                            if o.get("mean_time_to_detect_min") is not None and c.get("mean_time_to_detect_min") is not None else None),
            }
        rows.append(row)
    return {"opt_in": bool(org.benchmark_opt_in), "k_anonymity": K_ANON, "sectors": rows,
            "note": ("Reference figures are the library's modelled expectation, not survey data. "
                     "Cohort figures are medians across opted-in organisations on this instance and "
                     f"appear only when at least {K_ANON} organisations contribute.")}
