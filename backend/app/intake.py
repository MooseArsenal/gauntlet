"""Automated environment intake (F6).

Hand-entering an environment is the biggest adoption friction — teams already
have this data in their CMDB, EDR, SIEM, and attack-surface tools. This module
parses an export from one of those (JSON array or CSV) and maps it into the
Environment model, so intake becomes an upload.

Mappers are deliberately tolerant: exports vary by vendor, so each looks for a
range of common field names and falls back sensibly. A ``generic`` source maps
Gauntlet-native shapes straight through. No network calls — the caller uploads
the export text, keeping this safe and testable.
"""
from __future__ import annotations

import csv
import io
import json

SOURCES = ("cmdb", "edr", "siem", "asm", "generic")

# Environment list-fields this module can populate.
_FIELDS = ("assets", "controls", "detections", "personnel")


class IntakeError(Exception):
    pass


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def parse(fmt: str, data: str) -> list[dict]:
    """Parse an export into a list of record dicts."""
    if fmt == "json":
        try:
            obj = json.loads(data)
        except json.JSONDecodeError as exc:
            raise IntakeError(f"invalid JSON: {exc}") from exc
        # Accept a bare list, or a dict wrapping the list under a common key.
        if isinstance(obj, dict):
            for key in ("result", "results", "records", "items", "data"):
                if isinstance(obj.get(key), list):
                    return obj[key]
            return [obj]
        if isinstance(obj, list):
            return obj
        raise IntakeError("JSON must be a list or an object containing one")
    if fmt == "csv":
        return list(csv.DictReader(io.StringIO(data)))
    raise IntakeError(f"unsupported format {fmt!r} (use json or csv)")


def _first(row: dict, *names: str, default: str = "") -> str:
    for n in names:
        if n in row and row[n] not in (None, ""):
            return str(row[n])
    return default


def _as_list(value) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    # Comma / semicolon / pipe separated string.
    return [p.strip() for p in str(value).replace(";", ",").replace("|", ",").split(",") if p.strip()]


def _as_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# per-source mappers -> partial environment fields
# --------------------------------------------------------------------------- #
def map_cmdb(rows: list[dict]) -> dict:
    """Configuration items -> assets (+ owners as personnel)."""
    assets, personnel, seen = [], [], set()
    for r in rows:
        name = _first(r, "name", "hostname", "fqdn", "cmdb_ci", "ci_name", "asset")
        if not name:
            continue
        assets.append({
            "name": name,
            "type": _first(r, "type", "asset_class", "category", "sys_class_name", default="host"),
            "criticality": _first(r, "criticality", "business_criticality", "priority", default="medium"),
            "owner": _first(r, "owner", "owned_by", "assigned_to", "support_group"),
        })
        owner = _first(r, "owner", "owned_by", "assigned_to")
        if owner and owner not in seen:
            seen.add(owner)
            personnel.append({"name": owner, "role": "asset owner"})
    return {"assets": assets, "personnel": personnel}


def map_edr(rows: list[dict]) -> dict:
    """Endpoint coverage -> controls (type edr)."""
    controls = []
    for r in rows:
        name = _first(r, "product", "name", "tool", "agent", default="EDR")
        controls.append({
            "name": name,
            "type": "edr",
            "covers": _as_list(r.get("covers") or r.get("techniques") or r.get("attack") or "*") or ["*"],
            "assets": _as_list(r.get("assets") or r.get("hosts") or r.get("coverage") or "*") or ["*"],
            "efficacy": _as_float(r.get("efficacy") or r.get("confidence"), 0.7),
            "latency_min": int(_as_float(r.get("latency_min") or r.get("mttd"), 10)),
        })
    return {"controls": controls}


def map_siem(rows: list[dict]) -> dict:
    """Detection rules -> detections (type siem)."""
    detections = []
    for r in rows:
        name = _first(r, "rule", "rule_name", "name", "title", default="SIEM rule")
        detections.append({
            "name": name,
            "type": "siem",
            "covers": _as_list(r.get("techniques") or r.get("attack") or r.get("mitre") or r.get("covers")),
            "assets": _as_list(r.get("assets") or r.get("sources")) or ["*"],
            "efficacy": _as_float(r.get("efficacy"), 0.6),
            "latency_min": int(_as_float(r.get("latency_min"), 15)),
        })
    return {"detections": detections}


def map_asm(rows: list[dict]) -> dict:
    """Attack-surface findings -> internet-facing assets."""
    assets = []
    for r in rows:
        name = _first(r, "asset", "host", "domain", "hostname", "ip", "url")
        if not name:
            continue
        assets.append({
            "name": name,
            "type": "external",
            "criticality": _first(r, "severity", "risk", "criticality", default="medium"),
            "exposure": _first(r, "exposure", "ports", "service", "finding"),
            "internet_facing": True,
        })
    return {"assets": assets}


def map_generic(rows: list[dict]) -> dict:
    """Gauntlet-native rows: each already carries which field it belongs to via a
    ``_field`` key, or is treated as an asset."""
    out: dict[str, list] = {f: [] for f in _FIELDS}
    for r in rows:
        field = r.get("_field", "assets")
        if field in out:
            out[field].append({k: v for k, v in r.items() if k != "_field"})
    return {k: v for k, v in out.items() if v}


_MAPPERS = {
    "cmdb": map_cmdb, "edr": map_edr, "siem": map_siem, "asm": map_asm, "generic": map_generic,
}


def build_import(source: str, fmt: str, data: str) -> dict:
    """Parse + map an export into partial Environment fields."""
    if source not in _MAPPERS:
        raise IntakeError(f"unknown source {source!r} (use one of {list(SOURCES)})")
    rows = parse(fmt, data)
    return _MAPPERS[source](rows)
