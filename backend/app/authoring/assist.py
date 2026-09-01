"""LLM-assisted authoring (F8).

Drafts an inject from a short brief. Two generators, one interface:

* **template** (default) — deterministic, offline. Picks the best-matching entry
  from the vetted inject bank for the requested kill-chain phase / technique and
  fills it with a real asset. High quality, no network, fully reproducible; this
  is what tests and un-configured deployments use.
* **provider** (opt-in) — a real LLM (e.g. Anthropic), used only when
  ``GAUNTLET_LLM_PROVIDER`` + key are set. It runs behind a **defensive
  guardrail**: the system prompt constrains output to blue-team *exercise*
  content (a scenario event + defensive expected actions), and any brief that
  asks for operational offensive tooling is refused. If the provider errors or
  returns an unusable shape, we fall back to the template generator.

The result is a draft only — it is never persisted here; the facilitator reviews
it and adds it through the normal authoring endpoints.
"""
from __future__ import annotations

import json
import os

from .catalog import INJECT_BANK

# Briefs that request operational offensive capability, not exercise content.
_OFFENSIVE_MARKERS = (
    "write malware", "working exploit", "exploit code", "ransomware binary",
    "actual payload", "real malware", "shellcode", "weaponize", "weaponise",
    "bypass edr", "evade detection", "disable antivirus", "how do i hack",
)


class GuardrailError(Exception):
    """The brief asks for something outside defensive exercise authoring."""


def guard_brief(brief_text: str) -> None:
    low = (brief_text or "").lower()
    for marker in _OFFENSIVE_MARKERS:
        if marker in low:
            raise GuardrailError(
                "Authoring assist writes defensive exercise content only — it can't "
                "produce operational offensive tooling. Describe the scenario event "
                "you want the blue team to face instead."
            )


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def llm_enabled() -> bool:
    return bool(os.environ.get("GAUNTLET_LLM_PROVIDER") and os.environ.get("GAUNTLET_LLM_API_KEY"))


# --------------------------------------------------------------------------- #
# deterministic template generator
# --------------------------------------------------------------------------- #
def _score(entry: dict, phase: str, technique: str) -> int:
    score = 0
    if phase and entry.get("phase") == phase:
        score += 2
    if technique and technique in (entry.get("techniques") or []):
        score += 3
    return score


def select_entry(phase: str = "", technique: str = "") -> tuple[str, dict]:
    ranked = sorted(INJECT_BANK.items(),
                    key=lambda kv: _score(kv[1], phase, technique), reverse=True)
    return ranked[0]


def _fill(text: str, org: str, asset: dict) -> str:
    return (text.replace("{org}", org)
                .replace("{asset_name}", asset.get("name", asset.get("code", "the host")))
                .replace("{asset}", asset.get("code", "?")))


def template_inject(phase: str, technique: str, org: str, asset: dict) -> dict:
    _key, entry = select_entry(phase, technique)
    return {
        "title": _fill(entry["title"], org, asset),
        "channel": entry.get("channel", "briefing"),
        "narrative": _fill(entry["narrative"], org, asset),
        "expected_actions": list(entry.get("expected_actions", [])),
        "attack_techniques": list(entry.get("techniques", [])),
        "target_asset": asset.get("code", ""),
    }


# --------------------------------------------------------------------------- #
# provider (opt-in, guardrailed)
# --------------------------------------------------------------------------- #
_SYSTEM_PROMPT = (
    "You help a blue team author a cybersecurity tabletop/functional exercise. "
    "Produce ONE inject: a realistic scenario event the defenders would observe, "
    "plus the defensive actions they should consider. Never provide operational "
    "attacker instructions, exploit code, or steps to evade defenses. "
    "Respond ONLY with a JSON object: "
    '{"title": str, "channel": str, "narrative": str, '
    '"expected_actions": [str], "attack_techniques": [str]}.'
)


def _provider_inject(phase: str, technique: str, org: str, asset: dict, brief: str) -> dict | None:
    import httpx

    provider = os.environ.get("GAUNTLET_LLM_PROVIDER", "").lower()
    if provider != "anthropic":
        return None
    base = os.environ.get("GAUNTLET_LLM_BASE_URL", "https://api.anthropic.com")
    model = os.environ.get("GAUNTLET_LLM_MODEL", "claude-sonnet-5")
    user = (f"Organization: {org}. Target asset: {asset.get('name', asset.get('code', 'a host'))}. "
            f"Kill-chain phase: {phase or 'any'}. ATT&CK technique: {technique or 'any'}. "
            f"Brief: {brief or 'a plausible next event for this phase'}.")
    try:
        r = httpx.post(
            f"{base}/v1/messages",
            headers={"x-api-key": os.environ["GAUNTLET_LLM_API_KEY"],
                     "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": model, "max_tokens": 700, "system": _SYSTEM_PROMPT,
                  "messages": [{"role": "user", "content": user}]},
            timeout=30.0,
        )
        r.raise_for_status()
        blocks = r.json().get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        data = json.loads(_extract_json(text))
    except Exception:  # noqa: BLE001 - any failure falls back to the template
        return None
    if not isinstance(data, dict) or not data.get("narrative") or not data.get("title"):
        return None
    return {
        "title": str(data["title"])[:240],
        "channel": str(data.get("channel") or "briefing"),
        "narrative": str(data["narrative"]),
        "expected_actions": [str(a) for a in (data.get("expected_actions") or [])][:8],
        "attack_techniques": [str(t) for t in (data.get("attack_techniques") or [])][:8],
        "target_asset": asset.get("code", ""),
    }


def _extract_json(text: str) -> str:
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if start != -1 and end != -1 else text


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def generate_inject(phase: str = "", technique: str = "", org: str = "the organization",
                    asset: dict | None = None, brief: str = "") -> dict:
    """Return ``{"inject": {...}, "generator": "template"|"anthropic"}``."""
    guard_brief(brief)
    asset = asset or {"code": "", "name": "an in-scope host"}
    if llm_enabled():
        via_llm = _provider_inject(phase, technique, org, asset, brief)
        if via_llm is not None:
            return {"inject": via_llm, "generator": os.environ.get("GAUNTLET_LLM_PROVIDER", "llm")}
    return {"inject": template_inject(phase, technique, org, asset), "generator": "template"}
