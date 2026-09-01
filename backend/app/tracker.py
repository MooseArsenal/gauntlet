"""Issue-tracker sync for the improvement plan (F4).

An exercise's value is the follow-through: the corrective actions it surfaces.
Those belong in the tracker the team already lives in, and their **closure**
should be verifiable against that ticket — not re-typed into a spreadsheet.

A small adapter interface abstracts the tracker so the flow is identical whether
you use Jira, ServiceNow, or the built-in **simulation** adapter (the default,
which records intent and makes no network call — the same pattern as M4's range
adapter). Real adapters activate only when their config is present, and only
ever call the single operator-configured base URL, so request data can't steer
them at another host.
"""
from __future__ import annotations

import secrets

from . import config


class TrackerError(Exception):
    pass


# Map each tracker's native status vocabulary to our lifecycle.
def _norm(raw: str) -> str:
    r = (raw or "").strip().lower()
    if r in ("done", "closed", "resolved", "complete", "completed", "cancelled", "canceled"):
        return "closed"
    if r in ("in progress", "in_progress", "work in progress", "doing", "active"):
        return "in_progress"
    return "open"


class NullTracker:
    """No external system — record intent and hand back a simulated reference."""

    name = "simulation"

    def create_issue(self, title: str, description: str, severity: str) -> tuple[str, str]:
        ref = f"SIM-{secrets.token_hex(4).upper()}"
        return ref, f"https://simulation.local/issues/{ref}"

    def fetch_status(self, ref: str) -> str:
        # A simulation can't know real progress; callers/tests drive closure by
        # updating the item directly or via a stub adapter.
        return "open"


class JiraTracker:
    name = "jira"

    def create_issue(self, title: str, description: str, severity: str) -> tuple[str, str]:
        import httpx

        payload = {
            "fields": {
                "project": {"key": config.JIRA_PROJECT},
                "summary": title[:250],
                "description": description,
                "issuetype": {"name": "Task"},
            }
        }
        try:
            r = httpx.post(f"{config.JIRA_URL}/rest/api/2/issue",
                           json=payload, auth=(config.JIRA_USER, config.JIRA_TOKEN), timeout=10.0)
            r.raise_for_status()
            key = r.json()["key"]
        except Exception as exc:  # noqa: BLE001
            raise TrackerError(f"Jira create failed: {exc}") from exc
        return key, f"{config.JIRA_URL}/browse/{key}"

    def fetch_status(self, ref: str) -> str:
        import httpx

        try:
            r = httpx.get(f"{config.JIRA_URL}/rest/api/2/issue/{ref}?fields=status",
                          auth=(config.JIRA_USER, config.JIRA_TOKEN), timeout=10.0)
            r.raise_for_status()
            return _norm(r.json()["fields"]["status"]["name"])
        except Exception as exc:  # noqa: BLE001
            raise TrackerError(f"Jira status failed: {exc}") from exc


class ServiceNowTracker:
    name = "servicenow"

    def create_issue(self, title: str, description: str, severity: str) -> tuple[str, str]:
        import httpx

        try:
            r = httpx.post(f"{config.SERVICENOW_URL}/api/now/table/incident",
                           json={"short_description": title[:160], "description": description},
                           auth=(config.SERVICENOW_USER, config.SERVICENOW_PASSWORD),
                           headers={"Accept": "application/json"}, timeout=10.0)
            r.raise_for_status()
            rec = r.json()["result"]
            number, sys_id = rec["number"], rec["sys_id"]
        except Exception as exc:  # noqa: BLE001
            raise TrackerError(f"ServiceNow create failed: {exc}") from exc
        return number, f"{config.SERVICENOW_URL}/nav_to.do?uri=incident.do?sys_id={sys_id}"

    def fetch_status(self, ref: str) -> str:
        import httpx

        try:
            r = httpx.get(f"{config.SERVICENOW_URL}/api/now/table/incident",
                          params={"sysparm_query": f"number={ref}", "sysparm_fields": "state"},
                          auth=(config.SERVICENOW_USER, config.SERVICENOW_PASSWORD),
                          headers={"Accept": "application/json"}, timeout=10.0)
            r.raise_for_status()
            result = r.json().get("result") or [{}]
            # ServiceNow incident state 6/7 = Resolved/Closed.
            state = str(result[0].get("state", ""))
            return "closed" if state in ("6", "7") else _norm(state)
        except Exception as exc:  # noqa: BLE001
            raise TrackerError(f"ServiceNow status failed: {exc}") from exc


def get_adapter():
    """Pick the configured tracker, else the simulation adapter."""
    if config.JIRA_URL and config.JIRA_PROJECT:
        return JiraTracker()
    if config.SERVICENOW_URL:
        return ServiceNowTracker()
    return NullTracker()
