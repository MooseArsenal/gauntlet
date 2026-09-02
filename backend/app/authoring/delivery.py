"""Multi-channel inject delivery.

An inject arrives in an exercise the way the real event would — as an email, a
chat message, a ticket, a SIEM alert, a phone script, a news item, or a spoken
briefing. This renders one inject into a channel-appropriate presentation the
facilitator can read out or hand to the room.
"""
from __future__ import annotations


def render(inject) -> dict:
    """Return ``{channel, headline, fields, body}`` for an inject."""
    channel = inject.channel or "briefing"
    title = inject.title
    body = inject.narrative
    target = inject.target_asset or "the environment"
    clock = inject.clock or "T+00:00"

    if channel == "email":
        fields = {
            "From": "accounts@external-partner.example",
            "To": "finance@org.internal",
            "Subject": title,
            "Received": clock,
        }
    elif channel == "chat":
        fields = {"Channel": "#soc-triage", "From": "analyst.oncall", "Time": clock}
    elif channel == "ticket":
        fields = {
            "Ticket": f"IR-{abs(hash(inject.code)) % 9000 + 1000}",
            "Queue": "Security Incidents", "Priority": "High", "Asset": target,
        }
    elif channel in ("siem_alert", "edr_alert"):
        source = "EDR" if channel == "edr_alert" else "SIEM"
        fields = {
            "Source": source, "Rule": title, "Severity": "Medium", "Host": target,
            "Techniques": ", ".join(inject.attack_techniques or []) or "n/a", "Time": clock,
        }
    elif channel == "phone":
        fields = {"Caller": "Unknown / withheld", "Line": "SOC hotline", "Time": clock}
    elif channel == "news":
        fields = {"Outlet": "Sector Wire", "Headline": title, "Filed": clock}
    elif channel == "media":
        fields = {"From": "Reporter, Sector Wire", "Deadline": "45 minutes", "Asking about": title, "Time": clock}
    elif channel == "regulator":
        fields = {"From": "Supervisory authority", "Reference": f"REG-{abs(hash(inject.code)) % 900 + 100}",
                  "Subject": title, "Response due": "72 hours", "Time": clock}
    elif channel == "customer":
        fields = {"From": "Key account, procurement", "Subject": title, "Tone": "Concerned", "Time": clock}
    elif channel == "social":
        fields = {"Platform": "Public social feed", "Post": title, "Reach": "Climbing", "Time": clock}
    elif channel == "board":
        fields = {"From": "Chair of the board", "Subject": title, "Wants": "A position, in one page", "Time": clock}
    else:  # briefing
        fields = {"Presenter": "White Cell", "Time": clock}

    return {
        "channel": channel,
        "headline": title,
        "fields": fields,
        "body": body,
        "expected_actions": list(inject.expected_actions or []),
        "techniques": list(inject.attack_techniques or []),
    }
