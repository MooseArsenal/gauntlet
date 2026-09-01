# Air-gapped mode (D2)

Gauntlet's core — scenario generation, adjudication, scoring, the kill-chain and
purple-team engines, reports and evidence — is **deterministic and needs no
network**. Air-gapped mode makes that a hard guarantee: set

```
GAUNTLET_AIRGAPPED=1
```

and every outbound network path is refused, fail-closed, at a single choke point
(`app/egress.py`). This is a wedge that SaaS and AI-first tabletop tools
structurally cannot match for classified / defense / OT / ICS environments.

## What is blocked

Every outbound call passes `egress.guard()` first; in air-gapped mode it raises
`EgressBlocked` before any socket is opened:

- **OIDC / SSO** discovery and token exchange
- **LLM authoring assist** (the optional guardrailed generator)
- **Improvement-tracker** push / status (Jira, ServiceNow)
- **Range adapters** (Caldera, Atomic Red Team functional-mode execution)
- **Webhook notifications**

The deterministic authoring and adjudication engines are unaffected, so the
product remains fully usable offline — generation falls back to the built-in
catalog, and adjudication rules moves against the modelled environment as always.

## Surfacing

`GET /api/health` reports the posture:

```json
{ "status": "ok", "app": "Gauntlet", "version": "…", "airgapped": true }
```

The facilitator console shows a red **⛔ AIR-GAPPED** badge in the header when the
server reports it, so operators can see the guarantee is in force at a glance.

## Notes

- Air-gapped mode is independent of the other guardrails: encryption at rest,
  RBAC, MFA and audit logging all continue to apply.
- It is fail-closed by construction — a *new* outbound call added to the codebase
  should route through `egress.guard()`; the D2 tests assert the representative
  paths refuse when the flag is on.
