# Security review — post-M10 feature audit (A6)

A focused security pass over everything added **after** the M8–M10 hardening
milestones: the F1–F8 features, the Q2 visual scenario-graph editor, the Q3b
scenario library, and the A5 adversary-emulation catalog. Scope: input
validation on every new field, authorization / tenant isolation on every new
endpoint, injection (SQL / template / command / CSV), XSS, SSRF, and path
traversal.

## Verdict

The M8–M10 controls are intact and the new features mostly reuse them
correctly. **No critical or high-severity issues** (no injection, SSRF,
auth-bypass, or cross-tenant read/write) were found. The real findings were
input-validation / DoS gaps and one authorization-exposure — all fixed in this
change.

## Confirmed sound (no change needed)

- **No dangerous sinks** — no `eval` / `exec` / `subprocess` / `os.system` /
  `pickle`; YAML is `safe_load`; branch-guard conditions use an AST allow-list
  (`engine/conditions.py`) with no call/attribute access, so authored conditions
  can't execute code. All DB access is parametrized SQLAlchemy — no raw SQL.
- **SSRF** — intake (F6) makes no outbound calls; the range adapter (F7),
  tracker (F4), and LLM assist (F8) only reach operator-configured hosts, and the
  range adapter is fail-closed against a host allow-list. No user-controlled
  outbound host.
- **Path traversal** — export / report / evidence filenames are built from
  integer IDs only; report lookups are re-scoped to the parent session.
- **Tenant isolation** — every externally-supplied object ID routes through
  `scope_or_404`; no create endpoint trusts a client-supplied `org_id`.
- **Auth / crypto** — JWT pinned to HS256 with domain-separated keys, refresh
  rotation with family revocation, AES-256-GCM with per-write nonces, OIDC
  signature/issuer/audience/nonce + CSRF-state checks, single-use short-TTL WS
  tickets. No regressions.
- **Content-Security-Policy** — a strict `script-src 'self'` (no
  `unsafe-inline`) CSP is served on the app and its static pages, plus
  `X-Frame-Options: DENY`, `nosniff`, and HSTS in production.

## Findings fixed in this change

| # | Severity | Issue | Fix |
|---|----------|-------|-----|
| 1 | Medium | **Sensitive exports readable by the `participant` role.** Timeline CSV/JSON, DOCX/PDF reports, and compliance evidence were gated with `get_current_user` only — bypassing the fog-of-war redaction the product implements for participants. | Gated all export/evidence/report **read** endpoints to `require_evaluator` (admin / facilitator / evaluator). The framework *list* stays open. |
| 2 | Medium | **Stored HTML injection in the facilitator console.** Authored scenario/environment fields (inject codes, ATT&CK techniques, objective codes, branch `when`/`goto`, crown jewels, timeline `ref`) reached `innerHTML` unescaped in `app.js`. Script execution is blocked by the CSP, but the values still need escaping (defence-in-depth, content-spoofing). | Applied `escapeHtml()` to every affected sink in `app.js` (and `evaluator.js`). |
| 3 | Medium | **`MAX_INJECTS` bypass.** The YAML-import path capped inject count; the Q2 graph-save and direct scenario-create paths did not. | Enforce `MAX_INJECTS` in both (`_enforce_inject_cap`). |
| 4 | Medium | **F6 bulk import had no size limit.** `EnvironmentImportIn.data` was unbounded and parsed wholesale into memory. | Cap the import payload at `MAX_IMPORT_BYTES` (default 2 MB). |
| 5 | Low | **CSV formula injection.** Timeline CSV wrote authored `ref` values raw, so a cell like `=HYPERLINK(...)` would execute on open in a spreadsheet. | Prefix values starting with `= + - @` / tab / CR with a single quote. |
| 6 | Low | **Unbounded live-inject TTL.** A huge `ttl_minutes` could overflow (`500`) or create a never-expiring authorization grant. | Clamp to `[1, MAX_AUTHORIZATION_TTL_MIN]` (default 24 h). |
| 7 | Low | **No global request-body cap.** Individual string/list fields are schema-unbounded (SQLite doesn't enforce `String(N)`), so oversized JSON could abuse memory/storage. | Added a request-body-size middleware (`MAX_REQUEST_BYTES`, default 4 MB) as a backstop. |

## Residual / defence-in-depth (documented, not blocking)

- Per-field `max_length` / `max_items` are still absent on most schemas; the
  request-body cap (finding 7) bounds the DoS surface, but adding explicit
  per-field limits on the free-text fields (narratives, notes) remains a good
  follow-up.
- The tokens live in `localStorage` (readable from JS). This is an accepted
  design trade-off; the CSP and the escaping fixes (finding 2) remove the
  practical XSS path to them.

All fixes ship with tests in `backend/tests/test_a6_security_hardening.py`.
