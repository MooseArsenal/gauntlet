# Support policy

What "support" means on each Gauntlet tier: who to write to, when someone
answers, how fast, and what is out of scope. This is the policy the order
form refers to. Moose Arsenal is a small company; the policy promises what
it can keep, and says plainly what it does not offer yet.

## Hours

Support is staffed **09:00 to 15:00 US Central Time, Monday to Friday**,
excluding US federal holidays. A *business hour* is one hour inside that
window; a *business day* ends at 15:00 Central. Requests received outside
the window are treated as received at the start of the next window.

There is no out-of-hours or weekend support on any tier at this time. A
customer whose exercise runs on a Saturday should schedule a check-in with
support the Friday before; see *Run-day readiness* below.

## Channels

| Tier | Channel | Who answers |
|---|---|---|
| Community | [GitHub Issues](https://github.com/MooseArsenal/gauntlet/issues) and Discussions, public | Whoever is around; no response target. Security reports go to security@moosearsenal.com, see `SECURITY.md`, not to a public issue. |
| Team | support@moosearsenal.com | Moose Arsenal |
| Education | support@moosearsenal.com | Moose Arsenal |
| Enterprise | support@moosearsenal.com, with the severity in the subject line | Moose Arsenal |

Write from an address on the licensed organisation's domain and put the
licence serial (Members page) in the message; that is how a request is
matched to a tier without a portal.

## Severity

The severity is about the exercise, not the calendar. A customer sets it
when they write; support may re-classify it and will say why.

| Severity | Meaning | Examples |
|---|---|---|
| **1 — an exercise cannot run** | The product cannot be used for an exercise that is scheduled or in progress | Instance down or nobody can sign in with a run scheduled; injects will not fire, participants cannot answer, the timeline will not record, or the certificate cannot be issued in a run that is under way; a valid licence refused so paid features close during a scheduled exercise; a Gauntlet defect that destroys or corrupts exercise records (for example an upgrade migration that loses timelines) |
| **2 — a paid feature is broken, with a way round** | Something the tier pays for does not work, but the exercise can still be run | A report will not export; tracker push fails; a content pack will not install; SCIM stops provisioning; white-label branding does not apply |
| **3 — everything else** | Cosmetic defects, questions, requests | A layout fault; how to author a branch condition; a feature request; a question about a licence |

A broken export the day before a board meeting is severity 2 with an urgent
note, not severity 1. Severity 1 is reserved for the room that cannot sit.

**Your data and your instance are yours.** Gauntlet is self-hosted and
sends nothing to Moose Arsenal, so we hold none of your data and cannot
lose it. Loss or corruption caused by your own disks, backups, database,
upgrades you performed outside the documented procedure, or administrative
action is not a support case, though support will help you read what the
timeline's signed heads say about a restore. An intrusion on your instance
is your incident to run; support can confirm what Gauntlet recorded. A
vulnerability *in Gauntlet* is not a support severity at all: report it to
security@moosearsenal.com and it is handled under `SECURITY.md`, which
commits to a fix for confirmed high-severity issues within fourteen days.

## Response targets

| Tier | Severity 1 | Severity 2 | Severity 3 |
|---|---|---|---|
| Community | none | none | none |
| Team | next business day | next business day | best effort, usually within three business days |
| Education | next business day | next business day | best effort, usually within three business days |
| Enterprise | **4 business hours** | next business day | two business days |

"Response" means a person has read the request, confirmed the severity and
started work, with a first update on what is known. It is not a resolution
time. Because the window is six hours long, a severity 1 raised at 14:00 on
Friday is answered by 12:00 the following Monday, and one raised at 09:00
is answered by 13:00 the same day.

Fixes for confirmed severity 1 defects ship as a point release as soon as
they are ready, to every supported version. Fixes for severity 2 and 3 go
into the next scheduled release. `SECURITY.md` governs security fixes.

## Run-day readiness

A Team, Education or Enterprise customer may book a **run-day check-in**:
a 30-minute call in the support window, up to five business days before a
scheduled exercise, to confirm the instance, the scenario, the join codes,
inject delivery and the licence are ready. It is the best protection
against a severity 1 on the day, and it is free on every paid tier.

## What is included

- Defects in Gauntlet: the engine, the console, the API, exports, the
  licence and content-pack mechanism, the documented deployment.
- Questions about using a feature that exists and is documented.
- Help reading a ruling, a report or a certificate.
- Upgrade guidance between supported versions (`main` and the latest tagged
  release; see `SECURITY.md`).

## What is not included

- **Custom scenario authoring, facilitation or exercise design.** That is
  the facilitated-exercise product, sold separately.
- The customer's own infrastructure: their proxy, database, identity
  provider, mail relay, network or hosting. Support will say where Gauntlet
  stops and the platform starts, and no further.
- The customer's data and backups, and incident response on the customer's
  instance. Gauntlet holds no copy of either.
- Third-party services connected through the tracker, SSO, SCIM, SMTP or
  the range adapters, beyond confirming what Gauntlet sent and received.
- Versions older than the latest tagged release.
- Forks and modified builds.
- Training beyond the documentation, the tour and the solo learning mode.

## Escalation

If a response target is missed, write again with "escalation" in the
subject line; it goes to the founder. There is no separate phone line at
this time.

## Changes

This policy may change for new customers. A customer's policy is the one in
force on the date of their order form, for the term of that order.
