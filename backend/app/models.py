"""ORM models for the tabletop-exercise domain.

The vocabulary deliberately mirrors how exercise practitioners talk (HSEEP /
NIST SP 800-84), so an object on screen matches an object in an exercise
director's head: Environment, Scenario, Inject (the scene), Session (one run),
TimelineEvent (the tamper-evident record), Observation, Report.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .crypto import EncryptedJSON
from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Roles, most privileged first. Facilitators run exercises; evaluators only
# observe and log; participants read the surfaces meant for them.
ROLES = ("admin", "facilitator", "evaluator", "participant")


class Organization(Base):
    """A tenant. Every domain object belongs to exactly one organisation."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    # SCIM provisioning (M5): sha256 of the bearer token the identity provider
    # presents; null until an admin mints one.
    scim_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Sector benchmarking (M7): contribute this organisation's completed-exercise
    # figures to the instance cohort, and see the cohort in return.
    benchmark_opt_in: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    """A member of an organisation, with a role that gates what they may do."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(160), default="")
    role: Mapped[str] = mapped_column(String(20), default="facilitator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # TOTP multi-factor auth (M9).
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # A secret being enrolled but not yet confirmed (H2). Setup writes here so
    # it can never touch the live secret; enable promotes it.
    mfa_pending_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Set when the account is linked to an external OIDC identity provider (M9).
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    # The identity provider's id for this user when provisioned over SCIM (M5).
    scim_external_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="users")


class RefreshToken(Base):
    """A rotating refresh token (stored only as a hash).

    On use, the presented token is revoked and a new one issued (rotation).
    Presenting an already-revoked token is treated as compromise and revokes the
    whole family.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    family_id: Mapped[str] = mapped_column(String(64), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditLog(Base):
    """Security/administrative audit trail — who did what, from where.

    Distinct from the exercise TimelineEvent: this records account and admin
    actions (logins, user/role changes, evidence exports), the things an auditor
    or incident responder asks about.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_email: Mapped[str] = mapped_column(String(200), default="")
    action: Mapped[str] = mapped_column(String(80), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)


class Environment(Base):
    """The system under test — everything the team chooses to feed in.

    ``box_type`` sets the default knowledge posture (white / grey / black);
    per-audience redaction is expressed through the ``visibility`` map, which
    lists the environment keys each cell is allowed to see.
    """

    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    # Soft delete (U-3): hidden from lists and pickers, kept for the record.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    sector: Mapped[str] = mapped_column(String(120), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    box_type: Mapped[str] = mapped_column(String(20), default="grey")  # white|grey|black

    # Sensitive environment intelligence — encrypted at rest when a data key is
    # configured (M10); ordinary JSON otherwise. See app/crypto.py.
    assets: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    controls: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    detections: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    playbooks: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    policies: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    personnel: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    deception_assets: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    crown_jewels: Mapped[list] = mapped_column(EncryptedJSON, default=list)
    visibility: Mapped[dict] = mapped_column(EncryptedJSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scenarios: Mapped[list["Scenario"]] = relationship(back_populates="environment")


class Scenario(Base):
    """The exercise premise: a threat actor, a narrative arc, and its MSEL."""

    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    # Soft delete (U-3): hidden from lists and pickers, kept for the record.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"))
    name: Mapped[str] = mapped_column(String(200))
    threat_actor: Mapped[str] = mapped_column(String(200), default="")
    narrative: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(Text, default="")
    rules_of_engagement: Mapped[str] = mapped_column(Text, default="")
    cells: Mapped[list] = mapped_column(JSON, default=list)  # roles & fog-of-war
    exercise_type: Mapped[str] = mapped_column(String(40), default="tabletop")
    # Initial state variables (flags) branches can read/mutate — the mechanism
    # that lets paths diverge on accumulated decisions, not just the last one.
    variables: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    environment: Mapped["Environment"] = relationship(back_populates="scenarios")
    objectives: Mapped[list["Objective"]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan"
    )
    injects: Mapped[list["Inject"]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan"
    )


class Objective(Base):
    """A measurable goal plus its Exercise Evaluation Guide."""

    __tablename__ = "objectives"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    code: Mapped[str] = mapped_column(String(40))  # e.g. "OBJ-2"
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    success_criteria: Mapped[str] = mapped_column(Text, default="")
    eeg: Mapped[list] = mapped_column(JSON, default=list)  # evaluation-guide items
    # Free-form tags: canonical capability (detect/contain/...) and compliance
    # crosswalk hints the reporting layer consumes.
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    scenario: Mapped["Scenario"] = relationship(back_populates="objectives")


class Inject(Base):
    """One scene in the Master Scenario Events List.

    ``branches`` is the choose-your-own-adventure spine — a list of
    ``{when, trigger?, after?, goto, label}`` rules routing to the next inject
    on a player action, a game-clock timeout, or the proctor's choice.
    """

    __tablename__ = "injects"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    code: Mapped[str] = mapped_column(String(40))  # human id, e.g. "INJ-04"
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(240))
    channel: Mapped[str] = mapped_column(String(40), default="briefing")
    clock: Mapped[str] = mapped_column(String(20), default="")  # game time, e.g. "T+00:35"
    narrative: Mapped[str] = mapped_column(Text, default="")
    visible_to: Mapped[list] = mapped_column(JSON, default=list)
    expected_actions: Mapped[list] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    target_asset: Mapped[str] = mapped_column(String(120), default="")
    objective_code: Mapped[str] = mapped_column(String(40), default="")
    branches: Mapped[list] = mapped_column(JSON, default=list)
    is_start: Mapped[bool] = mapped_column(default=False)
    act: Mapped[str] = mapped_column(String(120), default="")  # phase/act grouping
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    scenario: Mapped["Scenario"] = relationship(back_populates="injects")


class Session(Base):
    """One run of a scenario. Holds live state the console reads and drives."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    # Soft delete (U-3): hidden from lists and pickers, kept for the record.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="setup")  # setup|running|paused|complete
    clock_mode: Mapped[str] = mapped_column(String(20), default="compressed")
    mode: Mapped[str] = mapped_column(String(20), default="tabletop")  # tabletop|sandbox|real_time
    # When true, a running inject with a timeout branch auto-advances after its
    # (clock-scaled) duration — for functional/real-time exercises.
    auto_advance: Mapped[bool] = mapped_column(Boolean, default=False)
    # Live exercise state: initialised from the scenario's variables, mutated by
    # branch `set` clauses, and read by branch `condition` guards.
    state: Mapped[dict] = mapped_column(JSON, default=dict)
    current_inject_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Short join code for large-group onboarding (D4); null until generated.
    join_code: Mapped[str | None] = mapped_column(String(12), nullable=True, index=True)
    # Signed chain head (S-6): the sequence and hash of the last timeline event,
    # HMAC-signed, so a truncated chain no longer verifies as intact.
    head_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    head_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    head_sig: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # When the armed auto-advance timer is due (F-5); re-armed on startup.
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Authorization for live/technical injects (M4). Empty until explicitly granted.
    auth_scope: Mapped[list] = mapped_column(JSON, default=list)  # allowed target codes/hosts, "*" = any
    authorized_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    auth_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    events: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="TimelineEvent.seq"
    )
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class TimelineEvent(Base):
    """Append-only, hash-chained record of everything that happened.

    Each event stores the previous event's hash and its own, so the timeline is
    tamper-evident — the property that makes a report defensible for audit.
    """

    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    seq: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    game_clock: Mapped[str] = mapped_column(String(20), default="")
    kind: Mapped[str] = mapped_column(String(30))  # inject_fired|decision|adjudication|note|observation|status
    ref: Mapped[str] = mapped_column(String(60), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")

    session: Mapped["Session"] = relationship(back_populates="events")


class Observation(Base):
    """An evaluator's note, tied to an objective and a moment on the timeline."""

    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    objective_code: Mapped[str] = mapped_column(String(40), default="")
    rating: Mapped[str] = mapped_column(String(20), default="note")  # met|partial|missed|note
    note: Mapped[str] = mapped_column(Text, default="")
    timeline_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    session: Mapped["Session"] = relationship(back_populates="observations")


class Report(Base):
    """A rendered output for one audience, generated from the timeline."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    audience: Mapped[str] = mapped_column(String(40))  # executive|technical|grc|training
    title: Mapped[str] = mapped_column(String(240))
    content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


# Cadences an exercise programme can recur on.
CADENCES = ("once", "daily", "weekly", "monthly", "quarterly")

# Improvement-plan item lifecycle and severity.
IMPROVEMENT_STATUSES = ("open", "in_progress", "closed")
IMPROVEMENT_SEVERITIES = ("low", "medium", "high", "critical")


class ImprovementItem(Base):
    """A follow-up action from an exercise — the corrective-action / improvement
    plan. Can be pushed to an external tracker (Jira/ServiceNow) and its closure
    verified back against that ticket (F4)."""

    __tablename__ = "improvement_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")
    source: Mapped[str] = mapped_column(String(40), default="manual")  # manual|gap|observation
    # External tracker linkage (empty until pushed).
    external_system: Mapped[str] = mapped_column(String(40), default="")  # jira|servicenow|simulation
    external_ref: Mapped[str] = mapped_column(String(80), default="")
    external_url: Mapped[str] = mapped_column(String(400), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class ExerciseSchedule(Base):
    """A recurring (or one-off) plan to run a scenario — the backbone of an
    exercise *programme*. Materialises into a Session when it comes due, and
    surfaces reminders ahead of each run (F3)."""

    __tablename__ = "exercise_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"))
    name: Mapped[str] = mapped_column(String(200))
    cadence: Mapped[str] = mapped_column(String(20), default="once")  # see CADENCES
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # How many hours before a run a reminder becomes due.
    reminder_lead_hours: Mapped[int] = mapped_column(Integer, default=24)
    # The run time we last emitted a reminder for (dedupes reminders per run).
    reminded_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invitees: Mapped[list] = mapped_column(JSON, default=list)  # emails / role labels
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class CustomAdversary(Base):
    """A proctor-designed adversary (real or fictitious), org-scoped. Stores the
    fields needed to build the same threat-actor dict the generator consumes, so
    a custom adversary produces scenarios exactly like a built-in one (A7)."""

    __tablename__ = "custom_adversaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    key: Mapped[str] = mapped_column(String(60), index=True)  # slug, unique per org
    name: Mapped[str] = mapped_column(String(120))
    label: Mapped[str] = mapped_column(String(240), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    motivation: Mapped[str] = mapped_column(String(60), default="")
    is_fictitious: Mapped[bool] = mapped_column(Boolean, default=True)
    sectors: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    kill_chain: Mapped[list] = mapped_column(JSON, default=list)  # inject-bank scene keys
    objectives: Mapped[list] = mapped_column(JSON, default=list)  # [{title, success_criteria}]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Certificate(Base):
    """An exercise certificate (M1): the numbers one completed exercise
    produced, frozen and HMAC-signed at issue so a third party can check them
    against the serial without an account. Contains no narrative."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    serial: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    issued_by: Mapped[str] = mapped_column(String(320), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SessionJoin(Base):
    """A participant who joined a session via its join code (D4). One row per
    (session, user); the cell they picked drives their fog-of-war view."""

    __tablename__ = "session_joins"
    __table_args__ = (UniqueConstraint("session_id", "user_id", name="uq_session_user"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    display_name: Mapped[str] = mapped_column(String(160), default="")
    cell: Mapped[str] = mapped_column(String(40), default="blue_cell")
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
