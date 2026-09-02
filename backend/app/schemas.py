"""Pydantic request/response models (API contract)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .engine import technique

_orm = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #
class EnvironmentBase(BaseModel):
    name: str = Field(max_length=300)
    sector: str = Field(default="", max_length=300)
    description: str = Field(default="", max_length=20000)
    box_type: str = Field(default="grey", max_length=300)
    assets: list = Field(default_factory=list)
    controls: list = Field(default_factory=list)
    detections: list = Field(default_factory=list)
    playbooks: list = Field(default_factory=list)
    policies: list = Field(default_factory=list)
    personnel: list = Field(default_factory=list)
    deception_assets: list = Field(default_factory=list)
    crown_jewels: list = Field(default_factory=list)
    visibility: dict = Field(default_factory=dict)


class EnvironmentCreate(EnvironmentBase):
    pass


class EnvironmentOut(EnvironmentBase):
    model_config = _orm
    id: int
    archived_at: Optional[datetime] = None
    created_at: datetime


class EnvironmentSummary(BaseModel):
    model_config = _orm
    id: int
    archived_at: Optional[datetime] = None
    name: str
    sector: str
    box_type: str


# --------------------------------------------------------------------------- #
# Objective / Inject / Scenario
# --------------------------------------------------------------------------- #
class ObjectiveIn(BaseModel):
    code: str = Field(max_length=300)
    title: str = Field(max_length=300)
    description: str = Field(default="", max_length=20000)
    success_criteria: str = ""
    eeg: list = Field(default_factory=list)
    meta: dict = Field(default_factory=dict)


class ObjectiveOut(ObjectiveIn):
    model_config = _orm
    id: int


class InjectIn(BaseModel):
    code: str = Field(max_length=300)
    sequence: int = 0
    title: str = Field(max_length=300)
    channel: str = Field(default="briefing", max_length=300)
    clock: str = Field(default="", max_length=300)
    narrative: str = Field(default="", max_length=20000)
    visible_to: list = Field(default_factory=list, max_length=500)
    expected_actions: list = Field(default_factory=list, max_length=500)
    attack_techniques: list = Field(default_factory=list, max_length=500)

    @field_validator("attack_techniques")
    @classmethod
    def _norm_techniques(cls, v):
        return technique.normalize_list(v)
    target_asset: str = Field(default="", max_length=300)
    objective_code: str = Field(default="", max_length=300)
    branches: list = Field(default_factory=list)
    is_start: bool = False
    act: str = ""
    meta: dict = Field(default_factory=dict)


class InjectOut(InjectIn):
    model_config = _orm
    id: int


class ScenarioCreate(BaseModel):
    environment_id: int
    name: str = Field(max_length=300)
    threat_actor: str = Field(default="", max_length=300)
    narrative: str = Field(default="", max_length=20000)
    scope: str = Field(default="", max_length=20000)
    rules_of_engagement: str = Field(default="", max_length=20000)
    cells: list = Field(default_factory=list)
    exercise_type: str = Field(default="tabletop", max_length=300)
    variables: dict = Field(default_factory=dict)
    objectives: list[ObjectiveIn] = Field(default_factory=list)
    injects: list[InjectIn] = Field(default_factory=list)


class ScenarioSummary(BaseModel):
    model_config = _orm
    id: int
    archived_at: Optional[datetime] = None
    name: str
    threat_actor: str
    exercise_type: str
    environment_id: int


class ScenarioOut(BaseModel):
    model_config = _orm
    id: int
    archived_at: Optional[datetime] = None
    environment_id: int
    name: str
    threat_actor: str
    narrative: str
    scope: str
    rules_of_engagement: str
    cells: list
    exercise_type: str
    variables: dict = Field(default_factory=dict)
    created_at: datetime
    objectives: list[ObjectiveOut] = Field(default_factory=list)
    injects: list[InjectOut] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Session / timeline / observations
# --------------------------------------------------------------------------- #
class SessionCreate(BaseModel):
    scenario_id: int
    name: str = Field(max_length=300)
    clock_mode: str = Field(default="compressed", max_length=300)
    mode: str = Field(default="tabletop", max_length=300)  # tabletop | sandbox | real_time
    auto_advance: bool = False


# --- join-code lobby (D4) --- #
class JoinCodeOut(BaseModel):
    join_code: str


class JoinIn(BaseModel):
    code: str = Field(max_length=300)
    cell: str = "blue_cell"      # which fog-of-war view the joiner takes
    display_name: Optional[str] = Field(default=None, max_length=300)


class JoinOut(BaseModel):
    session_id: int
    name: str
    cell: str
    status: str


class LobbyMember(BaseModel):
    model_config = _orm
    display_name: str
    cell: str
    joined_at: datetime


class JoinedSessionOut(BaseModel):
    """A session the caller has joined, and the cell they hold in it (H1)."""
    session: "SessionSummary"
    cell: str
    display_name: str = ""


class SessionSummary(BaseModel):
    model_config = _orm
    id: int
    archived_at: Optional[datetime] = None
    scenario_id: int
    name: str
    status: str
    mode: str = "tabletop"
    current_inject_code: Optional[str] = None
    created_at: datetime


class TimelineEventOut(BaseModel):
    model_config = _orm
    id: int
    seq: int
    at: datetime
    game_clock: str
    kind: str
    ref: str
    payload: dict
    hash: str


class ObservationIn(BaseModel):
    objective_code: str = Field(default="", max_length=300)
    rating: str = Field(default="note", max_length=300)
    note: str = Field(max_length=20000)
    timeline_seq: Optional[int] = None


class ObservationOut(ObservationIn):
    model_config = _orm
    id: int
    created_at: datetime


class SessionState(BaseModel):
    """Everything the facilitator console needs to render one moment."""
    session: SessionSummary
    scenario: ScenarioSummary
    current_inject: Optional[InjectOut] = None
    available_branches: list[dict] = Field(default_factory=list)
    timeline: list[TimelineEventOut] = Field(default_factory=list)
    observations: list[ObservationOut] = Field(default_factory=list)
    state: dict = Field(default_factory=dict)
    terminal: bool = False


# --------------------------------------------------------------------------- #
# Proctor actions
# --------------------------------------------------------------------------- #
class DecisionIn(BaseModel):
    when: str = Field(default="proctor_choice", max_length=300)  # action_taken | timeout | proctor_choice
    trigger: Optional[str] = Field(default=None, max_length=300)
    goto: Optional[str] = Field(default=None, max_length=300)  # explicit override; wins over rules
    note: str = Field(default="", max_length=20000)


class AdjudicateIn(BaseModel):
    techniques: list[str] = Field(default_factory=list, max_length=500)
    target_asset: str = Field(default="", max_length=300)
    description: str = Field(default="", max_length=20000)

    @field_validator("techniques")
    @classmethod
    def _techniques(cls, v):
        return technique.validate_list(v)


class NoteIn(BaseModel):
    text: str = Field(max_length=20000)


class AdjudicationOut(BaseModel):
    ruling: dict
    event: TimelineEventOut


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
class ReportRequest(BaseModel):
    audience: str = Field(default="executive", max_length=300)  # executive | technical | grc | training


class ReportOut(BaseModel):
    model_config = _orm
    id: int
    audience: str
    title: str
    content: str
    created_at: datetime


# --------------------------------------------------------------------------- #
# Authoring (M2): catalog, generation, delivery, editing
# --------------------------------------------------------------------------- #
class ActorOut(BaseModel):
    key: str
    name: str
    label: str
    description: str
    kill_chain: list[str]
    objective_count: int


class AttackGroupOut(BaseModel):
    """A real, curated MITRE ATT&CK group the proctor can emulate directly."""
    key: str
    attack_id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str
    sectors: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    kill_chain: list[str] = Field(default_factory=list)
    objective_count: int = 0


class AdversaryObjective(BaseModel):
    title: str
    success_criteria: str = ""


class CustomAdversaryIn(BaseModel):
    """A proctor-designed adversary (A7). ``kill_chain`` is an ordered list of
    inject-bank scene keys; objectives are optional (sensible defaults are
    derived from the chain when omitted)."""
    name: str = Field(max_length=300)
    description: str = Field(default="", max_length=20000)
    motivation: str = ""
    is_fictitious: bool = True
    sectors: list[str] = Field(default_factory=list, max_length=500)
    techniques: list[str] = Field(default_factory=list, max_length=500)
    kill_chain: list[str] = Field(default_factory=list, max_length=500)
    objectives: Optional[list[AdversaryObjective]] = None


class CustomAdversaryOut(BaseModel):
    model_config = _orm
    id: int
    key: str
    name: str
    label: str
    description: str
    motivation: str
    is_fictitious: bool
    sectors: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    kill_chain: list[str] = Field(default_factory=list)
    objectives: list[AdversaryObjective] = Field(default_factory=list)
    created_at: datetime


class AdversaryDraft(BaseModel):
    """A generated, unsaved adversary the proctor can review, tweak, and save."""
    name: str
    label: str
    description: str
    motivation: str
    is_fictitious: bool
    sectors: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    kill_chain: list[str] = Field(default_factory=list)
    objectives: list[AdversaryObjective] = Field(default_factory=list)


class CtepPackOut(BaseModel):
    """A bundled CISA-CTEP-derived pack the proctor can import (D5)."""
    key: str
    title: str
    threat_actor: str
    modules: int
    objectives: int
    sector: str = ""
    environment_key: str = ""  # library environment the pack is written against (M2)
    environment_name: str = ""
    description: str = ""


class CtepImportIn(BaseModel):
    """Import a CTEP pack: a bundled ``pack_key`` or an uploaded ``pack`` object.
    Omit ``environment_id`` to import a bundled pack into its own library
    environment, stamped into the organisation if it is not there yet (M2)."""
    environment_id: Optional[int] = None
    pack_key: Optional[str] = None
    pack: Optional[dict] = None
    name: Optional[str] = Field(default=None, max_length=300)


class TemplateOut(BaseModel):
    key: str
    name: str
    actor: str
    narrative: str


class InjectBankEntryOut(BaseModel):
    key: str
    phase: str
    channel: str
    techniques: list[str]
    title: str


class GenerateRequest(BaseModel):
    environment_id: int
    actor_key: Optional[str] = Field(default=None, max_length=300)
    template_key: Optional[str] = Field(default=None, max_length=300)
    name: Optional[str] = Field(default=None, max_length=300)


class ScenarioImport(BaseModel):
    environment_id: int
    yaml: str  # bounded by MAX_YAML_BYTES (bytes), not characters


class ValidateRequest(BaseModel):
    yaml: str  # bounded by MAX_YAML_BYTES (bytes), not characters


class ValidationOut(BaseModel):
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DeliveryOut(BaseModel):
    channel: str
    headline: str
    fields: dict
    body: str
    expected_actions: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class InjectUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=300)
    channel: Optional[str] = Field(default=None, max_length=300)
    clock: Optional[str] = Field(default=None, max_length=300)
    narrative: Optional[str] = Field(default=None, max_length=20000)
    visible_to: Optional[list] = None
    expected_actions: Optional[list] = None
    attack_techniques: Optional[list] = None

    @field_validator("attack_techniques")
    @classmethod
    def _norm_techniques(cls, v):
        return technique.normalize_list(v) if v is not None else None
    target_asset: Optional[str] = Field(default=None, max_length=300)
    objective_code: Optional[str] = Field(default=None, max_length=300)
    branches: Optional[list] = None
    sequence: Optional[int] = None
    is_start: Optional[bool] = None


class ScenarioGraphIn(BaseModel):
    """The full inject graph from the visual editor — replaces the scenario's
    injects wholesale (positions ride along in each inject's ``meta.pos``)."""
    injects: list[InjectIn] = Field(default_factory=list)
    variables: Optional[dict] = None


class ScenarioUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=300)
    threat_actor: Optional[str] = Field(default=None, max_length=300)
    narrative: Optional[str] = Field(default=None, max_length=20000)
    scope: Optional[str] = Field(default=None, max_length=20000)
    rules_of_engagement: Optional[str] = Field(default=None, max_length=20000)
    cells: Optional[list] = None
    exercise_type: Optional[str] = Field(default=None, max_length=300)


# --------------------------------------------------------------------------- #
# Multi-cell & parallel (M3)
# --------------------------------------------------------------------------- #
class CellSessionView(BaseModel):
    """A fog-of-war view of a running session for one cell."""
    cell_key: str
    cell_name: str
    can_see_all: bool
    session: SessionSummary
    current_inject: Optional[InjectOut] = None
    timeline: list[TimelineEventOut] = Field(default_factory=list)
    objectives: list[ObjectiveOut] = Field(default_factory=list)


class SessionRollupRow(BaseModel):
    id: int
    name: str
    status: str
    injects: int
    adjudications: int
    detected: int
    missed: int
    mttd: Optional[float] = None
    coverage_gaps: list[str] = Field(default_factory=list)
    objectives_met: int


class TechniqueCoverage(BaseModel):
    technique: str
    injects: int
    sessions_detected: int
    sessions_total: int


class RollupTotals(BaseModel):
    sessions: int
    adjudications: int
    detected: int
    detection_rate: Optional[float] = None
    mean_mttd: Optional[float] = None


class RollupOut(BaseModel):
    scenario_id: int
    scenario_name: str
    sessions: list[SessionRollupRow] = Field(default_factory=list)
    technique_coverage: list[TechniqueCoverage] = Field(default_factory=list)
    totals: RollupTotals


# --------------------------------------------------------------------------- #
# Sandbox & real-time (M4)
# --------------------------------------------------------------------------- #
class AuthorizeIn(BaseModel):
    scope: list[str] = Field(default_factory=list)  # allowed targets; "*" = any
    authorized_by: str = Field(max_length=300)
    note: str = Field(default="", max_length=20000)
    ttl_minutes: int = 120


class LiveInjectIn(BaseModel):
    technique: str = Field(max_length=300)
    target: str = Field(max_length=300)
    action: str = Field(default="", max_length=20000)


class LiveInjectOut(BaseModel):
    executed: bool
    adapter: str
    telemetry: list = Field(default_factory=list)
    ruling: dict
    event: TimelineEventOut


# --------------------------------------------------------------------------- #
# Auth & organisations (M5)
# --------------------------------------------------------------------------- #
class OrgOut(BaseModel):
    model_config = _orm
    id: int
    name: str
    slug: str


class UserOut(BaseModel):
    model_config = _orm
    id: int
    org_id: int
    email: str
    name: str
    role: str
    mfa_enabled: bool = False


class MemberOut(BaseModel):
    """An organisation member as the admin sees them (U-1)."""
    id: int
    email: str
    name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    sso_linked: bool
    created_at: datetime

    @classmethod
    def from_user(cls, u) -> "MemberOut":
        return cls(id=u.id, email=u.email, name=u.name or "", role=u.role, is_active=u.is_active,
                   mfa_enabled=bool(u.mfa_enabled), sso_linked=bool(u.oidc_subject),
                   created_at=u.created_at)


class MemberUpdateIn(BaseModel):
    role: Optional[str] = Field(default=None, max_length=300)
    name: Optional[str] = Field(default=None, max_length=300)
    is_active: Optional[bool] = None


class MemberPasswordIn(BaseModel):
    password: str = Field(min_length=8)


class RegisterIn(BaseModel):
    org_name: str = Field(max_length=300)
    email: str = Field(max_length=300)
    password: str = Field(min_length=8)
    name: str = Field(default="", max_length=300)


class LoginIn(BaseModel):
    email: str = Field(max_length=300)
    password: str


class CreateUserIn(BaseModel):
    email: str = Field(max_length=300)
    password: str = Field(min_length=8)
    name: str = Field(default="", max_length=300)
    role: str = Field(default="facilitator", max_length=300)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str = ""
    token_type: str = "bearer"
    user: UserOut


class LoginResult(BaseModel):
    """Login returns tokens, or an MFA challenge when the account requires MFA."""
    mfa_required: bool = False
    challenge: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[UserOut] = None


class MfaLoginIn(BaseModel):
    challenge: str
    code: str


class RefreshIn(BaseModel):
    refresh_token: str


class LogoutIn(BaseModel):
    refresh_token: str


class ChangePasswordIn(BaseModel):
    old_password: str
    new_password: str


class MfaSetupIn(BaseModel):
    # Required when MFA is already enabled: a current TOTP code proves the
    # caller holds the second factor before a new enrolment may begin (H2).
    code: Optional[str] = Field(default=None, max_length=300)


class MfaSetupOut(BaseModel):
    secret: str
    uri: str


class MfaCodeIn(BaseModel):
    code: str


class WsTicketRequest(BaseModel):
    session_id: int


class WsTicketOut(BaseModel):
    ticket: str
    expires_in: int


class ReencryptOut(BaseModel):
    encryption_enabled: bool
    reencrypted: int


class PurgeIn(BaseModel):
    days: Optional[int] = None  # override the configured retention window


class PurgeOut(BaseModel):
    sessions: int
    audit_logs: int
    days: int


class EraseIn(BaseModel):
    confirm: str  # must equal the org slug, to prevent accidental erasure


class EraseOut(BaseModel):
    erased: dict


class ScheduleCreate(BaseModel):
    scenario_id: int
    name: str = Field(max_length=300)
    cadence: str = Field(default="once", max_length=300)  # once|daily|weekly|monthly|quarterly
    next_run_at: datetime
    reminder_lead_hours: int = 24
    invitees: list = Field(default_factory=list)


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=300)
    cadence: Optional[str] = Field(default=None, max_length=300)
    next_run_at: Optional[datetime] = None
    reminder_lead_hours: Optional[int] = None
    invitees: Optional[list] = None
    enabled: Optional[bool] = None


class ScheduleOut(BaseModel):
    model_config = _orm
    id: int
    scenario_id: int
    name: str
    cadence: str
    next_run_at: datetime
    last_run_at: Optional[datetime] = None
    reminder_lead_hours: int
    invitees: list
    enabled: bool
    created_at: datetime


class RunDueOut(BaseModel):
    ran: int
    sessions: list[SessionSummary] = Field(default_factory=list)


class ReminderOut(BaseModel):
    schedule_id: int
    name: str
    scenario_id: int
    run_at: Optional[str] = None
    invitees: list = Field(default_factory=list)
    delivered: bool = False


class AssistInjectIn(BaseModel):
    phase: str = Field(default="", max_length=300)  # kill-chain phase hint (e.g. initial-access)
    technique: str = Field(default="", max_length=300)  # ATT&CK technique hint (e.g. T1566.001)
    environment_id: Optional[int] = None  # pick a real target asset from this env
    brief: str = Field(default="", max_length=20000)  # free-text steer for the LLM path


class AssistInjectOut(BaseModel):
    inject: dict          # a draft inject (title/channel/narrative/expected_actions/…)
    generator: str        # "template" or the provider name


class EnvironmentTemplateOut(BaseModel):
    """A sector template from the environment library (E1)."""
    key: str
    name: str
    sector: str
    box_type: str
    description: str
    assets: int
    controls: int
    deception: int
    crown_jewels: list[str] = Field(default_factory=list)


class EnvironmentFromTemplateIn(BaseModel):
    key: str = Field(max_length=60)
    name: Optional[str] = Field(default=None, max_length=300)


class EnvironmentImportIn(BaseModel):
    source: str  # cmdb | edr | siem | asm | generic
    format: str = Field(default="json", max_length=300)  # json | csv
    data: str
    environment_id: Optional[int] = None  # merge into this env, else create new
    name: Optional[str] = Field(default=None, max_length=300)  # name for a newly created env


class EnvironmentImportOut(BaseModel):
    environment: EnvironmentOut
    imported: dict  # per-field counts added by this import
    created: bool


class RedActionIn(BaseModel):
    techniques: list[str] = Field(default_factory=list, max_length=500)
    target: str = Field(default="", max_length=300)
    action: str = Field(default="", max_length=20000)  # free-text description of what the red cell did

    @field_validator("techniques")
    @classmethod
    def _techniques(cls, v):
        return technique.validate_list(v)


class RedActionOut(BaseModel):
    ruling: dict
    event: TimelineEventOut


class TechniqueScore(BaseModel):
    technique: str
    attempts: int
    detected: int


class Scoreboard(BaseModel):
    session_id: int
    red_actions: int
    detected: int
    missed: int
    detection_rate: Optional[float] = None
    mean_time_to_detect_min: Optional[float] = None
    deceptions_tripped: int = 0
    by_technique: list[TechniqueScore] = Field(default_factory=list)


class ImprovementCreate(BaseModel):
    title: str = Field(max_length=300)
    description: str = Field(default="", max_length=20000)
    severity: str = Field(default="medium", max_length=300)
    session_id: Optional[int] = None


class ImprovementUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=300)
    description: Optional[str] = Field(default=None, max_length=20000)
    severity: Optional[str] = Field(default=None, max_length=300)
    status: Optional[str] = Field(default=None, max_length=300)


class ImprovementOut(BaseModel):
    model_config = _orm
    id: int
    session_id: Optional[int] = None
    title: str
    description: str
    severity: str
    status: str
    source: str
    external_system: str
    external_ref: str
    external_url: str
    created_at: datetime
    updated_at: datetime


class TrackerSyncOut(BaseModel):
    id: int
    external_system: str
    external_ref: str
    external_status: Optional[str] = None
    status: str


class AuditLogOut(BaseModel):
    model_config = _orm
    id: int
    actor_user_id: Optional[int] = None
    actor_email: str
    action: str
    detail: dict
    ip: str
    at: datetime


# --------------------------------------------------------------------------- #
# Exercise certificates (M1)
# --------------------------------------------------------------------------- #
class CertificateOut(BaseModel):
    model_config = _orm
    id: int
    session_id: int
    serial: str
    issued_by: str
    payload: dict
    digest: str
    signature: str
    issued_at: datetime
    revoked_at: Optional[datetime] = None


class CertificateVerifyOut(BaseModel):
    serial: str
    valid: bool
    reason: str
    issued_at: Optional[datetime] = None
    record: dict = Field(default_factory=dict)


class ScimTokenOut(BaseModel):
    """The SCIM bearer token, shown once (M5)."""
    token: str
    base_url: str
