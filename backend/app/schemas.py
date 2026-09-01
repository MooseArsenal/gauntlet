"""Pydantic request/response models (API contract)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

_orm = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #
class EnvironmentBase(BaseModel):
    name: str
    sector: str = ""
    description: str = ""
    box_type: str = "grey"
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
    created_at: datetime


class EnvironmentSummary(BaseModel):
    model_config = _orm
    id: int
    name: str
    sector: str
    box_type: str


# --------------------------------------------------------------------------- #
# Objective / Inject / Scenario
# --------------------------------------------------------------------------- #
class ObjectiveIn(BaseModel):
    code: str
    title: str
    description: str = ""
    success_criteria: str = ""
    eeg: list = Field(default_factory=list)
    meta: dict = Field(default_factory=dict)


class ObjectiveOut(ObjectiveIn):
    model_config = _orm
    id: int


class InjectIn(BaseModel):
    code: str
    sequence: int = 0
    title: str
    channel: str = "briefing"
    clock: str = ""
    narrative: str = ""
    visible_to: list = Field(default_factory=list)
    expected_actions: list = Field(default_factory=list)
    attack_techniques: list = Field(default_factory=list)
    target_asset: str = ""
    objective_code: str = ""
    branches: list = Field(default_factory=list)
    is_start: bool = False
    act: str = ""
    meta: dict = Field(default_factory=dict)


class InjectOut(InjectIn):
    model_config = _orm
    id: int


class ScenarioCreate(BaseModel):
    environment_id: int
    name: str
    threat_actor: str = ""
    narrative: str = ""
    scope: str = ""
    rules_of_engagement: str = ""
    cells: list = Field(default_factory=list)
    exercise_type: str = "tabletop"
    variables: dict = Field(default_factory=dict)
    objectives: list[ObjectiveIn] = Field(default_factory=list)
    injects: list[InjectIn] = Field(default_factory=list)


class ScenarioSummary(BaseModel):
    model_config = _orm
    id: int
    name: str
    threat_actor: str
    exercise_type: str
    environment_id: int


class ScenarioOut(BaseModel):
    model_config = _orm
    id: int
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
    name: str
    clock_mode: str = "compressed"
    mode: str = "tabletop"  # tabletop | sandbox | real_time
    auto_advance: bool = False


class SessionSummary(BaseModel):
    model_config = _orm
    id: int
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
    objective_code: str = ""
    rating: str = "note"
    note: str
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
    when: str = "proctor_choice"  # action_taken | timeout | proctor_choice
    trigger: Optional[str] = None
    goto: Optional[str] = None  # explicit override; wins over rules
    note: str = ""


class AdjudicateIn(BaseModel):
    techniques: list[str] = Field(default_factory=list)
    target_asset: str = ""
    description: str = ""


class NoteIn(BaseModel):
    text: str


class AdjudicationOut(BaseModel):
    ruling: dict
    event: TimelineEventOut


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
class ReportRequest(BaseModel):
    audience: str = "executive"  # executive | technical | grc | training


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
    actor_key: Optional[str] = None
    template_key: Optional[str] = None
    name: Optional[str] = None


class ScenarioImport(BaseModel):
    environment_id: int
    yaml: str


class ValidateRequest(BaseModel):
    yaml: str


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
    title: Optional[str] = None
    channel: Optional[str] = None
    clock: Optional[str] = None
    narrative: Optional[str] = None
    visible_to: Optional[list] = None
    expected_actions: Optional[list] = None
    attack_techniques: Optional[list] = None
    target_asset: Optional[str] = None
    objective_code: Optional[str] = None
    branches: Optional[list] = None
    sequence: Optional[int] = None
    is_start: Optional[bool] = None


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    threat_actor: Optional[str] = None
    narrative: Optional[str] = None
    scope: Optional[str] = None
    rules_of_engagement: Optional[str] = None
    cells: Optional[list] = None
    exercise_type: Optional[str] = None


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
    authorized_by: str
    note: str = ""
    ttl_minutes: int = 120


class LiveInjectIn(BaseModel):
    technique: str
    target: str
    action: str = ""


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


class RegisterIn(BaseModel):
    org_name: str
    email: str
    password: str = Field(min_length=8)
    name: str = ""


class LoginIn(BaseModel):
    email: str
    password: str


class CreateUserIn(BaseModel):
    email: str
    password: str = Field(min_length=8)
    name: str = ""
    role: str = "facilitator"


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


class AuditLogOut(BaseModel):
    model_config = _orm
    id: int
    actor_user_id: Optional[int] = None
    actor_email: str
    action: str
    detail: dict
    ip: str
    at: datetime
