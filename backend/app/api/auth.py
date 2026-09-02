"""Authentication & organisation management (M5)."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, models, oidc, schemas, security
from ..audit import client_ip
from ..config import LOGIN_ACCOUNT_MAX_ATTEMPTS, OIDC_ENABLED, REGISTER_MAX_PER_WINDOW
from ..database import get_db
from ..security import (
    create_token,
    get_current_user,
    hash_password,
    issue_refresh_token,
    password_problems,
    require_role,
    verify_password,
)
from ..throttle import throttle

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _enforce_password(pw: str) -> None:
    problems = password_problems(pw)
    if problems:
        raise HTTPException(422, {"password": problems})


def _tokens(db: Session, user: models.User) -> schemas.TokenOut:
    return schemas.TokenOut(
        access_token=create_token(user),
        refresh_token=issue_refresh_token(db, user),
        user=user,
    )


def _slugify(name: str, db: Session) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "org"
    slug, n = base, 1
    while db.execute(select(models.Organization).where(models.Organization.slug == slug)).scalar_one_or_none():
        n += 1
        slug = f"{base}-{n}"
    return slug


def _email_taken(db: Session, email: str) -> bool:
    return db.execute(
        select(models.User).where(func.lower(models.User.email) == email.lower())
    ).scalar_one_or_none() is not None


@router.post("/register", response_model=schemas.TokenOut, status_code=201)
def register(payload: schemas.RegisterIn, request: Request, db: Session = Depends(get_db)):
    """Create a new organisation and its first user (an admin)."""
    reg_key = f"reg|{client_ip(request)}"
    if throttle.retry_after(reg_key) > 0:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many organisations created from this address; try again later")
    _enforce_password(payload.password)
    if _email_taken(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    org = models.Organization(name=payload.org_name, slug=_slugify(payload.org_name, db))
    db.add(org)
    db.flush()
    user = models.User(
        org_id=org.id, email=payload.email.lower(), name=payload.name,
        password_hash=hash_password(payload.password), role="admin",
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.register", request=request, user=user,
                 detail={"org": org.name}, commit=False)
    result = _tokens(db, user)
    db.commit()
    throttle.record_failure(reg_key, limit=REGISTER_MAX_PER_WINDOW)  # counts registrations, not failures
    return result


@router.post("/login", response_model=schemas.LoginResult)
def login(payload: schemas.LoginIn, request: Request, db: Session = Depends(get_db)):
    email = payload.email.lower()
    key = f"{client_ip(request)}|{email}"
    acct = f"acct|{email}"   # S-5: counted whatever address the attempt came from
    wait = max(throttle.retry_after(key), throttle.retry_after(acct))
    if wait > 0:
        audit.record(db, "auth.login.locked", request=request, actor_email=email,
                     detail={"retry_after": wait})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"too many attempts; retry in {wait}s")

    user = db.execute(
        select(models.User).where(func.lower(models.User.email) == email)
    ).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash) or not user.is_active:
        throttle.record_failure(key)
        throttle.record_failure(acct, limit=LOGIN_ACCOUNT_MAX_ATTEMPTS)
        audit.record(db, "auth.login.failure", request=request, actor_email=email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    throttle.reset(key)
    throttle.reset(acct)
    # First factor passed. If MFA is enabled, hand back a challenge, not tokens.
    if user.mfa_enabled and user.mfa_secret:
        audit.record(db, "auth.login.mfa_challenge", request=request, user=user)
        return schemas.LoginResult(mfa_required=True,
                                   challenge=security.create_mfa_challenge(user))

    audit.record(db, "auth.login.success", request=request, user=user)
    t = _tokens(db, user)
    db.commit()
    return schemas.LoginResult(access_token=t.access_token, refresh_token=t.refresh_token,
                               user=t.user)


@router.post("/login/mfa", response_model=schemas.LoginResult)
def login_mfa(payload: schemas.MfaLoginIn, request: Request, db: Session = Depends(get_db)):
    """Second factor: exchange an MFA challenge + TOTP code for tokens.

    The challenge is single-use, and code guessing is throttled per account:
    after LOGIN_MAX_ATTEMPTS wrong codes the challenge is spent and the account's
    second factor is locked for LOGIN_LOCKOUT_SEC (S-4)."""
    user_id, jti = security.read_mfa_challenge(payload.challenge)
    user = db.get(models.User, user_id)
    if not user or not user.is_active or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid challenge")
    key = f"mfa|{user.id}"
    wait = throttle.retry_after(key)
    if wait > 0:
        security._spent_challenges.spend(jti)
        audit.record(db, "auth.mfa.locked", request=request, user=user, detail={"retry_after": wait})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"too many codes; retry in {wait}s")
    if not security.totp_verify(user.mfa_secret, payload.code):
        throttle.record_failure(key)
        if throttle.retry_after(key) > 0:
            security._spent_challenges.spend(jti)
        audit.record(db, "auth.mfa.failure", request=request, user=user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    throttle.reset(key)
    security._spent_challenges.spend(jti)  # single use
    audit.record(db, "auth.login.success", request=request, user=user, detail={"mfa": True})
    t = _tokens(db, user)
    db.commit()
    return schemas.LoginResult(access_token=t.access_token, refresh_token=t.refresh_token,
                               user=t.user)


@router.post("/refresh", response_model=schemas.TokenOut)
def refresh(payload: schemas.RefreshIn, db: Session = Depends(get_db)):
    """Rotate a refresh token, returning a new access + refresh pair."""
    user, new_raw = security.rotate_refresh_token(db, payload.refresh_token)
    result = schemas.TokenOut(access_token=create_token(user), refresh_token=new_raw, user=user)
    db.commit()
    return result


@router.post("/logout", status_code=204)
def logout(payload: schemas.LogoutIn, db: Session = Depends(get_db)):
    security.revoke_refresh_token(db, payload.refresh_token)
    db.commit()


@router.post("/change-password", status_code=204)
def change_password(
    payload: schemas.ChangePasswordIn,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.old_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is incorrect")
    _enforce_password(payload.new_password)
    user.password_hash = hash_password(payload.new_password)
    security.revoke_all_refresh(db, user.id)  # force re-login everywhere
    audit.record(db, "auth.password.change", request=request, user=user, commit=False)
    db.commit()


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user


@router.post("/users", response_model=schemas.UserOut, status_code=201)
def create_user(
    payload: schemas.CreateUserIn,
    request: Request,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Admins add users to their own organisation."""
    if payload.role not in models.ROLES:
        raise HTTPException(422, f"role must be one of {list(models.ROLES)}")
    from .. import entitlements  # L1: facilitator seats are the unit of sale
    entitlements.check_seats(db, admin.org_id, payload.role)
    _enforce_password(payload.password)
    if _email_taken(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")
    user = models.User(
        org_id=admin.org_id, email=payload.email.lower(), name=payload.name,
        password_hash=hash_password(payload.password), role=payload.role,
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.user.create", request=request, user=admin,
                 detail={"new_user": user.email, "role": user.role}, commit=False)
    db.commit()
    db.refresh(user)
    return user


# --------------------------------------------------------------------------- #
# TOTP MFA enrolment
# --------------------------------------------------------------------------- #
@router.post("/mfa/setup", response_model=schemas.MfaSetupOut)
def mfa_setup(
    request: Request,
    payload: schemas.MfaSetupIn | None = None,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Begin a TOTP enrolment. The new secret is *pending* until confirmed with
    /mfa/enable — a live second factor is never touched by this call, and when
    one is already enabled a current code is required to start over (H2)."""
    if user.mfa_enabled and user.mfa_secret:
        code = (payload.code if payload else None) or ""
        if not security.totp_verify(user.mfa_secret, code):
            audit.record(db, "auth.mfa.setup_refused", request=request, user=user)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "two-factor is enabled; enter a current code to re-enrol")
    secret = security.new_totp_secret()
    user.mfa_pending_secret = secret
    db.commit()
    return schemas.MfaSetupOut(secret=secret, uri=security.totp_uri(secret, user.email))


@router.post("/mfa/enable", response_model=schemas.UserOut)
def mfa_enable(
    payload: schemas.MfaCodeIn,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not user.mfa_pending_secret:
        raise HTTPException(400, "start MFA setup first")
    if not security.totp_verify(user.mfa_pending_secret, payload.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    # Promote the confirmed secret; the old one (if any) is retired only now.
    user.mfa_secret = user.mfa_pending_secret
    user.mfa_pending_secret = None
    user.mfa_enabled = True
    audit.record(db, "auth.mfa.enabled", request=request, user=user, commit=False)
    db.commit()
    db.refresh(user)
    return user


# --------------------------------------------------------------------------- #
# OIDC SSO (config-gated)
# --------------------------------------------------------------------------- #
def _sso_user(db: Session, claims: dict) -> models.User:
    """Resolve the SSO identity to an existing account (link on first use)."""
    sub = str(claims.get("sub") or "")
    email = (claims.get("email") or "").lower()
    user = db.execute(
        select(models.User).where(models.User.oidc_subject == sub)
    ).scalar_one_or_none() if sub else None
    if user is None and email:
        # Linking an existing account by email is only safe when the provider
        # vouches for that email (S-8); an unverified claim could belong to anyone.
        if claims.get("email_verified") is not True:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "the identity provider has not verified this email address")
        user = db.execute(
            select(models.User).where(func.lower(models.User.email) == email)
        ).scalar_one_or_none()
        if user is not None and sub:
            user.oidc_subject = sub  # link on first SSO login
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "no active Gauntlet account for this identity")
    return user


@router.get("/oidc/config")
def oidc_config():
    """Lets the sign-in page decide whether to show the SSO button."""
    return {"enabled": OIDC_ENABLED}


@router.get("/oidc/login")
def oidc_login():
    if not OIDC_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not configured")
    try:
        return RedirectResponse(oidc.authorization_url(), status_code=302)
    except oidc.OidcError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


@router.get("/oidc/callback")
def oidc_callback(code: str = "", state: str = "", request: Request = None,
                  db: Session = Depends(get_db)):
    if not OIDC_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not configured")
    if not code or not state:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing code or state")
    try:
        claims = oidc.complete_login(code, state)
    except oidc.OidcError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc))
    user = _sso_user(db, claims)
    audit.record(db, "auth.login.success", request=request, user=user,
                 detail={"sso": True}, commit=False)
    t = _tokens(db, user)
    db.commit()
    # Deliver tokens to the SPA via the URL fragment (kept out of server logs),
    # which app.js reads on load and then scrubs from the address bar.
    from urllib.parse import urlencode
    frag = urlencode({"sso_access": t.access_token, "sso_refresh": t.refresh_token})
    return RedirectResponse(f"/#{frag}", status_code=302)


@router.post("/mfa/disable", response_model=schemas.UserOut)
def mfa_disable(
    payload: schemas.MfaCodeIn,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.mfa_enabled and not security.totp_verify(user.mfa_secret or "", payload.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_pending_secret = None
    audit.record(db, "auth.mfa.disabled", request=request, user=user, commit=False)
    db.commit()
    db.refresh(user)
    return user
