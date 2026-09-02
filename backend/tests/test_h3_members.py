"""U-1 — member lifecycle: list, role change, deactivate, MFA reset, unlock,
temporary password, sign-out-everywhere; all admin-only, org-scoped,
audit-logged, and unable to lock the last admin out."""
import time
import uuid

from fastapi.testclient import TestClient

from app import security
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(c):
    o = uuid.uuid4().hex[:8]
    r = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW})
    return o, r.json()


def _add(c, ha, o, role):
    em = f"{role}{o}@ex.com"
    u = c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role}).json()
    return em, u["id"]


def _login(c, em, pw=PW):
    return c.post("/api/auth/login", json={"email": em, "password": pw})


def test_list_and_role_change_are_admin_only_and_org_scoped():
    with TestClient(app) as c:
        o, reg = _org(c); ha = _h(reg["access_token"])
        em, uid = _add(c, ha, o, "facilitator")
        members = c.get("/api/members", headers=ha).json()
        assert {m["email"] for m in members} == {f"a{o}@ex.com", em}
        # a facilitator cannot manage members
        hf = _h(_login(c, em).json()["access_token"])
        assert c.get("/api/members", headers=hf).status_code == 403
        assert c.patch(f"/api/members/{uid}", headers=hf, json={"role": "admin"}).status_code == 403
        # role change takes effect on the next request (role is re-read from the DB)
        assert c.patch(f"/api/members/{uid}", headers=ha, json={"role": "evaluator"}).json()["role"] == "evaluator"
        assert c.post("/api/scenarios", headers=hf, json={"environment_id": 1, "name": "x"}).status_code == 403
        # another org cannot see or touch them
        o2, reg2 = _org(c); h2 = _h(reg2["access_token"])
        assert c.patch(f"/api/members/{uid}", headers=h2, json={"role": "admin"}).status_code == 404
        assert em not in {m["email"] for m in c.get("/api/members", headers=h2).json()}


def test_deactivate_ends_sessions_and_blocks_login():
    with TestClient(app) as c:
        o, reg = _org(c); ha = _h(reg["access_token"])
        em, uid = _add(c, ha, o, "facilitator")
        tok = _login(c, em).json()
        assert c.get("/api/auth/me", headers=_h(tok["access_token"])).status_code == 200
        r = c.patch(f"/api/members/{uid}", headers=ha, json={"is_active": False})
        assert r.status_code == 200 and r.json()["is_active"] is False
        assert c.get("/api/auth/me", headers=_h(tok["access_token"])).status_code == 401
        assert c.post("/api/auth/refresh", json={"refresh_token": tok["refresh_token"]}).status_code == 401
        assert _login(c, em).status_code == 401
        # reactivation restores login
        c.patch(f"/api/members/{uid}", headers=ha, json={"is_active": True})
        assert _login(c, em).status_code == 200


def test_cannot_lock_out_the_last_admin_or_yourself():
    with TestClient(app) as c:
        o, reg = _org(c); ha = _h(reg["access_token"]); me = reg["user"]["id"]
        assert c.patch(f"/api/members/{me}", headers=ha, json={"role": "facilitator"}).status_code == 409
        assert c.patch(f"/api/members/{me}", headers=ha, json={"is_active": False}).status_code == 409
        em, uid = _add(c, ha, o, "admin")
        # now there are two admins: the second may be demoted; then the first is the last again
        assert c.patch(f"/api/members/{uid}", headers=ha, json={"role": "evaluator"}).status_code == 200
        h2 = _h(_login(c, em).json()["access_token"])
        assert c.get("/api/members", headers=h2).status_code == 403


def test_reset_mfa_and_set_password_recover_a_locked_out_member():
    with TestClient(app) as c:
        o, reg = _org(c); ha = _h(reg["access_token"])
        em, uid = _add(c, ha, o, "evaluator")
        ht = _h(_login(c, em).json()["access_token"])
        sec = c.post("/api/auth/mfa/setup", headers=ht).json()["secret"]
        c.post("/api/auth/mfa/enable", headers=ht, json={"code": security._totp_at(sec, int(time.time() // 30))})
        assert _login(c, em).json()["mfa_required"] is True
        # lost authenticator → admin resets; next login is password-only
        r = c.post(f"/api/members/{uid}/reset-mfa", headers=ha)
        assert r.status_code == 200 and r.json()["mfa_enabled"] is False
        assert "access_token" in _login(c, em).json()
        # forgotten password → admin sets a temporary one
        assert c.post(f"/api/members/{uid}/set-password", headers=ha, json={"password": "short"}).status_code == 422
        assert c.post(f"/api/members/{uid}/set-password", headers=ha, json={"password": "Temp0raryPass!1"}).status_code == 204
        assert _login(c, em).status_code == 401
        assert _login(c, em, "Temp0raryPass!1").status_code == 200


def test_unlock_clears_a_lockout_and_actions_are_audited():
    with TestClient(app) as c:
        o, reg = _org(c); ha = _h(reg["access_token"])
        em, uid = _add(c, ha, o, "facilitator")
        for _ in range(6):
            _login(c, em, "wrong")
        assert _login(c, em).status_code == 429
        assert c.post(f"/api/members/{uid}/unlock", headers=ha).status_code == 204
        assert _login(c, em).status_code == 200
        assert c.post(f"/api/members/{uid}/revoke-sessions", headers=ha).status_code == 204
        actions = {a["action"] for a in c.get("/api/audit", headers=ha).json()}
        assert {"members.unlock", "members.revoke_sessions"} <= actions


def test_members_page_served():
    with TestClient(app) as c:
        assert c.get("/members.html").status_code == 200
        assert c.get("/members.js").status_code == 200
