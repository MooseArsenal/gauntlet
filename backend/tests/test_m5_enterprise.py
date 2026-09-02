"""M5 — enterprise checklist: SCIM 2.0 provisioning, Redis-shared throttles,
RLS default in production."""
import importlib
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.throttle import RedisThrottle

PW = "Str0ngPass!9"
SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role):
    em = f"{role}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def test_scim_token_is_admin_only_and_rotates():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        hf = _h(_user(c, ha, o, "facilitator"))
        assert c.post("/api/admin/scim-token", headers=hf).status_code == 403
        t1 = c.post("/api/admin/scim-token", headers=ha).json()
        assert t1["token"].startswith("gscim_") and t1["base_url"].endswith("/scim/v2")
        assert c.get("/scim/v2/ServiceProviderConfig", headers=_h(t1["token"])).status_code == 200
        t2 = c.post("/api/admin/scim-token", headers=ha).json()["token"]
        assert t2 != t1["token"]
        r = c.get("/scim/v2/Users", headers=_h(t1["token"]))
        assert r.status_code == 401 and r.headers["content-type"].startswith("application/scim+json")
        assert r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
        assert c.get("/scim/v2/Users", headers=_h(t2)).status_code == 200
        assert c.get("/scim/v2/Users").status_code == 401
        assert c.delete("/api/admin/scim-token", headers=ha).status_code == 204
        assert c.get("/scim/v2/Users", headers=_h(t2)).status_code == 401


def test_scim_user_lifecycle():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        tok = c.post("/api/admin/scim-token", headers=ha).json()["token"]
        hs = _h(tok)
        assert c.get("/scim/v2/ResourceTypes", headers=hs).json()["Resources"][0]["id"] == "User"
        assert c.get("/scim/v2/Schemas", headers=hs).json()["Resources"][0]["id"] == SCIM_USER
        # create
        r = c.post("/scim/v2/Users", headers=hs, json={
            "schemas": [SCIM_USER], "userName": f"Jo.Bloggs{o}@Ex.com", "externalId": "okta-1",
            "name": {"givenName": "Jo", "familyName": "Bloggs"}, "active": True,
            "roles": [{"value": "facilitator"}]})
        assert r.status_code == 201, r.text
        u = r.json()
        assert u["userName"] == f"jo.bloggs{o}@ex.com" and u["active"] is True
        assert u["name"]["formatted"] == "Jo Bloggs" and u["roles"][0]["value"] == "facilitator"
        assert u["meta"]["location"].endswith(f"/scim/v2/Users/{u['id']}")
        uid = u["id"]
        # duplicate
        assert c.post("/scim/v2/Users", headers=hs, json={"userName": f"jo.bloggs{o}@ex.com"}).status_code == 409
        assert c.post("/scim/v2/Users", headers=hs, json={"userName": "not-an-email"}).status_code == 400
        # provisioned users have no password: login fails, but the admin can set one
        assert c.post("/api/auth/login", json={"email": u["userName"], "password": ""}).status_code in (401, 422, 429)
        # filter
        lst = c.get('/scim/v2/Users', headers=hs, params={"filter": f'userName eq "jo.bloggs{o}@ex.com"'}).json()
        assert lst["totalResults"] == 1 and lst["Resources"][0]["id"] == uid
        lst = c.get('/scim/v2/Users', headers=hs, params={"filter": 'externalId eq "okta-1"'}).json()
        assert lst["totalResults"] == 1
        assert c.get('/scim/v2/Users', headers=hs, params={"filter": 'title co "x"'}).status_code == 400
        # unknown role is ignored; the console shows the member
        assert any(m["email"] == u["userName"] for m in c.get("/api/members", headers=ha).json())
        # patch: rename and deactivate
        r = c.patch(f"/scim/v2/Users/{uid}", headers=hs, json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "name.givenName", "value": "Joanna"},
                           {"op": "replace", "path": "active", "value": False}]})
        assert r.status_code == 200, r.text
        assert r.json()["name"]["givenName"] == "Joanna" and r.json()["active"] is False
        # an admin sets a password; the deactivated user still cannot sign in
        c.post(f"/api/members/{uid}/set-password", headers=ha, json={"password": PW})
        assert c.post("/api/auth/login", json={"email": u["userName"], "password": PW}).status_code == 401
        # reactivate through PUT, then the login works
        r = c.put(f"/scim/v2/Users/{uid}", headers=hs, json={
            "schemas": [SCIM_USER], "userName": u["userName"], "name": {"formatted": "Joanna Bloggs"},
            "active": True, "roles": [{"value": "evaluator"}]})
        assert r.status_code == 200 and r.json()["active"] is True and r.json()["roles"][0]["value"] == "evaluator"
        assert c.post("/api/auth/login", json={"email": u["userName"], "password": PW}).status_code == 200
        # delete = deactivate, the record stays
        assert c.delete(f"/scim/v2/Users/{uid}", headers=hs).status_code == 204
        assert c.get(f"/scim/v2/Users/{uid}", headers=hs).json()["active"] is False
        assert c.post("/api/auth/login", json={"email": u["userName"], "password": PW}).status_code == 401
        assert c.get("/scim/v2/Users/999999", headers=hs).status_code == 404
        # audit trail
        actions = {a["action"] for a in c.get("/api/audit", headers=ha).json()}
        assert {"scim.token.mint", "scim.user.create", "scim.user.patch", "scim.user.replace", "scim.user.deactivate"} <= actions


def test_scim_is_tenant_scoped_and_guards_the_last_admin():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        o2, admin2 = _org(c); ha2 = _h(admin2)
        tok = c.post("/api/admin/scim-token", headers=ha).json()["token"]; hs = _h(tok)
        tok2 = c.post("/api/admin/scim-token", headers=ha2).json()["token"]; hs2 = _h(tok2)
        me = c.get("/api/auth/me", headers=ha).json()
        other = c.get("/api/auth/me", headers=ha2).json()
        # each token sees only its own org
        ids = {u["id"] for u in c.get("/scim/v2/Users", headers=hs).json()["Resources"]}
        assert str(me["id"]) in ids and str(other["id"]) not in ids
        assert c.get(f"/scim/v2/Users/{other['id']}", headers=hs).status_code == 404
        assert c.delete(f"/scim/v2/Users/{other['id']}", headers=hs).status_code == 404
        assert c.get(f"/scim/v2/Users/{other['id']}", headers=hs2).status_code == 200
        # the identity provider cannot lock the org out
        r = c.delete(f"/scim/v2/Users/{me['id']}", headers=hs)
        assert r.status_code == 409 and r.json()["scimType"] == "mutability"
        r = c.patch(f"/scim/v2/Users/{me['id']}", headers=hs, json={"Operations": [{"op": "replace", "path": "roles", "value": [{"value": "participant"}]}]})
        assert r.status_code == 409
        # a second admin makes it allowed
        c.post("/scim/v2/Users", headers=hs, json={"userName": f"second{o}@ex.com", "roles": [{"value": "admin"}]})
        assert c.delete(f"/scim/v2/Users/{me['id']}", headers=hs).status_code == 204


class FakeRedis:
    """Enough of redis-py for the throttle: incr/expire/ttl/set/delete/scan_iter."""
    def __init__(self):
        self.kv = {}; self.exp = {}; self.now = 1000.0

    def _alive(self, k):
        if k in self.exp and self.exp[k] <= self.now:
            self.kv.pop(k, None); self.exp.pop(k, None)
        return k in self.kv

    def incr(self, k):
        self._alive(k); self.kv[k] = int(self.kv.get(k, 0)) + 1; return self.kv[k]

    def expire(self, k, secs): self.exp[k] = self.now + secs

    def ttl(self, k):
        if not self._alive(k): return -2
        return int(self.exp[k] - self.now) if k in self.exp else -1

    def set(self, k, v, ex=None):
        self.kv[k] = v
        if ex: self.exp[k] = self.now + ex

    def delete(self, *ks):
        for k in ks: self.kv.pop(k, None); self.exp.pop(k, None)

    def scan_iter(self, match="*"):
        import fnmatch
        return [k for k in list(self.kv) if fnmatch.fnmatch(k, match)]


def test_redis_throttle_locks_and_unlocks_like_the_memory_one():
    from app.config import LOGIN_LOCKOUT_SEC, LOGIN_MAX_ATTEMPTS
    r = FakeRedis(); t = RedisThrottle(r)
    key = "1.2.3.4|user@ex.com"
    assert t.retry_after(key) == 0
    for _ in range(LOGIN_MAX_ATTEMPTS - 1):
        t.record_failure(key)
    assert t.retry_after(key) == 0
    t.record_failure(key)
    assert 0 < t.retry_after(key) <= LOGIN_LOCKOUT_SEC
    # a lockout survives "another process" reading the same store
    assert RedisThrottle(r).retry_after(key) > 0
    r.now += LOGIN_LOCKOUT_SEC + 1
    assert t.retry_after(key) == 0
    t.record_failure("acct|user@ex.com", limit=1)
    assert t.retry_after("acct|user@ex.com") > 0
    t.reset_email("user@ex.com")
    assert t.retry_after("acct|user@ex.com") == 0
    t.record_failure(key, limit=1); t.reset(key); assert t.retry_after(key) == 0


def test_rls_defaults_on_in_production(monkeypatch):
    import app.config as config
    monkeypatch.setenv("GAUNTLET_ENV", "production"); monkeypatch.delenv("GAUNTLET_RLS_ENABLED", raising=False)
    monkeypatch.setenv("GAUNTLET_SECRET_KEY", "x" * 40); monkeypatch.setenv("GAUNTLET_CORS_ORIGINS", "https://a")
    importlib.reload(config)
    assert config.RLS_ENABLED is True
    monkeypatch.setenv("GAUNTLET_RLS_ENABLED", "0"); importlib.reload(config)
    assert config.RLS_ENABLED is False
    monkeypatch.setenv("GAUNTLET_ENV", "dev"); monkeypatch.delenv("GAUNTLET_RLS_ENABLED", raising=False); importlib.reload(config)
    assert config.RLS_ENABLED is False
