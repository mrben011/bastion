import pytest

ASSET = {"name": "orders-db", "asset_type": "postgresql", "environment": "test", "host": "db.internal", "port": 5432,
         "database_name": "orders", "secret_ref": "vault/orders-readonly"}

WRITE_ENDPOINTS = [("post", "/api/assets"), ("get", "/api/users"), ("get", "/api/audit"), ("get", "/api/audit/verify")]


def test_role_permission_matrix(make_api, org):
    admin = make_api(org, "platform_admin")
    asset_id = admin.post("/api/assets", json=ASSET).json()["id"]
    expectations = {
        "security_analyst": {"assets_read": 200, "assets_write": 403, "users": 403, "audit": 403, "verify": 403},
        "incident_responder": {"assets_read": 200, "assets_write": 403, "users": 403, "audit": 403, "verify": 403},
        "auditor": {"assets_read": 200, "assets_write": 403, "users": 200, "audit": 200, "verify": 200},
        "platform_admin": {"assets_read": 200, "assets_write": 201, "users": 200, "audit": 200, "verify": 200},
    }
    for role, exp in expectations.items():
        api = make_api(org, role)
        assert api.get(f"/api/assets/{asset_id}").status_code == exp["assets_read"], role
        body = {**ASSET, "name": f"n-{role}"}
        assert api.post("/api/assets", json=body).status_code == exp["assets_write"], role
        assert api.get("/api/users").status_code == exp["users"], role
        assert api.get("/api/audit").status_code == exp["audit"], role
        assert api.get("/api/audit/verify").status_code == exp["verify"], role
        assert api.get("/api/overview").status_code == 200, role
        assert api.delete(f"/api/assets/{asset_id}").status_code in (403, 200), role


def test_denied_actions_are_audited(make_api, org):
    analyst = make_api(org, "security_analyst")
    assert analyst.post("/api/assets", json=ASSET).status_code == 403
    admin = make_api(org, "platform_admin")
    events = admin.get("/api/audit", params={"action": "authz.denied"}).json()
    assert any(e["actor_label"] == analyst.email and e["outcome"] == "denied" for e in events)


def test_cross_tenant_isolation_in_api(make_api, make_org):
    a, b = make_api(make_org(), "platform_admin"), make_api(make_org(), "platform_admin")
    a_asset = a.post("/api/assets", json=ASSET).json()["id"]
    assert b.get(f"/api/assets/{a_asset}").status_code == 404
    assert b.put(f"/api/assets/{a_asset}", json=ASSET).status_code == 404
    assert b.delete(f"/api/assets/{a_asset}").status_code == 404
    assert b.get("/api/assets").json() == []
    a_user = a.get("/api/users").json()[0]["id"]
    assert b.patch(f"/api/users/{a_user}", json={"is_active": False}).status_code == 404
    assert b.post(f"/api/users/{a_user}/reset-mfa").status_code == 404
    assert a.get(f"/api/assets/{a_asset}").status_code == 200
    # the same asset name can exist in two organizations
    assert b.post("/api/assets", json=ASSET).status_code == 201


def test_row_level_security_blocks_cross_tenant_reads_even_without_app_filters(make_api, make_org):
    """Simulates an application bug: raw queries with no org filter, using the real API database role."""
    import os

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from app.db import set_org

    org_a, org_b = make_org(), make_org()
    make_api(org_a, "platform_admin").post("/api/assets", json=ASSET)
    make_api(org_b, "platform_admin").post("/api/assets", json={**ASSET, "name": "other"})
    with Session(create_engine(os.environ["BASTION_DATABASE_URL"])) as db:
        assert db.execute(text("SELECT count(*) FROM assets")).scalar() == 0  # no org bound: nothing visible
        assert db.execute(text("SELECT count(*) FROM users")).scalar() == 0
        assert db.execute(text("SELECT count(*) FROM audit_events")).scalar() == 0
        set_org(db, org_a)
        names = [r[0] for r in db.execute(text("SELECT name FROM assets"))]
        assert names == ["orders-db"]
        assert db.execute(text("SELECT count(*) FROM users WHERE org_id <> :o"), {"o": str(org_a)}).scalar() == 0
        # writing a row for another organization is rejected by the policy
        with pytest.raises(Exception):
            db.execute(text("INSERT INTO assets (org_id, name, asset_type, environment) VALUES (:o,'evil','server','test')"),
                       {"o": str(org_b)})


def test_api_database_role_is_least_privilege(org):
    import os

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from app.db import set_org

    with Session(create_engine(os.environ["BASTION_DATABASE_URL"])) as db:
        set_org(db, org)
        for stmt in ["DELETE FROM users", "UPDATE audit_events SET action='x'", "DELETE FROM audit_events",
                     "TRUNCATE audit_events", "DROP TABLE users", "UPDATE organizations SET name='x'"]:
            with pytest.raises(Exception):
                db.execute(text(stmt))
            db.rollback()
            set_org(db, org)


@pytest.mark.parametrize("payload", ["' OR '1'='1", "x'; DROP TABLE assets;--", "%' OR 1=1 --", "\\"])
def test_sql_injection_attempts_are_inert(make_api, org, payload):
    admin = make_api(org, "platform_admin")
    admin.post("/api/assets", json=ASSET)
    r = admin.get("/api/assets", params={"q": payload, "asset_type": payload, "environment": payload})
    assert r.status_code in (200, 422)  # rejected by validation or treated as plain data
    if r.status_code == 200:
        assert r.json() == []
    r = admin.get("/api/assets", params={"q": payload})
    assert r.status_code == 200 and r.json() == []
    r = admin.get("/api/audit", params={"action": payload})
    assert r.status_code in (200, 422)
    assert Api_login_status(admin.http, payload) == 401
    assert admin.get("/api/assets").json()[0]["name"] == "orders-db"  # table still intact


def Api_login_status(http, payload):
    return http.post("/api/auth/login", json={"email": "a@example.com", "password": payload}).status_code


def test_asset_validation_rejects_embedded_credentials_and_unknown_fields(admin):
    bad = [
        {**ASSET, "secret_ref": "postgresql://user:hunter2@db/x"},
        {**ASSET, "host": "db.internal; rm -rf /"},
        {**ASSET, "port": 70000},
        {**ASSET, "asset_type": "mainframe"},
        {**ASSET, "password": "hunter2"},
    ]
    for body in bad:
        assert admin.post("/api/assets", json=body).status_code == 422, body


def test_asset_crud_and_duplicate_names(admin):
    created = admin.post("/api/assets", json=ASSET)
    assert created.status_code == 201
    asset = created.json()
    assert asset["monitoring_status"] == "not_configured" and asset["last_event_at"] is None
    assert admin.post("/api/assets", json=ASSET).status_code == 409
    upd = admin.put(f"/api/assets/{asset['id']}", json={**ASSET, "description": "orders"})
    assert upd.status_code == 200 and upd.json()["description"] == "orders"
    assert admin.delete(f"/api/assets/{asset['id']}").status_code == 200
    assert admin.get(f"/api/assets/{asset['id']}").status_code == 404


def test_user_management_guards(admin, make_api, org):
    me = admin.get("/api/auth/me").json()["user"]
    assert admin.patch(f"/api/users/{me['id']}", json={"role": "auditor"}).status_code == 400
    assert admin.patch(f"/api/users/{me['id']}", json={"is_active": False}).status_code == 400
    r = admin.post("/api/users", json={"email": "new.analyst@example.com", "display_name": "New", "role": "security_analyst",
                                       "initial_password": "weak"})
    assert r.status_code == 422
    r = admin.post("/api/users", json={"email": "new.analyst@example.com", "display_name": "New", "role": "security_analyst",
                                       "initial_password": "initial-pass-phrase-1"})
    assert r.status_code == 201 and r.json()["must_change_password"] is True
    assert "password_hash" not in r.text and "initial-pass" not in r.text
    assert admin.post("/api/users", json={"email": "new.analyst@example.com", "display_name": "N", "role": "auditor",
                                          "initial_password": "initial-pass-phrase-1"}).status_code == 409


def test_deactivating_a_user_revokes_their_sessions(admin, make_api, org):
    analyst = make_api(org, "security_analyst")
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == analyst.email)
    assert analyst.get("/api/assets").status_code == 200
    assert admin.patch(f"/api/users/{uid}", json={"is_active": False}).status_code == 200
    assert analyst.get("/api/assets").status_code == 401
    assert analyst.login(analyst.email).status_code == 401


def test_cannot_demote_last_admin(admin, make_api, org):
    other = make_api(org, "platform_admin")
    other_id = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == other.email)
    assert admin.patch(f"/api/users/{other_id}", json={"role": "auditor"}).status_code == 200  # admin remains
    me_id = admin.get("/api/auth/me").json()["user"]["id"]
    assert admin.patch(f"/api/users/{me_id}", json={"role": "auditor"}).status_code == 400


def test_admin_can_reset_password_and_mfa(admin, make_api, org):
    victim = make_api(org, "incident_responder")
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == victim.email)
    assert admin.post(f"/api/users/{uid}/reset-mfa").status_code == 200
    assert victim.get("/api/assets").status_code == 401
    r = victim.login(victim.email)
    assert r.status_code == 200 and r.json()["restriction"] == "mfa_setup"
    assert admin.post(f"/api/users/{uid}/reset-password", json={"new_password": "temporary-pass-phrase-3"}).status_code == 200
    assert victim.login(victim.email, "temporary-pass-phrase-3").json()["restriction"] == "password_change"
