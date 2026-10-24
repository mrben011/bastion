import json

import pytest

from tests.conftest import _new_user


def test_actions_are_audited_with_a_valid_hash_chain(admin):
    admin.post("/api/assets", json={"name": "a1", "asset_type": "api", "environment": "test"})
    events = admin.get("/api/audit").json()
    actions = [e["action"] for e in events]
    assert "asset.registered" in actions and "auth.login" in actions
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] is True and v["checked"] >= 2 and v["head_seq"] == v["checked"]


def test_failed_logins_are_audited_and_contain_no_secrets(app, org, make_api):
    from tests.conftest import Api
    admin = make_api(org, "platform_admin")
    email, _ = _new_user(org, "security_analyst")
    Api(app).login(email, "SuperSecretWrong-123")
    events = admin.get("/api/audit", params={"action": "auth.login_failed"}).json()
    assert events and events[0]["actor_label"] == email
    assert "SuperSecretWrong" not in json.dumps(events)


def test_audit_log_is_append_only_even_for_the_table_owner(admin, owner):
    admin.get("/api/overview")
    with pytest.raises(Exception, match="append-only"):
        owner.execute("UPDATE audit_events SET action='tampered'")
    with pytest.raises(Exception, match="append-only"):
        owner.execute("DELETE FROM audit_events")
    with pytest.raises(Exception, match="append-only"):
        owner.execute("TRUNCATE audit_events")


def _with_trigger_disabled(owner, sql, params=()):
    """An attacker with full database control disables the trigger and edits history."""
    owner.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    try:
        owner.execute(sql, params)
    finally:
        owner.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")


def test_tampering_with_event_content_is_detected(admin, owner):
    admin.post("/api/assets", json={"name": "t1", "asset_type": "api", "environment": "test"})
    org_id = admin.get("/api/overview").json()["organization"]["id"]
    assert admin.get("/api/audit/verify").json()["valid"] is True
    _with_trigger_disabled(owner, "UPDATE audit_events SET action='asset.nothing' WHERE org_id=%s AND seq=2", (org_id,))
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] is False and v["first_bad_seq"] == 2


def test_deleting_a_middle_event_is_detected(admin, owner):
    admin.get("/api/audit/verify")
    admin.get("/api/audit/verify")
    org_id = admin.get("/api/overview").json()["organization"]["id"]
    _with_trigger_disabled(owner, "DELETE FROM audit_events WHERE org_id=%s AND seq=2", (org_id,))
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] is False and v["first_bad_seq"] == 2


def test_audit_endpoint_is_tenant_scoped(make_api, make_org):
    a, b = make_api(make_org(), "platform_admin"), make_api(make_org(), "platform_admin")
    a.post("/api/assets", json={"name": "only-in-a", "asset_type": "api", "environment": "test"})
    assert "only-in-a" not in json.dumps(b.get("/api/audit", params={"limit": 200}).json())
