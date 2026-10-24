import pyotp
import pytest

from tests.conftest import PW, Api, _new_user


def test_unauthenticated_requests_are_rejected(app):
    api = Api(app)
    for url in ["/api/auth/me", "/api/assets", "/api/users", "/api/audit", "/api/audit/verify", "/api/overview"]:
        assert api.get(url).status_code == 401, url


def test_login_logout_and_session_cookie_flags(admin):
    r = admin.get("/api/auth/me")
    assert r.status_code == 200 and r.json()["user"]["role"] == "platform_admin"
    assert "password_hash" not in r.text and "mfa_secret" not in r.text
    assert admin.post("/api/auth/logout").status_code == 200
    assert admin.get("/api/auth/me").status_code == 401


def test_cookie_is_httponly_and_samesite_strict(app, org):
    email, _ = _new_user(org, "security_analyst")
    r = Api(app).login(email)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_wrong_password_and_unknown_user_look_identical(app, org):
    email, _ = _new_user(org, "security_analyst")
    a = Api(app).login(email, "wrong-password-123")
    b = Api(app).login("nobody@example.com", "wrong-password-123")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_account_lockout_after_repeated_failures(app, org, owner):
    email, _ = _new_user(org, "security_analyst")
    api = Api(app)
    for _ in range(5):
        assert api.login(email, "bad-password-xyz").status_code == 401
    assert api.login(email, PW).status_code == 401  # correct password still refused while locked
    n = owner.execute("SELECT count(*) FROM audit_events WHERE actor_label=%s AND action='auth.login_blocked'", (email,)).fetchone()[0]
    assert n >= 1
    owner.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE email=%s", (email,))
    assert api.login(email, PW).status_code == 200


def test_ip_rate_limit_returns_429(app, org, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "login_rate_limit_per_minute", 3)
    codes = [Api(app).login("nobody@example.com", "x" * 12).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and 429 in codes[3:]


def test_csrf_token_required_for_unsafe_methods(admin):
    r = admin.http.post("/api/assets", json={"name": "x", "asset_type": "postgresql", "environment": "test"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf"
    r = admin.http.post("/api/assets", json={"name": "x", "asset_type": "postgresql", "environment": "test"},
                        headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403


def test_privileged_user_without_mfa_is_restricted_until_enrolled(app, org):
    email, _ = _new_user(org, "platform_admin")
    api = Api(app)
    r = api.login(email)
    assert r.status_code == 200 and r.json()["restriction"] == "mfa_setup"
    r = api.get("/api/assets")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "restricted_session"
    enroll = api.post("/api/auth/mfa/enroll").json()
    assert enroll["qr_svg"].startswith("<svg") and len(enroll["secret"]) >= 16
    bad = api.post("/api/auth/mfa/confirm", json={"code": "000000"})
    assert bad.status_code == 422
    ok = api.post("/api/auth/mfa/confirm", json={"code": pyotp.TOTP(enroll["secret"]).now()})
    assert ok.status_code == 200 and ok.json()["restriction"] is None
    assert api.get("/api/assets").status_code == 200


def test_mfa_is_required_and_totp_codes_cannot_be_replayed(app, org):
    email, secret = _new_user(org, "platform_admin", mfa=True)
    api = Api(app)
    assert api.login(email).json()["detail"]["code"] == "mfa_required"
    assert api.login(email, totp="123456").status_code == 401
    code = pyotp.TOTP(secret).now()
    assert api.login(email, totp=code).status_code == 200
    assert Api(app).login(email, totp=code).status_code == 401  # same code, second use


def test_forced_password_change_flow(app, org):
    email, _ = _new_user(org, "security_analyst", must_change=True)
    api = Api(app)
    assert api.login(email).json()["restriction"] == "password_change"
    assert api.get("/api/assets").status_code == 403
    assert api.post("/api/auth/change-password", json={"current_password": PW, "new_password": "short"}).status_code == 422
    assert api.post("/api/auth/change-password", json={"current_password": "nope-nope-nope", "new_password": "a-new-strong-pass-77"}).status_code == 403
    r = api.post("/api/auth/change-password", json={"current_password": PW, "new_password": "a-new-strong-pass-77"})
    assert r.status_code == 200 and r.json()["restriction"] is None
    assert api.get("/api/assets").status_code == 200
    assert Api(app).login(email, PW).status_code == 401
    assert Api(app).login(email, "a-new-strong-pass-77").status_code == 200


def test_password_change_revokes_other_sessions(app, org):
    email, _ = _new_user(org, "security_analyst")
    a, b = Api(app), Api(app)
    a.login(email), b.login(email)
    assert b.post("/api/auth/change-password", json={"current_password": PW, "new_password": "another-strong-one-88"}).status_code == 200
    assert a.get("/api/auth/me").status_code == 401
    assert b.get("/api/auth/me").status_code == 200


def test_idle_and_absolute_expiry(app, org, owner):
    email, _ = _new_user(org, "security_analyst")
    api = Api(app)
    api.login(email)
    owner.execute("UPDATE sessions SET last_seen_at = now() - interval '2 hours' WHERE user_id=(SELECT id FROM users WHERE email=%s)", (email,))
    assert api.get("/api/auth/me").status_code == 401
    api.login(email)
    owner.execute("UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE user_id=(SELECT id FROM users WHERE email=%s)", (email,))
    assert api.get("/api/auth/me").status_code == 401


def test_session_tokens_are_stored_hashed(app, org, owner):
    email, _ = _new_user(org, "security_analyst")
    api = Api(app)
    api.login(email)
    token = api.http.cookies.get("bastion_session")
    assert owner.execute("SELECT count(*) FROM sessions WHERE token_hash=%s", (token,)).fetchone()[0] == 0


def test_security_headers_present(app):
    r = Api(app).http.get("/api/healthz")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
