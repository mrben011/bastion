from app.security import password_problems, verify_totp
from app.audit import GENESIS


def test_password_policy():
    assert password_problems("short")
    assert password_problems("aaaaaaaaaaaaaaaa")
    assert password_problems("jordansmith-secret-1", "jordansmith@x.test")
    assert password_problems("correct-horse-battery-9", "a@x.test") == []


def test_totp_rejects_malformed_codes():
    assert verify_totp("JBSWY3DPEHPK3PXP", "abcdef", None) is None
    assert verify_totp("JBSWY3DPEHPK3PXP", "", None) is None


def test_health_and_ready(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/healthz").json() == {"status": "ok"}
    assert c.get("/api/readyz").status_code == 200


def test_oversized_body_rejected(app):
    from fastapi.testclient import TestClient
    r = TestClient(app).post("/api/auth/login", content=b"x" * 70000, headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_errors_do_not_leak_internals(app):
    from fastapi.testclient import TestClient
    r = TestClient(app).get("/api/auth/me")
    assert r.status_code == 401 and "Traceback" not in r.text


def test_genesis_hash_shape():
    assert len(GENESIS) == 64
