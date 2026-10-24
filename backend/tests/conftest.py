import os
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pyotp
import pytest
from cryptography.fernet import Fernet

ADMIN_BASE = os.environ.get("TEST_PG_ADMIN_URL", "postgresql+psycopg://bastion_owner:owner_pw@localhost:5432")
DB_NAME = "bastion_test"
APP_PW = "app_test_pw"

os.environ.update({
    "BASTION_DATABASE_URL": f"postgresql+psycopg://bastion_app:{APP_PW}@localhost:5432/{DB_NAME}",
    "BASTION_DATABASE_ADMIN_URL": f"{ADMIN_BASE}/{DB_NAME}",
    "BASTION_APP_DB_PASSWORD": APP_PW,
    "BASTION_FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "BASTION_COOKIE_SECURE": "false",
    "BASTION_ENVIRONMENT": "development",
    "BASTION_MAX_FAILED_LOGINS": "5",
    "BASTION_LOGIN_RATE_LIMIT_PER_MINUTE": "1000",
})

PW = "correct-horse-battery-9"


def _pg(url_suffix: str) -> str:
    return (ADMIN_BASE + url_suffix).replace("postgresql+psycopg", "postgresql")


@pytest.fixture(scope="session", autouse=True)
def database():
    with psycopg.connect(_pg("/postgres"), autocommit=True) as c:
        c.execute(f"DROP DATABASE IF EXISTS {DB_NAME} WITH (FORCE)")
        c.execute(f"CREATE DATABASE {DB_NAME}")
    backend = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=backend, check=True, env=os.environ.copy())
    yield


@pytest.fixture
def owner():
    """A superuser-owned connection used to arrange state and to simulate an attacker with DB access."""
    with psycopg.connect(_pg(f"/{DB_NAME}"), autocommit=True) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_limiter(database):
    with psycopg.connect(_pg(f"/{DB_NAME}"), autocommit=True) as c:
        c.execute("TRUNCATE rate_limits")


@pytest.fixture(scope="session")
def app():
    from app.main import app
    return app


class Api:
    """Thin test client that remembers the CSRF token the way the frontend does."""

    def __init__(self, app):
        from fastapi.testclient import TestClient
        self.http = TestClient(app, raise_server_exceptions=False)
        self.csrf = ""
        self.email = ""

    def login(self, email, password=PW, totp=None):
        body = {"email": email, "password": password}
        if totp:
            body["totp_code"] = totp
        r = self.http.post("/api/auth/login", json=body)
        if r.status_code == 200:
            self.csrf, self.email = r.json()["csrf_token"], email
        return r

    def req(self, method, url, **kw):
        return self.http.request(method, url, headers={"X-CSRF-Token": self.csrf}, **kw)

    def get(self, url, **kw): return self.req("GET", url, **kw)
    def post(self, url, **kw): return self.req("POST", url, **kw)
    def put(self, url, **kw): return self.req("PUT", url, **kw)
    def patch(self, url, **kw): return self.req("PATCH", url, **kw)
    def delete(self, url, **kw): return self.req("DELETE", url, **kw)


def _new_user(org_id, role, password=PW, must_change=False, mfa=False):
    """Create a user directly through the owner connection (bypasses the API, like a bootstrap)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.bootstrap import create_user
    from app.db import set_org
    from app.security import encrypt_field
    email = f"{role}-{uuid.uuid4().hex[:8]}@example.com"
    secret = None
    with Session(create_engine(os.environ["BASTION_DATABASE_ADMIN_URL"])) as db:
        set_org(db, org_id)
        u = create_user(db, org_id=org_id, email=email, display_name=role, role=role, password=password, must_change_password=must_change)
        if mfa:
            secret = pyotp.random_base32()
            u.mfa_secret_enc, u.mfa_enabled = encrypt_field(secret), True
        db.commit()
    return email, secret


@pytest.fixture
def make_org():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.bootstrap import create_organization

    def _make():
        with Session(create_engine(os.environ["BASTION_DATABASE_ADMIN_URL"])) as db:
            org = create_organization(db, f"org-{uuid.uuid4().hex[:8]}")
            db.commit()
            return org.id
    return _make


@pytest.fixture
def org(make_org):
    return make_org()


@pytest.fixture
def make_api(app):
    """make_api(org_id, role) -> signed-in Api. MFA-required roles get a pre-enrolled authenticator."""
    from app.permissions import MFA_REQUIRED_ROLES

    def _make(org_id, role="platform_admin"):
        email, secret = _new_user(org_id, role, mfa=role in MFA_REQUIRED_ROLES)
        api = Api(app)
        if secret:
            r = api.login(email)
            assert r.status_code == 401 and r.json()["detail"]["code"] == "mfa_required"
            r = api.login(email, totp=pyotp.TOTP(secret).now())
        else:
            r = api.login(email)
        assert r.status_code == 200, r.text
        api.secret = secret
        return api
    return _make


@pytest.fixture
def admin(make_api, org):
    return make_api(org, "platform_admin")
