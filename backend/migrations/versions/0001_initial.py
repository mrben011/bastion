"""Initial schema: tenants, users, sessions, assets, tamper-evident audit log, RLS, least-privilege role."""
import os

from alembic import op
from sqlalchemy import text

revision = "0001"
down_revision = None

SCHEMA = """
CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name varchar(200) NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id),
    email varchar(320) NOT NULL UNIQUE CHECK (email = lower(email)),
    display_name varchar(200) NOT NULL,
    role varchar(40) NOT NULL CHECK (role IN ('platform_admin','security_analyst','incident_responder','auditor')),
    password_hash text NOT NULL,
    must_change_password boolean NOT NULL DEFAULT false,
    password_changed_at timestamptz,
    mfa_secret_enc text,
    mfa_enabled boolean NOT NULL DEFAULT false,
    mfa_last_step bigint,
    is_active boolean NOT NULL DEFAULT true,
    failed_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    last_login_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_org_idx ON users(org_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id),
    user_id uuid NOT NULL REFERENCES users(id),
    token_hash varchar(64) NOT NULL UNIQUE,
    csrf_token varchar(64) NOT NULL,
    restriction varchar(30) CHECK (restriction IN ('mfa_setup','password_change')),
    mfa_verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    ip varchar(64),
    user_agent varchar(256)
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id),
    name varchar(120) NOT NULL,
    asset_type varchar(40) NOT NULL CHECK (asset_type IN ('postgresql','application','api','cloud_environment','server','identity_provider')),
    environment varchar(20) NOT NULL CHECK (environment IN ('production','staging','development','test')),
    description varchar(1000) NOT NULL DEFAULT '',
    host varchar(255),
    port integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    database_name varchar(120),
    secret_ref varchar(200),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id),
    seq bigint NOT NULL,
    ts timestamptz NOT NULL,
    actor_user_id uuid,
    actor_label varchar(320),
    action varchar(80) NOT NULL,
    outcome varchar(20) NOT NULL CHECK (outcome IN ('success','failure','denied')),
    target_type varchar(40),
    target_id varchar(64),
    ip varchar(64),
    user_agent varchar(256),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash varchar(64) NOT NULL,
    hash varchar(64) NOT NULL,
    UNIQUE (org_id, seq)
);
CREATE INDEX audit_org_action_idx ON audit_events(org_id, action, ts);

-- The audit log is append-only, even for the table owner.
CREATE FUNCTION bastion_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END $$;
CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION bastion_audit_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION bastion_audit_immutable();

-- Row-level security: the API role only sees rows of the organization named in app.org_id.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organizations
    USING (id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (id = nullif(current_setting('app.org_id', true), '')::uuid);
"""

TENANT_TABLES = ["users", "sessions", "assets", "audit_events"]

LOOKUPS = """
-- Pre-authentication lookups. They return only identifiers, so the API role never needs to
-- read across organizations.
CREATE FUNCTION bastion_find_login_user(p_email text) RETURNS TABLE (id uuid, org_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS
$$ SELECT u.id, u.org_id FROM users u WHERE u.email = lower(p_email) $$;

CREATE FUNCTION bastion_find_session(p_token_hash text) RETURNS TABLE (id uuid, org_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS
$$ SELECT s.id, s.org_id FROM sessions s WHERE s.token_hash = p_token_hash $$;

REVOKE ALL ON FUNCTION bastion_find_login_user(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION bastion_find_session(text) FROM PUBLIC;
"""

GRANTS = """
GRANT USAGE ON SCHEMA public TO bastion_app;
GRANT SELECT ON organizations TO bastion_app;
GRANT SELECT, INSERT, UPDATE ON users TO bastion_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO bastion_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO bastion_app;
GRANT SELECT, INSERT ON audit_events TO bastion_app;
GRANT EXECUTE ON FUNCTION bastion_find_login_user(text) TO bastion_app;
GRANT EXECUTE ON FUNCTION bastion_find_session(text) TO bastion_app;
"""


def upgrade() -> None:
    conn = op.get_bind()
    pw = os.environ.get("BASTION_APP_DB_PASSWORD")
    if not pw:
        raise SystemExit("BASTION_APP_DB_PASSWORD is required to create the least-privilege API role")

    op.execute(SCHEMA)
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant ON {t} "
            f"USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) "
            f"WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid)"
        )
    op.execute(LOOKUPS)

    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'bastion_app'")).scalar()
    verb = "ALTER" if exists else "CREATE"
    stmt = conn.execute(text(f"SELECT format('{verb} ROLE bastion_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %L', cast(:pw as text))"), {"pw": pw}).scalar()
    conn.exec_driver_sql(stmt)
    op.execute("DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO bastion_app', current_database()); END $$")
    op.execute(GRANTS)


def downgrade() -> None:
    raise SystemExit("Downgrades are disabled: the audit log must not be dropped by tooling.")
