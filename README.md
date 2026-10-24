# Bastion

An AI-assisted cybersecurity platform, built in milestones. This repository contains **Milestone 1: the working foundation**.

Bastion does not claim to prevent every attack. Each section below says what is built, what is tested, and what is not done yet.

## What Milestone 1 includes

| Area | Status |
| --- | --- |
| Sign-in with Argon2id passwords, TOTP two-step verification, lockout and rate limiting | Built and tested |
| Server-side sessions (hashed tokens, idle and absolute expiry, revocation, CSRF protection) | Built and tested |
| Role-based permissions, deny by default, enforced on the server | Built and tested |
| Tenant isolation by organization, enforced in code and by PostgreSQL row-level security | Built and tested |
| Protected asset registry (stores a reference to a secret, never the secret) | Built and tested |
| Tamper-evident, append-only audit log with hash-chain verification | Built and tested |
| React dashboard: overview, assets, people and access, audit and integrity, account | Built, type-checked and compiled. Not yet exercised in a browser test |
| Passkeys and hardware security keys (WebAuthn) | Not built. TOTP is the only second factor today |
| Event ingestion, detection, incidents | Milestone 2 |
| Signed policies, independent audit storage, service identities | Milestone 3 |
| Policy engine and response orchestration | Milestone 4 |
| AI analyst | Milestone 5 |
| Backup verification and recovery | Milestone 6 |

The dashboard shows only real data. Where a feature does not exist yet, the interface says so.

**Hosting on Vercel:** see `docs/VERCEL.md`.

**Fastest way to try it:** run `./scripts/setup.sh` (or `scripts\setup.ps1` on Windows). See `docs/TESTING.md` for a guided checklist.

## Run locally (without Docker)

Requirements: Python 3.12, Node 22, PostgreSQL 16.

```bash
# 1. Create the database and an owner role (run as a PostgreSQL superuser)
createdb bastion
psql -c "CREATE ROLE bastion_owner LOGIN PASSWORD 'choose-one'" -c "ALTER DATABASE bastion OWNER TO bastion_owner"

# 2. Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # then fill in the values; see the comments inside
export $(grep -v '^#' .env | xargs)
alembic upgrade head        # creates tables, row-level security, and the least-privilege role bastion_app
BASTION_BOOTSTRAP_PASSWORD='a-long-passphrase-here' \
  python -m app.cli bootstrap --org-name "My Organization" --admin-email you@example.com
uvicorn app.main:app --port 8000

# 3. Frontend (second terminal)
cd frontend && npm ci && npm run dev    # http://localhost:5173
```

Sign in with the administrator you just created. Because that role requires two-step verification, you will be asked to scan a QR code with an authenticator app before you can do anything else.

Generate the encryption key with:
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

## Run with Docker

```bash
cp .env.example .env     # fill in the three secrets
docker compose up --build
docker compose run --rm -e BASTION_BOOTSTRAP_PASSWORD='a-long-passphrase-here' \
  migrate python -m app.cli bootstrap --org-name "My Organization" --admin-email you@example.com
```

Open http://localhost:8080. The Docker files were written but have not been built or run in the environment that produced this milestone, so expect to fix small issues on first run.

## Run the tests

```bash
cd backend
export TEST_PG_ADMIN_URL=postgresql+psycopg://bastion_owner:YOUR_OWNER_PASSWORD@localhost:5432
pytest
```

The suite creates a throwaway `bastion_test` database, runs the real migrations, and exercises the API against real PostgreSQL. It needs a PostgreSQL role that can create databases. 41 tests passed when this milestone was produced.

```bash
cd frontend && npm run typecheck && npm run build
```

## Layout

```
backend/app/        FastAPI application (routers, audit, security helpers, permissions)
backend/migrations/ Alembic migration: schema, RLS, append-only trigger, API role and grants
backend/tests/      Security-focused integration tests
frontend/src/       React + TypeScript dashboard
docs/SECURITY.md    Permissions per service, controls, test coverage, known limitations
```

## Design decisions worth knowing

- **Two database roles.** Migrations and the bootstrap CLI use the owner role. The API runs as `bastion_app`, which has no DDL rights, cannot update or delete audit events, and is bound by row-level security.
- **Pre-login lookups** go through two narrow `SECURITY DEFINER` functions that return only identifiers, so the API role never needs to read across organizations.
- **No implicit commits.** Endpoints commit explicitly, so a failed request cannot half-apply.
