# Hosting Bastion on Vercel

One Vercel project serves both parts from the same address: the dashboard as static files, and the API as a Python function under `/api`. Keeping them on one origin is what lets the strict session cookie work.

## What you need

- A GitHub account (the repository should be **private**).
- A Vercel team that is **separate from the team hosting the sites Bastion will protect**. If one account is ever compromised, it should not take out both.
- A managed PostgreSQL database. Neon through the Vercel Marketplace is the simplest.
- Python 3.12 and this repository on your own computer, to run migrations once.

## 1. Push the code to GitHub

```bash
cd bastion
git init -b main
git add .
git commit -m "Bastion milestone 1"
git remote add origin git@github.com:YOUR-NAME/bastion.git
git push -u origin main
```

`.gitignore` already keeps `.env`, `.local-credentials.txt` and `node_modules` out of the repository. Check `git status` shows no secrets before you push.

## 2. Create the database

In your Vercel team, add a Neon Postgres database. Neon gives you two connection strings for the same database:

- a **direct** one, used only for migrations
- a **pooled** one, used by the running app

Both start with `postgresql://`. Our code needs `postgresql+psycopg://` instead, so change that prefix when you copy them.

## 3. Create the tables (once, from your computer)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export BASTION_DATABASE_ADMIN_URL='postgresql+psycopg://OWNER:PASSWORD@DIRECT-HOST/DBNAME?sslmode=require'
export BASTION_APP_DB_PASSWORD='choose-a-long-random-password'   # save it, you need it in step 4
alembic upgrade head

BASTION_BOOTSTRAP_PASSWORD='a-long-passphrase-here' \
  python -m app.cli bootstrap --org-name "Your Organization" --admin-email you@yourdomain.com
```

This creates the tables, the row-level security rules, the append-only audit log, and a least-privilege database role named `bastion_app`. The owner connection string is never given to Vercel.

If your provider documents `sslmode=verify-full`, use that instead of `require`.

## 4. Connect the repository and set variables

Import the repository as a new Vercel project. The settings come from `vercel.json`, so leave the framework preset alone.

Set these variables for the **Production** environment only. Do not enable them for Preview, so preview deployments can never reach the production database.

| Variable | Value | Mark as Sensitive |
| --- | --- | :-: |
| `BASTION_DATABASE_URL` | `postgresql+psycopg://bastion_app:APP-PASSWORD@POOLED-HOST/DBNAME?sslmode=require` | yes |
| `BASTION_FIELD_ENCRYPTION_KEY` | output of `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` | yes |
| `BASTION_SERVERLESS` | `true` | |
| `BASTION_ENVIRONMENT` | `production` | |
| `BASTION_COOKIE_SECURE` | `true` | |
| `BASTION_TRUST_PROXY_HEADERS` | `true` | |
| `BASTION_ALLOWED_ORIGIN` | `https://your-domain` | |

Back up the encryption key somewhere safe. Vercel will not show a Sensitive value again, and losing the key means every person must set up their authenticator app again.

Then redeploy.

## 5. Check it works

- Open `https://your-domain/api/readyz`. It should return `{"status":"ready"}`.
- Open the site, sign in as the administrator, and set up your authenticator app.

## 6. Lock down the Vercel side

Bastion's own controls do not protect the account that deploys it. Before relying on it:

- Require two-step verification for every member of the team, and keep the member list short.
- Keep Deployment Protection on, and keep production environment variables restricted to the team.
- Keep backups and, from Milestone 3, the audit-chain anchor outside Vercel.
- Review who can change environment variables or the Git connection. Anyone who can do that can change what Bastion runs.

## Known limits of this setup

- The database is reachable over the public internet, protected by TLS and the restricted role, not by a private network. If you need private connectivity, check whether your Vercel plan offers static outbound IPs and whether your database provider can allow-list them.
- Each request opens a new database connection. The pooled connection string keeps this fast. Under heavy load, watch connection counts.
- The login rate limiter now uses the database, which adds one small query per attempt.
- The background detection worker planned for Milestone 2 does not fit a request-driven function. It will need scheduled jobs, a queue, or a small worker elsewhere.
