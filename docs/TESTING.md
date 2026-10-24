# Trying Bastion yourself

## 1. Start it

You need Docker Desktop and an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Authy, or 1Password all work).

Mac, Linux, or Windows WSL:
```bash
./scripts/setup.sh you@yourdomain.com
```
Windows PowerShell:
```powershell
.\scripts\setup.ps1 -AdminEmail you@yourdomain.com
```
The script builds everything, creates the admin and three sample users, and prints the sign-in details (also saved to `.local-credentials.txt`). Then open http://localhost:8080.

No Docker? Use the manual steps in the README.

Stop: `docker compose down`. Start over from scratch: `docker compose down -v`, delete `.env`, run the script again.

If something fails, send me the output of `docker compose logs api migrate web`.

## 2. Things to try

| # | Try this | You should see |
| --- | --- | --- |
| 1 | Sign in as the admin | A screen asking you to scan a QR code. Nothing else is reachable until you finish. |
| 2 | Scan it, enter the 6-digit code | The overview. Sign out and back in: now it asks for a code. |
| 3 | Reuse the same code within 30 seconds | Rejected. Codes work once. |
| 4 | Enter a wrong password 5 times | Always the same generic error, then the account locks for 15 minutes. Check Audit and integrity for the entries. |
| 5 | Sign in as `analyst.demo@example.com` | Forced password change first. The analyst sees assets and overview only, with no People or Audit pages. |
| 6 | In the analyst session, open `http://localhost:8080/api/users` | A 403 denial. The administrator then sees an `authz.denied` entry. |
| 7 | Sign in as the responder, then the auditor | The responder needs the authenticator setup. The auditor can read users and the audit log but cannot change anything. |
| 8 | As admin, register an asset (try pasting `postgresql://user:pass@host/db` as the secret reference) | The asset saves, but a pasted connection string is rejected. Only a reference name is accepted. |
| 9 | As admin, deactivate the analyst while they are signed in elsewhere | Their next click sends them to sign-in. |
| 10 | As admin, try to change your own role | Refused. |
| 11 | Audit and integrity, then Verify audit chain | "Every hash matches." |
| 12 | Tamper test, below, then verify again | A broken chain is reported at the exact event. |

### Tamper test (item 12)
This simulates an attacker with full database control editing history. Do it on a throwaway setup.
```bash
set -a; . ./.env; set +a
docker compose exec db psql -U bastion_owner bastion -c \
 "ALTER TABLE audit_events DISABLE TRIGGER USER; UPDATE audit_events SET action='nothing.here' WHERE seq=2; ALTER TABLE audit_events ENABLE TRIGGER USER;"
```
Click Verify audit chain again. It should report a break at event 2. Without the first and last statements, the same edit is refused by the database trigger.

### Second organization (tenant isolation)
```bash
docker compose run --rm -T -e BASTION_BOOTSTRAP_PASSWORD='another-long-passphrase-1' migrate \
  python -m app.cli bootstrap --org-name "Other Company" --admin-email other@example.com
```
Sign in as that admin (after MFA setup). You should see none of the first organization's assets, people, or audit events.

## 3. Automated tests
```bash
cd backend && pip install -r requirements-dev.txt
export TEST_PG_ADMIN_URL=postgresql+psycopg://bastion_owner:YOUR_OWNER_PASSWORD@localhost:5432
pytest
```
This needs a PostgreSQL you can reach with a role allowed to create databases (the setup script's database is not published to your machine by design).

## 4. What not to expect yet
No alerts, incidents, event feeds, or monitoring status. The dashboard says so on purpose. Those arrive in Milestone 2.
