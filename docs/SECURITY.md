# Security notes for Milestone 1

## Principals and permissions

### Human roles (enforced in `backend/app/permissions.py`)

| Permission | Platform administrator | Security analyst | Incident responder | Auditor |
| --- | :-: | :-: | :-: | :-: |
| overview:read | yes | yes | yes | yes |
| assets:read | yes | yes | yes | yes |
| assets:write (register, edit, remove) | yes | | | |
| users:read | yes | | | yes |
| users:manage (create, change role, deactivate, reset password or MFA, revoke sessions) | yes | | | |
| audit:read | yes | | | yes |
| audit:verify | yes | | | yes |
| MFA required before any access | yes | no | yes | yes |

Anything not listed is denied. The auditor cannot change anything. An administrator cannot change their own role or deactivate themselves, and the last active administrator cannot be removed.

Service identities and AI agents are separate principal types and will not share these roles. They arrive in Milestones 3 and 5.

### Database roles

| Role | Used by | Rights |
| --- | --- | --- |
| `bastion_owner` | Migrations and the bootstrap CLI only | Owns the schema. Must never be given to the API container. |
| `bastion_app` | The API | SELECT, INSERT, UPDATE on `users`; SELECT, INSERT, UPDATE, DELETE on `sessions` and `assets`; SELECT, INSERT only on `audit_events`; SELECT on `organizations`; EXECUTE on two lookup functions. No DDL, no superuser, no BYPASSRLS. |

### Process secrets

| Secret | Needed by | Purpose |
| --- | --- | --- |
| `BASTION_DATABASE_URL` | API | Connect as `bastion_app` |
| `BASTION_FIELD_ENCRYPTION_KEY` | API | Encrypts TOTP secrets at rest (Fernet). Losing it forces every user to re-enroll MFA. |
| `BASTION_DATABASE_ADMIN_URL`, `BASTION_APP_DB_PASSWORD` | Migrations and CLI only | Create schema and the `bastion_app` role |

## Controls and where they are tested

| Control | Implementation | Tests |
| --- | --- | --- |
| Authentication required on every non-health endpoint | `deps.current_context` | `test_unauthenticated_requests_are_rejected` |
| Passwords hashed with Argon2id; unknown and wrong-password responses are identical | `security.py`, `routers/auth.py` | `test_wrong_password_and_unknown_user_look_identical` |
| Account lockout and per-IP rate limit | `routers/auth.py`, `ratelimit.py` | `test_account_lockout_*`, `test_ip_rate_limit_returns_429` |
| TOTP MFA, replay protection, forced enrollment for privileged roles | `security.verify_totp`, session `restriction` | `test_mfa_is_required_*`, `test_privileged_user_without_mfa_*` |
| Sessions: random token, only its hash stored, HttpOnly, SameSite=Strict, idle and absolute expiry, revocation | `deps.py`, `routers/auth.py` | `test_session_tokens_are_stored_hashed`, `test_idle_and_absolute_expiry`, `test_deactivating_a_user_*` |
| CSRF token required on all unsafe methods | `deps.current_context` | `test_csrf_token_required_for_unsafe_methods` |
| Role matrix enforced server-side, denials audited | `deps.require` | `test_role_permission_matrix`, `test_denied_actions_are_audited` |
| Tenant isolation in code and by row-level security | `db.set_org`, migration policies | `test_cross_tenant_isolation_in_api`, `test_row_level_security_*` |
| Least-privilege API database role | migration grants | `test_api_database_role_is_least_privilege` |
| SQL injection resistance (parameterized queries, strict validation) | SQLAlchemy, `schemas.py` | `test_sql_injection_attempts_are_inert` |
| Asset records cannot hold credentials | `schemas.AssetIn` validators | `test_asset_validation_rejects_*` |
| Append-only, hash-chained audit log | trigger, grants, `audit.py` | `test_audit_log_is_append_only_*`, `test_tampering_*`, `test_deleting_a_middle_event_is_detected` |
| Secrets and passwords never appear in responses or audit details | schemas, `audit.record` | `test_failed_logins_are_audited_and_contain_no_secrets` |

## Known limitations

These are real gaps. Do not rely on Milestone 1 as a complete defence.

1. **No passkeys or hardware keys yet.** TOTP can be phished. WebAuthn is the planned replacement for privileged roles.
2. **The audit chain lives in the same database it protects.** It detects edits, reordering and deletion in the middle of the log. Someone with full database control could delete the newest events or rebuild the entire chain, and the platform could not tell. Milestone 3 anchors the chain head in independent storage.
3. **Rate limiting is a fixed window stored in the database.** It is shared across all API instances, so it works on serverless hosts, but a client can briefly send up to twice the limit across a window boundary, and every login attempt costs one extra database query.
4. **Account lockout can be used to lock a victim out temporarily.** Lockouts last 15 minutes and are audited. Failed attempts against unknown email addresses are written to application logs only, because there is no organization to attribute them to.
5. **No step-up authentication** for sensitive administrator actions such as resetting another person's MFA. A stolen administrator session could do this until the idle timeout.
6. **Database TLS is configured by connection string, not enforced by the code.** Production must use `sslmode=verify-full`. The development compose file uses a private network without TLS. Encryption at rest depends on the database host or managed service.
7. **No HSM or KMS integration.** The field encryption key comes from an environment variable. Use a managed secrets service and KMS in any real deployment.
8. **No email, password reset by email, or account invitations.** Administrators set a temporary password that must be changed at first sign-in.
9. **No telemetry exists yet.** The dashboard reports zero monitored assets and shows no alerts, because none of those capabilities are built.
10. **Dependency, secret and artifact scanning, signed releases, and deployment hardening reviews** are not set up. They belong to Milestones 3 and 6.
11. **The dashboard has been type-checked and compiled but not exercised by automated browser tests or an accessibility audit.**
12. **Docker files are untested.** They were written but not built in the environment that produced this milestone.
