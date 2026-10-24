import logging
from datetime import datetime, timedelta, timezone

import segno
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db, set_org
from ..deps import COOKIE_NAME, AuthContext, client_ip, client_ua, current_context, revoke_user_sessions
from ..models import User, UserSession
from ..permissions import MFA_REQUIRED_ROLES, PERMISSIONS
from .. import ratelimit
from ..schemas import ChangePasswordIn, LoginIn, MfaConfirmIn, UserOut
from ..security import (
    decrypt_field, encrypt_field, hash_password, hash_token, new_token, new_totp_secret,
    password_problems, totp_uri, verify_password, verify_totp,
)

log = logging.getLogger("bastion.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])


def restriction_for(user: User) -> str | None:
    if user.must_change_password:
        return "password_change"
    if user.role in MFA_REQUIRED_ROLES and not user.mfa_enabled:
        return "mfa_setup"
    return None


def _invalid() -> HTTPException:
    return HTTPException(401, {"code": "invalid_credentials", "message": "Email, password, or code is incorrect."})


def _register_failure(db: Session, user: User, ip: str, ua: str, reason: str) -> None:
    cfg = get_settings()
    user.failed_attempts += 1
    locked = user.failed_attempts >= cfg.max_failed_logins
    if locked:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=cfg.lockout_minutes)
    audit.record(
        db, org_id=user.org_id, action="auth.login_failed", outcome="failure", actor_user_id=user.id,
        actor_label=user.email, ip=ip, user_agent=ua,
        details={"reason": reason, "attempts": user.failed_attempts, "locked": locked},
    )
    db.commit()


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    cfg = get_settings()
    ip, ua = client_ip(request), client_ua(request)
    if not ratelimit.allow(db, f"login:{ip}", cfg.login_rate_limit_per_minute):
        raise HTTPException(429, {"code": "rate_limited", "message": "Too many attempts. Try again in a minute."})

    email = body.email.lower()
    row = db.execute(text("SELECT id, org_id FROM bastion_find_login_user(:e)"), {"e": email}).first()
    user = None
    if row:
        set_org(db, row.org_id)
        user = db.get(User, row.id)
    now = datetime.now(timezone.utc)

    if not user or not user.is_active:
        verify_password(None, body.password)  # keep timing similar for unknown accounts
        if user:
            audit.record(db, org_id=user.org_id, action="auth.login_failed", outcome="failure", actor_user_id=user.id,
                         actor_label=email, ip=ip, user_agent=ua, details={"reason": "inactive"})
            db.commit()
        else:
            log.warning("login failed for unknown account from %s", ip)  # no org to attribute an audit event to
        raise _invalid()

    if user.locked_until and user.locked_until > now:
        verify_password(user.password_hash, body.password)
        audit.record(db, org_id=user.org_id, action="auth.login_blocked", outcome="denied", actor_user_id=user.id,
                     actor_label=email, ip=ip, user_agent=ua, details={"reason": "account_locked"})
        db.commit()
        raise _invalid()

    if not verify_password(user.password_hash, body.password):
        _register_failure(db, user, ip, ua, "bad_password")
        raise _invalid()

    step = None
    if user.mfa_enabled:
        if not body.totp_code:
            raise HTTPException(401, {"code": "mfa_required", "message": "Enter the 6-digit code from your authenticator app."})
        step = verify_totp(decrypt_field(user.mfa_secret_enc), body.totp_code, user.mfa_last_step)
        if step is None:
            _register_failure(db, user, ip, ua, "bad_mfa_code")
            raise _invalid()
        user.mfa_last_step = step

    user.failed_attempts, user.locked_until, user.last_login_at = 0, None, now
    token, csrf = new_token(), new_token()
    sess = UserSession(
        org_id=user.org_id, user_id=user.id, token_hash=hash_token(token), csrf_token=csrf,
        restriction=restriction_for(user), mfa_verified=user.mfa_enabled,
        expires_at=now + timedelta(hours=cfg.session_absolute_hours), ip=ip, user_agent=ua,
    )
    db.add(sess)
    audit.record(db, org_id=user.org_id, action="auth.login", actor_user_id=user.id, actor_label=email, ip=ip,
                 user_agent=ua, details={"mfa": user.mfa_enabled, "restriction": sess.restriction})
    db.commit()
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=cfg.cookie_secure, samesite="strict",
                        max_age=cfg.session_absolute_hours * 3600, path="/")
    return {"user": UserOut.model_validate(user), "csrf_token": csrf, "restriction": sess.restriction}


@router.post("/logout")
def logout(response: Response, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    ctx.session.revoked_at = datetime.now(timezone.utc)
    audit.record(db, org_id=ctx.org_id, action="auth.logout", actor_user_id=ctx.user.id, actor_label=ctx.user.email,
                 ip=ctx.ip, user_agent=ctx.ua)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(ctx: AuthContext = Depends(current_context)):
    return {
        "user": UserOut.model_validate(ctx.user),
        "csrf_token": ctx.session.csrf_token,
        "restriction": ctx.session.restriction,
        "permissions": sorted(PERMISSIONS.get(ctx.user.role, frozenset())) if not ctx.session.restriction else [],
        "session_expires_at": ctx.session.expires_at,
    }


@router.post("/change-password")
def change_password(body: ChangePasswordIn, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    user = ctx.user
    if not verify_password(user.password_hash, body.current_password):
        _register_failure(db, user, ctx.ip, ctx.ua, "bad_current_password")
        raise HTTPException(403, {"code": "invalid_credentials", "message": "Current password is incorrect."})
    problems = password_problems(body.new_password, user.email)
    if body.new_password == body.current_password:
        problems.append("must differ from the current password")
    if problems:
        raise HTTPException(422, {"code": "weak_password", "message": "New password " + "; ".join(problems) + "."})
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_attempts = 0
    revoked = revoke_user_sessions(db, user.id, except_session_id=ctx.session.id)
    ctx.session.restriction = restriction_for(user)
    audit.record(db, org_id=ctx.org_id, action="auth.password_changed", actor_user_id=user.id, actor_label=user.email,
                 ip=ctx.ip, user_agent=ctx.ua, details={"other_sessions_revoked": revoked})
    db.commit()
    return {"ok": True, "restriction": ctx.session.restriction}


@router.post("/mfa/enroll")
def mfa_enroll(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    user = ctx.user
    if user.mfa_enabled:
        raise HTTPException(409, {"code": "mfa_already_enabled", "message": "MFA is already enabled. Ask an administrator to reset it."})
    if ctx.session.restriction == "password_change":
        raise HTTPException(403, {"code": "restricted_session", "restriction": "password_change", "message": "Change your password first."})
    secret = new_totp_secret()
    user.mfa_secret_enc = encrypt_field(secret)
    uri = totp_uri(secret, user.email)
    audit.record(db, org_id=ctx.org_id, action="auth.mfa_enroll_started", actor_user_id=user.id, actor_label=user.email,
                 ip=ctx.ip, user_agent=ctx.ua)
    db.commit()
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": segno.make(uri, error="m").svg_inline(scale=5, border=2)}


@router.post("/mfa/confirm")
def mfa_confirm(body: MfaConfirmIn, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    user = ctx.user
    if user.mfa_enabled or not user.mfa_secret_enc:
        raise HTTPException(409, {"code": "mfa_not_pending", "message": "Start MFA enrollment first."})
    if not ratelimit.allow(db, f"mfa:{user.id}", 10):
        raise HTTPException(429, {"code": "rate_limited", "message": "Too many attempts. Try again in a minute."})
    step = verify_totp(decrypt_field(user.mfa_secret_enc), body.code, user.mfa_last_step)
    if step is None:
        audit.record(db, org_id=ctx.org_id, action="auth.mfa_enroll_failed", outcome="failure", actor_user_id=user.id,
                     actor_label=user.email, ip=ctx.ip, user_agent=ctx.ua)
        db.commit()
        raise HTTPException(422, {"code": "invalid_code", "message": "That code is not valid. Check the time on your device and try again."})
    user.mfa_enabled, user.mfa_last_step = True, step
    ctx.session.mfa_verified = True
    revoked = revoke_user_sessions(db, user.id, except_session_id=ctx.session.id)
    ctx.session.restriction = restriction_for(user)
    audit.record(db, org_id=ctx.org_id, action="auth.mfa_enabled", actor_user_id=user.id, actor_label=user.email,
                 ip=ctx.ip, user_agent=ctx.ua, details={"other_sessions_revoked": revoked})
    db.commit()
    return {"ok": True, "restriction": ctx.session.restriction}
