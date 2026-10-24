"""Request dependencies: client info, session authentication, CSRF, permission checks."""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import audit
from .config import get_settings
from .db import get_db, set_org
from .models import User, UserSession
from .permissions import has_permission
from .security import constant_time_equal, hash_token

COOKIE_NAME = "bastion_session"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def client_ip(request: Request) -> str:
    if get_settings().trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[-1].strip()[:64]  # last hop = address seen by our own proxy
    return (request.client.host if request.client else "unknown")[:64]


def client_ua(request: Request) -> str:
    return request.headers.get("user-agent", "")[:256]


@dataclass
class AuthContext:
    user: User
    session: UserSession
    ip: str
    ua: str

    @property
    def org_id(self) -> uuid.UUID:
        return self.user.org_id


def _unauthenticated() -> HTTPException:
    return HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "Sign in required."})


def current_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    """Authenticate the session cookie. Restricted sessions (MFA setup, forced password change) pass here."""
    cfg = get_settings()
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise _unauthenticated()
    row = db.execute(text("SELECT id, org_id FROM bastion_find_session(:h)"), {"h": hash_token(token)}).first()
    if not row:
        raise _unauthenticated()
    set_org(db, row.org_id)
    sess = db.get(UserSession, row.id)
    user = db.get(User, sess.user_id) if sess else None
    now = datetime.now(timezone.utc)
    idle = timedelta(minutes=cfg.session_idle_minutes)
    if (
        not sess or not user or sess.revoked_at is not None or not user.is_active
        or sess.expires_at <= now or now - sess.last_seen_at > idle
    ):
        raise _unauthenticated()

    if request.method in UNSAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not constant_time_equal(sent, sess.csrf_token):
            raise HTTPException(status_code=403, detail={"code": "csrf", "message": "Missing or invalid CSRF token."})

    if now - sess.last_seen_at > timedelta(seconds=60):
        sess.last_seen_at = now
        db.commit()
    return AuthContext(user=user, session=sess, ip=client_ip(request), ua=client_ua(request))


def active_context(ctx: AuthContext = Depends(current_context)) -> AuthContext:
    """Like current_context but rejects sessions that still owe MFA setup or a password change."""
    if ctx.session.restriction:
        raise HTTPException(
            status_code=403,
            detail={"code": "restricted_session", "restriction": ctx.session.restriction,
                    "message": "Complete the required account setup first."},
        )
    return ctx


def require(permission: str):
    """Dependency factory. Denials are written to the audit log before the 403 is returned."""

    def checker(ctx: AuthContext = Depends(active_context), db: Session = Depends(get_db)) -> AuthContext:
        if not has_permission(ctx.user.role, permission):
            audit.record(
                db, org_id=ctx.org_id, action="authz.denied", outcome="denied", actor_user_id=ctx.user.id,
                actor_label=ctx.user.email, ip=ctx.ip, user_agent=ctx.ua, details={"permission": permission},
            )
            db.commit()
            raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "You do not have permission to do this."})
        return ctx

    return checker


def revoke_user_sessions(db: Session, user_id: uuid.UUID, except_session_id: uuid.UUID | None = None) -> int:
    now = datetime.now(timezone.utc)
    q = select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    count = 0
    for s in db.execute(q).scalars():
        if except_session_id and s.id == except_session_id:
            continue
        s.revoked_at = now
        count += 1
    return count
