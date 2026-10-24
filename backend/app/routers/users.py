import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..bootstrap import create_user
from ..db import get_db
from ..deps import AuthContext, require, revoke_user_sessions
from ..models import User
from ..schemas import PasswordResetIn, UserCreateIn, UserOut, UserUpdateIn
from ..security import hash_password, password_problems

router = APIRouter(prefix="/api/users", tags=["users"])


def _target(db: Session, ctx: AuthContext, user_id: uuid.UUID) -> User:
    user = db.execute(select(User).where(User.id == user_id, User.org_id == ctx.org_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, {"code": "not_found", "message": "User not found."})
    return user


def _weak(password: str, email: str) -> None:
    problems = password_problems(password, email)
    if problems:
        raise HTTPException(422, {"code": "weak_password", "message": "Password " + "; ".join(problems) + "."})


def _audit(db: Session, ctx: AuthContext, action: str, target: User, details: dict | None = None) -> None:
    audit.record(db, org_id=ctx.org_id, action=action, actor_user_id=ctx.user.id, actor_label=ctx.user.email,
                 target_type="user", target_id=str(target.id), ip=ctx.ip, user_agent=ctx.ua, details=details)


@router.get("", response_model=list[UserOut])
def list_users(ctx: AuthContext = Depends(require("users:read")), db: Session = Depends(get_db)):
    return db.execute(select(User).where(User.org_id == ctx.org_id).order_by(User.created_at)).scalars().all()


@router.post("", response_model=UserOut, status_code=201)
def add_user(body: UserCreateIn, ctx: AuthContext = Depends(require("users:manage")), db: Session = Depends(get_db)):
    _weak(body.initial_password, body.email)
    try:
        user = create_user(db, org_id=ctx.org_id, email=body.email, display_name=body.display_name, role=body.role,
                           password=body.initial_password, must_change_password=True)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, {"code": "email_in_use", "message": "That email address is already registered."})
    _audit(db, ctx, "user.created", user, {"role": user.role})
    db.commit()
    return user


def _other_active_admins(db: Session, ctx: AuthContext, exclude: uuid.UUID) -> int:
    return db.execute(
        select(func.count()).select_from(User).where(
            User.org_id == ctx.org_id, User.role == "platform_admin", User.is_active.is_(True), User.id != exclude
        )
    ).scalar_one()


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserUpdateIn, ctx: AuthContext = Depends(require("users:manage")),
                db: Session = Depends(get_db)):
    user = _target(db, ctx, user_id)
    changes: dict = {}
    if body.role is not None and body.role != user.role:
        if user.id == ctx.user.id:
            raise HTTPException(400, {"code": "self_change", "message": "You cannot change your own role."})
        if user.role == "platform_admin" and _other_active_admins(db, ctx, user.id) == 0:
            raise HTTPException(400, {"code": "last_admin", "message": "The organization needs at least one active administrator."})
        changes["role"] = f"{user.role}->{body.role}"
        user.role = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        if user.id == ctx.user.id:
            raise HTTPException(400, {"code": "self_change", "message": "You cannot deactivate your own account."})
        if not body.is_active and user.role == "platform_admin" and _other_active_admins(db, ctx, user.id) == 0:
            raise HTTPException(400, {"code": "last_admin", "message": "The organization needs at least one active administrator."})
        user.is_active = body.is_active
        changes["is_active"] = body.is_active
    if body.display_name is not None:
        user.display_name = body.display_name
    if "role" in changes or changes.get("is_active") is False:
        changes["sessions_revoked"] = revoke_user_sessions(db, user.id)
    _audit(db, ctx, "user.updated", user, changes)
    db.commit()
    return user


@router.post("/{user_id}/reset-password")
def reset_password(user_id: uuid.UUID, body: PasswordResetIn, ctx: AuthContext = Depends(require("users:manage")),
                   db: Session = Depends(get_db)):
    user = _target(db, ctx, user_id)
    _weak(body.new_password, user.email)
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = True
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_attempts, user.locked_until = 0, None
    revoked = revoke_user_sessions(db, user.id)
    _audit(db, ctx, "user.password_reset", user, {"sessions_revoked": revoked})
    db.commit()
    return {"ok": True}


@router.post("/{user_id}/reset-mfa")
def reset_mfa(user_id: uuid.UUID, ctx: AuthContext = Depends(require("users:manage")), db: Session = Depends(get_db)):
    user = _target(db, ctx, user_id)
    user.mfa_enabled, user.mfa_secret_enc, user.mfa_last_step = False, None, None
    revoked = revoke_user_sessions(db, user.id)
    _audit(db, ctx, "user.mfa_reset", user, {"sessions_revoked": revoked})
    db.commit()
    return {"ok": True}


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(user_id: uuid.UUID, ctx: AuthContext = Depends(require("users:manage")), db: Session = Depends(get_db)):
    user = _target(db, ctx, user_id)
    revoked = revoke_user_sessions(db, user.id)
    _audit(db, ctx, "user.sessions_revoked", user, {"sessions_revoked": revoked})
    db.commit()
    return {"revoked": revoked}
