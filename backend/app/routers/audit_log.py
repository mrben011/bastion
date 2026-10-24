from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, require
from ..models import AuditEvent
from ..schemas import AuditOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_events(
    action: str | None = Query(default=None, max_length=80),
    outcome: str | None = Query(default=None, pattern="^(success|failure|denied)$"),
    before_seq: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require("audit:read")),
    db: Session = Depends(get_db),
):
    stmt = select(AuditEvent).where(AuditEvent.org_id == ctx.org_id)
    if action:
        stmt = stmt.where(AuditEvent.action.startswith(action))
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if before_seq:
        stmt = stmt.where(AuditEvent.seq < before_seq)
    return db.execute(stmt.order_by(AuditEvent.seq.desc()).limit(limit)).scalars().all()


@router.get("/verify")
def verify(ctx: AuthContext = Depends(require("audit:verify")), db: Session = Depends(get_db)):
    result = audit.verify_chain(db, ctx.org_id)
    audit.record(db, org_id=ctx.org_id, action="audit.verified", outcome="success" if result["valid"] else "failure",
                 actor_user_id=ctx.user.id, actor_label=ctx.user.email, ip=ctx.ip, user_agent=ctx.ua,
                 details={"checked": result["checked"], "valid": result["valid"]})
    db.commit()
    return result
