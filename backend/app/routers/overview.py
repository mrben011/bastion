from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, require
from ..models import Asset, AuditEvent, Organization, User, UserSession

router = APIRouter(prefix="/api/overview", tags=["overview"])

MODULES = [
    {"name": "Authentication, MFA and sessions", "status": "implemented", "milestone": 1},
    {"name": "Role-based access and tenant isolation", "status": "implemented", "milestone": 1},
    {"name": "Tamper-evident audit log", "status": "implemented", "milestone": 1},
    {"name": "Protected asset registry", "status": "implemented", "milestone": 1},
    {"name": "Event ingestion and database audit integration", "status": "not_implemented", "milestone": 2},
    {"name": "Detection rules and incidents", "status": "not_implemented", "milestone": 2},
    {"name": "Signed policies and independent audit storage", "status": "not_implemented", "milestone": 3},
    {"name": "Policy enforcement and response orchestration", "status": "not_implemented", "milestone": 4},
    {"name": "AI threat analyst", "status": "not_implemented", "milestone": 5},
    {"name": "Backup verification and recovery", "status": "not_implemented", "milestone": 6},
]


@router.get("")
def overview(ctx: AuthContext = Depends(require("overview:read")), db: Session = Depends(get_db)):
    org_id, now = ctx.org_id, datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    org = db.get(Organization, org_id)
    by_env = dict(db.execute(select(Asset.environment, func.count()).where(Asset.org_id == org_id).group_by(Asset.environment)).all())
    audit_24h = dict(
        db.execute(
            select(AuditEvent.outcome, func.count()).where(AuditEvent.org_id == org_id, AuditEvent.ts >= since)
            .group_by(AuditEvent.outcome)
        ).all()
    )
    failed_logins = db.execute(
        select(func.count()).select_from(AuditEvent).where(
            AuditEvent.org_id == org_id, AuditEvent.ts >= since, AuditEvent.action == "auth.login_failed")
    ).scalar_one()
    head = db.execute(
        select(AuditEvent.seq, AuditEvent.hash).where(AuditEvent.org_id == org_id).order_by(AuditEvent.seq.desc()).limit(1)
    ).first()
    return {
        "organization": {"id": str(org_id), "name": org.name if org else ""},
        "assets": {"total": sum(by_env.values()), "by_environment": by_env, "monitored": 0},
        "users": {"active": db.execute(select(func.count()).select_from(User).where(User.org_id == org_id, User.is_active.is_(True))).scalar_one()},
        "sessions": {"active": db.execute(select(func.count()).select_from(UserSession).where(
            UserSession.org_id == org_id, UserSession.revoked_at.is_(None), UserSession.expires_at > now)).scalar_one()},
        "activity_24h": {
            "audit_events": sum(audit_24h.values()), "failed_logins": failed_logins,
            "denied_actions": audit_24h.get("denied", 0),
        },
        "audit_chain_head": {"seq": head.seq, "hash": head.hash} if head else None,
        "modules": MODULES,
        "data_notice": (
            "No security telemetry is connected yet, so there are no alerts, incidents or detection "
            "coverage figures to show. Event ingestion arrives in Milestone 2."
        ),
    }
