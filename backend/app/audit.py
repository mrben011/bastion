"""Tamper-evident audit log.

Each event stores the hash of the previous event in the same organization, forming a chain.
Defence layers:
  * the API database role can only INSERT and SELECT on audit_events (no UPDATE or DELETE),
  * a database trigger rejects UPDATE, DELETE and TRUNCATE even from the table owner,
  * the hash chain lets anyone re-verify the history and detect edits, gaps and reordering.

Known limitation: a chain stored in the same database cannot detect deletion of its newest events by
someone with full database control. Milestone 3 anchors the chain head in independent storage.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import AuditEvent

GENESIS = "0" * 64
_SCALAR = (str, int, bool, type(None))


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _compute_hash(prev_hash: str, e: dict) -> str:
    canonical = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _payload(ev: AuditEvent | dict) -> dict:
    g = (lambda k: ev[k]) if isinstance(ev, dict) else (lambda k: getattr(ev, k))
    return {
        "org_id": str(g("org_id")),
        "seq": g("seq"),
        "ts": _iso(g("ts")),
        "actor_user_id": str(g("actor_user_id")) if g("actor_user_id") else None,
        "actor_label": g("actor_label"),
        "action": g("action"),
        "outcome": g("outcome"),
        "target_type": g("target_type"),
        "target_id": g("target_id"),
        "ip": g("ip"),
        "user_agent": g("user_agent"),
        "details": g("details"),
    }


def record(
    db: Session,
    *,
    org_id: uuid.UUID,
    action: str,
    outcome: str = "success",
    actor_user_id: uuid.UUID | None = None,
    actor_label: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    details: dict | None = None,
) -> AuditEvent:
    """Append one event. The caller commits. Never put secrets or passwords in `details`."""
    clean = {str(k)[:60]: (v[:300] if isinstance(v, str) else v) for k, v in (details or {}).items() if isinstance(v, _SCALAR)}
    # Serialize appends per organization so the chain has no forks.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"audit:{org_id}"})
    last = db.execute(
        select(AuditEvent.seq, AuditEvent.hash).where(AuditEvent.org_id == org_id).order_by(AuditEvent.seq.desc()).limit(1)
    ).first()
    seq = (last.seq + 1) if last else 1
    prev = last.hash if last else GENESIS
    fields = dict(
        org_id=org_id, seq=seq, ts=datetime.now(timezone.utc), actor_user_id=actor_user_id,
        actor_label=actor_label, action=action, outcome=outcome, target_type=target_type,
        target_id=target_id, ip=ip, user_agent=(user_agent or None) and user_agent[:256], details=clean,
    )
    ev = AuditEvent(**fields, prev_hash=prev, hash=_compute_hash(prev, _payload(fields)))
    db.add(ev)
    db.flush()
    return ev


def verify_chain(db: Session, org_id: uuid.UUID) -> dict:
    """Recompute every hash for the organization and report the first problem found."""
    expected_prev, expected_seq, checked = GENESIS, 1, 0
    rows = db.execute(select(AuditEvent).where(AuditEvent.org_id == org_id).order_by(AuditEvent.seq)).scalars()
    for ev in rows:
        if ev.seq != expected_seq:
            return {"valid": False, "checked": checked, "first_bad_seq": expected_seq, "reason": "missing or reordered event"}
        if ev.prev_hash != expected_prev:
            return {"valid": False, "checked": checked, "first_bad_seq": ev.seq, "reason": "previous hash mismatch"}
        if _compute_hash(ev.prev_hash, _payload(ev)) != ev.hash:
            return {"valid": False, "checked": checked, "first_bad_seq": ev.seq, "reason": "event content does not match its hash"}
        expected_prev, expected_seq, checked = ev.hash, ev.seq + 1, checked + 1
    return {"valid": True, "checked": checked, "first_bad_seq": None, "reason": None, "head_seq": expected_seq - 1, "head_hash": expected_prev}
