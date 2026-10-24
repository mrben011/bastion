"""Database access.

Tenant isolation is enforced twice: every query is filtered by org_id in application code, and
PostgreSQL row-level security restricts the API's database role to the organization stored in the
transaction-local setting `app.org_id`. If application code forgets a filter, RLS still applies.
"""
from collections.abc import Iterator
from functools import lru_cache
from uuid import UUID

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from .config import get_settings


@lru_cache
def get_engine() -> Engine:
    cfg = get_settings()
    if cfg.serverless:
        return create_engine(cfg.database_url, poolclass=NullPool, connect_args={"prepare_threshold": None})
    return create_engine(cfg.database_url, pool_pre_ping=True, pool_size=10, max_overflow=5)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def set_org(db: Session, org_id: UUID | str) -> None:
    """Bind this session (and the current transaction) to one organization for RLS."""
    db.info["org_id"] = str(org_id)
    db.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org_id)})


@event.listens_for(Session, "after_begin")
def _reapply_org(session: Session, transaction, connection) -> None:  # noqa: ANN001
    org = session.info.get("org_id")
    if org:
        connection.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": org})


def get_db() -> Iterator[Session]:
    """Request-scoped session. Nothing is committed implicitly: endpoints commit explicitly."""
    db = get_sessionmaker()()
    try:
        yield db
    finally:
        db.rollback()
        db.close()
