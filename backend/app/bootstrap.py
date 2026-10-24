"""Shared helpers to create organizations and users. Used by the CLI, the users API, and tests."""
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import Organization, User
from .security import hash_password


def create_organization(db: Session, name: str) -> Organization:
    org = Organization(id=uuid.uuid4(), name=name)
    db.add(org)
    db.flush()
    return org


def create_user(
    db: Session, *, org_id: uuid.UUID, email: str, display_name: str, role: str, password: str,
    must_change_password: bool = False,
) -> User:
    user = User(
        id=uuid.uuid4(), org_id=org_id, email=email.lower(), display_name=display_name, role=role,
        password_hash=hash_password(password), must_change_password=must_change_password,
        password_changed_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.flush()
    return user
