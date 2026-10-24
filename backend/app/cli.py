"""Operator CLI. Uses the admin database URL, which the API process must never have.

  python -m app.cli bootstrap --org-name "Acme" --admin-email admin@acme.test
"""
import argparse
import getpass
import os
import sys

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from . import audit
from .bootstrap import create_organization, create_user
from .db import set_org
from .models import Asset, Organization, User
from .security import password_problems


def bootstrap(org_name: str, email: str, password: str) -> None:
    url = os.environ.get("BASTION_DATABASE_ADMIN_URL")
    if not url:
        sys.exit("BASTION_DATABASE_ADMIN_URL is required")
    problems = password_problems(password, email)
    if problems:
        sys.exit("Password " + "; ".join(problems) + ".")
    with Session(create_engine(url)) as db:
        org = create_organization(db, org_name)
        set_org(db, org.id)
        user = create_user(db, org_id=org.id, email=email, display_name="Administrator", role="platform_admin", password=password)
        audit.record(db, org_id=org.id, action="org.bootstrapped", actor_label="cli", target_type="user",
                     target_id=str(user.id), details={"admin_email": user.email})
        db.commit()
    print(f"Created organization '{org_name}' with administrator {email}. MFA setup is required at first sign-in.")


DEMO_USERS = [
    ("analyst.demo@example.com", "Demo Analyst", "security_analyst"),
    ("responder.demo@example.com", "Demo Responder", "incident_responder"),
    ("auditor.demo@example.com", "Demo Auditor", "auditor"),
]
DEMO_ASSETS = [
    ("orders-db (sample)", "postgresql", "test", "db.sample.internal", 5432, "orders"),
    ("customer-api (sample)", "api", "staging", "api.sample.internal", 443, None),
    ("build-server (sample)", "server", "development", "build.sample.internal", 22, None),
]


def seed_demo(org_name: str, password: str) -> None:
    """Adds clearly labelled SAMPLE users and assets so every role can be tried. Not connected to anything."""
    url = os.environ.get("BASTION_DATABASE_ADMIN_URL")
    if not url:
        sys.exit("BASTION_DATABASE_ADMIN_URL is required")
    problems = password_problems(password)
    if problems:
        sys.exit("Demo password " + "; ".join(problems) + ".")
    with Session(create_engine(url)) as db:
        org = db.execute(select(Organization).where(Organization.name == org_name)).scalar_one_or_none()
        if not org:
            sys.exit(f"No organization named '{org_name}'. Run bootstrap first.")
        set_org(db, org.id)
        made = []
        for email, name, role in DEMO_USERS:
            if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
                continue
            u = create_user(db, org_id=org.id, email=email, display_name=name, role=role, password=password, must_change_password=True)
            audit.record(db, org_id=org.id, action="demo.user_seeded", actor_label="cli", target_type="user", target_id=str(u.id), details={"role": role})
            made.append(email)
        for name, kind, env, host, port, dbname in DEMO_ASSETS:
            if db.execute(select(Asset).where(Asset.org_id == org.id, Asset.name == name)).scalar_one_or_none():
                continue
            db.add(Asset(org_id=org.id, name=name, asset_type=kind, environment=env, host=host, port=port, database_name=dbname,
                         description="Sample record for testing. Not connected to anything real."))
        audit.record(db, org_id=org.id, action="demo.seeded", actor_label="cli", details={"users_added": len(made)})
        db.commit()
    print(f"Added {len(made)} sample users and the sample assets. Temporary password is the one you supplied; each person must change it at first sign-in.")


def main() -> None:
    p = argparse.ArgumentParser(prog="bastion")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bootstrap", help="create an organization and its first administrator")
    b.add_argument("--org-name", required=True)
    b.add_argument("--admin-email", required=True)
    d = sub.add_parser("seed-demo", help="add clearly labelled sample users and assets for testing")
    d.add_argument("--org-name", required=True)
    args = p.parse_args()
    if args.cmd == "seed-demo":
        seed_demo(args.org_name, os.environ.get("BASTION_DEMO_PASSWORD") or getpass.getpass("Temporary password for sample users: "))
        return
    password = os.environ.get("BASTION_BOOTSTRAP_PASSWORD") or getpass.getpass("Administrator password: ")
    bootstrap(args.org_name, args.admin_email, password)


if __name__ == "__main__":
    main()
