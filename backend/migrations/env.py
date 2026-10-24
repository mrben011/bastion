import os

from alembic import context
from sqlalchemy import create_engine

url = os.environ.get("BASTION_DATABASE_ADMIN_URL")
if not url:
    raise SystemExit("BASTION_DATABASE_ADMIN_URL is required to run migrations")

with create_engine(url).connect() as connection:
    context.configure(connection=connection, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()
