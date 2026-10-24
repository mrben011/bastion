"""Shared rate-limit counters for serverless deployments."""
from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE rate_limits (
            key varchar(200) NOT NULL,
            bucket bigint NOT NULL,
            hits integer NOT NULL DEFAULT 0,
            PRIMARY KEY (key, bucket)
        )
    """)
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO bastion_app")


def downgrade() -> None:
    raise SystemExit("Downgrades are disabled.")
