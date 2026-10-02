"""Store API keys as SHA-256 digests instead of plaintext

Replaces ``users.api_key`` (plaintext, unique) with:

* ``users.api_key_hash``      - SHA-256 hex digest, unique, indexed (lookup key)
* ``users.api_key_prefix``    - first 8 characters, for identification only
* ``users.api_key_issued_at`` - when the current key was issued

Existing plaintext keys cannot be migrated into digests without also being
able to show them to their owners again, and they must be considered exposed
anyway (they were readable by anyone with database access). The upgrade
therefore drops them: every user simply rotates a new key from /profile, and
the seeder issues fresh keys for the demo accounts.

Revision ID: 3a1c7f0b52e4
Revises: 20d5746fcc32
Create Date: 2026-10-01
"""
from alembic import op
import sqlalchemy as sa


revision = "3a1c7f0b52e4"
down_revision = "20d5746fcc32"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("api_key_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("api_key_prefix", sa.String(length=12), nullable=True))
        batch_op.add_column(sa.Column("api_key_issued_at", sa.DateTime(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_users_api_key_hash"), ["api_key_hash"], unique=True
        )
        # Drop the old index before the column it covers.
        try:
            batch_op.drop_index("ix_users_api_key")
        except Exception:  # pragma: no cover - index name varies by backend
            pass
        batch_op.drop_column("api_key")


def downgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("api_key", sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f("ix_users_api_key"), ["api_key"], unique=True)
        batch_op.drop_index(batch_op.f("ix_users_api_key_hash"))
        batch_op.drop_column("api_key_issued_at")
        batch_op.drop_column("api_key_prefix")
        batch_op.drop_column("api_key_hash")
