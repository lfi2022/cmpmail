"""Add telegram_requests table for inline-button callback answers."""
from alembic import op
import sqlalchemy as sa

revision = "0004_telegram_requests"
down_revision = "0003_expand_dynamic_client_scopes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "telegram_requests",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("kind", sa.String(100), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("chat_id", sa.String(64), nullable=False),
        sa.Column("message_id", sa.Integer()),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("answer", sa.String(200)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("answered_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_telegram_requests_status", "telegram_requests", ["status"])
    op.create_index("ix_telegram_requests_created_at", "telegram_requests", ["created_at"])


def downgrade():
    op.drop_table("telegram_requests")
