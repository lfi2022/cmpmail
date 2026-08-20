"""Initial production schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("mail_accounts",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("display_name", sa.String(200), nullable=False), sa.Column("email", sa.String(320), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("imap_host", sa.String(255), nullable=False), sa.Column("imap_port", sa.Integer(), nullable=False), sa.Column("imap_ssl", sa.Boolean(), nullable=False), sa.Column("imap_username", sa.String(320), nullable=False), sa.Column("imap_password_encrypted", sa.Text(), nullable=False),
        sa.Column("smtp_host", sa.String(255), nullable=False), sa.Column("smtp_port", sa.Integer(), nullable=False), sa.Column("smtp_ssl", sa.Boolean(), nullable=False), sa.Column("smtp_starttls", sa.Boolean(), nullable=False), sa.Column("smtp_username", sa.String(320), nullable=False), sa.Column("smtp_password_encrypted", sa.Text(), nullable=False),
        sa.Column("sent_mailbox", sa.String(500)), sa.Column("drafts_mailbox", sa.String(500)), sa.Column("trash_mailbox", sa.String(500)), sa.Column("archive_mailbox", sa.String(500)), sa.Column("junk_mailbox", sa.String(500)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("name"))
    op.create_index("ix_mail_accounts_name", "mail_accounts", ["name"])
    op.create_table("api_keys", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False, unique=True), sa.Column("prefix", sa.String(16), nullable=False), sa.Column("key_hash", sa.String(255), nullable=False), sa.Column("permissions", sa.JSON(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_used_at", sa.DateTime(timezone=True)))
    op.create_index("ix_api_keys_prefix", "api_keys", ["prefix"])
    op.create_table("operation_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False), sa.Column("tool", sa.String(100), nullable=False), sa.Column("account", sa.String(100)), sa.Column("actor", sa.String(100)), sa.Column("ip", sa.String(64)), sa.Column("user_agent", sa.String(500)), sa.Column("mcp_session", sa.String(200)), sa.Column("duration_ms", sa.Integer(), nullable=False), sa.Column("success", sa.Boolean(), nullable=False), sa.Column("error", sa.Text()), sa.Column("item_count", sa.Integer()))
    op.create_index("ix_operation_logs_timestamp", "operation_logs", ["timestamp"]); op.create_index("ix_operation_logs_tool", "operation_logs", ["tool"]); op.create_index("ix_operation_logs_account", "operation_logs", ["account"])
    op.create_table("audit_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False), sa.Column("action", sa.String(100), nullable=False), sa.Column("actor", sa.String(100)), sa.Column("account", sa.String(100)), sa.Column("target", sa.String(500)), sa.Column("details", sa.JSON(), nullable=False), sa.Column("success", sa.Boolean(), nullable=False))
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"]); op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_table("system_settings", sa.Column("key", sa.String(100), primary_key=True), sa.Column("value", sa.JSON(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table("system_settings"); op.drop_table("audit_logs"); op.drop_table("operation_logs"); op.drop_table("api_keys"); op.drop_table("mail_accounts")

