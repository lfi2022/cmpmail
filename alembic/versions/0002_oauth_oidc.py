"""OAuth 2.1 and OpenID Connect persistence."""

from alembic import op
import sqlalchemy as sa

revision = "0002_oauth_oidc"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "oauth_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_oauth_users_username", "oauth_users", ["username"])
    op.create_table(
        "oauth_clients",
        sa.Column("client_id", sa.String(255), primary_key=True),
        sa.Column("client_secret_hash", sa.String(255)),
        sa.Column("client_name", sa.String(200), nullable=False),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("grant_types", sa.JSON(), nullable=False),
        sa.Column("response_types", sa.JSON(), nullable=False),
        sa.Column("token_endpoint_auth_method", sa.String(50), nullable=False),
        sa.Column("allowed_scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "oauth_authorization_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "client_id",
            sa.String(255),
            sa.ForeignKey("oauth_clients.client_id"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("oauth_users.id"), nullable=False
        ),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=False),
        sa.Column("resource", sa.Text(), nullable=False),
        sa.Column("nonce", sa.String(255)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_oauth_authorization_codes_code_hash",
        "oauth_authorization_codes",
        ["code_hash"],
    )
    op.create_table(
        "oauth_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "client_id",
            sa.String(255),
            sa.ForeignKey("oauth_clients.client_id"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("oauth_users.id"), nullable=False
        ),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("resource", sa.Text(), nullable=False),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_oauth_sessions_client_id", "oauth_sessions", ["client_id"])
    op.create_index("ix_oauth_sessions_user_id", "oauth_sessions", ["user_id"])
    op.create_table(
        "oauth_refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column(
            "session_id",
            sa.String(64),
            sa.ForeignKey("oauth_sessions.id"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_oauth_refresh_tokens_token_hash", "oauth_refresh_tokens", ["token_hash"]
    )
    op.create_index(
        "ix_oauth_refresh_tokens_family_id", "oauth_refresh_tokens", ["family_id"]
    )
    op.create_index(
        "ix_oauth_refresh_tokens_session_id", "oauth_refresh_tokens", ["session_id"]
    )
    op.create_table(
        "oauth_revoked_tokens",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(100), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_oauth_revoked_tokens_expires_at", "oauth_revoked_tokens", ["expires_at"]
    )


def downgrade():
    for name in (
        "oauth_revoked_tokens",
        "oauth_refresh_tokens",
        "oauth_sessions",
        "oauth_authorization_codes",
        "oauth_clients",
        "oauth_users",
    ):
        op.drop_table(name)
