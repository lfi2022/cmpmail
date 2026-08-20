"""Allow existing dynamically registered clients to request advertised scopes."""

from alembic import op
import sqlalchemy as sa

revision = "0003_expand_dynamic_client_scopes"
down_revision = "0002_oauth_oidc"
branch_labels = None
depends_on = None

OLD_DEFAULT_SCOPES = ["accounts.read", "email", "mail.read", "openid", "profile"]
ALL_SCOPES = [
    "accounts.read",
    "accounts.write",
    "email",
    "mail.attachments",
    "mail.copy",
    "mail.delete",
    "mail.flags",
    "mail.folders",
    "mail.move",
    "mail.read",
    "mail.send",
    "offline_access",
    "openid",
    "profile",
]


def upgrade():
    clients = sa.table(
        "oauth_clients",
        sa.column("client_id", sa.String()),
        sa.column("allowed_scopes", sa.JSON()),
        sa.column("revoked_at", sa.DateTime(timezone=True)),
    )
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(clients.c.client_id, clients.c.allowed_scopes).where(
            clients.c.revoked_at.is_(None)
        )
    ).all()
    # JSON equality differs across SQLite/PostgreSQL, so update only when an
    # active legacy-default client exists and let the SQL expression remain
    # portable between both supported databases.
    legacy_ids = [
        row.client_id
        for row in rows
        if set(row.allowed_scopes or []) == set(OLD_DEFAULT_SCOPES)
    ]
    if legacy_ids:
        connection.execute(
            clients.update()
            .where(clients.c.client_id.in_(legacy_ids))
            .values(allowed_scopes=ALL_SCOPES)
        )


def downgrade():
    # Scope grants already consented by users must not be silently contracted.
    pass
