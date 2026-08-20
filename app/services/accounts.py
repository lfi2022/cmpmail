from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import MailAccount
from app.schemas import AccountCreate, AccountUpdate
from app.security import CredentialCipher


class AccountRepository:
    def __init__(self, db: AsyncSession, cipher: CredentialCipher):
        self.db = db
        self.cipher = cipher

    async def list(self, active_only: bool = False) -> list[MailAccount]:
        query = select(MailAccount).order_by(MailAccount.name)
        if active_only:
            query = query.where(MailAccount.enabled.is_(True))
        return list((await self.db.scalars(query)).all())

    async def get(self, name: str | None = None) -> MailAccount:
        query = select(MailAccount)
        query = (
            query.where(MailAccount.name == name)
            if name
            else query.where(
                MailAccount.is_default.is_(True), MailAccount.enabled.is_(True)
            )
        )
        account = await self.db.scalar(query)
        if not account:
            raise LookupError(f"Mail account not found: {name or 'default'}")
        return account

    async def create(self, payload: AccountCreate) -> MailAccount:
        if await self.db.scalar(
            select(MailAccount).where(MailAccount.name == payload.name)
        ):
            raise ValueError("Account name already exists")
        values = payload.model_dump(exclude={"imap_password", "smtp_password"})
        account = MailAccount(
            **values,
            imap_password_encrypted=self.cipher.encrypt(payload.imap_password),
            smtp_password_encrypted=self.cipher.encrypt(payload.smtp_password),
        )
        if payload.is_default:
            await self.db.execute(update(MailAccount).values(is_default=False))
        self.db.add(account)
        await self.db.commit()
        await self.db.refresh(account)
        return account

    async def update(self, name: str, payload: AccountUpdate) -> MailAccount:
        account = await self.get(name)
        values = payload.model_dump(exclude_unset=True)
        imap_password = values.pop("imap_password", None)
        smtp_password = values.pop("smtp_password", None)
        if imap_password:
            account.imap_password_encrypted = self.cipher.encrypt(imap_password)
        if smtp_password:
            account.smtp_password_encrypted = self.cipher.encrypt(smtp_password)
        if values.get("is_default"):
            await self.db.execute(
                update(MailAccount)
                .where(MailAccount.id != account.id)
                .values(is_default=False)
            )
        for key, value in values.items():
            setattr(account, key, value)
        await self.db.commit()
        await self.db.refresh(account)
        return account

    async def delete(self, name: str) -> None:
        account = await self.get(name)
        await self.db.delete(account)
        await self.db.commit()

    async def set_default(self, name: str) -> MailAccount:
        account = await self.get(name)
        if not account.enabled:
            raise ValueError("A disabled account cannot be the default")
        await self.db.execute(update(MailAccount).values(is_default=False))
        account.is_default = True
        await self.db.commit()
        await self.db.refresh(account)
        return account


def public_account(account: MailAccount) -> dict:
    return {
        "id": account.id,
        "name": account.name,
        "display_name": account.display_name,
        "email": account.email,
        "enabled": account.enabled,
        "is_default": account.is_default,
        "imap_host": account.imap_host,
        "imap_port": account.imap_port,
        "imap_ssl": account.imap_ssl,
        "imap_username": account.imap_username,
        "imap_password": "••••••••",
        "smtp_host": account.smtp_host,
        "smtp_port": account.smtp_port,
        "smtp_ssl": account.smtp_ssl,
        "smtp_starttls": account.smtp_starttls,
        "smtp_username": account.smtp_username,
        "smtp_password": "••••••••",
        "sent_mailbox": account.sent_mailbox,
        "drafts_mailbox": account.drafts_mailbox,
        "trash_mailbox": account.trash_mailbox,
        "archive_mailbox": account.archive_mailbox,
        "junk_mailbox": account.junk_mailbox,
        "created_at": account.created_at.isoformat(),
        "updated_at": account.updated_at.isoformat(),
    }
