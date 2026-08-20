from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class AccountBase(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,100}$")
    display_name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    enabled: bool = True
    is_default: bool = False
    imap_host: str
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_ssl: bool = True
    imap_username: str
    smtp_host: str
    smtp_port: int = Field(default=465, ge=1, le=65535)
    smtp_ssl: bool = True
    smtp_starttls: bool = False
    smtp_username: str
    sent_mailbox: str | None = None
    drafts_mailbox: str | None = None
    trash_mailbox: str | None = None
    archive_mailbox: str | None = None
    junk_mailbox: str | None = None

    @model_validator(mode="after")
    def tls_modes(self):
        if self.smtp_ssl and self.smtp_starttls:
            raise ValueError("SMTP implicit TLS and STARTTLS are mutually exclusive")
        return self


class AccountCreate(AccountBase):
    imap_password: str = Field(min_length=1)
    smtp_password: str = Field(min_length=1)


class AccountUpdate(BaseModel):
    display_name: str | None = None
    email: EmailStr | None = None
    enabled: bool | None = None
    is_default: bool | None = None
    imap_host: str | None = None
    imap_port: int | None = Field(default=None, ge=1, le=65535)
    imap_ssl: bool | None = None
    imap_username: str | None = None
    imap_password: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_ssl: bool | None = None
    smtp_starttls: bool | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    sent_mailbox: str | None = None
    drafts_mailbox: str | None = None
    trash_mailbox: str | None = None
    archive_mailbox: str | None = None
    junk_mailbox: str | None = None


class AccountPublic(AccountBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    updated_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    permissions: list[str]


class Result(BaseModel):
    success: bool = True
    data: object = None
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    partial: bool = False
    processed: int | None = None
    failed: int | None = None
