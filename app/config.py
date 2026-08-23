from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )

    app_host: str = "0.0.0.0"
    app_port: int = 8000
    public_url: str = "http://localhost:8000"
    mcp_path: str = "/mcp"
    database_url: str = "sqlite+aiosqlite:///./data/mailmcp.db"
    secret_key: str = "A_REMPLIR"
    encryption_key: str = "A_REMPLIR"
    admin_username: str = "admin"
    admin_email: str = "admin@localhost"
    admin_password_hash: str = "A_REMPLIR"
    mcp_auth_enabled: bool = True
    mcp_api_key: str = "A_REMPLIR"
    mcp_legacy_api_key_enabled: bool = False
    oauth_enabled: bool = True
    oauth_issuer: str | None = None
    oauth_resource: str | None = None
    oauth_signing_key_path: Path = Path("secrets/oauth-private.pem")
    oauth_signing_public_key_path: Path = Path("secrets/oauth-public.pem")
    oauth_signing_kid: str = "mailmcp-2026-01"
    oauth_access_token_minutes: int = 15
    oauth_refresh_token_days: int = 30
    oauth_authorization_code_minutes: int = 5
    oauth_session_hours: int = 8
    oauth_login_attempts: int = 5
    oauth_login_lock_minutes: int = 15
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"]
    )
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )
    trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=list)
    attachment_download_enabled: bool = False
    max_attachment_size_mb: int = 25
    attachment_save_dir: Path = Path("data/attachments")
    blocked_attachment_types: Annotated[list[str], NoDecode] = Field(
        default_factory=list
    )
    max_request_size_mb: int = 30
    temporary_upload_dir: Path = Path("data/uploads/temp")
    temporary_upload_ttl_minutes: int = 10
    temporary_upload_max_bytes: int = 10 * 1024 * 1024
    temporary_upload_max_base64_bytes: int = 14 * 1024 * 1024
    temporary_upload_optimize: bool = True
    temporary_upload_max_dimension: int = 1600
    temporary_upload_jpeg_quality: int = 85
    max_raw_message_size_mb: int = 10
    read_only: bool = False
    allow_copy_in_read_only: bool = False
    destructive_operations_enabled: bool = True
    facebook_graph_api_version: str = "v19.0"
    facebook_app_id: str = ""
    facebook_app_secret: str = ""
    facebook_user_access_token: str = ""
    facebook_page_access_token: str = ""
    facebook_default_page_id: str | None = None
    dolibarr_api_url: str = ""
    dolibarr_api_key: str = ""
    dolibarr_timeout_seconds: int = 30
    dolibarr_verify_ssl: bool = True
    rate_limit_per_minute: int = 120
    mail_timeout_seconds: int = 30
    log_level: str = "INFO"
    secure_cookies: bool = True
    frontend_dir: Path = Path("frontend/dist")

    @field_validator(
        "allowed_hosts",
        "allowed_origins",
        "trusted_proxies",
        "blocked_attachment_types",
        mode="before",
    )
    @classmethod
    def split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("mcp_path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return "/" + value.strip("/")

    @property
    def mcp_url(self) -> str:
        return f"{self.public_url.rstrip('/')}{self.mcp_path}"

    @property
    def issuer(self) -> str:
        return (self.oauth_issuer or self.public_url).rstrip("/")

    @property
    def resource(self) -> str:
        return self.oauth_resource or self.mcp_url

    def production_errors(self) -> list[str]:
        errors = []
        for name in ("secret_key", "encryption_key"):
            if getattr(self, name) == "A_REMPLIR":
                errors.append(f"{name.upper()} must be configured")
        if self.admin_password_hash == "A_REMPLIR":
            errors.append("ADMIN_PASSWORD_HASH must be configured")
        if (
            self.mcp_auth_enabled
            and self.mcp_legacy_api_key_enabled
            and self.mcp_api_key == "A_REMPLIR"
        ):
            errors.append(
                "MCP_API_KEY must be configured when legacy MCP API keys are enabled"
            )
        if self.oauth_enabled:
            for path in (
                self.oauth_signing_key_path,
                self.oauth_signing_public_key_path,
            ):
                if not path.is_file():
                    errors.append(f"OAuth signing key missing: {path}")
        return errors


@lru_cache
def get_settings() -> Settings:
    return Settings()
