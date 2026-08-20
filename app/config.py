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
    admin_password: str = "A_REMPLIR"
    mcp_auth_enabled: bool = True
    mcp_api_key: str = "A_REMPLIR"
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
    max_raw_message_size_mb: int = 10
    read_only: bool = False
    allow_copy_in_read_only: bool = False
    destructive_operations_enabled: bool = True
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

    def production_errors(self) -> list[str]:
        errors = []
        for name in ("secret_key", "encryption_key", "admin_password"):
            if getattr(self, name) == "A_REMPLIR":
                errors.append(f"{name.upper()} must be configured")
        if self.mcp_auth_enabled and self.mcp_api_key == "A_REMPLIR":
            errors.append(
                "MCP_API_KEY must be configured when MCP authentication is enabled"
            )
        return errors


@lru_cache
def get_settings() -> Settings:
    return Settings()
