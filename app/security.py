import base64
import hashlib
import hmac
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status

from app.config import Settings

PERMISSIONS = {
    "read",
    "send",
    "move",
    "copy",
    "flags",
    "delete",
    "folders",
    "attachments",
    "admin",
    "accounts.read",
    "accounts.write",
    "mail.read",
    "mail.send",
    "mail.move",
    "mail.copy",
    "mail.flags",
    "mail.delete",
    "mail.folders",
    "mail.attachments",
    "facebook.read",
    "facebook.write",
    "facebook.moderate",
    "dolibarr.read",
    "dolibarr.write",
    "dolibarr.delete",
    "nextcloud.read",
    "nextcloud.write",
    "nextcloud.delete",
    "telegram.read",
    "telegram.write",
}
MUTATING_PERMISSIONS = {
    "send",
    "move",
    "copy",
    "flags",
    "delete",
    "folders",
    "facebook.write",
    "facebook.moderate",
    "dolibarr.write",
    "dolibarr.delete",
    "nextcloud.write",
    "nextcloud.delete",
    "telegram.write",
}
_hasher = PasswordHasher()


def derive_fernet_key(value: str) -> bytes:
    if value == "A_REMPLIR" or not value:
        raise RuntimeError("ENCRYPTION_KEY is not configured")
    try:
        decoded = base64.urlsafe_b64decode(value.encode())
        if len(decoded) == 32:
            return value.encode()
    except Exception:
        pass
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest())


class CredentialCipher:
    def __init__(self, key: str):
        self._fernet = Fernet(derive_fernet_key(key))

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError(
                "Credential decryption failed; check ENCRYPTION_KEY"
            ) from exc


def hash_secret(value: str) -> str:
    return _hasher.hash(value)


def verify_secret(hashed: str, value: str) -> bool:
    try:
        return _hasher.verify(hashed, value)
    except Exception:
        return False


def verify_static_secret(expected: str, supplied: str) -> bool:
    return expected != "A_REMPLIR" and hmac.compare_digest(
        expected.encode(), supplied.encode()
    )


def create_api_key() -> tuple[str, str, str]:
    raw = f"mcp_{secrets.token_urlsafe(32)}"
    return raw, raw[:12], hash_secret(raw)


def require_permission(permission: str, granted: set[str], settings: Settings) -> None:
    if permission not in PERMISSIONS:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Unknown permission")
    if permission not in granted and "admin" not in granted:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Permission required: {permission} (insufficient_scope)",
            headers={
                "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{permission}"'
            },
        )
    mutating = permission in MUTATING_PERMISSIONS or permission in {
        "accounts.write",
        "mail.send",
        "mail.move",
        "mail.copy",
        "mail.flags",
        "mail.delete",
        "mail.folders",
    }
    if settings.read_only and mutating:
        if permission != "copy" or not settings.allow_copy_in_read_only:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Server is in read-only mode"
            )
    if (
        permission in {"delete", "mail.delete", "dolibarr.delete", "nextcloud.delete"}
        and not settings.destructive_operations_enabled
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Destructive operations are disabled"
        )


def sanitize_filename(value: str) -> str:
    name = Path(value.replace("\\", "/")).name.strip().replace("\x00", "")
    safe = "".join(c if c.isalnum() or c in "._- ()" else "_" for c in name)
    if safe in {"", ".", ".."}:
        safe = "attachment"
    return safe[:240]


def safe_destination(root: Path, filename: str) -> Path:
    root = root.resolve()
    target = (root / sanitize_filename(filename)).resolve()
    if root != target.parent:
        raise ValueError("Invalid attachment path")
    return target
