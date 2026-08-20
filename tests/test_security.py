from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.security import (
    CredentialCipher,
    create_api_key,
    require_permission,
    safe_destination,
    sanitize_filename,
    verify_secret,
)


def test_credential_encryption_roundtrip_and_no_plaintext():
    cipher = CredentialCipher(Fernet.generate_key().decode())
    encrypted = cipher.encrypt("super-secret")
    assert "super-secret" not in encrypted
    assert cipher.decrypt(encrypted) == "super-secret"


def test_api_key_is_hashed():
    raw, prefix, hashed = create_api_key()
    assert prefix == raw[:12]
    assert raw not in hashed
    assert verify_secret(hashed, raw)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("../../etc/passwd", "passwd"),
        ("bad<name>.pdf", "bad_name_.pdf"),
        ("..", "attachment"),
    ],
)
def test_filename_sanitation(value, expected):
    assert sanitize_filename(value) == expected


def test_safe_destination_cannot_escape(tmp_path: Path):
    target = safe_destination(tmp_path, "../../secret.txt")
    assert target.parent == tmp_path.resolve()


def test_read_only_blocks_mutation():
    settings = Settings(
        read_only=True, secret_key="x", encryption_key="x", admin_password="x"
    )
    with pytest.raises(Exception, match="read-only"):
        require_permission("send", {"send"}, settings)


def test_permissions_block_ungranted():
    settings = Settings(
        read_only=False, secret_key="x", encryption_key="x", admin_password="x"
    )
    with pytest.raises(Exception, match="Permission required"):
        require_permission("delete", {"read"}, settings)
