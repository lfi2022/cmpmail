from __future__ import annotations

import base64
import binascii
import mimetypes
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config import Settings

SUPPORTED_IMAGE_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}
MAX_IMAGE_BYTES = 10 * 1024 * 1024
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def _safe_filename(filename: str | None, mime_type: str) -> str:
    extension = SUPPORTED_IMAGE_MIME_TYPES[mime_type]
    name = Path(str(filename or "image")).name
    if not name or name in {".", ".."}:
        name = "image"
    provided_extension = Path(name).suffix.lower()
    if provided_extension and provided_extension != extension:
        raise ValueError("filename extension does not match mime_type")
    stem = Path(name).stem or "image"
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:80] or "image"
    return f"{stem}{extension}"


def _decode_image(image_base64: str, mime_type: str, filename: str | None) -> tuple[bytes, str]:
    mime = str(mime_type or mimetypes.guess_type(str(filename or ""))[0] or "image/jpeg").lower()
    if mime not in SUPPORTED_IMAGE_MIME_TYPES:
        raise ValueError("Supported image MIME types are JPEG, PNG, and WEBP")
    encoded = image_base64
    if encoded.startswith("data:"):
        header, separator, encoded = encoded.partition(",")
        if not separator or ";base64" not in header.lower():
            raise ValueError("image_base64 must contain base64 data")
        declared_mime = header[5:].split(";", 1)[0].lower()
        if declared_mime != mime:
            raise ValueError("image MIME type does not match the data URL")
    try:
        binary = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("image_base64 is not valid base64") from exc
    if not binary:
        raise ValueError("image_base64 must not be empty")
    if len(binary) > MAX_IMAGE_BYTES:
        raise ValueError("image exceeds the 10 MiB upload limit")
    return binary, _safe_filename(filename, mime)


def cleanup_expired_uploads(settings: Settings, now: datetime | None = None) -> int:
    current = now or datetime.now(timezone.utc)
    root = settings.temporary_upload_dir
    if not root.exists():
        return 0
    cutoff = current - timedelta(minutes=settings.temporary_upload_ttl_minutes)
    removed = 0
    for item in root.iterdir():
        if not item.is_dir() or not TOKEN_PATTERN.fullmatch(item.name):
            continue
        modified = datetime.fromtimestamp(item.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            for child in item.iterdir():
                if child.is_file() or child.is_symlink():
                    child.unlink(missing_ok=True)
            item.rmdir()
            removed += 1
    return removed


def store_temporary_image(
    settings: Settings,
    image_base64: str,
    filename: str | None = None,
    mime_type: str | None = None,
) -> dict[str, str]:
    mime = str(mime_type or mimetypes.guess_type(str(filename or ""))[0] or "image/jpeg").lower()
    binary, safe_name = _decode_image(image_base64, mime, filename)
    token = secrets.token_urlsafe(32)
    directory = settings.temporary_upload_dir / token
    directory.mkdir(parents=True, exist_ok=False)
    (directory / safe_name).write_bytes(binary)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.temporary_upload_ttl_minutes)
    return {
        "file_id": token,
        "url": f"{settings.public_url.rstrip('/')}/temp-media/{token}/{safe_name}",
        "expires_at": expires_at.isoformat(),
    }


def resolve_temporary_image(settings: Settings, file_id: str) -> tuple[Path, str]:
    if not TOKEN_PATTERN.fullmatch(file_id):
        raise ValueError("temporary_file_id is invalid")
    directory = settings.temporary_upload_dir / file_id
    candidates = [item for item in directory.iterdir() if item.is_file()] if directory.is_dir() else []
    if len(candidates) != 1:
        raise ValueError("temporary file was not found")
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.temporary_upload_ttl_minutes)
    if datetime.fromtimestamp(candidates[0].stat().st_mtime, timezone.utc) < cutoff:
        delete_temporary_image(settings, file_id)
        raise ValueError("temporary file has expired")
    return candidates[0], file_id


def delete_temporary_image(settings: Settings, file_id: str) -> None:
    if not TOKEN_PATTERN.fullmatch(file_id):
        return
    directory = settings.temporary_upload_dir / file_id
    if directory.is_dir():
        for child in directory.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
        directory.rmdir()
