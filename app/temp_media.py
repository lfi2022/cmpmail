from __future__ import annotations

import base64
import binascii
import logging
import mimetypes
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import Settings

SUPPORTED_IMAGE_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,}$")
logger = logging.getLogger(__name__)


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


def normalize_image_base64(image_base64: str) -> tuple[str, str | None]:
    encoded = str(image_base64 or "").strip()
    declared_mime = None
    if encoded.lower().startswith("data:"):
        header, separator, encoded = encoded.partition(",")
        if not separator or ";base64" not in header.lower():
            raise ValueError("image_base64 data URI is invalid")
        declared_mime = header[5:].split(";", 1)[0].lower()
    return re.sub(r"\s+", "", encoded), declared_mime


def validate_image_signature(binary: bytes, mime_type: str) -> None:
    signatures = {
        "image/jpeg": binary.startswith(b"\xff\xd8\xff"),
        "image/png": binary.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/webp": binary.startswith(b"RIFF") and binary[8:12] == b"WEBP",
    }
    if not signatures.get(mime_type, False):
        raise ValueError("image content does not match mime_type")


def _decode_image(
    settings: Settings,
    image_base64: str,
    mime_type: str,
    filename: str | None,
) -> tuple[bytes, str]:
    mime = str(mime_type or mimetypes.guess_type(str(filename or ""))[0] or "image/jpeg").lower()
    if mime not in SUPPORTED_IMAGE_MIME_TYPES:
        raise ValueError("Supported image MIME types are JPEG, PNG, and WEBP")
    encoded, declared_mime = normalize_image_base64(image_base64)
    if len(encoded.encode("ascii", errors="ignore")) > settings.temporary_upload_max_base64_bytes:
        raise ValueError("image_base64 exceeds the configured upload limit")
    if declared_mime and declared_mime != mime:
        raise ValueError("image MIME type does not match the data URL")
    try:
        binary = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("image_base64 is not valid base64") from exc
    if not binary:
        raise ValueError("image_base64 must not be empty")
    if len(binary) > settings.temporary_upload_max_bytes:
        raise ValueError("image exceeds the configured upload limit")
    validate_image_signature(binary, mime)
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
) -> dict[str, Any]:
    started = time.perf_counter()
    mime = str(mime_type or mimetypes.guess_type(str(filename or ""))[0] or "image/jpeg").lower()
    binary, safe_name = _decode_image(settings, image_base64, mime, filename)
    token = secrets.token_urlsafe(32)
    directory = settings.temporary_upload_dir / token
    directory.mkdir(parents=True, exist_ok=False)
    (directory / safe_name).write_bytes(binary)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.temporary_upload_ttl_minutes)
    output = {
        "file_id": token,
        "url": f"{settings.public_url.rstrip('/')}/temp-media/{token}/{safe_name}",
        "filename": safe_name,
        "mime_type": mime,
        "size": len(binary),
        "original_size": len(binary),
        "stored_size": len(binary),
        "optimized": False,
        "expires_at": expires_at.isoformat(),
    }
    logger.info(
        "[TEMP_MEDIA] stored filename=%s mime=%s original_size=%d stored_size=%d optimized=%s file_id=%s expires_at=%s duration_ms=%.1f",
        safe_name,
        mime,
        len(binary),
        len(binary),
        False,
        token,
        output["expires_at"],
        (time.perf_counter() - started) * 1000,
    )
    return output


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
