from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import Settings
from app.security import sanitize_filename


def _token(value: str) -> bool:
    return len(value) >= 32 and value.replace("_", "").replace("-", "").isalnum()


def store_temporary_file(settings: Settings, content: bytes, filename: str | None, mime_type: str | None) -> dict[str, Any]:
    if not content:
        raise ValueError("attachment file is empty")
    if len(content) > settings.temporary_file_max_bytes:
        raise ValueError(f"attachment exceeds configured temporary-file limit ({settings.temporary_file_max_bytes} bytes)")
    mime = str(mime_type or mimetypes.guess_type(filename or "")[0] or "application/octet-stream").lower()
    if mime in {str(value).lower() for value in settings.blocked_attachment_types}:
        raise ValueError(f"Attachment type is blocked: {mime}")
    file_id = secrets.token_urlsafe(32)
    directory = settings.temporary_file_dir / file_id
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "payload").write_bytes(content)
    metadata = {
        "temporary_file_id": file_id,
        "filename": sanitize_filename(filename or "attachment"),
        "mime_type": mime,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=settings.temporary_file_ttl_minutes)).isoformat(),
    }
    (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    return metadata


def resolve_temporary_file(settings: Settings, temporary_file_id: str) -> tuple[Path, dict[str, Any]]:
    if not _token(str(temporary_file_id or "")):
        raise ValueError("temporary_file_id is invalid")
    directory = settings.temporary_file_dir / temporary_file_id
    payload, metadata_file = directory / "payload", directory / "metadata.json"
    if not payload.is_file() or not metadata_file.is_file():
        raise ValueError("temporary file was not found")
    if datetime.fromtimestamp(payload.stat().st_mtime, timezone.utc) < datetime.now(timezone.utc) - timedelta(minutes=settings.temporary_file_ttl_minutes):
        delete_temporary_file(settings, temporary_file_id)
        raise ValueError("temporary file has expired")
    try:
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("temporary file metadata is invalid") from exc
    if metadata.get("temporary_file_id") != temporary_file_id:
        raise ValueError("temporary file metadata is invalid")
    return payload, metadata


def delete_temporary_file(settings: Settings, temporary_file_id: str) -> None:
    if not _token(str(temporary_file_id or "")):
        return
    directory = settings.temporary_file_dir / temporary_file_id
    if directory.is_dir():
        for item in directory.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink(missing_ok=True)
        directory.rmdir()


def cleanup_expired_temporary_files(settings: Settings, now: datetime | None = None) -> int:
    root = settings.temporary_file_dir
    if not root.exists():
        return 0
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(minutes=settings.temporary_file_ttl_minutes)
    count = 0
    for directory in root.iterdir():
        if directory.is_dir() and _token(directory.name) and datetime.fromtimestamp(directory.stat().st_mtime, timezone.utc) < cutoff:
            delete_temporary_file(settings, directory.name)
            count += 1
    return count
