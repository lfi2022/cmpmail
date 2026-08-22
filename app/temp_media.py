from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import mimetypes
import re
import secrets
import socket
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import httpx

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


def _validate_remote_image_host(url: str) -> None:
    from urllib.parse import urlparse

    hostname = (urlparse(url).hostname or "").rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        raise ValueError("image_url points to a private or metadata host")
    try:
        addresses = {ip_address(item[4][0]) for item in socket.getaddrinfo(hostname, None)}
    except socket.gaierror as exc:
        raise ValueError("image_url host could not be resolved") from exc
    if any(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
        for address in addresses
    ):
        raise ValueError("image_url points to a private or metadata host")


def _masked_url(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "***" if parsed.query else "", ""))


async def download_temporary_image_from_url(
    settings: Settings,
    image_url: str,
    filename: str | None = None,
    preserve_original: bool = True,
) -> dict[str, Any]:
    from urllib.parse import urljoin

    current_url = image_url.strip()
    redirect_count = 0
    chunks = bytearray()
    content_type = ""
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False) as client:
        for attempt in range(4):
            if not current_url or not current_url.lower().startswith(("http://", "https://")):
                raise ValueError("image_url must be an absolute HTTP(S) URL")
            _validate_remote_image_host(current_url)
            logger.info("[TEMP_MEDIA] remote download url=%s redirect_count=%d", _masked_url(current_url), redirect_count)
            try:
                stream_context = client.stream("GET", current_url, follow_redirects=False)
                async with stream_context as streamed:
                    if streamed.is_redirect:
                        if redirect_count >= 3 or not streamed.headers.get("location"):
                            raise ValueError("remote image has too many redirects")
                        current_url = urljoin(current_url, streamed.headers["location"])
                        redirect_count += 1
                        continue
                    if streamed.status_code in {401, 403}:
                        raise ValueError("remote image source requires authentication")
                    streamed.raise_for_status()
                    content_type = streamed.headers.get("content-type", "").split(";", 1)[0].lower()
                    if content_type not in SUPPORTED_IMAGE_MIME_TYPES:
                        raise ValueError("remote image MIME type is not supported")
                    declared_length = streamed.headers.get("content-length")
                    if declared_length and int(declared_length) > settings.temporary_upload_max_bytes:
                        raise ValueError("remote image exceeds the configured upload limit")
                    async for chunk in streamed.aiter_bytes(1024 * 1024):
                        chunks.extend(chunk)
                        if len(chunks) > settings.temporary_upload_max_bytes:
                            raise ValueError("remote image exceeds the configured upload limit")
            except httpx.RequestError as exc:
                raise ValueError("remote image download failed") from exc
            break
        else:
            raise ValueError("remote image has too many redirects")
    binary = bytes(chunks)
    validate_image_signature(binary, content_type)
    safe_name = _safe_filename(filename, content_type)
    original_size = len(binary)
    binary, content_type, safe_name, optimized = prepare_image_for_storage(
        settings, binary, content_type, safe_name, preserve_original
    )
    result = store_temporary_binary(settings, binary, safe_name, content_type, True)
    result.update(
        {
            "original_size": original_size,
            "stored_size": len(binary),
            "optimized": optimized,
            "sha256": hashlib.sha256(binary).hexdigest(),
            "preserve_original": preserve_original,
            "source_url": _masked_url(image_url),
            "redirect_count": redirect_count,
        }
    )
    return result


def prepare_image_for_storage(
    settings: Settings,
    binary: bytes,
    mime_type: str,
    filename: str,
    preserve_original: bool = False,
) -> tuple[bytes, str, str, bool]:
    if preserve_original:
        return binary, mime_type, filename, False
    try:
        from PIL import Image, ImageOps

        with Image.open(BytesIO(binary)) as image:
            image.load()
            original_format = image.format
            if original_format not in {"JPEG", "PNG", "WEBP"}:
                raise ValueError("image content format is not supported")
            output_mime = mime_type
            output_filename = filename
            needs_resize = max(image.size) > settings.temporary_upload_max_dimension
            needs_optimize = settings.temporary_upload_optimize and (
                len(binary) > 512 * 1024 or needs_resize or bool(image.getexif())
            )
            if not needs_optimize:
                return binary, output_mime, output_filename, False
            image = ImageOps.exif_transpose(image)
            if needs_resize:
                image.thumbnail(
                    (settings.temporary_upload_max_dimension, settings.temporary_upload_max_dimension),
                    Image.Resampling.LANCZOS,
                )
            output = BytesIO()
            save_kwargs: dict[str, Any] = {"optimize": True}
            if output_mime == "image/jpeg":
                if image.mode not in {"RGB", "L"}:
                    image = image.convert("RGB")
                save_kwargs["quality"] = settings.temporary_upload_jpeg_quality
            image.save(output, format=original_format, **save_kwargs)
            optimized = output.getvalue()
            if len(optimized) >= len(binary) and not needs_resize:
                return binary, output_mime, output_filename, False
            return optimized, output_mime, output_filename, True
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("image decode or optimization failed") from exc


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
    preserve_original: bool = False,
) -> dict[str, Any]:
    mime = str(mime_type or mimetypes.guess_type(str(filename or ""))[0] or "image/jpeg").lower()
    if mime not in SUPPORTED_IMAGE_MIME_TYPES:
        raise ValueError("Supported image MIME types are JPEG, PNG, and WEBP")
    encoded, _ = normalize_image_base64(image_base64)
    if len(encoded.encode("ascii", errors="ignore")) > settings.temporary_upload_max_base64_bytes:
        raise ValueError("image_base64 exceeds the configured upload limit")
    try:
        binary = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("image_base64 is not valid base64") from exc
    if not binary:
        raise ValueError("image_base64 must not be empty")
    safe_name = _safe_filename(filename, mime)
    return store_temporary_binary(settings, binary, safe_name, mime, preserve_original)


def store_temporary_binary(
    settings: Settings,
    binary: bytes,
    filename: str,
    mime: str,
    preserve_original: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    if mime not in SUPPORTED_IMAGE_MIME_TYPES:
        raise ValueError("Supported image MIME types are JPEG, PNG, and WEBP")
    if not binary:
        raise ValueError("image file is empty")
    if len(binary) > settings.temporary_upload_max_bytes:
        raise ValueError("image exceeds the configured upload limit")
    validate_image_signature(binary, mime)
    safe_name = _safe_filename(filename, mime)
    original_size = len(binary)
    binary, mime, safe_name, optimized = prepare_image_for_storage(
        settings, binary, mime, safe_name, preserve_original
    )
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
        "original_size": original_size,
        "stored_size": len(binary),
        "optimized": optimized,
        "expires_at": expires_at.isoformat(),
    }
    logger.info(
        "[TEMP_MEDIA] stored filename=%s mime=%s original_size=%d stored_size=%d optimized=%s file_id=%s expires_at=%s duration_ms=%.1f",
        safe_name,
        mime,
        len(binary),
        len(binary),
        optimized,
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
