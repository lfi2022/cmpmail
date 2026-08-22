import base64
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from PIL import Image

from app.config import Settings
from app.main import app
from app.services.facebook import FacebookService
from app.temp_media import (
    cleanup_expired_uploads,
    delete_temporary_image,
    resolve_temporary_image,
    store_temporary_image,
)


def _encoded_image(image_format="JPEG", size=(32, 32), quality=85):
    from io import BytesIO

    output = BytesIO()
    image = Image.new("RGB", size, (80, 120, 180))
    options = {"quality": quality} if image_format == "JPEG" else {}
    image.save(output, format=image_format, **options)
    return base64.b64encode(output.getvalue()).decode()


@pytest.mark.asyncio
async def test_upload_public_facebook_url_and_cleanup(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, public_url="https://example.com", temporary_upload_dir=tmp_path)
    from app import main

    monkeypatch.setattr(main, "settings", settings)
    stored = store_temporary_image(settings, _encoded_image("PNG"), "photo.png", "image/png")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        response = await client.get("/temp-media/" + stored["file_id"] + "/photo.png")
    assert response.status_code == 200
    assert response.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert stored["filename"] == "photo.png"
    assert stored["mime_type"] == "image/png"
    assert stored["size"] > 8

    calls = []

    async def fake_request(*args, **kwargs):
        calls.append(kwargs["data"]["url"])
        return {"id": "1"}

    service = FacebookService(settings, "token")
    monkeypatch.setattr(service, "_request", fake_request)
    await service.create_photo_post("123", image_url=stored["url"])
    assert calls == [stored["url"]]
    delete_temporary_image(settings, stored["file_id"])
    assert not (tmp_path / stored["file_id"]).exists()


def test_expired_uploads_are_removed(tmp_path):
    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path, temporary_upload_ttl_minutes=10)
    stored = store_temporary_image(settings, _encoded_image(), "photo.jpg", "image/jpeg")
    file_path = next((tmp_path / stored["file_id"]).iterdir())
    old = (datetime.now(timezone.utc) - timedelta(minutes=11)).timestamp()
    import os

    os.utime(file_path, (old, old))
    os.utime(tmp_path / stored["file_id"], (old, old))
    assert cleanup_expired_uploads(settings) == 1
    assert not (tmp_path / stored["file_id"]).exists()


@pytest.mark.asyncio
async def test_mcp_temporary_file_uses_binary_source_and_deletes_after_post(tmp_path, monkeypatch):
    from app import mcp_server

    settings = Settings(_env_file=None, public_url="https://mcp.example", temporary_upload_dir=tmp_path)
    stored = store_temporary_image(settings, _encoded_image(), "photo.jpg", "image/jpeg")
    captured = {}

    class FakeFacebookService:
        async def create_photo_post(self, page_id, **kwargs):
            captured.update(kwargs)
            return {"id": "1"}

    async def fake_facebook_action(tool, **kwargs):
        return await kwargs["callback"](FakeFacebookService(), "104823885473411")

    monkeypatch.setattr(mcp_server, "settings", settings)
    monkeypatch.setattr(mcp_server, "_facebook_action", fake_facebook_action)
    output = await mcp_server.facebook_create_photo_post(
        page_id="104823885473411",
        temporary_file_id=stored["file_id"],
        published=False,
    )

    assert output == {"id": "1"}
    assert captured["image_file_path"].name == "photo.jpg"
    assert captured["image_url"] is None
    assert captured["image_base64"] is None
    assert captured["published"] is False
    assert not (tmp_path / stored["file_id"]).exists()


def test_upload_accepts_data_uri_and_whitespace_wrapped_base64(tmp_path):
    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path)
    stored = store_temporary_image(
        settings,
        "  data:image/png;base64,\n " + _encoded_image("PNG") + " \t\n",
        "photo.png",
    )
    path, _ = resolve_temporary_image(settings, stored["file_id"])
    assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    delete_temporary_image(settings, stored["file_id"])


def test_upload_rejects_invalid_base64_and_mime(tmp_path):
    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path)
    for value, filename, mime_type in (
        ("not base64", "photo.jpg", "image/jpeg"),
        ("aGVsbG8=", "photo.svg", "image/svg+xml"),
    ):
        try:
            store_temporary_image(settings, value, filename, mime_type)
        except ValueError:
            continue
        raise AssertionError("Expected invalid image input to be rejected")


def test_upload_rejects_oversized_image(tmp_path):
    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path)
    oversized = base64.b64encode(b"x" * (10 * 1024 * 1024 + 1)).decode()
    try:
        store_temporary_image(settings, oversized, "photo.jpg", "image/jpeg")
    except ValueError as exc:
        assert "configured upload limit" in str(exc)
    else:
        raise AssertionError("Expected oversized image to be rejected")


@pytest.mark.parametrize("size", (50 * 1024, 100 * 1024, 200 * 1024, 500 * 1024, 1024 * 1024, 2 * 1024 * 1024))
def test_upload_progressive_sizes(size, tmp_path):
    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path)
    image_size = max(32, int(size**0.5))
    stored = store_temporary_image(
        settings,
        _encoded_image(size=(image_size, image_size), quality=95),
        "sized.jpg",
        "image/jpeg",
    )
    path, _ = resolve_temporary_image(settings, stored["file_id"])
    assert 0 < stored["size"] <= size * 2
    assert path.stat().st_size == stored["size"]
    delete_temporary_image(settings, stored["file_id"])


def test_large_image_is_resized_and_optimized(tmp_path):
    from io import BytesIO

    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path)
    image = Image.effect_noise((2400, 1800), 100).convert("RGB")
    source = BytesIO()
    image.save(source, format="JPEG", quality=95)
    encoded = base64.b64encode(source.getvalue()).decode()

    stored = store_temporary_image(settings, encoded, "large.jpg", "image/jpeg")

    with Image.open(tmp_path / stored["file_id"] / stored["filename"]) as result:
        assert max(result.size) <= 1600
    assert stored["optimized"] is True
    assert stored["stored_size"] < stored["original_size"]
    delete_temporary_image(settings, stored["file_id"])