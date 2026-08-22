from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import Settings
from app.main import app
from app.services.facebook import FacebookService
from app.temp_media import cleanup_expired_uploads, delete_temporary_image, store_temporary_image


@pytest.mark.asyncio
async def test_upload_public_facebook_url_and_cleanup(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, public_url="https://mcp.example", temporary_upload_dir=tmp_path)
    from app import main

    monkeypatch.setattr(main, "settings", settings)
    stored = store_temporary_image(settings, "iVBORw0KGgo=", "photo.png", "image/png")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        response = await client.get("/temp-media/" + stored["file_id"] + "/photo.png")
    assert response.status_code == 200
    assert response.content == b"\x89PNG\r\n\x1a\n"

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
    settings = Settings(_env_file=None, temporary_upload_dir=tmp_path, temporary_upload_ttl_minutes=20)
    stored = store_temporary_image(settings, "aGVsbG8=", "photo.jpg", "image/jpeg")
    file_path = next((tmp_path / stored["file_id"]).iterdir())
    old = (datetime.now(timezone.utc) - timedelta(minutes=21)).timestamp()
    import os

    os.utime(file_path, (old, old))
    assert cleanup_expired_uploads(settings) == 1
    assert not (tmp_path / stored["file_id"]).exists()