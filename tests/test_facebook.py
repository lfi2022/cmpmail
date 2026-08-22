import base64

import httpx
import pytest

from app.config import Settings
from app.mcp_server import TOOL_PERMISSIONS
from app.services.facebook import (
    PAGE_FIELDS,
    FacebookAPIError,
    FacebookService,
    redact_facebook_data,
    redact_facebook_text,
    validate_facebook_id,
    validate_image_url,
)


def test_page_fields_never_include_created_time():
    assert "created_time" not in PAGE_FIELDS
    assert {"id", "name", "picture{url}"}.issubset(PAGE_FIELDS)


def test_redaction_removes_tokens_and_tokenized_paging_urls():
    payload = {
        "data": [{"id": "104823885473411", "access_token": "EAAsecret"}],
        "paging": {"next": "https://graph.facebook.com/?access_token=EAAsecret"},
        "nested": {"client_secret": "secret", "name": "safe"},
    }
    assert redact_facebook_data(payload) == {
        "data": [{"id": "104823885473411"}],
        "paging": {},
        "nested": {"name": "safe"},
    }


def test_error_text_redacts_graph_token_fragments():
    error = redact_facebook_text("access_token=EAAsecret&foo=bar EAAanother")
    assert "EAAsecret" not in error
    assert "EAAanother" not in error
    assert "[REDACTED]" in error


def test_facebook_ids_stay_strings_and_are_validated():
    assert validate_facebook_id("104823885473411", page=True) == "104823885473411"
    assert validate_facebook_id("104823885473411_123456") == "104823885473411_123456"
    for invalid in ("", "123a", "1_2_3", "-1"):
        try:
            validate_facebook_id(invalid)
        except ValueError:
            continue
        raise AssertionError(f"Expected {invalid!r} to be rejected")


def test_image_urls_require_http_or_https():
    assert validate_image_url("https://example.com/image.jpg") == "https://example.com/image.jpg"
    for invalid in (
        "file:///tmp/a.jpg",
        "javascript:alert(1)",
        "relative.jpg",
        "http://localhost/image.jpg",
        "http://127.0.0.1/image.jpg",
        "http://10.0.0.1/image.jpg",
    ):
        try:
            validate_image_url(invalid)
        except ValueError:
            continue
        raise AssertionError(f"Expected {invalid!r} to be rejected")


def test_facebook_tools_and_permissions_remain_registered():
    expected = {
        "facebook_list_pages",
        "facebook_get_page",
        "facebook_list_posts",
        "facebook_get_post",
        "facebook_create_post",
        "facebook_create_photo_post",
        "facebook_delete_post",
        "facebook_get_comments",
        "facebook_reply_comment",
        "facebook_hide_comment",
        "facebook_get_insights",
        "facebook_health_check",
    }
    assert expected.issubset(TOOL_PERMISSIONS)


@pytest.mark.asyncio
async def test_photo_post_uses_source_for_base64_and_temporary_file(tmp_path):
    service = FacebookService(Settings(_env_file=None), "token")
    calls = []

    async def fake_request(*args, **kwargs):
        calls.append(kwargs)
        return {"id": "1"}

    service._request = fake_request
    await service.create_photo_post(
        "104823885473411",
        image_base64=base64.b64encode(b"\xff\xd8\xffjpeg-bytes").decode(),
        image_filename="test.jpg",
        image_mime_type="image/jpeg",
        published=False,
    )
    temporary_path = tmp_path / "test.png"
    temporary_path.write_bytes(b"\x89PNG\r\n\x1a\npng-bytes")
    await service.create_photo_post(
        "104823885473411",
        image_file_path=temporary_path,
        published=False,
    )

    assert [call["files"]["source"][0] for call in calls] == ["test.jpg", "test.png"]
    assert [call["files"]["source"][2] for call in calls] == ["image/jpeg", "image/png"]
    assert all(call["data"]["published"] == "false" for call in calls)
    assert all("url" not in call["data"] for call in calls)


@pytest.mark.asyncio
async def test_photo_post_uses_url_only_for_public_http_url():
    service = FacebookService(Settings(_env_file=None), "token")
    captured = {}

    async def fake_request(*args, **kwargs):
        captured.update(kwargs)
        return {"id": "1"}

    service._request = fake_request
    await service.create_photo_post(
        "104823885473411",
        image_url="https://example.com/test.jpg",
        published=False,
    )

    assert "files" not in captured
    assert captured["data"] == {"url": "https://example.com/test.jpg", "published": "false"}


@pytest.mark.asyncio
async def test_facebook_error_contains_upload_method_and_graph_details(monkeypatch):
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def request(self, **kwargs):
            return httpx.Response(
                400,
                json={"error": {"message": "bad image", "type": "OAuthException", "code": 1, "fbtrace_id": "trace"}},
                request=httpx.Request("POST", "https://graph.facebook.com"),
            )

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeClient())
    service = FacebookService(Settings(_env_file=None), "token")
    with pytest.raises(FacebookAPIError) as raised:
        await service.create_photo_post(
            "104823885473411",
            image_base64=base64.b64encode(b"\xff\xd8\xffjpeg-bytes").decode(),
            image_filename="test.jpg",
            image_mime_type="image/jpeg",
        )

    assert raised.value.metadata == {
        "facebook_error": {
            "message": "bad image",
            "type": "OAuthException",
            "code": 1,
            "error_subcode": None,
            "fbtrace_id": "trace",
        },
        "upload_method": "source",
    }
