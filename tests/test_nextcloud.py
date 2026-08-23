import httpx
import pytest

from app.config import Settings
from app.mcp_server import TOOL_PERMISSIONS
from app.services.nextcloud import (
    NextcloudAPIError,
    NextcloudService,
    redact_nextcloud_text,
    validate_path,
)


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        nextcloud_url="https://cloud.example.com",
        nextcloud_username="alice",
        nextcloud_app_password="app-secret",
    )


class FakeClient:
    def __init__(self, response: httpx.Response):
        self._response = response
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self._response


def test_redact_text_hides_basic_auth():
    text = redact_nextcloud_text("Authorization: Basic YWxpY2U6c2VjcmV0 failed")
    assert "YWxpY2U6c2VjcmV0" not in text
    assert "[REDACTED]" in text


def test_validate_path_rejects_traversal():
    assert validate_path("/Documents/report.pdf") == "Documents/report.pdf"
    assert validate_path("") == ""
    for invalid in ("../secret", "a/../b", "a/..", ".."):
        with pytest.raises(ValueError):
            validate_path(invalid)


def test_nextcloud_tools_and_permissions_remain_registered():
    expected = {
        "nextcloud_health_check": "nextcloud.read",
        "nextcloud_list_folder": "nextcloud.read",
        "nextcloud_get_file_info": "nextcloud.read",
        "nextcloud_download_file": "nextcloud.read",
        "nextcloud_upload_file": "nextcloud.write",
        "nextcloud_create_folder": "nextcloud.write",
        "nextcloud_move": "nextcloud.write",
        "nextcloud_copy": "nextcloud.write",
        "nextcloud_delete": "nextcloud.delete",
        "nextcloud_list_trash": "nextcloud.read",
        "nextcloud_restore_trash_item": "nextcloud.write",
        "nextcloud_delete_trash_item": "nextcloud.delete",
        "nextcloud_list_shares": "nextcloud.read",
        "nextcloud_create_share": "nextcloud.write",
        "nextcloud_update_share": "nextcloud.write",
        "nextcloud_delete_share": "nextcloud.delete",
        "nextcloud_get_account_info": "nextcloud.read",
        "nextcloud_update_account_field": "nextcloud.write",
        "nextcloud_webdav_request": "nextcloud.write",
        "nextcloud_ocs_request": "nextcloud.write",
    }
    for tool, permission in expected.items():
        assert TOOL_PERMISSIONS[tool] == permission


@pytest.mark.asyncio
async def test_list_folder_uses_propfind_and_drops_self_entry(monkeypatch):
    body = (
        '<?xml version="1.0"?>'
        '<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
        '<d:response><d:href>/remote.php/dav/files/alice/Documents/</d:href>'
        "<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        '<d:response><d:href>/remote.php/dav/files/alice/Documents/report.pdf</d:href>'
        "<d:propstat><d:prop><d:resourcetype/><d:getcontentlength>1024</d:getcontentlength>"
        "<d:getcontenttype>application/pdf</d:getcontenttype></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        "</d:multistatus>"
    )
    response = httpx.Response(207, content=body.encode(), request=httpx.Request("PROPFIND", "https://x"))
    fake_client = FakeClient(response)
    import app.services.nextcloud as nc_module

    monkeypatch.setattr(nc_module.httpx, "AsyncClient", lambda **kwargs: fake_client)
    service = NextcloudService(_settings())
    items = await service.list_folder("Documents")

    assert len(items) == 1
    assert items[0]["name"] == "report.pdf"
    assert items[0]["size"] == 1024
    assert items[0]["content_type"] == "application/pdf"
    assert fake_client.calls[0]["headers"]["Depth"] == "1"


@pytest.mark.asyncio
async def test_dav_error_raises_and_status_propagates(monkeypatch):
    response = httpx.Response(404, request=httpx.Request("GET", "https://x"))
    fake_client = FakeClient(response)
    import app.services.nextcloud as nc_module

    monkeypatch.setattr(nc_module.httpx, "AsyncClient", lambda **kwargs: fake_client)
    service = NextcloudService(_settings())
    with pytest.raises(NextcloudAPIError) as raised:
        await service.get_info("missing.txt")
    assert raised.value.status_code == 404


@pytest.mark.asyncio
async def test_ocs_error_uses_meta_message(monkeypatch):
    payload = {"ocs": {"meta": {"status": "failure", "statuscode": 404, "message": "Not found"}, "data": []}}
    response = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://x"))
    fake_client = FakeClient(response)
    import app.services.nextcloud as nc_module

    monkeypatch.setattr(nc_module.httpx, "AsyncClient", lambda **kwargs: fake_client)
    service = NextcloudService(_settings())
    with pytest.raises(NextcloudAPIError) as raised:
        await service.get_share("999")
    assert "Not found" in str(raised.value)


def test_missing_configuration_raises_before_request():
    service = NextcloudService(Settings(_env_file=None, nextcloud_url="", nextcloud_username=""))
    with pytest.raises(ValueError):
        _ = service.base_url
