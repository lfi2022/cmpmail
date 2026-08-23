import httpx
import pytest

from app.config import Settings
from app.mcp_server import TOOL_PERMISSIONS
from app.services.dolibarr import (
    DolibarrAPIError,
    DolibarrService,
    redact_dolibarr_data,
    redact_dolibarr_text,
    validate_object_id,
    validate_resource,
)


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        dolibarr_api_url="https://erp.example.com/api/index.php",
        dolibarr_api_key="secrettoken",
    )


def test_redaction_strips_api_key_and_tokens():
    payload = {"id": "1", "dolapikey": "secret", "token": "secret2", "name": "ok"}
    assert redact_dolibarr_data(payload) == {
        "id": "1",
        "dolapikey": "[REDACTED]",
        "token": "[REDACTED]",
        "name": "ok",
    }


def test_redact_text_hides_dolapikey_query_param():
    text = redact_dolibarr_text("GET /status?DOLAPIKEY=secrettoken failed")
    assert "secrettoken" not in text
    assert "[REDACTED]" in text


def test_validate_resource_rejects_bad_input():
    assert validate_resource("invoices") == "invoices"
    assert validate_resource("/thirdparties/") == "thirdparties"
    for invalid in ("", "  ", "invoices?x=1", "../../etc/passwd"):
        with pytest.raises(ValueError):
            validate_resource(invalid)


def test_validate_object_id_rejects_path_separators():
    assert validate_object_id(12) == "12"
    for invalid in ("", "1/2", "1;2"):
        with pytest.raises(ValueError):
            validate_object_id(invalid)


def test_dolibarr_tools_and_permissions_remain_registered():
    expected = {
        "dolibarr_health_check": "dolibarr.read",
        "dolibarr_list_resources": "dolibarr.read",
        "dolibarr_list": "dolibarr.read",
        "dolibarr_get": "dolibarr.read",
        "dolibarr_create": "dolibarr.write",
        "dolibarr_update": "dolibarr.write",
        "dolibarr_delete": "dolibarr.delete",
        "dolibarr_action": "dolibarr.write",
    }
    for tool, permission in expected.items():
        assert TOOL_PERMISSIONS[tool] == permission


@pytest.mark.asyncio
async def test_list_objects_sends_dolapikey_header_and_params():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def request(self, **kwargs):
            captured.update(kwargs)
            return httpx.Response(
                200,
                json=[{"id": "1", "name": "Acme"}],
                request=httpx.Request("GET", kwargs["url"]),
            )

    service = DolibarrService(_settings())

    import app.services.dolibarr as dolibarr_module

    original = httpx.AsyncClient
    dolibarr_module.httpx.AsyncClient = lambda **kwargs: FakeClient()
    try:
        out = await service.list_objects("thirdparties", sqlfilters="(t.client:=:1)", limit=10)
    finally:
        dolibarr_module.httpx.AsyncClient = original

    assert out == [{"id": "1", "name": "Acme"}]
    assert captured["headers"]["DOLAPIKEY"] == "secrettoken"
    assert captured["params"]["sqlfilters"] == "(t.client:=:1)"
    assert captured["params"]["limit"] == 10
    assert captured["method"] == "GET"
    assert captured["url"] == "https://erp.example.com/api/index.php/thirdparties"


@pytest.mark.asyncio
async def test_error_response_is_redacted_and_raises():
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def request(self, **kwargs):
            return httpx.Response(
                404,
                json={"error": {"code": 404, "message": "Object not found"}},
                request=httpx.Request("GET", kwargs["url"]),
            )

    import app.services.dolibarr as dolibarr_module

    original = httpx.AsyncClient
    dolibarr_module.httpx.AsyncClient = lambda **kwargs: FakeClient()
    service = DolibarrService(_settings())
    try:
        with pytest.raises(DolibarrAPIError) as raised:
            await service.get_object("thirdparties", "999")
    finally:
        dolibarr_module.httpx.AsyncClient = original

    assert raised.value.status_code == 404
    assert "Object not found" in str(raised.value)


def test_missing_configuration_raises_before_request():
    service = DolibarrService(Settings(_env_file=None, dolibarr_api_url="", dolibarr_api_key=""))
    with pytest.raises(ValueError):
        _ = service.base_url
