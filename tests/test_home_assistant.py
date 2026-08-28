import httpx
import pytest
from fastapi import HTTPException

from app.config import Settings
from app.mcp_server import TOOL_PERMISSIONS
from app.security import require_permission
from app.services.home_assistant import (
    READ_ONLY_WEBSOCKET_TYPES,
    HomeAssistantService,
    redact_home_assistant_data,
    redact_home_assistant_text,
    validate_api_path,
    validate_config_target,
    validate_entity_id,
)


def _settings(**overrides) -> Settings:
    values = {
        "_env_file": None,
        "home_assistant_url": "https://ha.example.com",
        "home_assistant_token": "secret-token",
    }
    values.update(overrides)
    return Settings(**values)


def test_validators_reject_traversal_and_malformed_identifiers():
    assert validate_entity_id("Light.Kitchen") == "light.kitchen"
    assert validate_config_target("automation", "night-mode_1") == (
        "automation",
        "night-mode_1",
    )
    assert validate_api_path("/api/states") == "/api/states"
    for value in ("light", "../light.kitchen", "light.kitchen/other"):
        with pytest.raises(ValueError):
            validate_entity_id(value)
    for path in ("/health", "/api/states?all=true", "/api/../config"):
        with pytest.raises(ValueError):
            validate_api_path(path)
    with pytest.raises(ValueError):
        validate_config_target("dashboard", "main")


def test_redaction_removes_tokens_recursively_and_from_text():
    assert redact_home_assistant_data(
        {"token": "one", "nested": [{"access_token": "two", "name": "ok"}]}
    ) == {
        "token": "[REDACTED]",
        "nested": [{"access_token": "[REDACTED]", "name": "ok"}],
    }
    text = redact_home_assistant_text(
        "Authorization: Bearer secret-token; token=secret-token",
        "secret-token",
    )
    assert "secret-token" not in text


def test_home_assistant_tools_have_least_privilege_scopes():
    expected = {
        "home_assistant_list_entities": "homeassistant.read",
        "home_assistant_websocket_query": "homeassistant.read",
        "home_assistant_call_service": "homeassistant.control",
        "home_assistant_create_entity": "homeassistant.admin",
        "home_assistant_update_entity": "homeassistant.admin",
        "home_assistant_update_entity_registry_entry": "homeassistant.admin",
        "home_assistant_set_managed_config": "homeassistant.admin",
        "home_assistant_websocket_command": "homeassistant.admin",
        "home_assistant_delete_entity": "homeassistant.delete",
        "home_assistant_delete_entity_registry_entry": "homeassistant.delete",
        "home_assistant_delete_managed_config": "homeassistant.delete",
    }
    for tool, scope in expected.items():
        assert TOOL_PERMISSIONS[tool] == scope
    assert "config/device_registry/list" in READ_ONLY_WEBSOCKET_TYPES
    assert "config/device_registry/remove_config_entry" not in READ_ONLY_WEBSOCKET_TYPES


def test_read_only_and_destructive_guards_apply_to_home_assistant():
    with pytest.raises(HTTPException):
        require_permission(
            "homeassistant.control",
            {"homeassistant.control"},
            _settings(read_only=True),
        )
    with pytest.raises(HTTPException):
        require_permission(
            "homeassistant.delete",
            {"homeassistant.delete"},
            _settings(destructive_operations_enabled=False),
        )


@pytest.mark.asyncio
async def test_rest_request_uses_bearer_and_never_query_token():
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def request(self, method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return httpx.Response(
                200,
                json={"entity_id": "light.kitchen", "state": "on"},
                request=httpx.Request(method, url),
            )

    import app.services.home_assistant as module

    original = module.httpx.AsyncClient
    module.httpx.AsyncClient = FakeClient
    try:
        output = await HomeAssistantService(_settings()).state("light.kitchen")
    finally:
        module.httpx.AsyncClient = original

    assert output["state"] == "on"
    assert captured["url"] == "https://ha.example.com/api/states/light.kitchen"
    assert "secret-token" not in captured["url"]
    assert captured["client"]["headers"]["Authorization"] == "Bearer secret-token"


@pytest.mark.asyncio
async def test_managed_config_uses_scoped_config_endpoint():
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def request(self, method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return httpx.Response(
                200,
                json={"result": "ok"},
                request=httpx.Request(method, url),
            )

    import app.services.home_assistant as module

    original = module.httpx.AsyncClient
    module.httpx.AsyncClient = FakeClient
    try:
        await HomeAssistantService(_settings()).set_config_object(
            "automation",
            "lights_at_dusk",
            {"alias": "Lights at dusk", "triggers": [], "actions": []},
        )
    finally:
        module.httpx.AsyncClient = original

    assert captured["method"] == "POST"
    assert captured["url"].endswith(
        "/api/config/automation/config/lights_at_dusk"
    )
    assert captured["json"]["alias"] == "Lights at dusk"


@pytest.mark.asyncio
async def test_runtime_entity_set_and_delete_use_states_endpoint():
    captured = []

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def request(self, method, url, **kwargs):
            captured.append({"method": method, "url": url, **kwargs})
            return httpx.Response(
                200,
                json={"entity_id": "sensor.mcp_value", "state": "42"},
                request=httpx.Request(method, url),
            )

    import app.services.home_assistant as module

    original = module.httpx.AsyncClient
    module.httpx.AsyncClient = FakeClient
    service = HomeAssistantService(_settings())
    try:
        await service.set_state(
            "sensor.mcp_value",
            "42",
            {"unit_of_measurement": "items"},
        )
        await service.delete_state("sensor.mcp_value")
    finally:
        module.httpx.AsyncClient = original

    assert captured[0]["method"] == "POST"
    assert captured[0]["url"].endswith("/api/states/sensor.mcp_value")
    assert captured[0]["json"] == {
        "state": "42",
        "attributes": {"unit_of_measurement": "items"},
    }
    assert captured[1]["method"] == "DELETE"
    assert captured[1]["url"].endswith("/api/states/sensor.mcp_value")
