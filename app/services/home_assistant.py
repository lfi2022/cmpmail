"""Secure async REST and WebSocket client for Home Assistant."""

from __future__ import annotations

import json
import logging
import re
import ssl
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from websockets.asyncio.client import connect

from app.config import Settings

logger = logging.getLogger(__name__)
_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_SLUG = re.compile(r"^[a-zA-Z0-9_-]+$")
_SERVICE_PART = re.compile(r"^[a-z0-9_]+$")
_CONFIG_TYPES = {"automation", "script", "scene"}
_SENSITIVE_KEYS = {"access_token", "authorization", "token", "refresh_token"}

READ_ONLY_WEBSOCKET_TYPES = {
    "get_config",
    "get_states",
    "get_services",
    "get_panels",
    "config/area_registry/list",
    "config/category_registry/list",
    "config/device_registry/list",
    "config/entity_registry/list",
    "config/entity_registry/list_for_display",
    "config/entity_registry/get",
    "config/entity_registry/get_entries",
    "config/floor_registry/list",
    "config/label_registry/list",
    "config_entries/get",
    "homeassistant/expose_entity/list",
    "lovelace/config",
    "repairs/list_issues",
    "script/config",
    "system_health/info",
}


def redact_home_assistant_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if str(key).lower() in _SENSITIVE_KEYS
            else redact_home_assistant_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_home_assistant_data(item) for item in value]
    return value


def redact_home_assistant_text(value: object, token: str = "") -> str:
    text = str(value)
    if token:
        text = text.replace(token, "[REDACTED]")
    return re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+",
        r"\1[REDACTED]",
        text,
    )


def validate_entity_id(value: str) -> str:
    entity_id = str(value or "").strip().lower()
    if not _ENTITY_ID.fullmatch(entity_id):
        raise ValueError("entity_id must look like 'domain.object_id'")
    return entity_id


def validate_service_part(value: str, name: str) -> str:
    part = str(value or "").strip().lower()
    if not _SERVICE_PART.fullmatch(part):
        raise ValueError(
            f"{name} must contain only lowercase letters, numbers and underscores"
        )
    return part


def validate_config_target(config_type: str, config_id: str) -> tuple[str, str]:
    kind = str(config_type or "").strip().lower()
    identifier = str(config_id or "").strip()
    if kind not in _CONFIG_TYPES:
        raise ValueError("config_type must be automation, script, or scene")
    if not _SLUG.fullmatch(identifier):
        raise ValueError(
            "config_id must contain only letters, numbers, underscores and hyphens"
        )
    return kind, identifier


def validate_api_path(path: str) -> str:
    candidate = "/" + str(path or "").strip().lstrip("/")
    parsed = urlparse(candidate)
    if parsed.query or parsed.fragment or not parsed.path.startswith("/api/"):
        raise ValueError(
            "path must be a query-free Home Assistant path below /api/"
        )
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        raise ValueError("path traversal is not allowed")
    return parsed.path


class HomeAssistantAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.metadata = metadata or {}


class HomeAssistantService:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def base_url(self) -> str:
        value = str(self.settings.home_assistant_url or "").strip().rstrip("/")
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
        ):
            raise ValueError(
                "HOME_ASSISTANT_URL must be an http(s) URL without credentials"
            )
        return value

    @property
    def token(self) -> str:
        value = str(self.settings.home_assistant_token or "").strip()
        if not value or value == "A_REMPLIR":
            raise ValueError("HOME_ASSISTANT_TOKEN is not configured")
        return value

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | list[Any] | None = None,
    ) -> Any:
        safe_path = validate_api_path(path)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    self.settings.home_assistant_timeout_seconds, connect=10.0
                ),
                verify=self.settings.home_assistant_verify_ssl,
                headers=self._headers(),
            ) as client:
                response = await client.request(
                    method.upper(),
                    f"{self.base_url}{safe_path}",
                    params=params,
                    json=payload,
                )
        except httpx.RequestError as exc:
            logger.warning(
                "Home Assistant network error method=%s path=%s error=%s",
                method,
                safe_path,
                exc.__class__.__name__,
            )
            raise HomeAssistantAPIError(
                f"Home Assistant request failed: {exc.__class__.__name__}"
            ) from exc

        if response.status_code >= 400:
            raw = redact_home_assistant_text(response.text[:2000], self.token)
            raise HomeAssistantAPIError(
                f"Home Assistant API error {response.status_code} on "
                f"{method.upper()} {safe_path}",
                status_code=response.status_code,
                metadata={"response": raw},
            )
        if not response.content:
            return {"status_code": response.status_code}
        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type:
            return redact_home_assistant_data(response.json())
        return {
            "content": redact_home_assistant_text(response.text, self.token),
            "content_type": content_type,
        }

    async def states(self) -> list[dict[str, Any]]:
        return await self.request("GET", "/api/states")

    async def state(self, entity_id: str) -> dict[str, Any]:
        entity_id = quote(validate_entity_id(entity_id), safe=".")
        return await self.request("GET", f"/api/states/{entity_id}")

    async def set_state(
        self,
        entity_id: str,
        state: str,
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entity_id = quote(validate_entity_id(entity_id), safe=".")
        if state is None:
            raise ValueError("state must not be null")
        return await self.request(
            "POST",
            f"/api/states/{entity_id}",
            payload={"state": str(state), "attributes": attributes or {}},
        )

    async def delete_state(self, entity_id: str) -> Any:
        entity_id = quote(validate_entity_id(entity_id), safe=".")
        return await self.request("DELETE", f"/api/states/{entity_id}")

    async def services(self) -> list[dict[str, Any]]:
        return await self.request("GET", "/api/services")

    async def call_service(
        self,
        domain: str,
        service: str,
        data: dict[str, Any],
        return_response: bool = False,
    ) -> Any:
        domain = validate_service_part(domain, "domain")
        service = validate_service_part(service, "service")
        params = {"return_response": ""} if return_response else None
        return await self.request(
            "POST",
            f"/api/services/{domain}/{service}",
            params=params,
            payload=data,
        )

    async def websocket_command(self, command: dict[str, Any]) -> Any:
        if not isinstance(command, dict) or not isinstance(command.get("type"), str):
            raise ValueError("command must be an object with a string 'type'")
        parsed = urlparse(self.base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = (
            f"{scheme}://{parsed.netloc}{parsed.path.rstrip('/')}/api/websocket"
        )
        ssl_arg: ssl.SSLContext | bool | None = None
        if scheme == "wss":
            if self.settings.home_assistant_verify_ssl:
                ssl_arg = True
            else:
                ssl_arg = ssl.create_default_context()
                ssl_arg.check_hostname = False
                ssl_arg.verify_mode = ssl.CERT_NONE
        try:
            async with connect(
                ws_url,
                open_timeout=self.settings.home_assistant_timeout_seconds,
                close_timeout=5,
                max_size=(
                    self.settings.home_assistant_websocket_max_size_mb
                    * 1024
                    * 1024
                ),
                ssl=ssl_arg,
            ) as websocket:
                hello = json.loads(await websocket.recv())
                if hello.get("type") != "auth_required":
                    raise HomeAssistantAPIError(
                        "Unexpected Home Assistant WebSocket handshake"
                    )
                await websocket.send(
                    json.dumps({"type": "auth", "access_token": self.token})
                )
                auth = json.loads(await websocket.recv())
                if auth.get("type") != "auth_ok":
                    raise HomeAssistantAPIError(
                        "Home Assistant WebSocket authentication failed"
                    )
                request = dict(command)
                request.pop("access_token", None)
                request["id"] = 1
                await websocket.send(json.dumps(request))
                while True:
                    response = json.loads(await websocket.recv())
                    if response.get("id") != 1:
                        continue
                    if (
                        response.get("type") == "result"
                        and not response.get("success", False)
                    ):
                        raise HomeAssistantAPIError(
                            "Home Assistant WebSocket command failed",
                            metadata={
                                "error": redact_home_assistant_data(
                                    response.get("error") or {}
                                )
                            },
                        )
                    return redact_home_assistant_data(
                        response.get("result", response)
                    )
        except HomeAssistantAPIError:
            raise
        except Exception as exc:
            logger.warning(
                "Home Assistant WebSocket error type=%s", exc.__class__.__name__
            )
            raise HomeAssistantAPIError(
                f"Home Assistant WebSocket request failed: "
                f"{exc.__class__.__name__}"
            ) from exc

    async def config_object(self, config_type: str, config_id: str) -> Any:
        kind, identifier = validate_config_target(config_type, config_id)
        return await self.request(
            "GET", f"/api/config/{kind}/config/{identifier}"
        )

    async def set_config_object(
        self,
        config_type: str,
        config_id: str,
        config: dict[str, Any],
    ) -> Any:
        kind, identifier = validate_config_target(config_type, config_id)
        if not isinstance(config, dict) or not config:
            raise ValueError("config must be a non-empty object")
        return await self.request(
            "POST",
            f"/api/config/{kind}/config/{identifier}",
            payload=config,
        )

    async def delete_config_object(
        self, config_type: str, config_id: str
    ) -> Any:
        kind, identifier = validate_config_target(config_type, config_id)
        return await self.request(
            "DELETE", f"/api/config/{kind}/config/{identifier}"
        )
