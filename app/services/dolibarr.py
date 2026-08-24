"""Client for the Dolibarr REST API (module 'API REST', Luracast Restler).

Reference: https://github.com/Dolibarr/dolibarr/blob/develop/htdocs/api/README.md
Base URL is `{DOLIBARR_API_URL}/api/index.php` and authentication uses the
`DOLAPIKEY` HTTP header (a per-user token generated in Dolibarr's user card).
The API is uniformly resource-based: GET/POST list+create on `/{resource}`,
GET/PUT/DELETE on `/{resource}/{id}`, and documented sub-actions such as
`/invoices/{id}/validate` or `/orders/{id}/close`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

_SECRET_KEYS = {"dolapikey", "token", "password", "pass", "pass_encoding"}
_RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-/]*$")
_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.\-@]+$")

# Common Dolibarr object endpoints, for discovery by callers that do not have
# access to the official documentation. Not exhaustive: any module exposing a
# REST API class (api_<module>.class.php) is reachable the same way.
RESOURCE_CATALOG: dict[str, str] = {
    "thirdparties": "Customers, prospects and suppliers (companies and individuals)",
    "contacts": "Contacts/addresses linked to thirdparties or standalone",
    "products": "Products and services catalog, including stock (GET /products/{id}/stock)",
    "categories": "Tag/category tree; POST /categories/{id}/objects/{type}/{objectid} to assign",
    "invoices": "Customer invoices; actions: validate, payments, settopaid, close",
    "orders": "Customer (sales) orders; actions: validate, close, settodraft, shipments",
    "proposals": "Commercial proposals / devis; actions: validate, close",
    "contracts": "Contracts; actions: validate, close, lines/{lineid}/activate, lines/{lineid}/close",
    "supplierinvoices": "Supplier (purchase) invoices; actions: validate, payments",
    "supplierorders": "Supplier orders; actions: validate, approve, close",
    "supplierproposals": "Supplier price requests",
    "projects": "Projects/affairs; sub-resource: tasks",
    "tasks": "Project tasks; action: addtimespent",
    "agendaevents": "Agenda/calendar events (actions, appointments)",
    "adherents": "Association members; actions: validate, subscriptions",
    "users": "Dolibarr users (sensitive: contains logins and rights)",
    "bankaccounts": "Bank accounts and their transactions",
    "warehouses": "Stock warehouses",
    "stockmovements": "Stock movement history and manual stock corrections",
    "expensereports": "Expense reports; action: validate",
    "interventions": "Interventions/field service sheets (fichinter); action: validate",
    "shipments": "Shipments linked to orders; action: validate, close",
    "documents": "Uploaded documents attached to any Dolibarr object",
    "setup/dictionary": "Read-only Dolibarr dictionaries (countries, currencies, ...)",
    "status": "API health/version endpoint",
}


def redact_dolibarr_text(value: object) -> str:
    """Redact API-key fragments that may leak into upstream error text or URLs."""
    text = str(value)
    return re.sub(r"(?i)(DOLAPIKEY)=([^&\s]+)", r"\1=[REDACTED]", text)


def redact_dolibarr_data(value: Any) -> Any:
    """Strip API keys/tokens/passwords from response payloads before returning them."""
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if key.lower() in _SECRET_KEYS else redact_dolibarr_data(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_dolibarr_data(item) for item in value]
    return value


def validate_resource(value: str) -> str:
    resource = str(value or "").strip().strip("/")
    if not resource or not _RESOURCE_PATTERN.fullmatch(resource):
        raise ValueError(
            "resource must be a non-empty path using letters, digits, '_', '-' and '/'"
        )
    return resource


def validate_object_id(value: str | int) -> str:
    identifier = str(value if value is not None else "").strip()
    if not identifier or not _ID_PATTERN.fullmatch(identifier):
        raise ValueError("id must be a non-empty identifier without path separators")
    return identifier


class DolibarrAPIError(RuntimeError):
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


class DolibarrService:
    def __init__(self, settings: Settings, api_key: str | None = None):
        self.settings = settings
        self.api_key = (api_key or settings.dolibarr_api_key or "").strip()

    @property
    def base_url(self) -> str:
        url = (self.settings.dolibarr_api_url or "").strip()
        if not url:
            raise ValueError("DOLIBARR_API_URL is not configured")
        return url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise ValueError("DOLIBARR_API_KEY is not configured")
        return {"DOLAPIKEY": self.api_key, "Accept": "application/json"}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.dolibarr_timeout_seconds, connect=10.0),
                verify=self.settings.dolibarr_verify_ssl,
            ) as client:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    json=json_body,
                    headers=self._headers(),
                )
        except httpx.RequestError as exc:
            logger.warning("Dolibarr network error path=%s error=%s", path, exc.__class__.__name__)
            raise DolibarrAPIError(
                f"Dolibarr API request failed on {path}: {exc.__class__.__name__}"
            ) from exc
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        if response.is_error:
            message = None
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, dict):
                    message = error.get("message")
                message = message or payload.get("message")
            if not message:
                message = payload if isinstance(payload, str) else "Dolibarr API error"
            logger.warning(
                "Dolibarr API error path=%s http_status=%s", path, response.status_code
            )
            raise DolibarrAPIError(
                f"Dolibarr API error on {path}: {message}",
                status_code=response.status_code,
                metadata={"dolibarr_error": redact_dolibarr_data(payload)},
            )
        return redact_dolibarr_data(payload)

    async def attach_file(self, resource: str, object_id: str | int, content: bytes, filename: str, *, modulepart: str | None = None, overwrite: bool = False) -> Any:
        resource = validate_resource(resource)
        object_id = validate_object_id(object_id)
        obj = await self.get_object(resource, object_id)
        reference = str((obj or {}).get("ref") or (obj or {}).get("ref_ext") or "").strip()
        if not reference:
            raise ValueError("Dolibarr object has no reference; cannot attach a document")
        default_parts = {"supplierinvoices": "supplier_invoice", "invoices": "facture", "orders": "commande", "supplierorders": "commande_fournisseur"}
        part = modulepart or default_parts.get(resource)
        if not part:
            raise ValueError("modulepart is required for this Dolibarr resource")
        import base64
        return await self._request("POST", "documents/upload", json_body={"modulepart": part, "ref": reference, "filename": filename, "filecontent": base64.b64encode(content).decode(), "overwriteifexists": 1 if overwrite else 0})
    async def status(self) -> Any:
        """GET /status: confirms the API is reachable and the token is valid."""
        return await self._request("GET", "status")

    async def list_objects(
        self,
        resource: str,
        *,
        sqlfilters: str | None = None,
        sortfield: str | None = None,
        sortorder: str | None = None,
        limit: int = 100,
        page: int = 0,
        extra_params: dict[str, Any] | None = None,
    ) -> Any:
        """GET /{resource}. `sqlfilters` follows Dolibarr's syntax, e.g. (t.email:like:'%@acme.com')."""
        resource = validate_resource(resource)
        params: dict[str, Any] = {
            "limit": max(1, min(int(limit), 1000)),
            "page": max(0, int(page)),
        }
        if sqlfilters:
            params["sqlfilters"] = sqlfilters
        if sortfield:
            params["sortfield"] = sortfield
        if sortorder:
            params["sortorder"] = sortorder
        if extra_params:
            params.update(extra_params)
        return await self._request("GET", resource, params=params)

    async def get_object(
        self, resource: str, object_id: str | int, *, extra_params: dict[str, Any] | None = None
    ) -> Any:
        """GET /{resource}/{id}."""
        resource = validate_resource(resource)
        object_id = validate_object_id(object_id)
        return await self._request("GET", f"{resource}/{object_id}", params=extra_params)

    async def create_object(self, resource: str, payload: dict[str, Any]) -> Any:
        """POST /{resource}. Dolibarr returns the new object id."""
        resource = validate_resource(resource)
        if not isinstance(payload, dict) or not payload:
            raise ValueError("payload must be a non-empty object")
        return await self._request("POST", resource, json_body=payload)

    async def update_object(self, resource: str, object_id: str | int, payload: dict[str, Any]) -> Any:
        """PUT /{resource}/{id}. Only fields present in payload are changed."""
        resource = validate_resource(resource)
        object_id = validate_object_id(object_id)
        if not isinstance(payload, dict) or not payload:
            raise ValueError("payload must be a non-empty object")
        return await self._request("PUT", f"{resource}/{object_id}", json_body=payload)

    async def delete_object(self, resource: str, object_id: str | int) -> Any:
        """DELETE /{resource}/{id}."""
        resource = validate_resource(resource)
        object_id = validate_object_id(object_id)
        return await self._request("DELETE", f"{resource}/{object_id}")

    async def call_action(
        self,
        resource: str,
        object_id: str | int | None,
        action: str,
        *,
        method: str = "POST",
        payload: dict[str, Any] | None = None,
    ) -> Any:
        """Call a documented sub-action, e.g. resource='invoices', action='validate' -> POST /invoices/{id}/validate."""
        resource = validate_resource(resource)
        action = validate_resource(action)
        if object_id is not None:
            path = f"{resource}/{validate_object_id(object_id)}/{action}"
        else:
            path = f"{resource}/{action}"
        return await self._request(method.upper(), path, json_body=payload)
