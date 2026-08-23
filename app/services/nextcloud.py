"""Client for a personal Nextcloud account: WebDAV (files/folders/trash) and the
OCS API (shares, account profile, capabilities).

References:
- WebDAV files: https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/index.html
- OCS Share API: https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/ocs-share-api.html
- Provisioning API (self-service fields): https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/ocs-provisioning-api.html
- Trashbin: https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/trashbin.html

Authentication uses HTTP Basic Auth with an app password (Security settings ->
"Devices & sessions" -> create app password), never the account's main password.
"""

from __future__ import annotations

import base64
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote, unquote

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

_DAV_NS = "DAV:"
_NC_NS = "http://nextcloud.org/ns"
_TRAVERSAL_PATTERN = re.compile(r"(^|/)\.\.(/|$)")

_PROPFIND_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">'
    "<d:prop>"
    "<d:displayname/><d:getcontentlength/><d:getcontenttype/><d:getlastmodified/>"
    "<d:getetag/><d:resourcetype/><oc:id/><oc:fileid/><oc:permissions/><oc:size/>"
    "</d:prop></d:propfind>"
).encode()

_TRASH_PROPFIND_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<d:propfind xmlns:d="DAV:" xmlns:nc="http://nextcloud.org/ns">'
    "<d:prop>"
    "<d:displayname/><d:getcontentlength/><d:getlastmodified/><d:resourcetype/>"
    "<nc:trashbin-filename/><nc:trashbin-original-location/><nc:trashbin-deletion-time/>"
    "</d:prop></d:propfind>"
).encode()


def redact_nextcloud_text(value: object) -> str:
    """Redact Basic-auth fragments that may leak into upstream error text."""
    text = str(value)
    return re.sub(r"(?i)(authorization\s*[:=]\s*basic\s+)[a-z0-9+/=]+", r"\1[REDACTED]", text)


def validate_path(value: str) -> str:
    """Normalize a WebDAV-relative path and reject traversal outside the account root."""
    path = str(value or "").strip().strip("/")
    if not path:
        return ""
    if _TRAVERSAL_PATTERN.search(f"/{path}/") or "\x00" in path:
        raise ValueError("path must not contain '..' segments")
    return path


def _encode_path(path: str) -> str:
    return "/".join(quote(segment, safe="") for segment in path.split("/") if segment)


class NextcloudAPIError(RuntimeError):
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


class NextcloudService:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def username(self) -> str:
        username = (self.settings.nextcloud_username or "").strip()
        if not username:
            raise ValueError("NEXTCLOUD_USERNAME is not configured")
        return username

    @property
    def base_url(self) -> str:
        url = (self.settings.nextcloud_url or "").strip()
        if not url:
            raise ValueError("NEXTCLOUD_URL is not configured")
        return url.rstrip("/")

    @property
    def webdav_base(self) -> str:
        return f"{self.base_url}/remote.php/dav/files/{quote(self.username, safe='')}"

    @property
    def trash_base(self) -> str:
        return f"{self.base_url}/remote.php/dav/trashbin/{quote(self.username, safe='')}"

    @property
    def ocs_base(self) -> str:
        return f"{self.base_url}/ocs/v2.php"

    def _auth(self) -> tuple[str, str]:
        password = (self.settings.nextcloud_app_password or "").strip()
        if not password:
            raise ValueError("NEXTCLOUD_APP_PASSWORD is not configured")
        return (self.username, password)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.nextcloud_timeout_seconds, connect=10.0),
            verify=self.settings.nextcloud_verify_ssl,
            auth=self._auth(),
        )

    # ---- low level transports --------------------------------------
    async def _dav_request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        base: str | None = None,
    ) -> httpx.Response:
        target_base = base or self.webdav_base
        url = f"{target_base}/{_encode_path(path)}" if path else target_base
        try:
            async with self._client() as client:
                response = await client.request(method.upper(), url, headers=headers, content=content)
        except httpx.RequestError as exc:
            logger.warning("Nextcloud network error method=%s path=%s error=%s", method, path, exc.__class__.__name__)
            raise NextcloudAPIError(
                f"Nextcloud request failed on {method} {path or '/'}: {exc.__class__.__name__}"
            ) from exc
        if response.status_code >= 400:
            logger.warning("Nextcloud WebDAV error method=%s path=%s status=%s", method, path, response.status_code)
            raise NextcloudAPIError(
                f"Nextcloud WebDAV error {response.status_code} on {method} {path or '/'}",
                status_code=response.status_code,
            )
        return response

    async def _ocs_request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.ocs_base}/{endpoint.lstrip('/')}"
        request_params = dict(params or {})
        request_params["format"] = "json"
        headers = {"OCS-APIRequest": "true", "Accept": "application/json"}
        try:
            async with self._client() as client:
                response = await client.request(
                    method.upper(), url, params=request_params, data=data, headers=headers
                )
        except httpx.RequestError as exc:
            logger.warning("Nextcloud OCS network error endpoint=%s error=%s", endpoint, exc.__class__.__name__)
            raise NextcloudAPIError(
                f"Nextcloud OCS request failed on {endpoint}: {exc.__class__.__name__}"
            ) from exc
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        ocs = payload.get("ocs") if isinstance(payload, dict) else None
        meta = (ocs or {}).get("meta", {}) if isinstance(ocs, dict) else {}
        statuscode = meta.get("statuscode")
        if response.status_code >= 400 or (statuscode is not None and int(statuscode) >= 300):
            message = meta.get("message") or f"HTTP {response.status_code}"
            logger.warning("Nextcloud OCS error endpoint=%s status=%s message=%s", endpoint, response.status_code, message)
            raise NextcloudAPIError(
                f"Nextcloud OCS error on {endpoint}: {message}",
                status_code=response.status_code,
                metadata={"meta": meta},
            )
        return (ocs or {}).get("data") if isinstance(ocs, dict) else None

    # ---- PROPFIND parsing --------------------------------------------
    def _parse_multistatus(self, xml_bytes: bytes) -> list[dict[str, Any]]:
        root = ET.fromstring(xml_bytes)
        items: list[dict[str, Any]] = []
        for response in root.findall(f"{{{_DAV_NS}}}response"):
            href_el = response.find(f"{{{_DAV_NS}}}href")
            href = (href_el.text or "") if href_el is not None else ""
            props: dict[str, Any] = {"is_dir": False}
            for propstat in response.findall(f"{{{_DAV_NS}}}propstat"):
                status_el = propstat.find(f"{{{_DAV_NS}}}status")
                if status_el is not None and " 200 " not in f" {status_el.text} ":
                    continue
                prop = propstat.find(f"{{{_DAV_NS}}}prop")
                if prop is None:
                    continue
                for child in prop:
                    tag = child.tag.split("}")[-1]
                    if tag == "resourcetype":
                        props["is_dir"] = child.find(f"{{{_DAV_NS}}}collection") is not None
                    else:
                        props[tag] = child.text
            props["href"] = unquote(href)
            items.append(props)
        return items

    @staticmethod
    def _size_of(entry: dict[str, Any]) -> int | None:
        for key in ("size", "getcontentlength"):
            value = entry.get(key)
            if value is not None and str(value).isdigit():
                return int(value)
        return None

    def _file_item(self, entry: dict[str, Any]) -> dict[str, Any]:
        href = entry.get("href", "").rstrip("/")
        name = entry.get("displayname") or href.rsplit("/", 1)[-1]
        return {
            "name": name,
            "path": href,
            "is_dir": bool(entry.get("is_dir")),
            "size": self._size_of(entry),
            "content_type": entry.get("getcontenttype"),
            "last_modified": entry.get("getlastmodified"),
            "etag": (entry.get("getetag") or "").strip('"') or None,
            "fileid": entry.get("fileid") or entry.get("id"),
        }

    # ---- files & folders (WebDAV) -------------------------------------
    async def list_folder(self, path: str = "", *, depth: str = "1") -> list[dict[str, Any]]:
        path = validate_path(path)
        if depth not in {"0", "1", "infinity"}:
            raise ValueError("depth must be '0', '1' or 'infinity'")
        headers = {"Depth": depth, "Content-Type": "application/xml; charset=utf-8"}
        response = await self._dav_request("PROPFIND", path, headers=headers, content=_PROPFIND_BODY)
        entries = self._parse_multistatus(response.content)
        self_href = f"/remote.php/dav/files/{self.username}/{path}".rstrip("/")
        items = [self._file_item(entry) for entry in entries if entry.get("href", "").rstrip("/") != self_href]
        return items

    async def get_info(self, path: str) -> dict[str, Any]:
        path = validate_path(path)
        headers = {"Depth": "0", "Content-Type": "application/xml; charset=utf-8"}
        response = await self._dav_request("PROPFIND", path, headers=headers, content=_PROPFIND_BODY)
        entries = self._parse_multistatus(response.content)
        if not entries:
            raise NextcloudAPIError(f"Not found: {path or '/'}", status_code=404)
        return self._file_item(entries[0])

    async def download_file(self, path: str) -> tuple[bytes, str | None]:
        path = validate_path(path)
        if not path:
            raise ValueError("path is required")
        info = await self.get_info(path)
        if info["is_dir"]:
            raise ValueError("path is a folder; use list_folder instead")
        max_bytes = self.settings.nextcloud_max_download_mb * 1024 * 1024
        if info.get("size") and info["size"] > max_bytes:
            raise ValueError(f"file exceeds the configured download limit ({self.settings.nextcloud_max_download_mb} MiB)")
        response = await self._dav_request("GET", path)
        if len(response.content) > max_bytes:
            raise ValueError("downloaded content exceeds the configured limit")
        return response.content, info.get("content_type")

    async def upload_file(self, path: str, content: bytes, *, overwrite: bool = True) -> dict[str, Any]:
        path = validate_path(path)
        if not path:
            raise ValueError("path is required")
        max_bytes = self.settings.nextcloud_max_upload_mb * 1024 * 1024
        if len(content) > max_bytes:
            raise ValueError(f"content exceeds the configured upload limit ({self.settings.nextcloud_max_upload_mb} MiB)")
        headers = {"If-None-Match": "*"} if not overwrite else None
        response = await self._dav_request("PUT", path, headers=headers, content=content)
        return {"path": path, "status_code": response.status_code}

    async def create_folder(self, path: str) -> dict[str, Any]:
        path = validate_path(path)
        if not path:
            raise ValueError("path is required")
        response = await self._dav_request("MKCOL", path)
        return {"path": path, "status_code": response.status_code}

    async def delete(self, path: str) -> dict[str, Any]:
        path = validate_path(path)
        if not path:
            raise ValueError("path is required; refusing to delete the account root")
        response = await self._dav_request("DELETE", path)
        return {"path": path, "deleted": True, "status_code": response.status_code}

    async def _move_or_copy(self, method: str, source: str, destination: str, *, overwrite: bool) -> dict[str, Any]:
        source = validate_path(source)
        destination = validate_path(destination)
        if not source or not destination:
            raise ValueError("source_path and destination_path are required")
        headers = {
            "Destination": f"{self.webdav_base}/{_encode_path(destination)}",
            "Overwrite": "T" if overwrite else "F",
        }
        response = await self._dav_request(method, source, headers=headers)
        return {"source_path": source, "destination_path": destination, "status_code": response.status_code}

    async def move(self, source: str, destination: str, *, overwrite: bool = False) -> dict[str, Any]:
        return await self._move_or_copy("MOVE", source, destination, overwrite=overwrite)

    async def copy(self, source: str, destination: str, *, overwrite: bool = False) -> dict[str, Any]:
        return await self._move_or_copy("COPY", source, destination, overwrite=overwrite)

    # ---- trash (WebDAV) -------------------------------------------------
    async def list_trash(self) -> list[dict[str, Any]]:
        headers = {"Depth": "1", "Content-Type": "application/xml; charset=utf-8"}
        response = await self._dav_request(
            "PROPFIND", "trash", headers=headers, content=_TRASH_PROPFIND_BODY, base=self.trash_base
        )
        entries = self._parse_multistatus(response.content)
        results = []
        for entry in entries:
            href = entry.get("href", "").rstrip("/")
            if href.endswith("/trash"):
                continue
            deletion_time = entry.get("trashbin-deletion-time")
            results.append(
                {
                    "name": entry.get("trashbin-filename") or entry.get("displayname"),
                    "path": href,
                    "is_dir": bool(entry.get("is_dir")),
                    "original_location": entry.get("trashbin-original-location"),
                    "deleted_at": int(deletion_time) if deletion_time and str(deletion_time).isdigit() else deletion_time,
                }
            )
        return results

    async def restore_trash_item(self, trash_filename: str) -> dict[str, Any]:
        trash_filename = validate_path(trash_filename)
        if not trash_filename:
            raise ValueError("trash_filename is required")
        basename = trash_filename.rsplit("/", 1)[-1]
        headers = {
            "Destination": f"{self.trash_base}/restore/{_encode_path(basename)}",
            "Overwrite": "F",
        }
        response = await self._dav_request("MOVE", f"trash/{trash_filename}", headers=headers, base=self.trash_base)
        return {"restored": True, "trash_filename": trash_filename, "status_code": response.status_code}

    async def delete_trash_item(self, trash_filename: str | None = None) -> dict[str, Any]:
        trash_filename = validate_path(trash_filename) if trash_filename else ""
        path = f"trash/{trash_filename}" if trash_filename else "trash"
        response = await self._dav_request("DELETE", path, base=self.trash_base)
        return {"deleted": True, "trash_filename": trash_filename or None, "status_code": response.status_code}

    # ---- shares (OCS Share API) -----------------------------------------
    async def list_shares(self, path: str | None = None, *, reshares: bool = False, subfiles: bool = False) -> Any:
        params: dict[str, Any] = {}
        if path:
            params["path"] = validate_path(path)
        if reshares:
            params["reshares"] = "true"
        if subfiles:
            params["subfiles"] = "true"
        return await self._ocs_request("GET", "apps/files_sharing/api/v1/shares", params=params)

    async def get_share(self, share_id: str) -> Any:
        return await self._ocs_request("GET", f"apps/files_sharing/api/v1/shares/{share_id}")

    async def create_share(
        self,
        path: str,
        share_type: int,
        *,
        share_with: str | None = None,
        permissions: int | None = None,
        password: str | None = None,
        expire_date: str | None = None,
        public_upload: bool = False,
        note: str | None = None,
    ) -> Any:
        data: dict[str, Any] = {"path": validate_path(path), "shareType": share_type}
        if share_with is not None:
            data["shareWith"] = share_with
        if permissions is not None:
            data["permissions"] = permissions
        if password is not None:
            data["password"] = password
        if expire_date is not None:
            data["expireDate"] = expire_date
        if public_upload:
            data["publicUpload"] = "true"
        if note is not None:
            data["note"] = note
        return await self._ocs_request("POST", "apps/files_sharing/api/v1/shares", data=data)

    async def update_share(
        self,
        share_id: str,
        *,
        permissions: int | None = None,
        password: str | None = None,
        expire_date: str | None = None,
        note: str | None = None,
        public_upload: bool | None = None,
    ) -> Any:
        data: dict[str, Any] = {}
        if permissions is not None:
            data["permissions"] = permissions
        if password is not None:
            data["password"] = password
        if expire_date is not None:
            data["expireDate"] = expire_date
        if note is not None:
            data["note"] = note
        if public_upload is not None:
            data["publicUpload"] = "true" if public_upload else "false"
        if not data:
            raise ValueError("at least one field must be provided")
        return await self._ocs_request("PUT", f"apps/files_sharing/api/v1/shares/{share_id}", data=data)

    async def delete_share(self, share_id: str) -> Any:
        return await self._ocs_request("DELETE", f"apps/files_sharing/api/v1/shares/{share_id}")

    # ---- account / capabilities (OCS) ------------------------------------
    async def get_account_info(self) -> Any:
        return await self._ocs_request("GET", "cloud/user")

    async def update_account_field(self, field: str, value: str) -> Any:
        allowed = {
            "email",
            "displayname",
            "phone",
            "address",
            "website",
            "twitter",
            "fediverse",
            "organisation",
            "role",
            "headline",
            "biography",
            "language",
            "locale",
            "additional_mail",
        }
        if field not in allowed:
            raise ValueError(f"field must be one of {sorted(allowed)}")
        return await self._ocs_request(
            "PUT", f"cloud/users/{quote(self.username, safe='')}", data={"key": field, "value": value}
        )

    async def get_capabilities(self) -> Any:
        return await self._ocs_request("GET", "cloud/capabilities")

    # ---- generic escape hatches ------------------------------------------
    async def webdav_call(
        self, method: str, path: str, *, headers: dict[str, str] | None = None, content: bytes | None = None
    ) -> dict[str, Any]:
        path = validate_path(path)
        response = await self._dav_request(method, path, headers=headers, content=content)
        content_type = response.headers.get("content-type", "")
        body = response.content
        output: dict[str, Any] = {"status_code": response.status_code, "content_type": content_type}
        if body:
            if "xml" in content_type or content_type.startswith("text/"):
                output["text"] = body.decode("utf-8", errors="replace")
            else:
                output["content_base64"] = base64.b64encode(body).decode()
        return output

    async def ocs_call(
        self, method: str, endpoint: str, *, params: dict[str, Any] | None = None, data: dict[str, Any] | None = None
    ) -> Any:
        return await self._ocs_request(method, endpoint, params=params, data=data)
