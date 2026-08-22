from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import mimetypes
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.config import Settings
from app.temp_media import normalize_image_base64

PAGE_FIELDS = (
    "id",
    "name",
    "username",
    "about",
    "description",
    "category",
    "category_list",
    "link",
    "website",
    "phone",
    "emails",
    "fan_count",
    "followers_count",
    "picture{url}",
    "cover",
    "verification_status",
)
PAGE_LIST_FIELDS = (
    "id",
    "name",
    "category",
    "category_list",
    "access_token",
    "instagram_business_account",
    "link",
    "picture{url}",
    "fan_count",
)
POST_FIELDS = (
    "id",
    "message",
    "story",
    "created_time",
    "updated_time",
    "permalink_url",
    "is_published",
    "status_type",
    "attachments{media_type,media,subattachments}",
)
COMMENT_FIELDS = (
    "id",
    "message",
    "created_time",
    "from{id,name,picture}",
    "like_count",
    "comment_count",
    "attachment",
    "can_hide",
    "is_hidden",
)
NOTIFICATION_FIELDS = (
    "id",
    "created_time",
    "updated_time",
    "title",
    "link",
    "unread",
    "application{id,name}",
    "from{id,name}",
    "object{id,application}",
)
_SECRET_FIELDS = {
    "access_token",
    "app_secret",
    "client_secret",
    "authorization",
    "refresh_token",
}
_PAGE_ID_PATTERN = re.compile(r"^\d+$")
_OBJECT_ID_PATTERN = re.compile(r"^\d+(?:_\d+)?$")
_SUPPORTED_IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
_MAX_PHOTO_BYTES = 10 * 1024 * 1024
logger = logging.getLogger(__name__)


def redact_facebook_data(value: Any) -> Any:
    """Remove credential-bearing fields and tokenized pagination URLs."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in _SECRET_FIELDS:
                continue
            if key == "next" and isinstance(item, str) and "access_token=" in item:
                continue
            redacted[key] = redact_facebook_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_facebook_data(item) for item in value]
    return value


def redact_facebook_text(value: object) -> str:
    """Redact credential-like fragments that may appear in upstream errors."""
    text = str(value)
    text = re.sub(r"(?i)(access_token|client_secret|app_secret)=([^&\s]+)", r"\1=[REDACTED]", text)
    return re.sub(r"\bEAA[A-Za-z0-9_-]+", "[REDACTED]", text)


def validate_facebook_id(value: str, *, page: bool = False) -> str:
    """Validate Graph object IDs without ever coercing them to a number."""
    identifier = str(value or "").strip()
    pattern = _PAGE_ID_PATTERN if page else _OBJECT_ID_PATTERN
    if not pattern.fullmatch(identifier):
        raise ValueError("Facebook IDs must be numeric strings or PAGE_ID_OBJECT_ID")
    return identifier


def validate_image_url(value: str) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("image_url must be an absolute HTTP(S) URL")
    return url


class FacebookAPIError(RuntimeError):
    def __init__(self, message: str, *, metadata: dict[str, Any] | None = None):
        super().__init__(message)
        self.metadata = metadata or {}


class FacebookService:
    def __init__(self, settings: Settings, access_token: str | None = None):
        self.settings = settings
        self.access_token = access_token or settings.facebook_page_access_token

    @property
    def api_base(self) -> str:
        version = (self.settings.facebook_graph_api_version or "v19.0").strip("/")
        return f"https://graph.facebook.com/{version}"

    def _token(self, access_token: str | None = None) -> str:
        token = access_token or self.access_token or self.settings.facebook_page_access_token
        if not token:
            raise ValueError("Facebook page access token is not configured")
        return token

    def _fields(self, fields: list[str] | str | None) -> str | None:
        if fields is None:
            return None
        if isinstance(fields, str):
            return fields
        return ",".join(fields)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        access_token: str | None = None,
        debug_endpoint: str | None = None,
    ) -> dict[str, Any]:
        token = self._token(access_token)
        request_params = dict(params or {})
        request_params["access_token"] = token
        for key in ("fields", "metric"):
            if key in request_params and isinstance(request_params[key], (list, tuple)):
                request_params[key] = ",".join(str(v) for v in request_params[key])
        
        url = f"{self.api_base}/{path.lstrip('/')}"
        endpoint_log = debug_endpoint or path or "unknown"
        upload_method = "source" if files else "url" if data and "url" in data else None
        
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
                for attempt in range(2):
                    response = await client.request(
                        method=method.upper(),
                        url=url,
                        params=request_params,
                        json=json_body,
                        data=data,
                        files=files,
                    )
                    if response.status_code not in {429, 500, 502, 503, 504} or attempt:
                        break
                    await asyncio.sleep(0.25)
        except httpx.RequestError as exc:
            logger.warning("Facebook network error endpoint=%s upload_method=%s error=%s", endpoint_log, upload_method, exc.__class__.__name__)
            raise FacebookAPIError(
                f"Facebook API request failed on {endpoint_log}: {exc.__class__.__name__}",
                metadata={"upload_method": upload_method} if upload_method else None,
            ) from exc
        try:
            payload = response.json()
        except ValueError:
            payload = {"error": {"message": response.text}}
        if response.is_error:
            error = payload.get("error") if isinstance(payload, dict) else None
            error_detail = {}
            message = ""
            if isinstance(error, dict):
                message = error.get("message") or error.get("type") or "Facebook Graph API error"
                error_detail = {
                    "code": error.get("code"),
                    "type": error.get("type"),
                    "subcode": error.get("error_subcode"),
                    "trace_id": error.get("fbtrace_id"),
                }
            else:
                message = str(payload)
            metadata = {
                "facebook_error": {
                    "message": message,
                    "type": error_detail.get("type"),
                    "code": error_detail.get("code"),
                    "error_subcode": error_detail.get("subcode"),
                    "fbtrace_id": error_detail.get("trace_id"),
                },
                "upload_method": upload_method,
            }
            logger.warning(
                "Facebook API error endpoint=%s upload_method=%s http_status=%s graph_code=%s fbtrace_id=%s",
                endpoint_log,
                upload_method,
                response.status_code,
                error_detail.get("code"),
                error_detail.get("trace_id"),
            )
            error_msg = f"Facebook API error on {endpoint_log}: {message}"
            if error_detail.get("code"):
                error_msg += f" (code: {error_detail['code']}"
                if error_detail.get("subcode"):
                    error_msg += f", subcode: {error_detail['subcode']}"
                if error_detail.get("trace_id"):
                    error_msg += f", trace_id: {error_detail['trace_id']}"
                error_msg += ")"
            raise FacebookAPIError(error_msg, metadata=metadata)
        if not isinstance(payload, dict):
            return {"value": redact_facebook_data(payload)}
        return redact_facebook_data(payload)

    async def list_pages(self, access_token: str | None = None) -> dict[str, Any]:
        return await self._request(
            "GET",
            "me/accounts",
            params={
                "fields": PAGE_LIST_FIELDS
            },
            access_token=access_token,
        )

    async def get_page(self, page_id: str, access_token: str | None = None) -> dict[str, Any]:
        target = validate_facebook_id(page_id, page=True)
        try:
            return await self._request(
                "GET", target, params={"fields": PAGE_FIELDS}, access_token=access_token
            )
        except FacebookAPIError as exc:
            if "nonexisting field" not in str(exc).lower():
                raise
            # Meta rejects a complete fields request when one optional field is
            # unavailable for an app/token combination. Preserve core reading.
            return await self._request(
                "GET",
                target,
                params={"fields": ("id", "name", "category", "link", "picture{url}")},
                access_token=access_token,
            )

    async def list_posts(
        self,
        page_id: str,
        *,
        limit: int = 25,
        since: str | None = None,
        until: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        target = validate_facebook_id(page_id, page=True)
        params: dict[str, Any] = {
            "fields": POST_FIELDS,
            "limit": max(1, min(limit, 100)),
        }
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        return await self._request("GET", f"{target}/posts", params=params, access_token=access_token)

    async def get_post(self, post_id: str, access_token: str | None = None) -> dict[str, Any]:
        return await self._request(
            "GET",
            validate_facebook_id(post_id),
            params={
                "fields": [
                    *POST_FIELDS,
                    "from{id,name}",
                    "comments.summary(true)",
                    "reactions.summary(true)",
                ]
            },
            access_token=access_token,
        )

    async def create_post(
        self,
        page_id: str,
        *,
        message: str | None = None,
        link: str | None = None,
        published: bool = True,
        scheduled_publish_time: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        target = validate_facebook_id(page_id, page=True)
        if not message and not link:
            raise ValueError("message or link is required")
        if scheduled_publish_time and published:
            raise ValueError("scheduled_publish_time requires published=false")
        body: dict[str, Any] = {"published": str(published).lower()}
        if message is not None:
            body["message"] = message
        if link is not None:
            body["link"] = link
        if scheduled_publish_time is not None:
            body["scheduled_publish_time"] = scheduled_publish_time
        return await self._request("POST", f"{target}/feed", json_body=body, access_token=access_token)

    async def create_photo_post(
        self,
        page_id: str,
        *,
        message: str | None = None,
        image_url: str | None = None,
        image_base64: str | None = None,
        image_file_path: Path | None = None,
        image_filename: str = "facebook-post.jpg",
        image_mime_type: str | None = None,
        published: bool = True,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        if sum(bool(value) for value in (image_url, image_base64, image_file_path)) != 1:
            raise ValueError("Provide exactly one of image_url, image_base64, or image_file_path")
        target = validate_facebook_id(page_id, page=True)
        if image_base64 or image_file_path:
            filename = image_filename
            if image_base64:
                encoded, declared_mime = normalize_image_base64(image_base64)
                if declared_mime:
                    if image_mime_type and image_mime_type.lower() != declared_mime:
                        raise ValueError("image MIME type does not match the data URI")
                    image_mime_type = declared_mime
                try:
                    binary = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise ValueError("image_base64 is not valid base64") from exc
            else:
                if not image_file_path.is_file():
                    raise ValueError("temporary image file was not found")
                binary = image_file_path.read_bytes()
                filename = image_file_path.name
            if not binary:
                raise ValueError("image file is empty")
            if len(binary) > _MAX_PHOTO_BYTES:
                raise ValueError("image exceeds the 10 MiB upload limit")
            mime = image_mime_type or mimetypes.guess_type(filename)[0] or "image/jpeg"
            if mime not in _SUPPORTED_IMAGE_MIME_TYPES:
                raise ValueError("Supported image MIME types are JPEG, PNG, and WEBP")
            files = {"source": (filename, binary, mime)}
            form_data: dict[str, Any] = {}
            if message:
                form_data["message"] = message
            form_data["published"] = "true" if published else "false"
            return await self._request(
                "POST",
                f"{target}/photos",
                data=form_data,
                files=files,
                access_token=access_token,
                debug_endpoint=f"{target}/photos (source upload)",
            )
        else:
            public_url = validate_image_url(image_url)
            form_data = {"url": public_url, "published": "true" if published else "false"}
            if message:
                form_data["message"] = message
            return await self._request(
                "POST",
                f"{target}/photos",
                data=form_data,
                access_token=access_token,
                debug_endpoint=f"{target}/photos (url)",
            )

    async def delete_post(self, post_id: str, access_token: str | None = None) -> dict[str, Any]:
        target = validate_facebook_id(post_id)
        response = await self._request("DELETE", target, access_token=access_token)
        return {"deleted": bool(response.get("success")), "post_id": target}

    async def get_comments(
        self,
        object_id: str,
        *,
        limit: int = 25,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"{validate_facebook_id(object_id)}/comments",
            params={
                "fields": COMMENT_FIELDS,
                "limit": max(1, min(limit, 100)),
                "order": "chronological",
            },
            access_token=access_token,
        )

    async def reply_comment(
        self,
        comment_id: str,
        *,
        message: str,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"{validate_facebook_id(comment_id)}/comments",
            json_body={"message": message},
            access_token=access_token,
        )

    async def hide_comment(
        self,
        comment_id: str,
        *,
        hidden: bool = True,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            validate_facebook_id(comment_id),
            json_body={"is_hidden": bool(hidden)},
            access_token=access_token,
        )

    async def get_insights(
        self,
        page_id: str,
        *,
        metric: str | list[str] | None = None,
        period: str = "day",
        since: str | None = None,
        until: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        target = validate_facebook_id(page_id, page=True)
        if metric is None:
            raise ValueError("metric is required; Meta insight availability depends on the Page and API version")
        params: dict[str, Any] = {
            "period": period,
            "metric": metric,
        }
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        return await self._request("GET", f"{target}/insights", params=params, access_token=access_token)

    async def get_notifications(
        self,
        *,
        page_id: str | None = None,
        unread_only: bool = False,
        limit: int = 25,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        endpoint = f"{validate_facebook_id(page_id, page=True)}/notifications" if page_id else "me/notifications"
        params: dict[str, Any] = {
            "fields": NOTIFICATION_FIELDS,
            "limit": max(1, min(limit, 100)),
        }
        if unread_only:
            params["unread"] = "true"
        return await self._request("GET", endpoint, params=params, access_token=access_token)
