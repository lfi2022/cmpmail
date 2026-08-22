from __future__ import annotations

import base64
import mimetypes
from typing import Any

import httpx

from app.config import Settings


class FacebookAPIError(RuntimeError):
    pass


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
    ) -> dict[str, Any]:
        token = self._token(access_token)
        request_params = dict(params or {})
        request_params["access_token"] = token
        for key in ("fields", "metric"):
            if key in request_params and isinstance(request_params[key], (list, tuple)):
                request_params[key] = ",".join(str(v) for v in request_params[key])
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=method.upper(),
                url=f"{self.api_base}/{path.lstrip('/')}",
                params=request_params,
                json=json_body,
                data=data,
                files=files,
            )
        try:
            payload = response.json()
        except ValueError:
            payload = {"error": {"message": response.text}}
        if response.is_error:
            error = payload.get("error") if isinstance(payload, dict) else None
            message = ""
            if isinstance(error, dict):
                message = error.get("message") or error.get("type") or "Facebook Graph API error"
            else:
                message = str(payload)
            raise FacebookAPIError(message)
        if not isinstance(payload, dict):
            return {"value": payload}
        return payload

    async def list_pages(self, access_token: str | None = None) -> dict[str, Any]:
        return await self._request(
            "GET",
            "me/accounts",
            params={
                "fields": [
                    "id",
                    "name",
                    "category",
                    "category_list",
                    "access_token",
                    "instagram_business_account",
                    "link",
                    "picture{url}",
                    "fan_count",
                ]
            },
            access_token=access_token,
        )

    async def get_page(self, page_id: str, access_token: str | None = None) -> dict[str, Any]:
        return await self._request(
            "GET",
            str(page_id),
            params={
                "fields": [
                    "id",
                    "name",
                    "username",
                    "about",
                    "category",
                    "link",
                    "picture{url}",
                    "fan_count",
                    "followers_count",
                    "created_time",
                ]
            },
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
        params: dict[str, Any] = {
            "fields": [
                "id",
                "message",
                "story",
                "created_time",
                "updated_time",
                "permalink_url",
                "is_published",
                "status_type",
                "attachments{media_type,media,subattachments}",
            ],
            "limit": max(1, min(limit, 100)),
        }
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        return await self._request("GET", f"{page_id}/posts", params=params, access_token=access_token)

    async def get_post(self, post_id: str, access_token: str | None = None) -> dict[str, Any]:
        return await self._request(
            "GET",
            str(post_id),
            params={
                "fields": [
                    "id",
                    "message",
                    "story",
                    "created_time",
                    "updated_time",
                    "permalink_url",
                    "is_published",
                    "status_type",
                    "attachments{media_type,media,subattachments}",
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
        body: dict[str, Any] = {"published": str(published).lower()}
        if message is not None:
            body["message"] = message
        if link is not None:
            body["link"] = link
        if scheduled_publish_time is not None:
            body["scheduled_publish_time"] = scheduled_publish_time
        return await self._request("POST", f"{page_id}/feed", json_body=body, access_token=access_token)

    async def create_photo_post(
        self,
        page_id: str,
        *,
        message: str | None = None,
        image_url: str | None = None,
        image_base64: str | None = None,
        image_filename: str = "facebook-post.jpg",
        image_mime_type: str | None = None,
        published: bool = True,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        form_data: dict[str, Any] = {"published": str(published).lower()}
        if message:
            form_data["message"] = message
        if image_url:
            form_data["url"] = image_url
        if image_base64:
            binary = base64.b64decode(image_base64)
            mime = image_mime_type or mimetypes.guess_type(image_filename)[0] or "image/jpeg"
            files = {"source": (image_filename, binary, mime)}
            form_data.update({k: v for k, v in form_data.items() if v is not None})
            return await self._request(
                "POST",
                f"{page_id}/photos",
                data=form_data,
                files=files,
                access_token=access_token,
            )
        if image_url:
            return await self._request("POST", f"{page_id}/photos", data=form_data, access_token=access_token)
        raise ValueError("Either image_url or image_base64 must be provided")

    async def delete_post(self, post_id: str, access_token: str | None = None) -> dict[str, Any]:
        return await self._request("DELETE", str(post_id), access_token=access_token)

    async def get_comments(
        self,
        object_id: str,
        *,
        limit: int = 25,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"{object_id}/comments",
            params={
                "fields": [
                    "id",
                    "message",
                    "created_time",
                    "from{id,name,picture}",
                    "like_count",
                    "comment_count",
                    "attachment",
                    "can_hide",
                    "is_hidden",
                ],
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
            f"{comment_id}/comments",
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
            str(comment_id),
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
        params: dict[str, Any] = {
            "period": period,
            "metric": metric or [
                "page_impressions",
                "page_engaged_users",
                "post_engagements",
                "page_posts_impressions",
            ],
        }
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        return await self._request("GET", f"{page_id}/insights", params=params, access_token=access_token)

    async def get_notifications(
        self,
        *,
        page_id: str | None = None,
        unread_only: bool = False,
        limit: int = 25,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        endpoint = f"{page_id}/notifications" if page_id else "me/notifications"
        params: dict[str, Any] = {
            "fields": [
                "id",
                "created_time",
                "updated_time",
                "title",
                "link",
                "unread",
                "application{id,name}",
                "from{id,name}",
                "object{id,application}",
            ],
            "limit": max(1, min(limit, 100)),
        }
        if unread_only:
            params["unread"] = "true"
        return await self._request("GET", endpoint, params=params, access_token=access_token)
