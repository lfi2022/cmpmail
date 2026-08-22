import email
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from mcp.server import MCPServer
from mcp_types import ToolAnnotations
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth import current_actor, current_permissions, current_request_meta
from app.config import get_settings
from app.database import SessionLocal
from app.models import AuditLog, OperationLog, SystemSetting
from app.security import CredentialCipher, require_permission
from app.services.accounts import AccountRepository, public_account
from app.services.facebook import FacebookAPIError, FacebookService, redact_facebook_text
from app.services.facebook_token_manager import FacebookTokenManager
from app.services.mail import MailService, failure, partial, plain_forward, result
from app.temp_media import delete_temporary_image, resolve_temporary_image, store_temporary_image

settings = get_settings()
mcp = MCPServer(
    "LFINFO Mail MCP",
    instructions="Production IMAP/SMTP tools protected by OAuth scopes. UIDs are scoped to an account and canonical mailbox. Permanent-delete tools are destructive.",
    version="1.0.0",
)

TOOL_PERMISSIONS = {
    "list_accounts": "accounts.read",
    "get_account": "accounts.read",
    "test_account": "accounts.read",
    "set_default_account": "accounts.write",
    "list_mailboxes": "read",
    "get_mailbox": "read",
    "resolve_mailbox": "read",
    "create_mailbox": "folders",
    "rename_mailbox": "folders",
    "delete_mailbox": "folders",
    "subscribe_mailbox": "folders",
    "unsubscribe_mailbox": "folders",
    "list_emails": "read",
    "search_emails": "read",
    "get_email": "read",
    "get_emails": "read",
    "get_email_headers": "read",
    "get_raw_message": "read",
    "get_thread": "read",
    "get_conversation": "read",
    "mark_read": "flags",
    "mark_unread": "flags",
    "add_flags": "flags",
    "remove_flags": "flags",
    "set_flags": "flags",
    "star_email": "flags",
    "unstar_email": "flags",
    "move_email": "move",
    "move_emails": "move",
    "copy_email": "copy",
    "copy_emails": "copy",
    "archive_email": "move",
    "archive_emails": "move",
    "trash_email": "move",
    "trash_emails": "move",
    "restore_email": "move",
    "restore_emails": "move",
    "delete_email_permanently": "delete",
    "delete_emails_permanently": "delete",
    "create_draft": "send",
    "update_draft": "send",
    "delete_draft": "delete",
    "send_draft": "send",
    "send_email": "send",
    "reply_email": "send",
    "reply_all": "send",
    "forward_email": "send",
    "list_attachments": "attachments",
    "download_attachment": "attachments",
    "save_attachment": "attachments",
    "facebook_list_pages": "facebook.read",
    "facebook_get_page": "facebook.read",
    "facebook_list_posts": "facebook.read",
    "facebook_get_post": "facebook.read",
    "facebook_create_post": "facebook.write",
    "facebook_create_photo_post": "facebook.write",
    "facebook_delete_post": "facebook.write",
    "facebook_get_comments": "facebook.read",
    "facebook_reply_comment": "facebook.write",
    "facebook_hide_comment": "facebook.moderate",
    "facebook_get_insights": "facebook.read",
    "facebook_get_notifications": "facebook.read",
    "facebook_health_check": "facebook.read",
    "upload_temporary_image": "facebook.write",
}

# Convert the legacy capability names into explicit OAuth scopes. Keeping the
# table centralized makes each tool's least-privilege requirement auditable.
_SCOPE_BY_PERMISSION = {
    "read": "mail.read",
    "send": "mail.send",
    "move": "mail.move",
    "copy": "mail.copy",
    "flags": "mail.flags",
    "delete": "mail.delete",
    "folders": "mail.folders",
    "attachments": "mail.attachments",
}
TOOL_PERMISSIONS = {
    name: _SCOPE_BY_PERMISSION.get(permission, permission)
    for name, permission in TOOL_PERMISSIONS.items()
}
SENSITIVE = {
    "send_email",
    "reply_email",
    "reply_all",
    "forward_email",
    "move_email",
    "move_emails",
    "trash_email",
    "trash_emails",
    "delete_email_permanently",
    "delete_emails_permanently",
    "delete_mailbox",
    "set_default_account",
}


@asynccontextmanager
async def service_for(account_name: str | None):
    async with SessionLocal() as db:
        cipher = CredentialCipher(settings.encryption_key)
        repo = AccountRepository(db, cipher)
        account = await repo.get(account_name)
        if not account.enabled:
            raise ValueError(f"Account is disabled: {account.name}")
        yield db, repo, account, MailService(account, cipher, settings)


async def execute(
    tool: str,
    account_name: str | None,
    callback: Callable[
        [AsyncSession, AccountRepository, Any, MailService], Awaitable[dict[str, Any]]
    ],
) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    actor = current_actor.get()
    request_meta = current_request_meta.get()
    success = False
    error = None
    output: dict[str, Any]
    try:
        require_permission(TOOL_PERMISSIONS[tool], current_permissions.get(), settings)
        if tool == "list_accounts":
            async with SessionLocal() as db:
                repo = AccountRepository(db, CredentialCipher(settings.encryption_key))
                output = await callback(db, repo, None, None)
        else:
            async with service_for(account_name) as (db, repo, account, service):
                output = await callback(db, repo, account, service)
                account_name = account.name
        success = bool(output.get("success"))
        error = "; ".join(output.get("errors", [])) or None
    except Exception as exc:
        error = str(getattr(exc, "detail", exc))
        output = failure(error)
    duration = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    try:
        async with SessionLocal() as log_db:
            log_db.add(
                OperationLog(
                    tool=tool,
                    account=account_name,
                    actor=actor,
                    ip=request_meta.get("ip"),
                    user_agent=request_meta.get("user_agent"),
                    mcp_session=request_meta.get("mcp_session"),
                    duration_ms=duration,
                    success=success,
                    error=error,
                )
            )
            if tool in SENSITIVE:
                log_db.add(
                    AuditLog(
                        action=tool,
                        actor=actor,
                        account=account_name,
                        target=None,
                        details={},
                        success=success,
                    )
                )
                audit_event(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    action=tool,
                    actor=actor,
                    account=account_name,
                    success=success,
                )
            await log_db.commit()
    except Exception:
        pass
    return output


async def _resolve_facebook_user_token() -> str | None:
    """Resolve a Facebook user token (prefer long-lived from DB)."""
    token_mgr = FacebookTokenManager()
    long_lived_token, expiry = await token_mgr.get_long_lived_token()
    if long_lived_token and expiry and expiry > datetime.now(timezone.utc):
        return long_lived_token

    # Deployment-only fallback. The frontend exchange endpoint persists only
    # the long-lived replacement and takes precedence above.
    configured = (settings.facebook_user_access_token or "").strip()
    if configured:
        return configured
    return None


async def _resolve_page_token_from_post_id(
    post_id: str, user_token: str | None = None
) -> tuple[str | None, str | None]:
    """
    Extract page_id from post_id format (PAGE_ID_POST_ID) and resolve the page access token.
    Returns (page_access_token, page_id).
    """
    parts = str(post_id).split("_")
    if len(parts) < 2:
        return None, None
    
    page_id_candidate = parts[0]
    user_token_to_use = user_token or await _resolve_facebook_user_token()
    
    if not user_token_to_use:
        return None, page_id_candidate
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"https://graph.facebook.com/{settings.facebook_graph_api_version}/me/accounts",
            params={
                "access_token": user_token_to_use,
                "fields": "id,name,access_token",
            },
        )
        if response.is_error:
            return None, page_id_candidate
        payload = response.json()
        pages = payload.get("data", []) if isinstance(payload, dict) else []
        
        for page in pages:
            if str(page.get("id") or "") == str(page_id_candidate):
                token = str(page.get("access_token") or "").strip()
                if token:
                    return token, page_id_candidate
    
    return None, page_id_candidate


async def _resolve_facebook_token(
    *,
    page_id: str | None = None,
    access_token: str | None = None,
) -> tuple[str | None, str | None]:
    if access_token:
        return access_token, page_id or settings.facebook_default_page_id

    user_candidate = await _resolve_facebook_user_token()
    if user_candidate:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"https://graph.facebook.com/{settings.facebook_graph_api_version}/me/accounts",
                params={
                    "access_token": user_candidate,
                    "fields": "id,name,access_token",
                },
            )
            if response.is_error:
                if page_id or settings.facebook_default_page_id:
                    raise FacebookAPIError("Unable to resolve a Page access token from /me/accounts")
                return user_candidate, None
            payload = response.json()
            pages = payload.get("data", []) if isinstance(payload, dict) else []
            if isinstance(pages, list) and pages:
                if page_id:
                    for page in pages:
                        if str(page.get("id") or "") == str(page_id):
                            token = str(page.get("access_token") or "").strip()
                            if token:
                                return token, page_id
                default_page_id = str(settings.facebook_default_page_id or "").strip()
                if default_page_id:
                    for page in pages:
                        if str(page.get("id") or "") == default_page_id:
                            token = str(page.get("access_token") or "").strip()
                            if token:
                                return token, default_page_id
                first_page = pages[0]
                token = str(first_page.get("access_token") or "").strip()
                page_key = str(first_page.get("id") or "").strip()
                if token:
                    return token, page_key or page_id or settings.facebook_default_page_id
        if page_id or settings.facebook_default_page_id:
            raise FacebookAPIError("No Page access token is available for the requested page")
        return user_candidate, None

    return settings.facebook_page_access_token, page_id or settings.facebook_default_page_id


async def _facebook_action(
    tool: str,
    *,
    access_token: str | None = None,
    page_id: str | None = None,
    callback: Callable[[FacebookService], Awaitable[Any]],
) -> dict[str, Any]:
    try:
        require_permission(TOOL_PERMISSIONS[tool], current_permissions.get(), settings)
        resolved_access_token, resolved_page_id = await _resolve_facebook_token(
            page_id=page_id,
            access_token=access_token,
        )
        service = FacebookService(settings, resolved_access_token)
        output = await callback(service, resolved_page_id)
        return result(output)
    except Exception as exc:
        return failure(redact_facebook_text(getattr(exc, "detail", exc)))


@mcp.tool()
async def facebook_list_pages(access_token: str | None = None) -> dict[str, Any]:
    """List the Facebook Pages available to the configured user token. Permission: facebook.read."""

    async def action(service: FacebookService, page_id: str | None):
        user_token = access_token or await _resolve_facebook_user_token() or service.access_token
        return await service.list_pages(access_token=user_token)

    return await _facebook_action("facebook_list_pages", access_token=access_token, callback=action)


@mcp.tool()
async def facebook_get_page(page_id: str | None = None, access_token: str | None = None) -> dict[str, Any]:
    """Get a single Facebook Page by ID or the configured default page. Permission: facebook.read."""

    async def action(service: FacebookService, resolved_page_id: str | None):
        target = page_id or resolved_page_id
        if not target:
            raise ValueError("A Facebook page_id is required or set FACEBOOK_DEFAULT_PAGE_ID")
        return await service.get_page(target, access_token=access_token)

    return await _facebook_action("facebook_get_page", access_token=access_token, page_id=page_id, callback=action)


@mcp.tool()
async def facebook_list_posts(
    page_id: str | None = None,
    limit: int = 25,
    since: str | None = None,
    until: str | None = None,
    access_token: str | None = None,
) -> dict[str, Any]:
    """List recent posts for a Facebook Page. Permission: facebook.read."""

    async def action(service: FacebookService, resolved_page_id: str | None):
        target = page_id or resolved_page_id
        if not target:
            raise ValueError("A Facebook page_id is required or set FACEBOOK_DEFAULT_PAGE_ID")
        return await service.list_posts(target, limit=limit, since=since, until=until, access_token=access_token)

    return await _facebook_action("facebook_list_posts", access_token=access_token, page_id=page_id, callback=action)


@mcp.tool()
async def facebook_get_post(post_id: str, access_token: str | None = None) -> dict[str, Any]:
    """Get one Facebook Page post including metadata and comments summary. Permission: facebook.read."""

    async def action(service: FacebookService, page_id: str | None):
        if access_token:
            return await service.get_post(post_id, access_token=access_token)
        
        user_token = await _resolve_facebook_user_token()
        resolved_token, resolved_page_id = await _resolve_page_token_from_post_id(post_id, user_token)
        
        if not resolved_token:
            return await service.get_post(post_id, access_token=None)
        
        return await service.get_post(post_id, access_token=resolved_token)

    return await _facebook_action("facebook_get_post", access_token=access_token, callback=action)


@mcp.tool()
async def facebook_create_post(
    page_id: str | None = None,
    message: str | None = None,
    link: str | None = None,
    published: bool = True,
    scheduled_publish_time: str | None = None,
    access_token: str | None = None,
) -> dict[str, Any]:
    """Create a text or link post on a Facebook Page. Permission: facebook.write."""

    async def action(service: FacebookService, resolved_page_id: str | None):
        target = page_id or resolved_page_id
        if not target:
            raise ValueError("A Facebook page_id is required or set FACEBOOK_DEFAULT_PAGE_ID")
        return await service.create_post(
            target,
            message=message,
            link=link,
            published=published,
            scheduled_publish_time=scheduled_publish_time,
            access_token=access_token,
        )

    return await _facebook_action("facebook_create_post", access_token=access_token, page_id=page_id, callback=action)


@mcp.tool()
async def upload_temporary_image(
    image_base64: str,
    filename: str | None = None,
    mime_type: str | None = None,
) -> dict[str, Any]:
    """Upload a ChatGPT image for Facebook. Call this first, then pass data.file_id as temporary_file_id to facebook_create_photo_post. Permission: facebook.write."""
    try:
        require_permission(TOOL_PERMISSIONS["upload_temporary_image"], current_permissions.get(), settings)
        return result(store_temporary_image(settings, image_base64, filename, mime_type))
    except Exception as exc:
        return failure(redact_facebook_text(getattr(exc, "detail", exc)))


@mcp.tool()
async def facebook_create_photo_post(
    page_id: str | None = None,
    message: str | None = None,
    image_url: str | None = None,
    image_base64: str | None = None,
    image_filename: str = "facebook-post.jpg",
    image_mime_type: str | None = None,
    temporary_file_id: str | None = None,
    published: bool = True,
    access_token: str | None = None,
) -> dict[str, Any]:
    """Create a Facebook photo post. Use temporary_file_id from upload_temporary_image, or pass image_base64 directly for automatic temporary upload. Permission: facebook.write."""
    provided_images = sum(bool(value) for value in (image_url, image_base64, temporary_file_id))
    if provided_images != 1:
        return failure("Provide exactly one of image_url, image_base64, or temporary_file_id")

    async def action(service: FacebookService, resolved_page_id: str | None):
        target = page_id or resolved_page_id
        if not target:
            raise ValueError("A Facebook page_id is required or set FACEBOOK_DEFAULT_PAGE_ID")
        photo_url = image_url
        temporary_id = temporary_file_id
        if image_base64:
            stored = store_temporary_image(settings, image_base64, image_filename, image_mime_type)
            temporary_id = stored["file_id"]
            photo_url = stored["url"]
        elif temporary_id:
            path, _ = resolve_temporary_image(settings, temporary_id)
            photo_url = f"{settings.public_url.rstrip('/')}/temp-media/{temporary_id}/{path.name}"
        try:
            return await service.create_photo_post(
                target,
                message=message,
                image_url=photo_url,
                image_base64=None,
                image_filename=image_filename,
                image_mime_type=image_mime_type,
                published=published,
                access_token=access_token,
            )
        finally:
            if temporary_id:
                delete_temporary_image(settings, temporary_id)

    return await _facebook_action("facebook_create_photo_post", access_token=access_token, page_id=page_id, callback=action)


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True))
async def facebook_delete_post(post_id: str, access_token: str | None = None) -> dict[str, Any]:
    """Delete a Facebook Page post. Permission: facebook.write."""

    async def action(service: FacebookService, page_id: str | None):
        if access_token:
            return await service.delete_post(post_id, access_token=access_token)
        
        user_token = await _resolve_facebook_user_token()
        resolved_token, resolved_page_id = await _resolve_page_token_from_post_id(post_id, user_token)
        
        if not resolved_token:
            return await service.delete_post(post_id, access_token=None)
        
        return await service.delete_post(post_id, access_token=resolved_token)

    return await _facebook_action("facebook_delete_post", access_token=access_token, callback=action)


@mcp.tool()
async def facebook_get_comments(
    object_id: str,
    limit: int = 25,
    access_token: str | None = None,
) -> dict[str, Any]:
    """List comments for a Facebook post or comment thread. Permission: facebook.read."""

    async def action(service: FacebookService, page_id: str | None):
        return await service.get_comments(object_id, limit=limit, access_token=access_token)

    return await _facebook_action("facebook_get_comments", access_token=access_token, callback=action)


@mcp.tool()
async def facebook_reply_comment(
    comment_id: str,
    message: str,
    access_token: str | None = None,
) -> dict[str, Any]:
    """Reply to a Facebook comment. Permission: facebook.write."""

    async def action(service: FacebookService, page_id: str | None):
        return await service.reply_comment(comment_id, message=message, access_token=access_token)

    return await _facebook_action("facebook_reply_comment", access_token=access_token, callback=action)


@mcp.tool()
async def facebook_hide_comment(
    comment_id: str,
    hidden: bool = True,
    access_token: str | None = None,
) -> dict[str, Any]:
    """Hide or unhide a Facebook comment. Permission: facebook.moderate."""

    async def action(service: FacebookService, page_id: str | None):
        return await service.hide_comment(comment_id, hidden=hidden, access_token=access_token)

    return await _facebook_action("facebook_hide_comment", access_token=access_token, callback=action)


@mcp.tool()
async def facebook_get_insights(
    page_id: str | None = None,
    metric: str | list[str] | None = None,
    period: str = "day",
    since: str | None = None,
    until: str | None = None,
    access_token: str | None = None,
) -> dict[str, Any]:
    """Fetch Facebook Page insights for the configured or provided page. Permission: facebook.read."""

    async def action(service: FacebookService, resolved_page_id: str | None):
        target = page_id or resolved_page_id
        if not target:
            raise ValueError("A Facebook page_id is required or set FACEBOOK_DEFAULT_PAGE_ID")
        return await service.get_insights(target, metric=metric, period=period, since=since, until=until, access_token=access_token)

    return await _facebook_action("facebook_get_insights", access_token=access_token, page_id=page_id, callback=action)


@mcp.tool()
async def facebook_get_notifications(
    page_id: str | None = None,
    unread_only: bool = False,
    limit: int = 25,
    access_token: str | None = None,
) -> dict[str, Any]:
    """List Facebook notifications. Permission: facebook.read."""

    async def action(service: FacebookService, resolved_page_id: str | None):
        target = page_id or resolved_page_id
        return await service.get_notifications(page_id=target, unread_only=unread_only, limit=limit, access_token=access_token)

    return await _facebook_action("facebook_get_notifications", access_token=access_token, page_id=page_id, callback=action)


@mcp.tool()
async def facebook_health_check(page_id: str | None = None) -> dict[str, Any]:
    """Check Facebook configuration and read access without creating or changing content. Permission: facebook.read."""
    try:
        require_permission("facebook.read", current_permissions.get(), settings)
        user_token = await _resolve_facebook_user_token()
        configured_page_id = page_id or settings.facebook_default_page_id
        health: dict[str, Any] = {
            "configured": bool(settings.facebook_app_id and settings.facebook_app_secret),
            "user_token_configured": bool(user_token),
            "default_page_id": configured_page_id,
            "read": False,
            "write_permissions_detected": False,
            "warnings": [],
        }
        if not user_token:
            health["warnings"].append("No Facebook user token is configured")
            return result(health)

        service = FacebookService(settings, user_token)
        pages = await service.list_pages(access_token=user_token)
        available_pages = pages.get("data", [])
        selected_page = next(
            (item for item in available_pages if str(item.get("id")) == str(configured_page_id)),
            None,
        )
        if not selected_page:
            health["warnings"].append("Configured page is not accessible to the current user token")
            return result(health)

        health["default_page_name"] = selected_page.get("name")
        page_token, resolved_page_id = await _resolve_facebook_token(page_id=str(selected_page["id"]))
        if not page_token or not resolved_page_id:
            health["warnings"].append("No Page access token could be resolved")
            return result(health)

        await FacebookService(settings, page_token).get_page(resolved_page_id)
        health["read"] = True
        health["warnings"].append(
            "Write permission is confirmed only when Meta accepts a write operation"
        )
        return result(health)
    except Exception as exc:
        return failure(redact_facebook_text(getattr(exc, "detail", exc)))


@mcp.tool()
async def list_accounts() -> dict[str, Any]:
    """List configured mail accounts without credentials. Permission: read."""

    async def action(db, repo, account, service):
        return result([public_account(a) for a in await repo.list()])

    return await execute("list_accounts", None, action)


@mcp.tool()
async def get_account(account_name: str | None = None) -> dict[str, Any]:
    """Get one account (default when omitted), never secrets. Permission: read."""

    async def action(db, repo, account, service):
        return result(public_account(account))

    return await execute("get_account", account_name, action)


@mcp.tool()
async def test_account(account_name: str | None = None) -> dict[str, Any]:
    """Test IMAP authentication and LIST. Permission: read."""

    async def action(db, repo, account, service):
        return await service.test()

    return await execute("test_account", account_name, action)


@mcp.tool()
async def set_default_account(account_name: str) -> dict[str, Any]:
    """Set the default account. Sensitive; permission: admin."""

    async def action(db, repo, account, service):
        return result(public_account(await repo.set_default(account.name)))

    return await execute("set_default_account", account_name, action)


@mcp.tool()
async def list_mailboxes(account_name: str | None = None) -> dict[str, Any]:
    """List canonical IMAP mailboxes, real delimiters, flags and RFC 6154 special-use. Permission: read."""

    async def action(db, repo, account, service):
        return await service.list_mailboxes()

    return await execute("list_mailboxes", account_name, action)


@mcp.tool()
async def resolve_mailbox(
    mailbox: str, account_name: str | None = None
) -> dict[str, Any]:
    """Resolve an unambiguous friendly mailbox to its canonical IMAP name. Permission: read."""

    async def action(db, repo, account, service):
        return result(
            {"input": mailbox, "canonical_name": await service.resolve_mailbox(mailbox)}
        )

    return await execute("resolve_mailbox", account_name, action)


@mcp.tool()
async def get_mailbox(mailbox: str, account_name: str | None = None) -> dict[str, Any]:
    """Get mailbox metadata using canonical resolution. Permission: read."""

    async def action(db, repo, account, service):
        canonical = await service.resolve_mailbox(mailbox)
        return result(
            next(
                m
                for m in (await service.list_mailboxes())["data"]
                if m["canonical_name"] == canonical
            )
        )

    return await execute("get_mailbox", account_name, action)


async def _folder(
    tool: str,
    account_name: str | None,
    mailbox: str,
    action_name: str,
    target: str | None = None,
):
    async def action(db, repo, account, service):
        return await service.folder_action(action_name, mailbox, target)

    return await execute(tool, account_name, action)


@mcp.tool()
async def create_mailbox(
    mailbox: str, account_name: str | None = None
) -> dict[str, Any]:
    """Create a mailbox. Mutating; permission: folders."""
    return await _folder("create_mailbox", account_name, mailbox, "create_folder")


@mcp.tool()
async def rename_mailbox(
    mailbox: str, new_canonical_name: str, account_name: str | None = None
) -> dict[str, Any]:
    """Rename a canonical mailbox. Mutating; permission: folders."""
    return await _folder(
        "rename_mailbox", account_name, mailbox, "rename_folder", new_canonical_name
    )


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False))
async def delete_mailbox(
    mailbox: str, account_name: str | None = None
) -> dict[str, Any]:
    """Permanently delete a mailbox. Destructive; permission: folders."""
    return await _folder("delete_mailbox", account_name, mailbox, "delete_folder")


@mcp.tool()
async def subscribe_mailbox(
    mailbox: str, account_name: str | None = None
) -> dict[str, Any]:
    """Subscribe to an IMAP mailbox. Mutating; permission: folders."""
    return await _folder("subscribe_mailbox", account_name, mailbox, "subscribe_folder")


@mcp.tool()
async def unsubscribe_mailbox(
    mailbox: str, account_name: str | None = None
) -> dict[str, Any]:
    """Unsubscribe from an IMAP mailbox. Mutating; permission: folders."""
    return await _folder(
        "unsubscribe_mailbox", account_name, mailbox, "unsubscribe_folder"
    )


@mcp.tool()
async def list_emails(
    mailbox: str = "INBOX",
    account_name: str | None = None,
    page: int = 1,
    page_size: int = 50,
    since: str | None = None,
    before: str | None = None,
    sender: str | None = None,
    to: str | None = None,
    cc: str | None = None,
    bcc: str | None = None,
    subject: str | None = None,
    body: str | None = None,
    text: str | None = None,
    seen: bool | None = None,
    unseen: bool | None = None,
    flagged: bool | None = None,
    unflagged: bool | None = None,
    answered: bool | None = None,
    unanswered: bool | None = None,
    draft: bool | None = None,
    deleted: bool | None = None,
    has_attachment: bool | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    message_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
    sort: str = "date",
    descending: bool = True,
) -> dict[str, Any]:
    """List/search mail with pagination. SUBJECT is partial, not equality. Permission: read."""

    async def action(db, repo, account, service):
        return await service.list_emails(
            mailbox=mailbox,
            page=page,
            page_size=page_size,
            since=since,
            before=before,
            sender=sender,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            text=text,
            seen=seen,
            unseen=unseen,
            flagged=flagged,
            unflagged=unflagged,
            answered=answered,
            unanswered=unanswered,
            draft=draft,
            deleted=deleted,
            has_attachment=has_attachment,
            min_size=min_size,
            max_size=max_size,
            message_id=message_id,
            in_reply_to=in_reply_to,
            references=references,
            sort=sort,
            descending=descending,
        )

    return await execute("list_emails", account_name, action)


@mcp.tool()
async def search_emails(
    mailbox: str = "INBOX",
    account_name: str | None = None,
    page: int = 1,
    page_size: int = 50,
    since: str | None = None,
    before: str | None = None,
    sender: str | None = None,
    to: str | None = None,
    cc: str | None = None,
    bcc: str | None = None,
    subject: str | None = None,
    body: str | None = None,
    text: str | None = None,
    seen: bool | None = None,
    unseen: bool | None = None,
    flagged: bool | None = None,
    unflagged: bool | None = None,
    answered: bool | None = None,
    unanswered: bool | None = None,
    draft: bool | None = None,
    deleted: bool | None = None,
    has_attachment: bool | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    message_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
    sort: str = "date",
    descending: bool = True,
) -> dict[str, Any]:
    """Search email using combinable IMAP criteria. Permission: read."""

    async def action(db, repo, account, service):
        return await service.list_emails(
            mailbox=mailbox,
            page=page,
            page_size=page_size,
            since=since,
            before=before,
            sender=sender,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            text=text,
            seen=seen,
            unseen=unseen,
            flagged=flagged,
            unflagged=unflagged,
            answered=answered,
            unanswered=unanswered,
            draft=draft,
            deleted=deleted,
            has_attachment=has_attachment,
            min_size=min_size,
            max_size=max_size,
            message_id=message_id,
            in_reply_to=in_reply_to,
            references=references,
            sort=sort,
            descending=descending,
        )

    return await execute("search_emails", account_name, action)


@mcp.tool()
async def get_email(
    mailbox: str,
    uid: int,
    account_name: str | None = None,
    offset: int = 0,
    limit: int = 1_000_000,
) -> dict[str, Any]:
    """Read a message by account+mailbox+UID with body slicing. Permission: read."""

    async def action(db, repo, account, service):
        return await service.get_email(mailbox, uid, offset, limit)

    return await execute("get_email", account_name, action)


@mcp.tool()
async def get_emails(
    mailbox: str,
    uids: list[int],
    account_name: str | None = None,
    offset: int = 0,
    limit: int = 1_000_000,
) -> dict[str, Any]:
    """Read multiple messages; reports partial failures. Permission: read."""

    async def action(db, repo, account, service):
        values, errors = [], []
        for uid in uids:
            try:
                values.append(
                    (await service.get_email(mailbox, uid, offset, limit))["data"]
                )
            except Exception as exc:
                errors.append(f"UID {uid}: {exc}")
        return (
            partial(values, len(values), len(errors), errors)
            if errors
            else result(values)
        )

    return await execute("get_emails", account_name, action)


@mcp.tool()
async def get_email_headers(
    mailbox: str, uid: int, account_name: str | None = None
) -> dict[str, Any]:
    """Get parsed message headers without bodies. Permission: read."""

    async def action(db, repo, account, service):
        value = (await service.get_email(mailbox, uid, 0, 0))["data"]
        value.pop("text", None)
        value.pop("html", None)
        value.pop("attachments", None)
        return result(value)

    return await execute("get_email_headers", account_name, action)


@mcp.tool()
async def get_raw_message(
    mailbox: str, uid: int, account_name: str | None = None
) -> dict[str, Any]:
    """Get controlled base64 RFC822 source, subject to configured maximum. Permission: read."""

    async def action(db, repo, account, service):
        return await service.get_raw_message(mailbox, uid)

    return await execute("get_raw_message", account_name, action)


async def _conversation(tool: str, mailbox: str, uid: int, account_name: str | None):
    async def action(db, repo, account, service):
        root = (await service.get_email(mailbox, uid))["data"]
        ids = set(
            root["references"]
            + [x for x in [root["message_id"], root["in_reply_to"]] if x]
        )
        candidates = (await service.list_emails(mailbox, 1, 500))["data"]
        matches = []
        for item in candidates:
            if (
                item["message_id"] in ids
                or item["in_reply_to"] in ids
                or ids.intersection(item["references"])
            ):
                matches.append((await service.get_email(mailbox, item["uid"]))["data"])
        if root["uid"] not in [m["uid"] for m in matches]:
            matches.append(root)
        matches.sort(key=lambda m: m.get("date") or "")
        return result(matches)

    return await execute(tool, account_name, action)


@mcp.tool()
async def get_thread(
    mailbox: str, uid: int, account_name: str | None = None
) -> dict[str, Any]:
    """Build a thread using Message-ID/In-Reply-To/References, never subject alone. Permission: read."""
    return await _conversation("get_thread", mailbox, uid, account_name)


@mcp.tool()
async def get_conversation(
    mailbox: str, uid: int, account_name: str | None = None
) -> dict[str, Any]:
    """Alias for reference-based thread retrieval. Permission: read."""
    return await _conversation("get_conversation", mailbox, uid, account_name)


async def _flags(
    tool: str,
    mailbox: str,
    uids: list[int],
    mode: str,
    flags: list[str],
    account_name: str | None,
):
    async def action(db, repo, account, service):
        return await service.change_flags(mailbox, uids, mode, flags)

    return await execute(tool, account_name, action)


@mcp.tool()
async def mark_read(mailbox: str, uid: int, account_name: str | None = None):
    return await _flags(
        "mark_read", mailbox, [uid], "add_flags", ["\\Seen"], account_name
    )


@mcp.tool()
async def mark_unread(mailbox: str, uid: int, account_name: str | None = None):
    return await _flags(
        "mark_unread", mailbox, [uid], "remove_flags", ["\\Seen"], account_name
    )


@mcp.tool()
async def star_email(mailbox: str, uid: int, account_name: str | None = None):
    return await _flags(
        "star_email", mailbox, [uid], "add_flags", ["\\Flagged"], account_name
    )


@mcp.tool()
async def unstar_email(mailbox: str, uid: int, account_name: str | None = None):
    return await _flags(
        "unstar_email", mailbox, [uid], "remove_flags", ["\\Flagged"], account_name
    )


@mcp.tool()
async def add_flags(
    mailbox: str, uids: list[int], flags: list[str], account_name: str | None = None
):
    return await _flags("add_flags", mailbox, uids, "add_flags", flags, account_name)


@mcp.tool()
async def remove_flags(
    mailbox: str, uids: list[int], flags: list[str], account_name: str | None = None
):
    return await _flags(
        "remove_flags", mailbox, uids, "remove_flags", flags, account_name
    )


@mcp.tool()
async def set_flags(
    mailbox: str, uids: list[int], flags: list[str], account_name: str | None = None
):
    return await _flags("set_flags", mailbox, uids, "set_flags", flags, account_name)


async def _transfer(
    tool: str,
    mailbox: str,
    target: str,
    uids: list[int],
    move: bool,
    account_name: str | None,
):
    async def action(db, repo, account, service):
        return await service.move_or_copy(mailbox, target, uids, move)

    return await execute(tool, account_name, action)


@mcp.tool()
async def move_email(
    mailbox: str, target_mailbox: str, uid: int, account_name: str | None = None
):
    return await _transfer(
        "move_email", mailbox, target_mailbox, [uid], True, account_name
    )


@mcp.tool()
async def move_emails(
    mailbox: str, target_mailbox: str, uids: list[int], account_name: str | None = None
):
    return await _transfer(
        "move_emails", mailbox, target_mailbox, uids, True, account_name
    )


@mcp.tool()
async def copy_email(
    mailbox: str, target_mailbox: str, uid: int, account_name: str | None = None
):
    return await _transfer(
        "copy_email", mailbox, target_mailbox, [uid], False, account_name
    )


@mcp.tool()
async def copy_emails(
    mailbox: str, target_mailbox: str, uids: list[int], account_name: str | None = None
):
    return await _transfer(
        "copy_emails", mailbox, target_mailbox, uids, False, account_name
    )


async def _special(
    tool: str, mailbox: str, uids: list[int], kind: str, account_name: str | None
):
    async def action(db, repo, account, service):
        configured = getattr(account, f"{kind}_mailbox")
        if not configured:
            folders = (await service.list_mailboxes())["data"]
            configured = next(
                (m["canonical_name"] for m in folders if m["special_use"] == kind), None
            )
        if not configured:
            return failure(f"{kind.title()} mailbox is not configured or advertised")
        return await service.move_or_copy(mailbox, configured, uids, True)

    return await execute(tool, account_name, action)


@mcp.tool()
async def archive_email(mailbox: str, uid: int, account_name: str | None = None):
    return await _special("archive_email", mailbox, [uid], "archive", account_name)


@mcp.tool()
async def archive_emails(
    mailbox: str, uids: list[int], account_name: str | None = None
):
    return await _special("archive_emails", mailbox, uids, "archive", account_name)


@mcp.tool()
async def trash_email(mailbox: str, uid: int, account_name: str | None = None):
    return await _special("trash_email", mailbox, [uid], "trash", account_name)


@mcp.tool()
async def trash_emails(mailbox: str, uids: list[int], account_name: str | None = None):
    return await _special("trash_emails", mailbox, uids, "trash", account_name)


@mcp.tool()
async def restore_email(
    uid: int, target_mailbox: str = "INBOX", account_name: str | None = None
):
    async def action(db, repo, account, service):
        trash = account.trash_mailbox or next(
            (
                m["canonical_name"]
                for m in (await service.list_mailboxes())["data"]
                if m["special_use"] == "trash"
            ),
            None,
        )
        if not trash:
            return failure("Trash mailbox is not configured or advertised")
        return await service.move_or_copy(trash, target_mailbox, [uid], True)

    return await execute("restore_email", account_name, action)


@mcp.tool()
async def restore_emails(
    uids: list[int], target_mailbox: str = "INBOX", account_name: str | None = None
):
    async def action(db, repo, account, service):
        trash = account.trash_mailbox or next(
            (
                m["canonical_name"]
                for m in (await service.list_mailboxes())["data"]
                if m["special_use"] == "trash"
            ),
            None,
        )
        if not trash:
            return failure("Trash mailbox is not configured or advertised")
        return await service.move_or_copy(trash, target_mailbox, uids, True)

    return await execute("restore_emails", account_name, action)


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True))
async def delete_email_permanently(
    mailbox: str, uid: int, account_name: str | None = None
):
    """EXPUNGE a message permanently. DESTRUCTIVE; permission: delete."""

    async def action(db, repo, account, service):
        return await service.permanent_delete(mailbox, [uid])

    return await execute("delete_email_permanently", account_name, action)


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True))
async def delete_emails_permanently(
    mailbox: str, uids: list[int], account_name: str | None = None
):
    """EXPUNGE messages permanently. DESTRUCTIVE; permission: delete."""

    async def action(db, repo, account, service):
        return await service.permanent_delete(mailbox, uids)

    return await execute("delete_emails_permanently", account_name, action)


@mcp.tool()
async def send_email(
    to: list[str],
    subject: str,
    account_name: str | None = None,
    text: str | None = None,
    html: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to: str | None = None,
    attachments: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
):
    """Send SMTP mail and APPEND the exact same Message-ID to Sent. Permission: send."""

    async def action(db, repo, account, service):
        return await service.send_email(
            to, subject, text, html, cc, bcc, reply_to, attachments, headers
        )

    return await execute("send_email", account_name, action)


async def _reply(
    tool: str,
    mailbox: str,
    uid: int,
    body: str,
    reply_all_mode: bool,
    account_name: str | None,
):
    async def action(db, repo, account, service):
        original = (await service.get_email(mailbox, uid))["data"]
        raw = (await service.get_raw_message(mailbox, uid))["data"]["raw"]
        parent = email.message_from_bytes(__import__("base64").b64decode(raw))
        from app.services.mail import build_reply_headers, reply_all_recipients

        in_reply_to, references = build_reply_headers(parent)
        if reply_all_mode:
            to, cc = reply_all_recipients(parent, account.email)
        else:
            to, cc = (
                [
                    email.utils.parseaddr(parent.get("Reply-To") or parent.get("From"))[
                        1
                    ]
                ],
                [],
            )
        subject = (
            original["subject"]
            if original["subject"].lower().startswith("re:")
            else f"Re: {original['subject']}"
        )
        return await service.send_email(
            to,
            subject,
            body,
            None,
            cc,
            None,
            None,
            None,
            {"In-Reply-To": in_reply_to or "", "References": references},
        )

    return await execute(tool, account_name, action)


@mcp.tool()
async def reply_email(
    mailbox: str, uid: int, text: str, account_name: str | None = None
):
    return await _reply("reply_email", mailbox, uid, text, False, account_name)


@mcp.tool()
async def reply_all(mailbox: str, uid: int, text: str, account_name: str | None = None):
    return await _reply("reply_all", mailbox, uid, text, True, account_name)


@mcp.tool()
async def forward_email(
    mailbox: str,
    uid: int,
    to: list[str],
    account_name: str | None = None,
    text: str = "",
    include_attachments: bool = False,
):
    async def action(db, repo, account, service):
        original = (await service.get_email(mailbox, uid))["data"]
        subject = (
            original["subject"]
            if original["subject"].lower().startswith("fwd:")
            else f"Fwd: {original['subject']}"
        )
        attachments = []
        if include_attachments:
            for attachment in original["attachments"]:
                downloaded = await service.download_attachment(
                    mailbox, uid, attachment["index"]
                )
                if not downloaded["success"]:
                    return downloaded
                item = downloaded["data"]
                attachments.append(
                    {
                        "filename": item["filename"],
                        "content_type": item["content_type"],
                        "content_base64": item["content"],
                    }
                )
        return await service.send_email(
            to, subject, plain_forward(original, text), attachments=attachments
        )

    return await execute("forward_email", account_name, action)


@mcp.tool()
async def create_draft(
    to: list[str],
    subject: str,
    account_name: str | None = None,
    text: str = "",
    html: str | None = None,
):
    async def action(db, repo, account, service):
        return await service.create_draft(to, subject, text, html)

    return await execute("create_draft", account_name, action)


@mcp.tool()
async def update_draft(
    mailbox: str,
    uid: int,
    to: list[str],
    subject: str,
    account_name: str | None = None,
    text: str = "",
    html: str | None = None,
):
    async def action(db, repo, account, service):
        created = await service.create_draft(to, subject, text, html)
        if created["success"]:
            await service.permanent_delete(mailbox, [uid])
        return created

    return await execute("update_draft", account_name, action)


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True))
async def delete_draft(mailbox: str, uid: int, account_name: str | None = None):
    async def action(db, repo, account, service):
        return await service.permanent_delete(mailbox, [uid])

    return await execute("delete_draft", account_name, action)


@mcp.tool()
async def send_draft(mailbox: str, uid: int, account_name: str | None = None):
    async def action(db, repo, account, service):
        draft = (await service.get_email(mailbox, uid))["data"]
        sent = await service.send_email(
            draft["recipients"],
            draft["subject"],
            draft["text"],
            draft["html"],
            draft["cc"],
            draft["bcc"],
            draft["reply_to"],
        )
        if sent["success"]:
            await service.permanent_delete(mailbox, [uid])
        return sent

    return await execute("send_draft", account_name, action)


@mcp.tool()
async def list_attachments(mailbox: str, uid: int, account_name: str | None = None):
    async def action(db, repo, account, service):
        return await service.list_attachments(mailbox, uid)

    return await execute("list_attachments", account_name, action)


@mcp.tool()
async def download_attachment(
    mailbox: str, uid: int, index: int, account_name: str | None = None
):
    async def action(db, repo, account, service):
        return await service.download_attachment(mailbox, uid, index)

    return await execute("download_attachment", account_name, action)


@mcp.tool()
async def save_attachment(
    mailbox: str, uid: int, index: int, account_name: str | None = None
):
    """Save into ATTACHMENT_SAVE_DIR with a sanitized filename. Arbitrary paths are forbidden. Permission: attachments."""

    async def action(db, repo, account, service):
        return await service.save_attachment(mailbox, uid, index)

    return await execute("save_attachment", account_name, action)
