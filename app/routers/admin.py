import asyncio
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.audit import audit_event
from app.auth import create_admin_session, require_admin
from app.config import Settings, get_settings
from app.database import check_database, get_db
from app.models import (
    ApiKey,
    AuditLog,
    MailAccount,
    OperationLog,
    OAuthClient,
    OAuthRefreshToken,
    OAuthSession,
    OAuthUser,
    SystemSetting,
)
from app.schemas import AccountCreate, AccountUpdate, ApiKeyCreate, LoginRequest
from app.security import (
    CredentialCipher,
    PERMISSIONS,
    create_api_key,
    verify_secret,
)
from app.services.accounts import AccountRepository, public_account
from app.services.mail import MailService

router = APIRouter(prefix="/api")
started_at = datetime.now(timezone.utc)


async def record_admin_audit(
    db: AsyncSession, action: str, target: str, details: dict | None = None
) -> None:
    db.add(
        AuditLog(
            action=action,
            actor="admin",
            target=target,
            details=details or {},
            success=True,
        )
    )
    await db.commit()
    audit_event(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action=action,
        actor="admin",
        target=target,
        success=True,
        details=details,
    )


def repository(
    db: AsyncSession = Depends(get_db), settings: Settings = Depends(get_settings)
) -> AccountRepository:
    try:
        cipher = CredentialCipher(settings.encryption_key)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return AccountRepository(db, cipher)


@router.post("/auth/login")
async def login(
    payload: LoginRequest,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(OAuthUser).where(OAuthUser.username == payload.username)
    )
    valid = bool(
        user and user.active and verify_secret(user.password_hash, payload.password)
    )
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    response.set_cookie(
        "mailmcp_session",
        create_admin_session(payload.username, settings),
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=8 * 3600,
        path="/",
    )
    csrf = create_admin_session("csrf", settings)
    response.set_cookie(
        "mailmcp_csrf",
        csrf,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=8 * 3600,
        path="/",
    )
    return {"success": True, "csrf_token": csrf}


@router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("mailmcp_session", path="/")
    response.delete_cookie("mailmcp_csrf", path="/")
    return {"success": True}


@router.get("/dashboard", dependencies=[Depends(require_admin)])
async def dashboard(
    db: AsyncSession = Depends(get_db), settings: Settings = Depends(get_settings)
):
    accounts = await db.scalar(select(func.count()).select_from(MailAccount))
    operations = await db.scalar(select(func.count()).select_from(OperationLog))
    default = await db.scalar(
        select(MailAccount.name).where(MailAccount.is_default.is_(True))
    )
    errors = list(
        (
            await db.scalars(
                select(OperationLog.error)
                .where(OperationLog.success.is_(False))
                .order_by(OperationLog.timestamp.desc())
                .limit(5)
            )
        ).all()
    )
    return {
        "status": "ok",
        "uptime_seconds": int(
            (datetime.now(timezone.utc) - started_at).total_seconds()
        ),
        "version": __version__,
        "accounts": accounts,
        "default_account": default,
        "recent_operations": operations,
        "last_errors": errors,
        "database": await check_database(),
        "mcp_url": settings.mcp_url,
        "read_only": settings.read_only,
    }


@router.get("/accounts", dependencies=[Depends(require_admin)])
async def list_accounts(repo: AccountRepository = Depends(repository)):
    return [public_account(account) for account in await repo.list()]


@router.post("/accounts", status_code=201, dependencies=[Depends(require_admin)])
async def create_account(
    payload: AccountCreate, repo: AccountRepository = Depends(repository)
):
    try:
        account = await repo.create(payload)
        await record_admin_audit(repo.db, "account.create", account.name)
        return public_account(account)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.patch("/accounts/{name}", dependencies=[Depends(require_admin)])
async def update_account(
    name: str, payload: AccountUpdate, repo: AccountRepository = Depends(repository)
):
    try:
        account = await repo.update(name, payload)
        await record_admin_audit(repo.db, "account.update", name)
        return public_account(account)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.delete(
    "/accounts/{name}", status_code=204, dependencies=[Depends(require_admin)]
)
async def delete_account(name: str, repo: AccountRepository = Depends(repository)):
    try:
        await repo.delete(name)
        await record_admin_audit(repo.db, "account.delete", name)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/accounts/{name}/default", dependencies=[Depends(require_admin)])
async def set_default(name: str, repo: AccountRepository = Depends(repository)):
    return public_account(await repo.set_default(name))


@router.post("/accounts/{name}/test", dependencies=[Depends(require_admin)])
async def test_account(
    name: str,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    account = await repo.get(name)
    return await MailService(account, repo.cipher, settings).test()


@router.post("/accounts/{name}/test-imap", dependencies=[Depends(require_admin)])
async def test_account_imap(
    name: str,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    account = await repo.get(name)
    return await MailService(account, repo.cipher, settings).test_imap()


@router.post("/accounts/{name}/test-smtp", dependencies=[Depends(require_admin)])
async def test_account_smtp(
    name: str,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    account = await repo.get(name)
    return await MailService(account, repo.cipher, settings).test_smtp()


@router.post("/accounts/{name}/detect-folders", dependencies=[Depends(require_admin)])
async def detect_folders(
    name: str,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    account = await repo.get(name)
    folders = (await MailService(account, repo.cipher, settings).list_mailboxes())[
        "data"
    ]
    values = {
        f"{item['special_use']}_mailbox": item["canonical_name"]
        for item in folders
        if item["special_use"]
    }
    await repo.update(name, AccountUpdate(**values))
    return {"success": True, "detected": values, "mailboxes": folders}


@router.get("/accounts/{name}/mailboxes", dependencies=[Depends(require_admin)])
async def account_mailboxes(
    name: str,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    return await MailService(
        await repo.get(name), repo.cipher, settings
    ).list_mailboxes()


@router.get("/accounts/{name}/messages", dependencies=[Depends(require_admin)])
async def account_messages(
    name: str,
    mailbox: str = "INBOX",
    page: int = 1,
    page_size: int = 50,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    return await MailService(await repo.get(name), repo.cipher, settings).list_emails(
        mailbox, page, page_size
    )


@router.get("/api-keys", dependencies=[Depends(require_admin)])
async def list_keys(db: AsyncSession = Depends(get_db)):
    keys = (await db.scalars(select(ApiKey).order_by(ApiKey.created_at.desc()))).all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "permissions": k.permissions,
            "enabled": k.enabled,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
        }
        for k in keys
    ]


@router.post("/api-keys", status_code=201, dependencies=[Depends(require_admin)])
async def add_key(payload: ApiKeyCreate, db: AsyncSession = Depends(get_db)):
    invalid = set(payload.permissions) - PERMISSIONS
    if invalid:
        raise HTTPException(422, f"Unknown permissions: {sorted(invalid)}")
    raw, prefix, hashed = create_api_key()
    key = ApiKey(
        name=payload.name,
        prefix=prefix,
        key_hash=hashed,
        permissions=payload.permissions,
    )
    db.add(key)
    await db.commit()
    await record_admin_audit(
        db, "api_key.create", key.name, {"permissions": key.permissions}
    )
    return {
        "id": key.id,
        "name": key.name,
        "key": raw,
        "permissions": key.permissions,
        "warning": "This key is shown only once.",
    }


@router.delete(
    "/api-keys/{key_id}", status_code=204, dependencies=[Depends(require_admin)]
)
async def remove_key(key_id: int, db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(404, "API key not found")
    name = key.name
    await db.delete(key)
    await db.commit()
    await record_admin_audit(db, "api_key.delete", name)


@router.get("/logs", dependencies=[Depends(require_admin)])
async def logs(
    limit: int = 100,
    tool: str | None = None,
    account: str | None = None,
    success: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(OperationLog)
        .order_by(OperationLog.timestamp.desc())
        .limit(min(limit, 500))
    )
    if tool:
        query = query.where(OperationLog.tool == tool)
    if account:
        query = query.where(OperationLog.account == account)
    if success is not None:
        query = query.where(OperationLog.success == success)
    rows = (await db.scalars(query)).all()
    return [
        {
            column.name: getattr(row, column.name)
            for column in OperationLog.__table__.columns
        }
        for row in rows
    ]


@router.get("/audit", dependencies=[Depends(require_admin)])
async def audit(limit: int = 100, db: AsyncSession = Depends(get_db)):
    rows = (
        await db.scalars(
            select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(min(limit, 500))
        )
    ).all()
    return [
        {
            column.name: getattr(row, column.name)
            for column in AuditLog.__table__.columns
        }
        for row in rows
    ]


async def tcp_check(host: str, port: int, tls: bool) -> dict:
    started = asyncio.get_running_loop().time()
    try:
        context = ssl.create_default_context() if tls else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=context, server_hostname=host if tls else None
            ),
            timeout=10,
        )
        cert = writer.get_extra_info("peercert")
        writer.close()
        await writer.wait_closed()
        return {
            "status": "ok",
            "duration_ms": int((asyncio.get_running_loop().time() - started) * 1000),
            "certificate": cert.get("notAfter") if cert else None,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@router.post("/diagnostics", dependencies=[Depends(require_admin)])
async def diagnostics(
    account_name: str | None = None,
    repo: AccountRepository = Depends(repository),
    settings: Settings = Depends(get_settings),
):
    checks = {
        "database": {"status": "ok" if await check_database() else "error"},
        "configuration": {
            "status": "ok" if not settings.production_errors() else "warning",
            "details": settings.production_errors(),
        },
        "filesystem": {"status": "ok" if Path("data").exists() else "warning"},
        "mcp": {"status": "ok", "url": settings.mcp_url},
    }
    try:
        account = await repo.get(account_name)
        checks["dns_imap"] = {
            "status": "ok",
            "addresses": await asyncio.to_thread(
                socket.gethostbyname_ex, account.imap_host
            ),
        }
        checks["tcp_tls_imap"] = await tcp_check(
            account.imap_host, account.imap_port, account.imap_ssl
        )
        checks["dns_smtp"] = {
            "status": "ok",
            "addresses": await asyncio.to_thread(
                socket.gethostbyname_ex, account.smtp_host
            ),
        }
        checks["tcp_tls_smtp"] = await tcp_check(
            account.smtp_host, account.smtp_port, account.smtp_ssl
        )
        checks["imap_login_list"] = await MailService(
            account, repo.cipher, settings
        ).test()
    except Exception as exc:
        checks["mail_account"] = {"status": "error", "error": str(exc)}
    return {
        "success": all(v.get("status") != "error" for v in checks.values()),
        "checks": checks,
    }


@router.get("/configuration", dependencies=[Depends(require_admin)])
async def configuration(
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
):
    stored = await db.get(SystemSetting, "facebook_accounts")
    accounts = []
    if stored and isinstance(stored.value, dict):
        accounts = stored.value.get("accounts", [])
    return {
        "public_url": settings.public_url,
        "mcp_path": settings.mcp_path,
        "mcp_url": settings.mcp_url,
        "allowed_hosts": settings.allowed_hosts,
        "allowed_origins": settings.allowed_origins,
        "trusted_proxies": settings.trusted_proxies,
        "read_only": settings.read_only,
        "attachment_download_enabled": settings.attachment_download_enabled,
        "max_attachment_size_mb": settings.max_attachment_size_mb,
        "attachment_save_dir": str(settings.attachment_save_dir),
        "blocked_attachment_types": settings.blocked_attachment_types,
        "max_request_size_mb": settings.max_request_size_mb,
        "destructive_operations_enabled": settings.destructive_operations_enabled,
        "facebook": {
            "graph_api_version": settings.facebook_graph_api_version,
            "credentials_managed_in_frontend": True,
            "profiles": accounts,
        },
        "oauth": {
            "enabled": settings.oauth_enabled,
            "issuer": settings.issuer,
            "resource": settings.resource,
            "legacy_api_keys": settings.mcp_legacy_api_key_enabled,
            "signing_kid": settings.oauth_signing_kid,
        },
        "secrets": {
            "secret_key": "configured"
            if settings.secret_key != "A_REMPLIR"
            else "missing",
            "encryption_key": "configured"
            if settings.encryption_key != "A_REMPLIR"
            else "missing",
            "mcp_api_key": "configured"
            if settings.mcp_api_key != "A_REMPLIR"
            else "missing",
        },
    }


@router.get("/facebook/config", dependencies=[Depends(require_admin)])
async def facebook_config(db: AsyncSession = Depends(get_db)):
    stored = await db.get(SystemSetting, "facebook_accounts")
    accounts = []
    if stored and isinstance(stored.value, dict):
        accounts = stored.value.get("accounts", [])
    return {"accounts": accounts}


@router.post("/facebook/config", dependencies=[Depends(require_admin)])
async def save_facebook_config(
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
    accounts = payload.get("accounts") or []
    if not isinstance(accounts, list):
        raise HTTPException(422, "accounts must be a list")
    normalized = []
    for item in accounts:
        if not isinstance(item, dict):
            raise HTTPException(422, "Each account must be an object")
        normalized.append(
            {
                "id": str(item.get("id") or item.get("label") or f"facebook-{len(normalized)}"),
                "label": str(item.get("label") or "Facebook"),
                "app_id": str(item.get("app_id") or ""),
                "app_secret": str(item.get("app_secret") or ""),
                "user_access_token": str(item.get("user_access_token") or ""),
                "page_access_token": str(item.get("page_access_token") or ""),
                "default_page_id": str(item.get("default_page_id") or ""),
                "pages": [
                    {
                        "id": str(page.get("id") or ""),
                        "name": str(page.get("name") or ""),
                        "access_token": str(page.get("access_token") or ""),
                        "default": bool(page.get("default")),
                    }
                    for page in (item.get("pages") or [])
                    if isinstance(page, dict)
                ],
            }
        )
    setting = await db.get(SystemSetting, "facebook_accounts")
    if setting is None:
        setting = SystemSetting(key="facebook_accounts", value={"accounts": normalized})
    else:
        setting.value = {"accounts": normalized}
    db.add(setting)
    await db.commit()
    await record_admin_audit(db, "facebook.config.saved", "facebook_accounts", {"count": len(normalized)})
    return {"success": True, "accounts": normalized}


@router.get("/oauth/clients", dependencies=[Depends(require_admin)])
async def oauth_clients(db: AsyncSession = Depends(get_db)):
    rows = (
        await db.scalars(select(OAuthClient).order_by(OAuthClient.created_at.desc()))
    ).all()
    return [
        {
            "client_id": x.client_id,
            "client_name": x.client_name,
            "redirect_uris": x.redirect_uris,
            "allowed_scopes": x.allowed_scopes,
            "token_endpoint_auth_method": x.token_endpoint_auth_method,
            "created_at": x.created_at,
            "last_used_at": x.last_used_at,
            "revoked_at": x.revoked_at,
        }
        for x in rows
    ]


@router.delete("/oauth/clients/{client_id}", dependencies=[Depends(require_admin)])
async def revoke_oauth_client(client_id: str, db: AsyncSession = Depends(get_db)):
    client = await db.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "OAuth client not found")
    client.revoked_at = datetime.now(timezone.utc)
    sessions = (
        await db.scalars(
            select(OAuthSession).where(
                OAuthSession.client_id == client_id, OAuthSession.revoked_at.is_(None)
            )
        )
    ).all()
    for session in sessions:
        session.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    await record_admin_audit(
        db, "oauth.client.revoked", client_id, {"sessions": len(sessions)}
    )
    return {"success": True, "revoked_sessions": len(sessions)}


@router.get("/oauth/sessions", dependencies=[Depends(require_admin)])
async def oauth_sessions(db: AsyncSession = Depends(get_db)):
    rows = (
        await db.scalars(
            select(OAuthSession).order_by(OAuthSession.last_used_at.desc()).limit(500)
        )
    ).all()
    users = {u.id: u.username for u in (await db.scalars(select(OAuthUser))).all()}
    return [
        {
            "id": x.id,
            "client_id": x.client_id,
            "user": users.get(x.user_id),
            "scopes": x.scopes,
            "resource": x.resource,
            "ip": x.ip,
            "user_agent": x.user_agent,
            "created_at": x.created_at,
            "last_used_at": x.last_used_at,
            "expires_at": x.expires_at,
            "revoked_at": x.revoked_at,
        }
        for x in rows
    ]


@router.delete("/oauth/sessions/{session_id}", dependencies=[Depends(require_admin)])
async def revoke_oauth_session(session_id: str, db: AsyncSession = Depends(get_db)):
    session = await db.get(OAuthSession, session_id)
    if not session:
        raise HTTPException(404, "OAuth session not found")
    session.revoked_at = datetime.now(timezone.utc)
    tokens = (
        await db.scalars(
            select(OAuthRefreshToken).where(OAuthRefreshToken.session_id == session_id)
        )
    ).all()
    for token in tokens:
        token.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    await record_admin_audit(db, "oauth.session.revoked", session_id)
    return {"success": True}
