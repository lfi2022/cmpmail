"""OAuth 2.1 / OpenID Connect authorization server for MCP clients."""

import base64
import hashlib
import html
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth import limiter
from app.config import Settings, get_settings
from app.database import get_db
from app.models import (
    AuditLog,
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthRefreshToken,
    OAuthRevokedToken,
    OAuthSession,
    OAuthUser,
)
from app.security import hash_secret, verify_secret

router = APIRouter()

SCOPES = {
    "openid": "Authenticate the user",
    "profile": "Read the user profile",
    "email": "Read the user email address",
    "offline_access": "Keep access using a rotating refresh token",
    "accounts.read": "List and inspect configured mail accounts",
    "accounts.write": "Change the default account",
    "mail.read": "Read folders, message metadata and message content",
    "mail.send": "Create drafts and send, reply to or forward mail",
    "mail.move": "Move, archive, trash and restore mail",
    "mail.copy": "Copy mail",
    "mail.flags": "Change read, starred and IMAP flags",
    "mail.delete": "Permanently delete messages and drafts",
    "mail.folders": "Create, rename, subscribe and delete folders",
    "mail.attachments": "List and download attachments",
    "facebook.read": "Read Facebook Page data, posts, comments, notifications and insights",
    "facebook.write": "Create or delete Facebook posts and replies",
    "facebook.moderate": "Hide or moderate Facebook comments and content",
    "dolibarr.read": "Read Dolibarr objects (thirdparties, invoices, orders, products, ...)",
    "dolibarr.write": "Create, update and trigger actions on Dolibarr objects",
    "dolibarr.delete": "Permanently delete Dolibarr objects",
    "nextcloud.read": "Read Nextcloud files, folders, shares and account profile",
    "nextcloud.write": "Upload, move, copy and share Nextcloud files and folders, edit profile fields",
    "nextcloud.delete": "Delete Nextcloud files, folders, shares and trash items",
    "telegram.read": "Read Telegram bot status, updates and pending button answers",
    "telegram.write": "Send Telegram messages, reports and inline buttons",
}
DEFAULT_SCOPES = [
    "openid",
    "profile",
    "email",
    "accounts.read",
    "mail.read",
    "facebook.read",
    "dolibarr.read",
    "nextcloud.read",
    "telegram.read",
]


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def oauth_serializer(settings: Settings, salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key, salt=salt)


def _private_key(settings: Settings) -> bytes:
    try:
        return Path(settings.oauth_signing_key_path).read_bytes()
    except OSError as exc:
        raise HTTPException(503, "OAuth signing key is unavailable") from exc


def _public_key(settings: Settings) -> bytes:
    try:
        return Path(settings.oauth_signing_public_key_path).read_bytes()
    except OSError as exc:
        raise HTTPException(503, "OAuth verification key is unavailable") from exc


def jwk(settings: Settings) -> dict:
    public = serialization.load_pem_public_key(_public_key(settings))
    value = json.loads(RSAAlgorithm.to_jwk(public))
    value.update({"kid": settings.oauth_signing_kid, "use": "sig", "alg": "RS256"})
    return value


def issue_jwt(settings: Settings, claims: dict, minutes: int | None = None) -> str:
    issued = now()
    payload = {
        "iss": settings.issuer,
        "iat": issued,
        "exp": issued
        + timedelta(minutes=minutes or settings.oauth_access_token_minutes),
        **claims,
    }
    return jwt.encode(
        payload,
        _private_key(settings),
        algorithm="RS256",
        headers={"kid": settings.oauth_signing_kid, "typ": "JWT"},
    )


async def validate_access_token(
    token: str, settings: Settings, db: AsyncSession
) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        if (
            header.get("alg") != "RS256"
            or header.get("kid") != settings.oauth_signing_kid
        ):
            raise jwt.InvalidTokenError("Unexpected signing key")
        claims = jwt.decode(
            token,
            _public_key(settings),
            algorithms=["RS256"],
            audience=settings.resource,
            issuer=settings.issuer,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub", "jti", "scope", "sid"]
            },
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid or expired access token") from exc
    if await db.get(OAuthRevokedToken, claims["jti"]):
        raise HTTPException(401, "Access token has been revoked")
    session = await db.get(OAuthSession, claims["sid"])
    if not session or session.revoked_at or aware(session.expires_at) <= now():
        raise HTTPException(401, "OAuth session is invalid or expired")
    session.last_used_at = now()
    await db.commit()
    return claims


def _request_ip(request: Request, settings: Settings) -> str:
    peer = request.client.host if request.client else "unknown"
    # Forwarded headers are consumed only for the explicitly trusted reverse proxy.
    if peer in settings.trusted_proxies and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",", 1)[0].strip()
    return peer


async def oauth_audit(
    db: AsyncSession,
    action: str,
    actor: str | None,
    target: str | None,
    success: bool,
    **details,
):
    db.add(
        AuditLog(
            action=action, actor=actor, target=target, details=details, success=success
        )
    )
    await db.commit()
    audit_event(
        timestamp=now().isoformat(),
        action=action,
        actor=actor,
        target=target,
        success=success,
        details=details,
    )


def _validate_redirect_uri(uri: str, settings: Settings) -> None:
    parsed = urlparse(uri)
    if parsed.fragment or parsed.username or parsed.password or not parsed.hostname:
        raise HTTPException(400, "invalid_redirect_uri")
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise HTTPException(
            400, "redirect_uris must use HTTPS (localhost HTTP is allowed)"
        )
    if "*" in uri or len(uri) > 2048:
        raise HTTPException(400, "invalid_redirect_uri")


def _scope_set(value: str) -> set[str]:
    values = {item for item in value.split() if item}
    unknown = values - set(SCOPES)
    if unknown:
        raise HTTPException(400, f"invalid_scope: {', '.join(sorted(unknown))}")
    return values


def _auth_error(
    redirect_uri: str,
    error: str,
    settings: Settings,
    state: str | None = None,
    description: str | None = None,
):
    params = {"error": error, "iss": settings.issuer}
    if state:
        params["state"] = state
    if description:
        params["error_description"] = description
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


def _page(title: str, content: str) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content='width=device-width'><title>{html.escape(title)}</title><style>body{{font:16px system-ui;background:#f4f7fb;color:#152033;margin:0;display:grid;place-items:center;min-height:100vh}}main{{background:white;max-width:580px;width:calc(100% - 48px);padding:32px;border-radius:18px;box-shadow:0 18px 55px #182a4720}}h1{{margin-top:0}}label{{display:block;margin:16px 0 6px}}input{{box-sizing:border-box;width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:8px}}button{{margin-top:20px;background:#3157d5;color:white;border:0;padding:12px 18px;border-radius:8px;font-weight:700}}.scope{{padding:10px 0;border-bottom:1px solid #e5e7eb}}.mutating{{color:#a13b18}}small{{color:#64748b}}.deny{{background:#64748b;margin-left:8px}}</style></head><body><main>{content}</main></body></html>"""
    )


async def bootstrap_oauth_user(settings: Settings, db: AsyncSession) -> None:
    if await db.scalar(select(OAuthUser.id).limit(1)):
        return
    password_hash = settings.admin_password_hash
    if password_hash != "A_REMPLIR":
        db.add(
            OAuthUser(
                username=settings.admin_username,
                email=settings.admin_email,
                password_hash=password_hash,
            )
        )
        await db.commit()


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource(settings: Settings = Depends(get_settings)):
    return {
        "resource": settings.resource,
        "authorization_servers": [settings.issuer],
        "scopes_supported": list(SCOPES),
        "bearer_methods_supported": ["header"],
        "resource_name": "LFINFO Mail MCP",
    }


def authorization_metadata(settings: Settings) -> dict:
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "registration_endpoint": f"{issuer}/oauth/register",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ],
        "scopes_supported": list(SCOPES),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": False,
    }


@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/openid-configuration")
async def discovery(settings: Settings = Depends(get_settings)):
    return authorization_metadata(settings)


@router.get("/.well-known/jwks.json")
async def jwks(settings: Settings = Depends(get_settings)):
    return {"keys": [jwk(settings)]}


@router.post("/oauth/register", status_code=201)
async def register(
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    if not limiter.allow(f"dcr:{_request_ip(request, settings)}", 20):
        raise HTTPException(429, "registration rate limit exceeded")
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(400, "invalid_client_metadata") from exc
    uris = body.get("redirect_uris")
    if (
        not isinstance(uris, list)
        or not uris
        or len(uris) > 10
        or not all(isinstance(x, str) for x in uris)
    ):
        raise HTTPException(400, "redirect_uris is required")
    for uri in uris:
        _validate_redirect_uri(uri, settings)
    grants = body.get("grant_types", ["authorization_code", "refresh_token"])
    responses = body.get("response_types", ["code"])
    method = body.get("token_endpoint_auth_method", "none")
    if (
        set(grants) - {"authorization_code", "refresh_token"}
        or responses != ["code"]
        or method not in {"none", "client_secret_basic", "client_secret_post"}
    ):
        raise HTTPException(400, "unsupported client metadata")
    # RFC 7591 clients such as ChatGPT may omit `scope` at registration and
    # request the concrete scopes only at authorization time. In that case the
    # client is eligible for every scope advertised by this authorization
    # server; the user still sees and approves the exact requested set.
    requested = _scope_set(body.get("scope", " ".join(SCOPES)))
    client_id = secrets.token_urlsafe(32)
    raw_secret = secrets.token_urlsafe(48) if method != "none" else None
    client = OAuthClient(
        client_id=client_id,
        client_secret_hash=hash_secret(raw_secret) if raw_secret else None,
        client_name=str(body.get("client_name", "Dynamic MCP client"))[:200],
        redirect_uris=uris,
        grant_types=grants,
        response_types=responses,
        token_endpoint_auth_method=method,
        allowed_scopes=sorted(requested),
    )
    db.add(client)
    await db.commit()
    await oauth_audit(
        db,
        "oauth.client.register",
        client_id,
        client.client_name,
        True,
        redirect_uris=uris,
        scopes=sorted(requested),
    )
    result = {
        "client_id": client_id,
        "client_id_issued_at": int(now().timestamp()),
        "client_name": client.client_name,
        "redirect_uris": uris,
        "grant_types": grants,
        "response_types": responses,
        "token_endpoint_auth_method": method,
        "scope": " ".join(sorted(requested)),
    }
    if raw_secret:
        result.update({"client_secret": raw_secret, "client_secret_expires_at": 0})
    return result


async def _authorization_request(
    request: Request, db: AsyncSession, settings: Settings
) -> tuple[OAuthClient, dict]:
    q = dict(request.query_params)
    required = (
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "resource",
    )
    if any(not q.get(item) for item in required):
        raise HTTPException(
            400, "invalid_request: required authorization parameter missing"
        )
    client = await db.get(OAuthClient, q["client_id"])
    if not client or client.revoked_at:
        raise HTTPException(400, "invalid_client")
    if q["redirect_uri"] not in client.redirect_uris:
        raise HTTPException(400, "redirect_uri does not exactly match a registered URI")
    if q["response_type"] != "code" or q["code_challenge_method"] != "S256":
        return client, {
            "error": "invalid_request",
            "description": "Authorization Code with PKCE S256 is required",
            **q,
        }
    if q["resource"] != settings.resource:
        return client, {
            "error": "invalid_target",
            "description": "resource does not match this MCP server",
            **q,
        }
    scopes = _scope_set(q.get("scope", " ".join(DEFAULT_SCOPES)))
    if not scopes.issubset(set(client.allowed_scopes)):
        return client, {
            "error": "invalid_scope",
            "description": "scope is not allowed for this client",
            **q,
        }
    q["scope"] = " ".join(sorted(scopes))
    return client, q


@router.get("/oauth/authorize")
async def authorize(
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    client, q = await _authorization_request(request, db, settings)
    if q.get("error"):
        await oauth_audit(
            db,
            "oauth.authorize.rejected",
            None,
            client.client_id,
            False,
            error=q["error"],
            description=q.get("description"),
            requested_scopes=q.get("scope", "").split(),
        )
        return _auth_error(
            q["redirect_uri"],
            q["error"],
            settings,
            q.get("state"),
            q.get("description"),
        )
    signed = oauth_serializer(settings, "oauth-request").dumps(q)
    session_cookie = request.cookies.get("mailmcp_oauth_session")
    user = None
    if session_cookie:
        try:
            data = oauth_serializer(settings, "oauth-user-session").loads(
                session_cookie, max_age=settings.oauth_session_hours * 3600
            )
            user = await db.get(OAuthUser, int(data["uid"]))
        except (BadSignature, SignatureExpired, KeyError, ValueError):
            pass
    csrf = secrets.token_urlsafe(24)
    csrf_signed = oauth_serializer(settings, "oauth-csrf").dumps(csrf)
    if not user or not user.active:
        response = _page(
            "Connexion",
            f"<h1>Connexion sécurisée</h1><p><b>{html.escape(client.client_name)}</b> demande l’accès à votre serveur mail.</p><form method=post action='/oauth/login'><input type=hidden name=request_token value='{html.escape(signed)}'><input type=hidden name=csrf value='{html.escape(csrf_signed)}'><label>Utilisateur</label><input name=username autocomplete=username required><label>Mot de passe</label><input type=password name=password autocomplete=current-password required><button>Se connecter</button></form>",
        )
        response.set_cookie(
            "mailmcp_oauth_csrf",
            csrf_signed,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="lax",
            max_age=600,
            path="/oauth",
        )
        return response
    scope_html = "".join(
        f"<div class='scope{' mutating' if s in {'mail.send', 'mail.move', 'mail.delete', 'mail.folders', 'accounts.write'} else ''}'><b>{html.escape(s)}</b><br><small>{html.escape(SCOPES[s])}</small></div>"
        for s in q["scope"].split()
    )
    response = _page(
        "Autorisation",
        f"<h1>Autoriser {html.escape(client.client_name)} ?</h1><p>Connecté en tant que <b>{html.escape(user.username)}</b>.</p>{scope_html}<form method=post action='/oauth/authorize'><input type=hidden name=request_token value='{html.escape(signed)}'><input type=hidden name=csrf value='{html.escape(csrf_signed)}'><button name=decision value=allow>Autoriser</button><button class=deny name=decision value=deny>Refuser</button></form>",
    )
    response.set_cookie(
        "mailmcp_oauth_csrf",
        csrf_signed,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=600,
        path="/oauth",
    )
    return response


def _load_signed(value: str, settings: Settings, salt: str, age: int = 600) -> dict:
    try:
        return oauth_serializer(settings, salt).loads(value, max_age=age)
    except (BadSignature, SignatureExpired) as exc:
        raise HTTPException(400, "invalid or expired authorization request") from exc


def _verify_csrf(request: Request, value: str, settings: Settings) -> None:
    cookie = request.cookies.get("mailmcp_oauth_csrf", "")
    if not cookie or not secrets.compare_digest(cookie, value):
        raise HTTPException(403, "CSRF token missing or invalid")
    _load_signed(value, settings, "oauth-csrf")


@router.post("/oauth/login")
async def oauth_login(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    request_token: str = Form(),
    csrf: str = Form(),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    _verify_csrf(request, csrf, settings)
    q = _load_signed(request_token, settings, "oauth-request")
    ip = _request_ip(request, settings)
    if not limiter.allow(
        f"oauth-login:{ip}:{username.lower()}", settings.oauth_login_attempts
    ):
        await oauth_audit(db, "oauth.login.rate_limited", username, None, False, ip=ip)
        raise HTTPException(429, "Too many login attempts")
    user = await db.scalar(select(OAuthUser).where(OAuthUser.username == username))
    locked = user and user.locked_until and aware(user.locked_until) > now()
    if (
        not user
        or not user.active
        or locked
        or not verify_secret(user.password_hash, password)
    ):
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.oauth_login_attempts:
                user.locked_until = now() + timedelta(
                    minutes=settings.oauth_login_lock_minutes
                )
            await db.commit()
        await oauth_audit(db, "oauth.login.failed", username, None, False, ip=ip)
        raise HTTPException(401, "Invalid credentials")
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now()
    await db.commit()
    await oauth_audit(db, "oauth.login.success", user.username, None, True, ip=ip)
    response = RedirectResponse(f"/oauth/authorize?{urlencode(q)}", status_code=303)
    response.set_cookie(
        "mailmcp_oauth_session",
        oauth_serializer(settings, "oauth-user-session").dumps({"uid": user.id}),
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=settings.oauth_session_hours * 3600,
        path="/oauth",
    )
    return response


@router.post("/oauth/authorize")
async def authorize_decision(
    request: Request,
    request_token: str = Form(),
    csrf: str = Form(),
    decision: str = Form(),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    _verify_csrf(request, csrf, settings)
    q = _load_signed(request_token, settings, "oauth-request")
    try:
        session_data = oauth_serializer(settings, "oauth-user-session").loads(
            request.cookies.get("mailmcp_oauth_session", ""),
            max_age=settings.oauth_session_hours * 3600,
        )
        user = await db.get(OAuthUser, int(session_data["uid"]))
    except (BadSignature, SignatureExpired, KeyError, ValueError) as exc:
        raise HTTPException(401, "Authentication required") from exc
    if not user or not user.active:
        raise HTTPException(401, "Authentication required")
    if decision != "allow":
        await oauth_audit(
            db,
            "oauth.consent.denied",
            user.username,
            q["client_id"],
            False,
            scopes=q["scope"].split(),
        )
        return _auth_error(q["redirect_uri"], "access_denied", settings, q.get("state"))
    raw_code = secrets.token_urlsafe(48)
    db.add(
        OAuthAuthorizationCode(
            code_hash=digest(raw_code),
            client_id=q["client_id"],
            user_id=user.id,
            redirect_uri=q["redirect_uri"],
            scopes=q["scope"].split(),
            code_challenge=q["code_challenge"],
            resource=q["resource"],
            nonce=q.get("nonce"),
            expires_at=now()
            + timedelta(minutes=settings.oauth_authorization_code_minutes),
        )
    )
    await db.commit()
    await oauth_audit(
        db,
        "oauth.consent.granted",
        user.username,
        q["client_id"],
        True,
        scopes=q["scope"].split(),
    )
    params = {"code": raw_code, "iss": settings.issuer}
    if q.get("state"):
        params["state"] = q["state"]
    return RedirectResponse(f"{q['redirect_uri']}?{urlencode(params)}", status_code=303)


async def _client_auth(request: Request, form, db: AsyncSession) -> OAuthClient:
    client_id = form.get("client_id")
    secret = form.get("client_secret")
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(authorization.split(None, 1)[1]).decode()
            client_id, secret = decoded.split(":", 1)
        except Exception as exc:
            raise HTTPException(401, "invalid_client") from exc
    client = await db.get(OAuthClient, client_id or "")
    if not client or client.revoked_at:
        raise HTTPException(401, "invalid_client")
    if client.token_endpoint_auth_method != "none" and not (
        secret
        and client.client_secret_hash
        and verify_secret(client.client_secret_hash, secret)
    ):
        raise HTTPException(401, "invalid_client")
    return client


def _token_response(
    settings: Settings,
    client: OAuthClient,
    user: OAuthUser,
    session: OAuthSession,
    refresh_raw: str | None,
    nonce: str | None = None,
) -> dict:
    jti = secrets.token_urlsafe(24)
    scope = " ".join(session.scopes)
    access = issue_jwt(
        settings,
        {
            "sub": str(user.id),
            "aud": session.resource,
            "jti": jti,
            "sid": session.id,
            "client_id": client.client_id,
            "scope": scope,
        },
    )
    result = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.oauth_access_token_minutes * 60,
        "scope": scope,
    }
    if refresh_raw:
        result["refresh_token"] = refresh_raw
    if "openid" in session.scopes:
        identity_claims = {}
        if "profile" in session.scopes:
            identity_claims["preferred_username"] = user.username
        if "email" in session.scopes:
            identity_claims.update({"email": user.email, "email_verified": True})
        result["id_token"] = issue_jwt(
            settings,
            {
                "sub": str(user.id),
                "aud": client.client_id,
                "jti": secrets.token_urlsafe(24),
                "sid": session.id,
                **identity_claims,
                **({"nonce": nonce} if nonce else {}),
            },
        )
    return result


def _oauth_json_error(error: str, description: str, status: int = 400):
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.post("/oauth/token")
async def token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    form = await request.form()
    try:
        client = await _client_auth(request, form, db)
    except HTTPException:
        return _oauth_json_error("invalid_client", "Client authentication failed", 401)
    grant = form.get("grant_type")
    if grant == "authorization_code":
        code = await db.scalar(
            select(OAuthAuthorizationCode).where(
                OAuthAuthorizationCode.code_hash == digest(str(form.get("code", "")))
            )
        )
        if (
            not code
            or code.client_id != client.client_id
            or code.used_at
            or aware(code.expires_at) <= now()
            or code.redirect_uri != form.get("redirect_uri")
        ):
            return _oauth_json_error(
                "invalid_grant",
                "Authorization code is invalid, expired or already used",
            )
        verifier = str(form.get("code_verifier", ""))
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        if len(verifier) < 43 or not secrets.compare_digest(
            challenge, code.code_challenge
        ):
            return _oauth_json_error("invalid_grant", "PKCE verification failed")
        if form.get("resource") and form.get("resource") != code.resource:
            return _oauth_json_error("invalid_target", "resource mismatch")
        code.used_at = now()
        session = OAuthSession(
            id=secrets.token_urlsafe(32),
            client_id=client.client_id,
            user_id=code.user_id,
            scopes=code.scopes,
            resource=code.resource,
            ip=_request_ip(request, settings),
            user_agent=request.headers.get("user-agent"),
            expires_at=now() + timedelta(days=settings.oauth_refresh_token_days),
        )
        db.add(session)
        refresh_raw = None
        if "offline_access" in code.scopes:
            refresh_raw = secrets.token_urlsafe(64)
            db.add(
                OAuthRefreshToken(
                    token_hash=digest(refresh_raw),
                    family_id=secrets.token_urlsafe(24),
                    session_id=session.id,
                    expires_at=session.expires_at,
                )
            )
        client.last_used_at = now()
        await db.commit()
        user = await db.get(OAuthUser, code.user_id)
        await oauth_audit(
            db,
            "oauth.token.issued",
            user.username,
            client.client_id,
            True,
            scopes=code.scopes,
            session_id=session.id,
        )
        return JSONResponse(
            _token_response(settings, client, user, session, refresh_raw, code.nonce),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    if grant == "refresh_token":
        old = await db.scalar(
            select(OAuthRefreshToken).where(
                OAuthRefreshToken.token_hash
                == digest(str(form.get("refresh_token", "")))
            )
        )
        if not old:
            return _oauth_json_error("invalid_grant", "Refresh token is invalid")
        session = await db.get(OAuthSession, old.session_id)
        if (
            not session
            or session.client_id != client.client_id
            or session.revoked_at
            or aware(session.expires_at) <= now()
            or old.revoked_at
            or aware(old.expires_at) <= now()
        ):
            return _oauth_json_error(
                "invalid_grant", "Refresh token is invalid or expired"
            )
        if old.used_at:
            session.revoked_at = now()
            await db.execute(
                update(OAuthRefreshToken)
                .where(OAuthRefreshToken.family_id == old.family_id)
                .values(revoked_at=now())
            )
            await db.commit()
            await oauth_audit(
                db,
                "oauth.refresh.reuse_detected",
                None,
                client.client_id,
                False,
                session_id=session.id,
            )
            return _oauth_json_error(
                "invalid_grant", "Refresh token reuse detected; token family revoked"
            )
        requested = _scope_set(str(form.get("scope", " ".join(session.scopes))))
        if not requested.issubset(set(session.scopes)):
            return _oauth_json_error("invalid_scope", "Refresh cannot expand scopes")
        old.used_at = now()
        session.scopes = sorted(requested)
        session.last_used_at = now()
        refresh_raw = secrets.token_urlsafe(64)
        db.add(
            OAuthRefreshToken(
                token_hash=digest(refresh_raw),
                family_id=old.family_id,
                session_id=session.id,
                expires_at=old.expires_at,
            )
        )
        await db.commit()
        user = await db.get(OAuthUser, session.user_id)
        await oauth_audit(
            db,
            "oauth.token.refreshed",
            user.username,
            client.client_id,
            True,
            session_id=session.id,
        )
        return JSONResponse(
            _token_response(settings, client, user, session, refresh_raw),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    return _oauth_json_error(
        "unsupported_grant_type",
        "Only authorization_code and refresh_token are supported",
    )


@router.post("/oauth/revoke")
async def revoke(
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    form = await request.form()
    try:
        client = await _client_auth(request, form, db)
    except HTTPException:
        return Response(status_code=200)
    supplied = str(form.get("token", ""))
    refresh = await db.scalar(
        select(OAuthRefreshToken).where(
            OAuthRefreshToken.token_hash == digest(supplied)
        )
    )
    if refresh:
        session = await db.get(OAuthSession, refresh.session_id)
        if session and session.client_id == client.client_id:
            session.revoked_at = now()
            await db.execute(
                update(OAuthRefreshToken)
                .where(OAuthRefreshToken.family_id == refresh.family_id)
                .values(revoked_at=now())
            )
            await db.commit()
            await oauth_audit(
                db,
                "oauth.session.revoked",
                None,
                client.client_id,
                True,
                session_id=session.id,
            )
    else:
        try:
            claims = jwt.decode(
                supplied,
                _public_key(settings),
                algorithms=["RS256"],
                audience=settings.resource,
                issuer=settings.issuer,
            )
            if claims.get("client_id") == client.client_id:
                db.add(
                    OAuthRevokedToken(
                        jti=claims["jti"],
                        expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
                        reason="client_revocation",
                    )
                )
                await db.commit()
        except Exception:
            pass
    return Response(status_code=200)


@router.get("/oauth/userinfo")
async def userinfo(
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    claims = await validate_access_token(authorization.split(None, 1)[1], settings, db)
    if "openid" not in claims["scope"].split():
        raise HTTPException(403, "openid scope required")
    user = await db.get(OAuthUser, int(claims["sub"]))
    result = {"sub": str(user.id)}
    scopes = set(claims["scope"].split())
    if "profile" in scopes:
        result["preferred_username"] = user.username
    if "email" in scopes:
        result.update({"email": user.email, "email_verified": True})
    return result
