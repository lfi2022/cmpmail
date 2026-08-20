import time
from collections import defaultdict, deque
from contextvars import ContextVar
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select

from app.config import Settings, get_settings
from app.database import SessionLocal
from app.models import ApiKey
from app.security import PERMISSIONS, verify_secret, verify_static_secret

current_permissions: ContextVar[set[str]] = ContextVar(
    "current_permissions", default=set()
)
current_actor: ContextVar[str] = ContextVar("current_actor", default="anonymous")
current_request_meta: ContextVar[dict[str, str | None]] = ContextVar(
    "current_request_meta", default={}
)


class SlidingWindowLimiter:
    def __init__(self):
        self.buckets: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        bucket = self.buckets[key]
        while bucket and bucket[0] < now - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


limiter = SlidingWindowLimiter()


def serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key, salt="mailmcp-admin")


def create_admin_session(username: str, settings: Settings) -> str:
    return serializer(settings).dumps({"sub": username})


async def require_admin(
    request: Request, settings: Settings = Depends(get_settings)
) -> str:
    token = request.cookies.get("mailmcp_session")
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        data = serializer(settings).loads(token, max_age=8 * 3600)
        return str(data["sub"])
    except (BadSignature, SignatureExpired, KeyError) as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid or expired session"
        ) from exc


async def authenticate_mcp(
    request: Request, settings: Settings
) -> tuple[str, set[str]]:
    if not settings.mcp_auth_enabled:
        return "authentication-disabled", set(PERMISSIONS)
    supplied = request.headers.get("x-api-key", "")
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if supplied and settings.oauth_enabled:
        from app.oauth import validate_access_token

        async with SessionLocal() as db:
            try:
                claims = await validate_access_token(supplied, settings, db)
                return f"oauth:{claims['sub']}", set(claims["scope"].split())
            except HTTPException:
                if not settings.mcp_legacy_api_key_enabled:
                    raise
    if (
        supplied
        and settings.mcp_legacy_api_key_enabled
        and verify_static_secret(settings.mcp_api_key, supplied)
    ):
        return "environment-key", set(PERMISSIONS)
    if supplied and settings.mcp_legacy_api_key_enabled:
        prefix = supplied[:12]
        async with SessionLocal() as db:
            keys = (
                await db.scalars(
                    select(ApiKey).where(
                        ApiKey.prefix == prefix, ApiKey.enabled.is_(True)
                    )
                )
            ).all()
            for key in keys:
                if verify_secret(key.key_hash, supplied):
                    key.last_used_at = datetime.now(timezone.utc)
                    await db.commit()
                    return key.name, set(key.permissions)
    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Missing or invalid MCP credential",
        headers={
            "WWW-Authenticate": (
                f'Bearer resource_metadata="{settings.issuer}/.well-known/'
                'oauth-protected-resource", scope="accounts.read mail.read"'
            )
        },
    )
