from collections.abc import Callable
from ipaddress import ip_address, ip_network
from typing import Any

from app.auth import (
    authenticate_mcp,
    current_actor,
    current_permissions,
    current_request_meta,
    limiter,
)
from app.config import Settings


class SecurityMiddleware:
    """Pure ASGI middleware so MCP streaming is never buffered by BaseHTTPMiddleware."""

    def __init__(self, app: Callable, settings: Settings):
        self.app = app
        self.settings = settings
        self.max_body = settings.max_request_size_mb * 1024 * 1024

    def _trusted_proxy(self, value: str) -> bool:
        try:
            address = ip_address(value)
            return any(
                address in ip_network(item, strict=False)
                for item in self.settings.trusted_proxies
            )
        except ValueError:
            return False

    async def _reject(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,
        status: int,
        detail: str,
        headers: list[tuple[bytes, bytes]] | None = None,
    ):
        import json

        body = json.dumps({"detail": detail}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ]
                + (headers or []),
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        length = int(headers.get("content-length", "0") or 0)
        if length > self.max_body:
            return await self._reject(
                scope, receive, send, 413, "Request body too large"
            )
        peer = scope.get("client", ("unknown", 0))[0]
        client_ip = (
            headers.get("x-forwarded-for", "").split(",")[0].strip()
            if self._trusted_proxy(peer) and headers.get("x-forwarded-for")
            else peer
        )
        if not limiter.allow(client_ip, self.settings.rate_limit_per_minute):
            return await self._reject(
                scope,
                receive,
                send,
                429,
                "Rate limit exceeded",
                [(b"retry-after", b"60")],
            )
        path = scope.get("path", "")
        actor_token = permission_token = meta_token = None
        if path == self.settings.mcp_path or path.startswith(
            self.settings.mcp_path + "/"
        ):
            from starlette.requests import Request

            try:
                actor, permissions = await authenticate_mcp(
                    Request(scope, receive=receive), self.settings
                )
            except Exception as exc:
                response_headers = []
                for key, value in getattr(exc, "headers", {}).items():
                    response_headers.append((key.lower().encode(), value.encode()))
                return await self._reject(
                    scope,
                    receive,
                    send,
                    getattr(exc, "status_code", 401),
                    str(getattr(exc, "detail", exc)),
                    response_headers,
                )
            actor_token = current_actor.set(actor)
            permission_token = current_permissions.set(permissions)
            meta_token = current_request_meta.set(
                {
                    "ip": client_ip,
                    "user_agent": headers.get("user-agent"),
                    "mcp_session": headers.get("mcp-session-id"),
                }
            )
            # MCP transports normally use JSON-RPC errors for tool failures,
            # but authorization is enforced at the HTTP resource boundary so
            # clients can react to RFC 6750 `insufficient_scope` responses.
            if scope.get("method") == "POST" and "json" in headers.get(
                "content-type", ""
            ):
                import json

                chunks = []
                more = True
                while more:
                    message = await receive()
                    chunks.append(message.get("body", b""))
                    more = message.get("more_body", False)
                request_body = b"".join(chunks)
                delivered = False

                async def replay_receive():
                    nonlocal delivered
                    if delivered:
                        return {"type": "http.request", "body": b"", "more_body": False}
                    delivered = True
                    return {
                        "type": "http.request",
                        "body": request_body,
                        "more_body": False,
                    }

                receive = replay_receive
                try:
                    payload = json.loads(request_body)
                    if payload.get("method") == "tools/call":
                        from app.mcp_server import TOOL_PERMISSIONS

                        tool = payload.get("params", {}).get("name")
                        required = TOOL_PERMISSIONS.get(tool)
                        if (
                            required
                            and required not in permissions
                            and "admin" not in permissions
                        ):
                            current_actor.reset(actor_token)
                            current_permissions.reset(permission_token)
                            current_request_meta.reset(meta_token)
                            return await self._reject(
                                scope,
                                receive,
                                send,
                                403,
                                f"insufficient_scope: required scope {required}",
                                [
                                    (
                                        b"www-authenticate",
                                        f'Bearer error="insufficient_scope", scope="{required}", resource_metadata="{self.settings.issuer}/.well-known/oauth-protected-resource"'.encode(),
                                    )
                                ],
                            )
                except (ValueError, AttributeError):
                    pass
        if (
            path.startswith("/api/")
            and scope.get("method") in {"POST", "PUT", "PATCH", "DELETE"}
            and path not in {"/api/auth/login", "/api/auth/logout"}
        ):
            cookies = {}
            for pair in headers.get("cookie", "").split(";"):
                if "=" in pair:
                    key, value = pair.strip().split("=", 1)
                    cookies[key] = value
            if not cookies.get("mailmcp_csrf") or headers.get(
                "x-csrf-token"
            ) != cookies.get("mailmcp_csrf"):
                return await self._reject(
                    scope, receive, send, 403, "CSRF token missing or invalid"
                )
        # A mounted Starlette app does not match its bare prefix. Normalize the
        # internal path so POST /mcp reaches the mounted root without a redirect.
        if path == self.settings.mcp_path:
            scope = dict(scope)
            scope["path"] = f"{path}/"
            scope["raw_path"] = f"{path}/".encode()

        async def secure_send(message: dict[str, Any]):
            if message.get("type") == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"permissions-policy",
                            b"camera=(), microphone=(), geolocation=()",
                        ),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                        ),
                    ]
                )
                if self.settings.public_url.startswith("https://"):
                    response_headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        )
                    )
                message = {**message, "headers": response_headers}
            await send(message)

        try:
            await self.app(scope, receive, secure_send)
        finally:
            if actor_token is not None:
                current_actor.reset(actor_token)
            if permission_token is not None:
                current_permissions.reset(permission_token)
            if meta_token is not None:
                current_request_meta.reset(meta_token)
