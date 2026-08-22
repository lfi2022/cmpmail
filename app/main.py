import contextlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from starlette.middleware.trustedhost import TrustedHostMiddleware
from mcp.server.transport_security import TransportSecuritySettings

from app import __version__
from app.config import get_settings
from app.database import SessionLocal, check_database
from app.mcp_server import mcp
from app.middleware import SecurityMiddleware
from app.models import MailAccount
from app.oauth import bootstrap_oauth_user, router as oauth_router
from app.routers.admin import router as admin_router

settings = get_settings()
logger = logging.getLogger(__name__)
transport_hosts = list(
    dict.fromkeys(
        settings.allowed_hosts
        + [f"{host}:*" for host in settings.allowed_hosts if ":" not in host]
    )
)
mcp_asgi = mcp.streamable_http_app(
    streamable_http_path="/",
    json_response=True,
    stateless_http=False,
    max_request_body_size=settings.max_request_size_mb * 1024 * 1024,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=transport_hosts,
        allowed_origins=settings.allowed_origins,
    ),
)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    Path("data").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    async with SessionLocal() as db:
        await bootstrap_oauth_user(settings, db)
    async with mcp.session_manager.run():
        yield


app = FastAPI(
    title="LFINFO Mail MCP",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-CSRF-Token",
        "Mcp-Protocol-Version",
        "Mcp-Session-Id",
        "Last-Event-ID",
    ],
    expose_headers=["Mcp-Session-Id"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(SecurityMiddleware, settings=settings)
app.include_router(admin_router)
app.include_router(oauth_router)


@app.exception_handler(Exception)
async def unhandled_exception(request, exc: Exception):
    """Keep unexpected HTTP failures isolated without logging request secrets."""
    logger.exception("Unhandled request failure method=%s path=%s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    database = await check_database()
    accounts = 0
    if database:
        try:
            async with SessionLocal() as db:
                accounts = int(
                    await db.scalar(
                        select(func.count())
                        .select_from(MailAccount)
                        .where(MailAccount.enabled.is_(True))
                    )
                    or 0
                )
        except Exception:
            database = False
    errors = settings.production_errors()
    payload = {
        "status": "ready" if database and not errors and accounts else "not_ready",
        "checks": {
            "database": database,
            "configuration": not errors,
            "active_accounts": accounts,
        },
        "errors": errors,
    }
    return JSONResponse(
        payload, status_code=200 if payload["status"] == "ready" else 503
    )


@app.get("/version")
async def version():
    return {
        "name": "lfinfo-mail-mcp",
        "version": __version__,
        "mcp_transport": "streamable-http",
        "time": datetime.now(timezone.utc).isoformat(),
    }


app.mount(settings.mcp_path, mcp_asgi, name="mcp")

frontend = settings.frontend_dir.resolve()
assets = frontend / "assets"
if assets.exists():
    app.mount("/assets", StaticFiles(directory=assets), name="assets")


@app.get("/{path:path}", include_in_schema=False)
async def frontend_spa(path: str):
    index = frontend / "index.html"
    candidate = (frontend / path).resolve()
    if candidate.is_file() and frontend in candidate.parents:
        return FileResponse(candidate)
    if index.exists():
        return FileResponse(index)
    return JSONResponse(
        {
            "status": "frontend_not_built",
            "hint": "Run: cd frontend && npm install && npm run build",
        },
        status_code=503,
    )
