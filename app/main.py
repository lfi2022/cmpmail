import asyncio
import contextlib
import logging
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import func, select
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.auth import authenticate_mcp
from app.config import get_settings
from app.database import SessionLocal, check_database
from app.mcp_server import mcp
from app.middleware import SecurityMiddleware
from app.models import MailAccount
from app.oauth import bootstrap_oauth_user
from app.oauth import router as oauth_router
from app.routers.admin import router as admin_router
from app.security import require_permission
from app.services.mail import result
from app.temp_media import (
    cleanup_expired_uploads,
    resolve_temporary_image,
    store_temporary_binary,
)

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
    settings.temporary_upload_dir.mkdir(parents=True, exist_ok=True)
    cleanup_expired_uploads(settings)
    async with SessionLocal() as db:
        await bootstrap_oauth_user(settings, db)

    async def purge_uploads():
        while True:
            cleanup_expired_uploads(settings)
            await asyncio.sleep(300)

    cleanup_task = asyncio.create_task(purge_uploads())
    try:
        async with mcp.session_manager.run():
            yield
    finally:
        cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await cleanup_task


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


@app.get("/temp-media/{file_id}/{filename}", include_in_schema=False)
async def temporary_media(file_id: str, filename: str):
    if Path(filename).name != filename:
        raise HTTPException(status_code=404, detail="Temporary file not found")
    try:
        path, _ = resolve_temporary_image(settings, file_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Temporary file not found") from exc
    if path.name != filename:
        raise HTTPException(status_code=404, detail="Temporary file not found")
    return FileResponse(
        path,
        media_type=mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.post("/api/temp-media/upload", include_in_schema=False)
async def upload_temporary_media(
    request: Request,
    image_file: Annotated[UploadFile, File(...)],
    preserve_original: bool = False,
):
    _, permissions = await authenticate_mcp(request, settings)
    require_permission("facebook.write", permissions, settings)
    mime = (image_file.content_type or "").lower()
    filename = image_file.filename or "image"
    if mime not in {"image/jpeg", "image/png", "image/webp"}:
        raise HTTPException(status_code=415, detail="Supported image MIME types are JPEG, PNG, and WEBP")
    chunks = bytearray()
    while True:
        chunk = await image_file.read(1024 * 1024)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > settings.temporary_upload_max_bytes:
            raise HTTPException(status_code=413, detail="image exceeds the configured upload limit")
    try:
        return result(store_temporary_binary(settings, bytes(chunks), filename, mime, preserve_original))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
