import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import get_settings
from .db import get_sessionmaker
from .routers import assets, audit_log, auth, overview, users

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
log = logging.getLogger("bastion")


def create_app() -> FastAPI:
    cfg = get_settings()
    app = FastAPI(
        title="Bastion API", version="0.1.0",
        docs_url="/api/docs" if cfg.is_development else None,
        redoc_url=None, openapi_url="/api/openapi.json" if cfg.is_development else None,
    )
    app.add_middleware(
        CORSMiddleware, allow_origins=[cfg.allowed_origin], allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"],
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > cfg.max_body_bytes:
            return JSONResponse({"detail": {"code": "too_large", "message": "Request body too large."}}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "error", "message": str(exc.detail)}
        return JSONResponse({"detail": detail}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled error on %s %s", request.method, request.url.path)  # details stay in logs
        return JSONResponse({"detail": {"code": "internal_error", "message": "Something went wrong."}}, status_code=500)

    @app.get("/api/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/api/readyz")
    def readyz():
        with get_sessionmaker()() as db:
            db.execute(text("SELECT 1"))
        return {"status": "ready"}

    for r in (auth.router, users.router, assets.router, audit_log.router, overview.router):
        app.include_router(r)
    return app


app = create_app()
