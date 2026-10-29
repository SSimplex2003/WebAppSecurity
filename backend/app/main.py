from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import models  # noqa: F401  (registers the tables on Base.metadata)
from .config import FRONTEND_DIR, get_settings
from .db import Base, engine
from .routes_auth import router as auth_router
from .routes_vault import router as vault_router

settings = get_settings()

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(engine)
    yield


# Interactive docs and the OpenAPI schema are disabled to keep the surface small.
app = FastAPI(
    title="Secure Password Manager API",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    headers = response.headers
    headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    headers["X-Content-Type-Options"] = "nosniff"
    headers["X-Frame-Options"] = "DENY"
    headers["Referrer-Policy"] = "no-referrer"
    headers["Cross-Origin-Opener-Policy"] = "same-origin"
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        headers["Cache-Control"] = "no-store"
    if settings.enable_hsts:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    # Built by hand so the rejected input (e.g. a password) is never echoed back.
    errors = []
    for error in exc.errors():
        location = [
            part for part in error.get("loc", ()) if isinstance(part, str) and part != "body"
        ]
        message = str(error.get("msg", "Invalid value")).removeprefix("Value error, ")
        errors.append({"field": ".".join(location), "message": message})
    detail = "; ".join(
        f"{e['field']}: {e['message']}" if e["field"] else e["message"] for e in errors
    )
    return JSONResponse(
        status_code=422, content={"detail": detail or "Invalid input", "errors": errors}
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(vault_router)

# Mounted last so it only serves paths no API route claimed.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
