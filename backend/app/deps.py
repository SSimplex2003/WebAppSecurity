import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, Response

from .config import get_settings
from .sessions import SessionData, session_store

_settings = get_settings()

# The __Host- prefix makes browsers require Secure, Path=/ and no Domain.
COOKIE_NAME = "__Host-sid" if _settings.cookie_secure else "sid"


@dataclass
class AuthContext:
    sid: str
    session: SessionData

    @property
    def user_id(self) -> int:
        return self.session.user_id

    @property
    def key(self) -> bytes:
        return self.session.key


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def too_many_attempts(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail="Too many attempts. Try again later.",
        headers={"Retry-After": str(retry_after)},
    )


def set_session_cookie(response: Response, sid: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=sid,
        httponly=True,
        secure=_settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=COOKIE_NAME,
        httponly=True,
        secure=_settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def get_auth(request: Request) -> AuthContext:
    sid = request.cookies.get(COOKIE_NAME)
    session = session_store.get(sid) if sid else None
    if sid is None or session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return AuthContext(sid=sid, session=session)


def require_csrf(request: Request, ctx: AuthContext = Depends(get_auth)) -> AuthContext:
    sent = request.headers.get("x-csrf-token", "")
    expected = ctx.session.csrf_token
    if not hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return ctx
