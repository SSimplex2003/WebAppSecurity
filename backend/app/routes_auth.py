from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import audit
from .crypto import (
    DUMMY_PASSWORD_HASH,
    derive_key,
    hash_password,
    new_kdf_salt,
    verify_password,
)
from .db import get_db
from .deps import (
    COOKIE_NAME,
    AuthContext,
    clear_session_cookie,
    client_ip,
    get_auth,
    require_csrf,
    set_session_cookie,
    too_many_attempts,
)
from .models import User
from .ratelimit import login_email_limiter, login_ip_limiter, register_ip_limiter
from .schemas import LoginRequest, RegisterRequest
from .sessions import session_store

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    wait = register_ip_limiter.retry_after(f"ip:{ip}")
    if wait:
        raise too_many_attempts(wait)
    register_ip_limiter.record(f"ip:{ip}")

    user = User(
        email=body.email,
        password_hash=hash_password(body.master_password),
        kdf_salt=new_kdf_salt(),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    audit.info("register user_id=%s ip=%s", user.id, ip)
    return {"email": user.email}


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    ip_key = f"ip:{ip}"
    email_key = f"email:{body.email}"

    wait = max(login_ip_limiter.retry_after(ip_key), login_email_limiter.retry_after(email_key))
    if wait:
        audit.warning("login_blocked ip=%s email=%s", ip, body.email)
        raise too_many_attempts(wait)

    user = db.scalar(select(User).where(User.email == body.email))
    if user is None:
        verify_password(DUMMY_PASSWORD_HASH, body.master_password)
        authenticated = False
    else:
        authenticated = verify_password(user.password_hash, body.master_password)

    if user is None or not authenticated:
        login_ip_limiter.record(ip_key)
        login_email_limiter.record(email_key)
        audit.warning("login_failed ip=%s email=%s", ip, body.email)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    login_email_limiter.reset(email_key)
    key = derive_key(body.master_password, user.kdf_salt)

    # Session fixation: never adopt a client-supplied id. Drop whatever session
    # the browser presented and issue a brand new random one.
    previous = request.cookies.get(COOKIE_NAME)
    if previous:
        session_store.delete(previous)
    sid, data = session_store.create(user.id, key)
    set_session_cookie(response, sid)

    audit.info("login user_id=%s ip=%s", user.id, ip)
    return {"email": user.email, "csrf_token": data.csrf_token}


@router.get("/me")
def me(ctx: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    user = db.get(User, ctx.user_id)
    if user is None:
        session_store.delete(ctx.sid)
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"email": user.email, "csrf_token": ctx.session.csrf_token}


@router.post("/logout", status_code=204)
def logout(ctx: AuthContext = Depends(require_csrf)):
    session_store.delete(ctx.sid)
    audit.info("logout user_id=%s", ctx.user_id)
    response = Response(status_code=204)
    clear_session_cookie(response)
    return response
