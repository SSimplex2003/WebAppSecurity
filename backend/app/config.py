import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
FRONTEND_DIR = REPO_DIR / "frontend"

load_dotenv(BACKEND_DIR / ".env")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str | None
    cookie_secure: bool
    enable_hsts: bool
    session_idle_seconds: int
    session_absolute_seconds: int


@lru_cache
def get_settings() -> Settings:
    default_db = "sqlite:///" + (BACKEND_DIR / "data" / "vault.db").as_posix()
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "").strip() or default_db,
        redis_url=os.environ.get("REDIS_URL", "").strip() or None,
        cookie_secure=_env_bool("COOKIE_SECURE", True),
        enable_hsts=_env_bool("ENABLE_HSTS", False),
        session_idle_seconds=_env_int("SESSION_IDLE_SECONDS", 15 * 60),
        session_absolute_seconds=_env_int("SESSION_ABSOLUTE_SECONDS", 12 * 60 * 60),
    )
