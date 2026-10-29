import base64
import json
import secrets
import threading
import time
from dataclasses import dataclass

from .config import Settings, get_settings


@dataclass
class SessionData:
    user_id: int
    key: bytes
    csrf_token: str
    created_at: float
    last_seen: float


def _is_expired(data: SessionData, now: float, idle: int, absolute: int) -> bool:
    return now - data.last_seen > idle or now - data.created_at > absolute


def _new_session(user_id: int, key: bytes) -> tuple[str, SessionData]:
    now = time.time()
    sid = secrets.token_urlsafe(32)
    return sid, SessionData(user_id, key, secrets.token_urlsafe(32), now, now)


class MemorySessionStore:
    """Sessions (and the derived encryption keys) live only in this process."""

    def __init__(self, idle: int, absolute: int):
        self._idle = idle
        self._absolute = absolute
        self._data: dict[str, SessionData] = {}
        self._lock = threading.Lock()

    def create(self, user_id: int, key: bytes) -> tuple[str, SessionData]:
        sid, data = _new_session(user_id, key)
        with self._lock:
            now = data.created_at
            for stale in [
                s for s, d in self._data.items() if _is_expired(d, now, self._idle, self._absolute)
            ]:
                del self._data[stale]
            self._data[sid] = data
        return sid, data

    def get(self, sid: str) -> SessionData | None:
        now = time.time()
        with self._lock:
            data = self._data.get(sid)
            if data is None:
                return None
            if _is_expired(data, now, self._idle, self._absolute):
                del self._data[sid]
                return None
            data.last_seen = now
            return data

    def delete(self, sid: str) -> None:
        with self._lock:
            self._data.pop(sid, None)


class RedisSessionStore:
    """Same contract as MemorySessionStore, shared across processes via Redis."""

    def __init__(self, url: str, idle: int, absolute: int):
        import redis

        self._redis = redis.Redis.from_url(url)
        self._idle = idle
        self._absolute = absolute

    @staticmethod
    def _name(sid: str) -> str:
        return f"session:{sid}"

    def _save(self, sid: str, data: SessionData) -> None:
        payload = json.dumps(
            {
                "user_id": data.user_id,
                "key": base64.b64encode(data.key).decode("ascii"),
                "csrf_token": data.csrf_token,
                "created_at": data.created_at,
                "last_seen": data.last_seen,
            }
        )
        self._redis.set(self._name(sid), payload, ex=self._idle)

    def create(self, user_id: int, key: bytes) -> tuple[str, SessionData]:
        sid, data = _new_session(user_id, key)
        self._save(sid, data)
        return sid, data

    def get(self, sid: str) -> SessionData | None:
        raw = self._redis.get(self._name(sid))
        if raw is None:
            return None
        fields = json.loads(raw)
        data = SessionData(
            user_id=fields["user_id"],
            key=base64.b64decode(fields["key"]),
            csrf_token=fields["csrf_token"],
            created_at=fields["created_at"],
            last_seen=fields["last_seen"],
        )
        now = time.time()
        if _is_expired(data, now, self._idle, self._absolute):
            self._redis.delete(self._name(sid))
            return None
        data.last_seen = now
        self._save(sid, data)
        return data

    def delete(self, sid: str) -> None:
        self._redis.delete(self._name(sid))


def build_session_store(settings: Settings) -> MemorySessionStore | RedisSessionStore:
    if settings.redis_url:
        return RedisSessionStore(
            settings.redis_url, settings.session_idle_seconds, settings.session_absolute_seconds
        )
    return MemorySessionStore(settings.session_idle_seconds, settings.session_absolute_seconds)


session_store = build_session_store(get_settings())
