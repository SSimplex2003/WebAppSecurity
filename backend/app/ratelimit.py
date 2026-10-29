import math
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    """Blocks a key once it has `max_events` events inside the window."""

    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _prune(self, key: str, now: float) -> deque[float] | None:
        queue = self._events.get(key)
        if queue is None:
            return None
        cutoff = now - self.window
        while queue and queue[0] <= cutoff:
            queue.popleft()
        if not queue:
            del self._events[key]
            return None
        return queue

    def retry_after(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            queue = self._prune(key, now)
            if queue is None or len(queue) < self.max_events:
                return 0
            return max(1, math.ceil(queue[0] + self.window - now))

    def record(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_sweep > 60:
                for existing in list(self._events):
                    self._prune(existing, now)
                self._last_sweep = now
            self._events.setdefault(key, deque()).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


login_ip_limiter = SlidingWindowLimiter(max_events=20, window_seconds=15 * 60)
login_email_limiter = SlidingWindowLimiter(max_events=5, window_seconds=15 * 60)
register_ip_limiter = SlidingWindowLimiter(max_events=10, window_seconds=60 * 60)


def reset_all() -> None:
    login_ip_limiter.clear()
    login_email_limiter.clear()
    register_ip_limiter.clear()
