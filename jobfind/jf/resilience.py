"""Bounded retry policy and shared, thread-safe HTTP host backpressure."""
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
import random
import socket
import ssl
import threading
import time
import urllib.error

RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
SAFE_METHODS = frozenset({"GET", "HEAD"})


def retry_after(value: str | None, now: datetime | None = None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
        return max(0.0, seconds) if math.isfinite(seconds) else None
    except (TypeError, ValueError):
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return max(0.0, (date - (now or datetime.now(timezone.utc))).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


def transient_error(error: BaseException) -> bool:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLError):
        return not isinstance(reason, ssl.SSLCertVerificationError) and (
            isinstance(reason, ssl.SSLEOFError) or getattr(reason, "reason", "") in
            {"DECRYPTION_FAILED_OR_BAD_RECORD_MAC", "UNEXPECTED_EOF_WHILE_READING"})
    if isinstance(reason, socket.gaierror):
        return reason.errno == socket.EAI_AGAIN
    return isinstance(reason, (TimeoutError, ConnectionError))


def error_text(error: BaseException) -> str:
    """Exclude arbitrary messages which can embed credentials or server bodies."""
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLError):
        return "TLS validation or handshake failed"
    if isinstance(reason, socket.gaierror):
        return "DNS resolution failed"
    if isinstance(reason, TimeoutError):
        return "Network request timed out"
    if isinstance(reason, ConnectionError):
        return "Network connection failed"
    return "Network request failed"


@dataclass(frozen=True)
class RetryPolicy:
    retries: int = 2
    total_timeout: float = 80.0
    max_delay: float = 12.0

    def attempts(self, method: str) -> int:
        return 1 + min(4, max(0, int(self.retries))) if method in SAFE_METHODS else 1

    def delay(self, attempt: int, header: str | None = None) -> float:
        instructed = retry_after(header)
        if instructed is not None:
            return instructed
        return min(self.max_delay, 2 ** max(0, attempt - 1) + random.uniform(0.0, 0.5))


class HostWaitTimeout(TimeoutError):
    pass


@dataclass
class _HostState:
    slots: threading.BoundedSemaphore = field(default_factory=lambda: threading.BoundedSemaphore(2))
    start_lock: threading.Lock = field(default_factory=threading.Lock)
    next_start: float = 0.0
    cooldown: float = 0.0


class HostLimiter:
    """Two in-flight requests and spaced starts per host across worker threads."""
    def __init__(self):
        self._states: dict[str, _HostState] = {}
        self._lock = threading.Lock()

    def _state(self, host: str) -> _HostState:
        with self._lock:
            key = host.lower()
            if key not in self._states:
                self._states[key] = _HostState()
            return self._states[key]

    def defer(self, host: str, seconds: float) -> None:
        state = self._state(host)
        with state.start_lock:
            state.cooldown = max(state.cooldown, time.monotonic() + min(300.0, max(0.0, seconds)))

    def wait(self, host: str, min_interval: float = 1.1, deadline: float | None = None) -> None:
        state = self._state(host)
        while True:
            with state.start_lock:
                now = time.monotonic()
                delay = max(0.0, state.next_start - now, state.cooldown - now)
                if deadline is not None and delay >= deadline - now:
                    raise HostWaitTimeout("Host rate limit delay exceeds request time budget")
                if delay <= 0:
                    state.next_start = now + max(0.0, min_interval)
                    return
            # Never sleep while holding the state lock. A different request
            # must be able to publish a new server cooldown immediately.
            time.sleep(delay)

    @contextmanager
    def slot(self, host: str, deadline: float):
        state = self._state(host)
        if not state.slots.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise HostWaitTimeout("Host concurrency queue exceeded time budget")
        try:
            yield
        finally:
            state.slots.release()


class CircuitBreaker:
    """Dynamic fail-fast circuit breaker for endpoints and job sources.

    If a source or host encounters failure_threshold consecutive errors
    (e.g., HTTP 403 Forbidden, 429 Too Many Requests, DNS or connection timeout),
    the circuit trips OPEN for recovery_timeout seconds (default 300s),
    immediately skipping subsequent requests to prevent hanging the batch run.
    """
    def __init__(self, failure_threshold: int = 2, recovery_timeout: float = 300.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures: dict[str, int] = {}
        self._tripped_at: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_available(self, name: str) -> bool:
        with self._lock:
            key = name.lower()
            if key in self._tripped_at:
                elapsed = time.monotonic() - self._tripped_at[key]
                if elapsed < self.recovery_timeout:
                    return False
                del self._tripped_at[key]
                self._failures[key] = 0
            return True

    def record_success(self, name: str) -> None:
        with self._lock:
            key = name.lower()
            self._failures[key] = 0
            self._tripped_at.pop(key, None)

    def record_failure(self, name: str, reason: str = "") -> bool:
        """Records a failure. Returns True if the circuit just tripped OPEN."""
        with self._lock:
            key = name.lower()
            self._failures[key] = self._failures.get(key, 0) + 1
            if self._failures[key] >= self.failure_threshold:
                self._tripped_at[key] = time.monotonic()
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._tripped_at.clear()

