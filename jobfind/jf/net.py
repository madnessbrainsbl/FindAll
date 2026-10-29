"""HTTP transport with bounded retries, per-host limits and route preservation."""
import json
import math
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit
from .resilience import HostLimiter, HostWaitTimeout, RetryPolicy, RETRY_STATUSES, error_text, transient_error

USER_AGENT = "FindAll/1.0 (public-source research; contact: local user)"
TIMEOUT = 25
MAX_BODY = 25_000_000
_limiter = HostLimiter()


def _polite_wait(host: str, min_interval: float = 1.1, deadline: float | None = None) -> None:
    _limiter.wait(host, min_interval, deadline)


class HttpResult:
    def __init__(self, status: int, body: bytes, url: str, error: str = "", metadata: dict | None = None):
        self.status = status
        self.body = body
        self.url = url
        self.error = error
        self.metadata = metadata or {}

    def json(self, log_errors: bool = True):
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            if log_errors:
                print(f"  [!] JSON decode failed for {urlsplit(self.url).hostname or 'unknown host'}", file=sys.stderr)
            return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace") if self.body else ""


def _request(url: str, method: str, headers: dict, body: bytes | None, retries: int,
             timeout: float | None = None, max_bytes: int = MAX_BODY) -> HttpResult:
    started = time.monotonic()
    attempts = 0
    retried = 0
    waited = 0.0
    status = 0
    failure = ""
    host = ""
    policy = RetryPolicy(retries=retries, total_timeout=timeout if timeout is not None else 80.0)
    deadline = started + policy.total_timeout

    def finish(payload: bytes = b"") -> HttpResult:
        state = "ok" if 200 <= status < 400 else (
            "blocked" if status in (403, 429) or "rate limit delay" in failure else "timeout" if "timed out" in failure or "time budget" in failure
            else "error")
        metadata = {"host": host, "method": method, "status": status, "state": state,
                    "attempts": attempts, "retry_count": retried,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "retry_wait_seconds": round(waited, 3)}
        result = HttpResult(status, payload, url, error=failure, metadata=metadata)
        try:
            from .diagnostics import record_network
            record_network(metadata)
        except Exception:
            # Optional diagnostics cannot change the outcome of a request.
            pass
        return result

    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            failure = "Unsupported or invalid HTTP URL"
            return finish()
        host = parsed.hostname.lower()
        for attempt in range(1, policy.attempts(method) + 1):
            if time.monotonic() >= deadline:
                failure = "Request time budget exhausted"
                break
            retry_header = None
            retryable = False
            try:
                with _limiter.slot(host, deadline):
                    _polite_wait(host, deadline=deadline)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise HostWaitTimeout("Request time budget exhausted")
                    req = urllib.request.Request(url, data=body, method=method, headers=headers)
                    # API credentials must not follow an upstream redirect to another host.
                    for name in ("Authorization", "X-subscription-token"):
                        value = req.headers.pop(name, None)
                        if value is not None:
                            req.add_unredirected_header(name, value)
                    attempts += 1
                    # Use the installed urllib opener; Apex routing must remain
                    # active without silently falling back to another transport.
                    with urllib.request.urlopen(req, timeout=min(TIMEOUT, remaining)) as response:
                        status = response.status
                        payload = response.read(max_bytes)
                    failure = ""
                    return finish(payload)
            except urllib.error.HTTPError as exc:
                status = exc.code
                failure = f"HTTP {status}"
                retryable = status in RETRY_STATUSES
                retry_header = exc.headers.get("Retry-After") if exc.headers else None
                exc.close()
            except HostWaitTimeout as exc:
                failure = str(exc)
                break
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                status = 0
                failure = error_text(exc)
                retryable = transient_error(exc)
            delay = policy.delay(attempt, retry_header) if retryable else 0.0
            if retryable and status in (429, 503):
                _limiter.defer(host, delay)
            if not retryable or attempt >= policy.attempts(method):
                break
            # A long Retry-After stops retries; it is never shortened to fit.
            if delay >= deadline - time.monotonic():
                break
            retried += 1
            waited += delay
            time.sleep(delay)
        return finish()
    except (TypeError, ValueError, OverflowError):
        failure = "Invalid HTTP request configuration"
        return finish()


def post_json(url: str, payload: dict, retries: int = 2,
              extra_headers: dict | None = None) -> HttpResult:
    """Send JSON once: POST outcomes are not assumed safe to replay."""
    try:
        body = json.dumps(payload).encode("utf-8")
    except (TypeError, ValueError):
        return HttpResult(0, b"", url, error="Payload is not JSON serializable")
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return _request(url, "POST", headers, body, retries)


def get(url: str, params: dict | None = None, retries: int = 2,
        extra_headers: dict | None = None, *, timeout: float | None = None,
        max_bytes: int = MAX_BODY) -> HttpResult:
    """GET with bounded transient retries; failures retain the HTTP status."""
    if (timeout is not None and (not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or not 0 < timeout <= 600)) or \
            type(max_bytes) is not int or not 0 < max_bytes <= MAX_BODY:
        return HttpResult(0, b"", url, error="Invalid HTTP request limits")
    if params:
        try:
            url = url + ("&" if "?" in url else "?") + urlencode(params)
        except (TypeError, ValueError):
            return HttpResult(0, b"", url, error="Invalid HTTP query parameters")
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    return _request(url, "GET", headers, None, retries, timeout, max_bytes)
