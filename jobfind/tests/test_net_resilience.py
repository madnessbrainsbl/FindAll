"""Offline transport policy checks: no credentials and no external requests."""
import io
import json
import ssl
import threading
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import unittest
import urllib.error
from unittest.mock import patch

from jf import net
from jf.resilience import HostLimiter, HostWaitTimeout, RetryPolicy, retry_after


def http_error(code, retry_after=None):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return urllib.error.HTTPError("https://example.org/private?key=SECRET", code, "failure", headers, io.BytesIO(b""))


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, size):
        return b'{"ok":true}'


class NetResilienceTests(unittest.TestCase):
    def setUp(self):
        self.gate = patch.object(net, "_limiter", HostLimiter())
        self.gate.start()
        self.addCleanup(self.gate.stop)

    def test_authentication_failure_is_not_retried_and_status_preserved(self):
        with patch.object(net, "_polite_wait"), patch.object(net.time, "sleep"), \
                patch.object(net.urllib.request, "urlopen", side_effect=http_error(401)) as send:
            result = net.get("https://example.org/private?key=SECRET")
        self.assertEqual(result.status, 401)
        self.assertEqual(send.call_count, 1)

    def test_post_is_not_replayed_after_unknown_outcome(self):
        with patch.object(net, "_polite_wait"), patch.object(net.time, "sleep"), \
                patch.object(net.urllib.request, "urlopen", side_effect=TimeoutError("SECRET")) as send:
            result = net.post_json("https://example.org/private?key=SECRET", {"key": "SECRET"})
        self.assertEqual(send.call_count, 1)
        self.assertNotIn("SECRET", result.error)

    def test_transient_failure_retries_and_preserves_final_http_status(self):
        with patch.object(net, "_polite_wait"), patch.object(net.time, "sleep"), \
                patch.object(net.urllib.request, "urlopen", side_effect=http_error(503)) as send:
            result = net.get("https://example.org")
        self.assertEqual(result.status, 503)
        self.assertEqual(send.call_count, 3)

    def test_tls_validation_failure_is_not_retried(self):
        failure = urllib.error.URLError(ssl.SSLCertVerificationError("bad certificate"))
        with patch.object(net, "_polite_wait"), patch.object(net.time, "sleep"), \
                patch.object(net.urllib.request, "urlopen", side_effect=failure) as send:
            result = net.get("https://example.org")
        self.assertEqual(send.call_count, 1)
        self.assertIn("TLS", result.error)

    def test_retry_after_numeric_and_http_date(self):
        now = datetime(2026, 10, 3, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(retry_after("7"), 7)
        self.assertEqual(retry_after("Sat, 03 Oct 2026 00:00:09 GMT", now), 9)
        self.assertEqual(retry_after("Fri, 02 Oct 2026 00:00:00 GMT", now), 0)
        for value in ("not a date", "nan", "inf"):
            self.assertIsNone(retry_after(value))

    def test_server_delay_is_not_shortened(self):
        with patch.object(net, "_polite_wait"), patch.object(net.time, "sleep") as sleep, \
                patch.object(net.urllib.request, "urlopen", side_effect=http_error(429, "3600")) as send:
            result = net.get("https://example.org")
        self.assertEqual(result.status, 429)
        self.assertEqual(result.metadata["state"], "blocked")
        self.assertEqual(send.call_count, 1)
        sleep.assert_not_called()

    def test_transient_recovery_and_sanitized_metadata(self):
        with patch.object(net, "_polite_wait"), patch.object(net.time, "sleep") as sleep, \
                patch.object(net.urllib.request, "urlopen", side_effect=[http_error(503, "4"), Response()]) as send:
            result = net.get("https://example.org/private?api_key=SECRET", extra_headers={"Authorization": "Bearer SECRET"})
        self.assertEqual(result.json(), {"ok": True})
        self.assertEqual(result.metadata["attempts"], 2)
        self.assertEqual(result.metadata["retry_count"], 1)
        self.assertEqual(result.metadata["retry_wait_seconds"], 4)
        sleep.assert_called_once_with(4)
        serialized = json.dumps(result.metadata)
        for forbidden in ("SECRET", "private", "api_key", "Bearer"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(send.call_count, 2)

    def test_retry_attempts_have_an_absolute_cap(self):
        self.assertEqual(RetryPolicy(retries=999).attempts("GET"), 5)
        self.assertEqual(RetryPolicy(retries=-1).attempts("GET"), 1)
        self.assertEqual(RetryPolicy(retries=999).attempts("POST"), 1)

    def test_unsupported_scheme_and_invalid_payload_do_not_send(self):
        with patch.object(net.urllib.request, "urlopen") as send:
            self.assertEqual(net.get("file:///private").status, 0)
            self.assertEqual(net.post_json("https://example.org", {"bad": object()}).status, 0)
        send.assert_not_called()

    def test_host_cooldown_respects_deadline(self):
        limiter = HostLimiter()
        limiter.defer("example.org", 30)
        started = time.monotonic()
        with self.assertRaises(HostWaitTimeout):
            limiter.wait("example.org", deadline=started + 0.1)
        self.assertLess(time.monotonic() - started, 0.1)
        limiter.wait("other.example.org", min_interval=0, deadline=started + 0.1)

    def test_host_concurrency_is_bounded(self):
        limiter = HostLimiter()
        lock = threading.Lock()
        active = 0
        peak = 0
        def work(_):
            nonlocal active, peak
            with limiter.slot("example.org", time.monotonic() + 2):
                with lock:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.02)
                with lock:
                    active -= 1
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(workers.map(work, range(8)))
        self.assertEqual(peak, 2)

    def test_host_starts_are_spaced_under_concurrency(self):
        limiter = HostLimiter()
        def start(_):
            limiter.wait("example.org", min_interval=0.02, deadline=time.monotonic() + 2)
            return time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as workers:
            times = sorted(workers.map(start, range(4)))
        self.assertTrue(all(b - a >= 0.018 for a, b in zip(times, times[1:])), times)

    def test_diagnostic_hook_receives_sanitized_terminal_metadata(self):
        with patch.object(net, "_polite_wait"), \
                patch.object(net.urllib.request, "urlopen", return_value=Response()), \
                patch("jf.diagnostics.record_network") as trace:
            result = net.get("https://example.org/private?api_key=SECRET")
        trace.assert_called_once_with(result.metadata)
        self.assertNotIn("SECRET", json.dumps(trace.call_args.args[0]))

    def test_diagnostic_failure_does_not_break_transport(self):
        with patch.object(net, "_polite_wait"), \
                patch.object(net.urllib.request, "urlopen", return_value=Response()), \
                patch("jf.diagnostics.record_network", side_effect=OSError("disk full")):
            self.assertEqual(net.get("https://example.org").json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
