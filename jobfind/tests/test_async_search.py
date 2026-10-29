"""Synthetic concurrent source adapters; no network requests."""
import asyncio
import threading
import time
import unittest
from unittest.mock import patch

from jf import diagnostics, osint


class AsyncSearchTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_limit_errors_callbacks_and_context(self):
        lock = threading.Lock()
        active = peak = 0
        def fetch(query, source, limit):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.02)
                diagnostics.record_network({"host": "example.org", "method": "GET", "state": "ok", "retry_count": 1})
                if source == "broken":
                    raise RuntimeError("HTTP 503")
                return [{"url": "https://example.org/", "title": "Synthetic", "source": source}]
            finally:
                with lock:
                    active -= 1
        callbacks = []
        names = ["a", "b", "broken", "c", "d", "e", "a"]
        with (patch.dict(osint.SEARCHERS, {name: lambda q, n, s=name: fetch(q, s, n) for name in names}),
              diagnostics.trace_run() as trace):
            rows, errors, statuses = await osint.search_async("sample", names, lambda *item: callbacks.append(item))
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 4)
        self.assertEqual(len(callbacks), 6)
        self.assertEqual([row["source"] for row in statuses], list(dict.fromkeys(names)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(next(row for row in statuses if row["source"] == "broken")["state"], "error")
        self.assertEqual(trace.summary()["network_retries"], 6)

    async def test_cancellation_stops_queued_adapters(self):
        started = []
        gate = threading.Event()
        def fetch(query, source, limit):
            started.append(source)
            gate.wait(2)
            return []
        try:
            with patch.dict(osint.SEARCHERS, {str(i): lambda q, n, s=str(i): fetch(q, s, n) for i in range(12)}):
                task = asyncio.create_task(osint.search_async("sample", [str(i) for i in range(12)]))
                for _ in range(100):
                    if len(started) == 4:
                        break
                    await asyncio.sleep(0.005)
                self.assertEqual(len(started), 4)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertEqual(len(started), 4)
        finally:
            gate.set()

    async def test_sync_entry_inside_event_loop_stays_compatible(self):
        with patch.dict(osint.SEARCHERS, {"synthetic": lambda q, n: []}):
            self.assertEqual(osint.search("sample", ["synthetic"])[2][0]["state"], "empty")


if __name__ == "__main__":
    unittest.main()
