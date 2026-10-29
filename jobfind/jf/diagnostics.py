"""Local, bounded collection traces without request bodies or credentials."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
import json
from pathlib import Path
import threading
import time
import uuid

_CURRENT = ContextVar("findall_collection_trace", default=None)
NETWORK_FIELDS = ("host", "method", "attempts", "retry_count", "retry_wait_seconds", "elapsed_seconds", "state", "status")
SOURCE_FIELDS = ("source", "state", "count", "elapsed_seconds", "filtered_count", "candidate_count", "method")


class CollectionTrace:
    def __init__(self):
        self.run_id = uuid.uuid4().hex
        self.started = time.monotonic()
        self.lock = threading.RLock()
        self.path = None
        self.pending = []
        self.source_starts = {}
        self.source_outcomes = {}
        self.network_requests = 0
        self.network_retries = 0
        self.network_failures = 0
        self.events = 0
        self.omitted = 0
        self.write_error = ""

    def attach(self, result):
        with self.lock:
            self.path = Path(result["report_json"]).resolve().with_name("diagnostics.jsonl")
            for item in self.pending:
                self._write(item)
            self.pending.clear()
            result["diagnostics"] = self.summary()
            result["diagnostics"]["trace_path"] = str(self.path)
            result.setdefault("exported_paths", {})["diagnostics_trace"] = str(self.path)

    def _write(self, item):
        try:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(item, ensure_ascii=False) + "\n")
        except OSError:
            self.write_error = "Could not write local diagnostic trace"

    def emit(self, event, fields):
        with self.lock:
            if self.events >= 1000:
                self.omitted += 1
                return
            item = {"run_id": self.run_id, "observed_at": datetime.now(timezone.utc).isoformat(),
                    "event": event, **fields}
            self.events += 1
            if self.path is not None:
                self._write(item)
            else:
                self.pending.append(item)

    def source(self, row):
        key = (row.get("source", "source"), row.get("url", ""))
        with self.lock:
            if row.get("state") in {"running", "attempted"}:
                self.source_starts.setdefault(key, time.monotonic())
            elif key in self.source_starts:
                row.setdefault("elapsed_seconds", round(time.monotonic() - self.source_starts.pop(key), 3))
            self.source_outcomes[key] = row.get("state", "unknown")
        self.emit("source", {key: row[key] for key in SOURCE_FIELDS if key in row})

    def network(self, metadata):
        safe = {key: metadata[key] for key in NETWORK_FIELDS if key in metadata}
        with self.lock:
            self.network_requests += 1
            self.network_retries += int(safe.get("retry_count", 0))
            self.network_failures += int(safe.get("state") != "ok")
        self.emit("http_request", safe)

    def summary(self):
        with self.lock:
            states = {}
            for state in self.source_outcomes.values():
                states[state] = states.get(state, 0) + 1
            return {"run_id": self.run_id, "elapsed_seconds": round(time.monotonic() - self.started, 3),
                    "network_requests": self.network_requests, "network_retries": self.network_retries,
                    "network_failures": self.network_failures, "source_states": states,
                    "events": self.events, "omitted_events": self.omitted,
                    "write_error": self.write_error,
                    "scope": "FindAll collection; external tools may use their own transports"}


@contextmanager
def trace_run():
    trace = CollectionTrace()
    token = _CURRENT.set(trace)
    try:
        yield trace
    finally:
        _CURRENT.reset(token)


def attach(result):
    trace = _CURRENT.get()
    if trace:
        trace.attach(result)


def record_source(row):
    trace = _CURRENT.get()
    if trace:
        trace.source(row)


def record_network(metadata):
    trace = _CURRENT.get()
    if trace:
        trace.network(metadata)


def traced_collection(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with trace_run() as trace:
            trace.emit("collection_started", {})
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                trace.emit("collection_failed", {"error_type": type(exc).__name__})
                raise
            trace.emit("collection_completed", {})
            result["diagnostics"].update(trace.summary())
            Path(result["report_json"]).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            return result
    return wrapped
