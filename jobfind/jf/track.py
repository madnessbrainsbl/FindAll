"""Трекер откликов: статусы по вакансиям/компаниям в той же SQLite-базе.

Статусы: new → contacted → interview → offer / rejected / closed.
Поля: job_url (ключ, опционален), company, role, contact, status, next_date, notes.
"""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path

from .db import connect, now_iso

STATUSES = ("new", "contacted", "interview", "offer", "rejected", "closed")

TRACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY,
    job_url TEXT,
    company TEXT NOT NULL,
    role TEXT DEFAULT '',
    contact TEXT DEFAULT '',
    status TEXT DEFAULT 'new',
    next_date TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    updated TEXT
);
"""


def _ensure(conn: sqlite3.Connection) -> None:
    conn.executescript(TRACK_SCHEMA)


def add(conn: sqlite3.Connection, company: str, role: str = "", job_url: str = "",
        contact: str = "", status: str = "new", next_date: str = "", notes: str = "") -> int:
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
    _ensure(conn)
    cur = conn.execute(
        "INSERT INTO applications (job_url, company, role, contact, status, next_date, notes, updated) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (job_url, company, role, contact, status, next_date, notes, now_iso()),
    )
    conn.commit()
    return cur.lastrowid


def update_status(conn: sqlite3.Connection, app_id: int, status: str,
                  next_date: str = None, notes: str = None) -> bool:
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
    _ensure(conn)
    sets = ["status=?", "updated=?"]
    vals = [status, now_iso()]
    if next_date is not None:
        sets.append("next_date=?")
        vals.append(next_date)
    if notes is not None:
        sets.append("notes=?")
        vals.append(notes)
    vals.append(app_id)
    cur = conn.execute(f"UPDATE applications SET {', '.join(sets)} WHERE id=?", vals)
    conn.commit()
    return cur.rowcount > 0


def find_by_url(conn: sqlite3.Connection, job_url: str) -> list[sqlite3.Row]:
    _ensure(conn)
    return conn.execute("SELECT * FROM applications WHERE job_url=?", (job_url,)).fetchall()


def list_all(conn: sqlite3.Connection, status: str = "") -> list[sqlite3.Row]:
    _ensure(conn)
    if status:
        return conn.execute(
            "SELECT * FROM applications WHERE status=? ORDER BY updated DESC", (status,)).fetchall()
    return conn.execute(
        "SELECT * FROM applications ORDER BY CASE status "
        "WHEN 'offer' THEN 0 WHEN 'interview' THEN 1 WHEN 'contacted' THEN 2 "
        "ELSE 3 END, updated DESC").fetchall()


def stats(conn: sqlite3.Connection) -> dict:
    _ensure(conn)
    out = {s: 0 for s in STATUSES}
    for s, n in conn.execute("SELECT status, COUNT(*) FROM applications GROUP BY status"):
        out[s] = n
    return out


def next_followups(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Активные заявки с назначенной датой следующего шага (включая просроченные)."""
    _ensure(conn)
    return conn.execute(
        "SELECT * FROM applications WHERE next_date != '' "
        "AND next_date <= ? AND status IN ('new','contacted','interview') ORDER BY next_date",
        (date.today().isoformat(),)).fetchall()
