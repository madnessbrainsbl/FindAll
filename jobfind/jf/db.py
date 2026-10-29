"""SQLite-хранилище: вакансии, компании, контакты. Повторные запуски дедуплицируются."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    title TEXT, company TEXT, location TEXT,
    source TEXT, remote INTEGER, description TEXT, posted TEXT,
    found_emails TEXT,
    first_seen TEXT
);
CREATE TABLE IF NOT EXISTS companies (
    name TEXT PRIMARY KEY,
    source TEXT, domains TEXT, notes TEXT, first_seen TEXT
);
CREATE TABLE IF NOT EXISTS contacts (
    email TEXT PRIMARY KEY,
    company TEXT, kind TEXT, source TEXT, job_url TEXT, verified INTEGER, first_seen TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    ts TEXT, command TEXT, stats TEXT
);
CREATE TABLE IF NOT EXISTS projects (
    url TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    language TEXT,
    stars INTEGER DEFAULT 0,
    updated TEXT,
    query TEXT,
    first_seen TEXT
);
CREATE TABLE IF NOT EXISTS people_contacts (
    email TEXT PRIMARY KEY,
    company TEXT NOT NULL,
    domain TEXT NOT NULL,
    full_name TEXT,
    position TEXT,
    department TEXT,
    confidence INTEGER,
    verification TEXT,
    evidence TEXT,
    source TEXT NOT NULL DEFAULT 'Public website',
    first_seen TEXT,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS email_sends (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    recipient TEXT NOT NULL,
    company TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS osint_results (
    query TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    snippet TEXT,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (query, url)
);
CREATE TABLE IF NOT EXISTS osint_emails (
    query TEXT NOT NULL,
    url TEXT NOT NULL,
    email TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (query, url, email)
);
CREATE TABLE IF NOT EXISTS osint_pages (
    query TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    excerpt TEXT,
    observed_at TEXT NOT NULL,
    html_sha256 TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY (query, url)
);
CREATE TABLE IF NOT EXISTS osint_integrations (
    query TEXT NOT NULL,
    provider TEXT NOT NULL,
    payload TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (query, provider)
);
CREATE TABLE IF NOT EXISTS directory_businesses (
    url TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    city TEXT NOT NULL,
    address TEXT,
    phones TEXT NOT NULL,
    emails TEXT NOT NULL,
    websites TEXT NOT NULL,
    categories TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    source TEXT NOT NULL,
    query TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_cache (
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    expires_at REAL NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (domain, kind)
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row  # доступ к колонкам по имени в трекере и отчётах
    conn.executescript(SCHEMA)
    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cache_get_domain(conn: sqlite3.Connection, domain: str, kind: str) -> dict | None:
    """Извлечь кэшированные данные по домену, если TTL не истёк."""
    import time
    row = conn.execute(
        "SELECT data, expires_at FROM domain_cache WHERE domain=? AND kind=?",
        (domain.strip().lower(), kind),
    ).fetchone()
    if not row:
        return None
    data_str, expires_at = row[0], row[1]
    if time.time() > expires_at:
        return None
    try:
        return json.loads(data_str)
    except Exception:
        return None


def cache_set_domain(conn: sqlite3.Connection, domain: str, kind: str, data: dict, ttl_seconds: int = 86400) -> None:
    """Сохранить данные по домену в кэш с TTL (по умолчанию 24 часа)."""
    import time
    expires_at = time.time() + max(1, ttl_seconds)
    data_str = json.dumps(data, ensure_ascii=False)
    conn.execute(
        "INSERT INTO domain_cache (domain, kind, data, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(domain, kind) DO UPDATE SET data=excluded.data, expires_at=excluded.expires_at, created_at=excluded.created_at",
        (domain.strip().lower(), kind, data_str, expires_at, now_iso()),
    )
    conn.commit()


def save_jobs(conn: sqlite3.Connection, jobs: list[dict]) -> tuple[int, int]:
    """Вставка вакансий. Возвращает (новых, обновлённых)."""
    new = upd = 0
    ts = now_iso()
    for j in jobs:
        url = j.get("url") or ""
        if not url:
            continue
        existed = conn.execute("SELECT 1 FROM jobs WHERE url=?", (url,)).fetchone() is not None
        cur = conn.execute(
            "INSERT INTO jobs (url, title, company, location, source, remote, description, posted, found_emails, first_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(url) DO UPDATE SET title=excluded.title, company=excluded.company, "
            "location=excluded.location, source=excluded.source, remote=excluded.remote, "
            "description=excluded.description, posted=excluded.posted, found_emails=excluded.found_emails",
            (url, j.get("title"), j.get("company"), j.get("location"), j.get("source"),
             int(j.get("remote", False)), j.get("description"), j.get("posted"),
             j.get("found_emails", ""), ts),
        )
        if cur.rowcount:
            if existed:
                upd += 1
            else:
                new += 1
    conn.commit()
    return new, upd


def save_companies(conn: sqlite3.Connection, jobs: list[dict]) -> int:
    ts = now_iso()
    n = 0
    for j in jobs:
        name = (j.get("company") or "").strip()
        if not name or name.startswith("("):
            continue
        cur = conn.execute(
            "INSERT INTO companies (name, source, domains, notes, first_seen) VALUES (?,?,?,?,?) "
            "ON CONFLICT(name) DO NOTHING",
            (name, j.get("source", ""), "", "", ts),
        )
        n += cur.rowcount
    conn.commit()
    return n


def save_contacts(conn: sqlite3.Connection, emails: list[dict]) -> int:
    ts = now_iso()
    n = 0
    for e in emails:
        cur = conn.execute(
            "INSERT INTO contacts (email, company, kind, source, job_url, verified, first_seen) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(email) DO NOTHING",
            (e.get("email"), e.get("company"), e.get("kind"), e.get("source"), e.get("job_url"),
             int(bool(e.get("verified"))), ts),
        )
        n += cur.rowcount
    conn.commit()
    return n


def log_run(conn: sqlite3.Connection, command: str, stats: dict) -> None:
    conn.execute("INSERT INTO runs (ts, command, stats) VALUES (?,?,?)",
                 (now_iso(), command, json.dumps(stats, ensure_ascii=False)))
    conn.commit()


def save_osint_results(conn: sqlite3.Connection, query: str, rows: list[dict]) -> int:
    ts = now_iso()
    new = 0
    for row in rows:
        new += conn.execute(
            "INSERT INTO osint_results (query,url,title,snippet,source,category,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(query,url) DO NOTHING",
            (query, row["url"], row["title"], row["snippet"], row["source"], row["category"], ts, ts),
        ).rowcount
        conn.execute(
            "UPDATE osint_results SET title=?, snippet=?, source=?, category=?, last_seen=? "
            "WHERE query=? AND url=?",
            (row["title"], row["snippet"], row["source"], row["category"], ts, query, row["url"]),
        )
    conn.commit()
    return new


def save_osint_emails(conn: sqlite3.Connection, query: str, url: str, emails: list[str]) -> int:
    ts = now_iso()
    new = 0
    for email in emails:
        new += conn.execute(
            "INSERT OR IGNORE INTO osint_emails (query,url,email,first_seen) VALUES (?,?,?,?)",
            (query, url, email, ts),
        ).rowcount
    conn.commit()
    return new


def save_osint_integrations(conn: sqlite3.Connection, query: str, integrations: dict) -> None:
    for provider, payload in integrations.items():
        conn.execute(
            "INSERT INTO osint_integrations (query,provider,payload,observed_at) VALUES (?,?,?,?) "
            "ON CONFLICT(query,provider) DO UPDATE SET payload=excluded.payload, observed_at=excluded.observed_at",
            (query, provider, json.dumps(payload, ensure_ascii=False), now_iso()),
        )
    conn.commit()


def save_osint_page(conn: sqlite3.Connection, query: str, page: dict) -> None:
    conn.execute(
        "INSERT INTO osint_pages (query,url,title,excerpt,observed_at,html_sha256,snapshot) "
        "VALUES (?,?,?,?,?,?,?) ON CONFLICT(query,url) DO UPDATE SET "
        "title=excluded.title,excerpt=excluded.excerpt,observed_at=excluded.observed_at,"
        "html_sha256=excluded.html_sha256,snapshot=excluded.snapshot",
        (query, page["url"], page["title"], page["excerpt"], page["observed_at"],
         page["html_sha256"], page["snapshot"]),
    )
    conn.commit()


def save_projects(conn: sqlite3.Connection, projects: list[dict]) -> tuple[int, int]:
    new = updated = 0
    ts = now_iso()
    for p in projects:
        url = p.get("url") or ""
        if not url:
            continue
        existed = conn.execute("SELECT 1 FROM projects WHERE url=?", (url,)).fetchone() is not None
        conn.execute(
            "INSERT INTO projects (url, name, description, language, stars, updated, query, first_seen) "
            "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET "
            "name=excluded.name, description=excluded.description, language=excluded.language, "
            "stars=excluded.stars, updated=excluded.updated, query=excluded.query",
            (url, p.get("name", ""), p.get("description", ""), p.get("language", ""),
             int(p.get("stars") or 0), p.get("updated", ""), p.get("query", ""), ts),
        )
        if existed:
            updated += 1
        else:
            new += 1
    conn.commit()
    return new, updated


def save_people_contacts(conn: sqlite3.Connection, contacts: list[dict]) -> tuple[int, int]:
    new = updated = 0
    ts = now_iso()
    for c in contacts:
        email = (c.get("email") or "").strip().lower()
        if not email:
            continue
        existed = conn.execute("SELECT 1 FROM people_contacts WHERE email=?", (email,)).fetchone() is not None
        conn.execute(
            "INSERT INTO people_contacts (email, company, domain, full_name, position, department, "
            "confidence, verification, evidence, source, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(email) DO UPDATE SET company=excluded.company, domain=excluded.domain, "
            "full_name=excluded.full_name, position=excluded.position, department=excluded.department, "
            "confidence=excluded.confidence, verification=excluded.verification, evidence=excluded.evidence, "
            "source=excluded.source, last_seen=excluded.last_seen",
            (email, c.get("company", ""), c.get("domain", ""), c.get("full_name", ""),
             c.get("position", ""), c.get("department", ""), c.get("confidence", 0),
             c.get("verification", "unknown"), json.dumps(c.get("evidence", []), ensure_ascii=False),
             c.get("source", "Public website"), ts, ts),
        )
        if existed:
            updated += 1
        else:
            new += 1
    conn.commit()
    return new, updated


def save_directory_businesses(conn: sqlite3.Connection, query: str, rows: list[dict]) -> tuple[int, int]:
    new = updated = 0
    ts = now_iso()
    for row in rows:
        existed = conn.execute("SELECT 1 FROM directory_businesses WHERE url=?", (row["url"],)).fetchone()
        conn.execute(
            "INSERT INTO directory_businesses (url,name,city,address,phones,emails,websites,categories,"
            "latitude,longitude,source,query,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(url) DO UPDATE SET name=excluded.name,city=excluded.city,address=excluded.address,"
            "phones=excluded.phones,emails=excluded.emails,websites=excluded.websites,"
            "categories=excluded.categories,latitude=excluded.latitude,longitude=excluded.longitude,"
            "query=excluded.query,last_seen=excluded.last_seen",
            (row["url"], row["name"], row["city"], row["address"],
             json.dumps(row["phones"], ensure_ascii=False), json.dumps(row["emails"], ensure_ascii=False),
             json.dumps(row["websites"], ensure_ascii=False), json.dumps(row["categories"], ensure_ascii=False),
             row["latitude"], row["longitude"], "2GIS", query, ts, ts),
        )
        updated += bool(existed)
        new += not bool(existed)
    conn.commit()
    return new, updated


def log_email_send(conn: sqlite3.Connection, recipient: str, company: str, subject: str,
                   status: str, detail: str = "") -> None:
    conn.execute("INSERT INTO email_sends (ts, recipient, company, subject, status, detail) "
                 "VALUES (?,?,?,?,?,?)", (now_iso(), recipient, company, subject, status, detail[:500]))
    conn.commit()
