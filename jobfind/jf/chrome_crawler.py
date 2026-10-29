"""Offline import of explicitly exported Chrome crawler page observations."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import dossier, flowsint

SOURCE = "Chrome crawler / imported DOM"
UPSTREAM = "https://github.com/ir00nman/chrome-crawler"
COMMIT = "664f5fa9cc7c374638d07ae7eddcee9f282bebf3"
ATTRIBUTION = ("User-selected browser DOM; imported observation, not independently verified. "
               "Public visibility, identity and ownership unverified; linked pages were not fetched.")
MAX_BYTES = 2_000_000


def _text(value, limit):
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise ValueError("Invalid Chrome crawler text field")
    return value


def load(path: Path) -> tuple[dict, bytes]:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Chrome crawler export exceeds 2 MB")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("Choose a valid Chrome crawler FindAll JSON export") from None
    fields = {"schema", "url", "title", "text", "observed_at", "extension_version", "items", "text_truncated"}
    if not isinstance(data, dict) or set(data) != fields or data.get("schema") != "findall.chrome-crawler.v1":
        raise ValueError("Unsupported Chrome crawler export schema")
    data["url"] = flowsint.entity("Website", data["url"])["value"]
    host = urlsplit(data["url"]).hostname
    if host.endswith((".test", ".invalid", ".onion")):
        raise ValueError("Choose an HTTPS page on a public hostname")
    for key, limit in (("title", 500), ("text", 100_000), ("extension_version", 40), ("observed_at", 80)):
        _text(data[key], limit)
    try:
        stamp = datetime.fromisoformat(data["observed_at"].replace("Z", "+00:00"))
        if stamp.utcoffset() is None:
            raise ValueError()
    except ValueError:
        raise ValueError("Chrome crawler observation time must include a timezone") from None
    if type(data["text_truncated"]) is not bool:
        raise ValueError("Invalid Chrome crawler truncation flag")
    listing = data["items"]
    if (not isinstance(listing, dict) or set(listing) != {"method", "total", "items"}
            or not isinstance(listing["items"], list) or len(listing["items"]) > 100
            or type(listing["total"]) is not int or not len(listing["items"]) <= listing["total"] <= 1_000_000):
        raise ValueError("Invalid Chrome crawler listing limits")
    _text(listing["method"], 80)
    for item in listing["items"]:
        if (not isinstance(item, dict) or set(item) != {"title", "url", "details", "price", "currency"}
                or (item["price"] is not None and (type(item["price"]) not in (int, float)
                    or not 0 <= item["price"] <= 1e15))):
            raise ValueError("Invalid Chrome crawler listing")
        for key, limit in (("title", 500), ("details", 2000), ("currency", 20)):
            _text(item[key], limit)
        if item["url"]:
            item["url"] = flowsint.entity("Website", item["url"])["value"]
        else:
            _text(item["url"], 1800)
    return data, raw


def _delta(data: dict, raw: bytes, output: Path) -> dict:
    digest = hashlib.sha256(raw).hexdigest()
    folder = Path(output) / digest
    folder.mkdir(parents=True, exist_ok=True)
    snapshot = folder / "chrome-crawler.json"
    snapshot.write_bytes(raw)
    textfile = folder / "page.txt"
    textfile.write_text(data["text"], encoding="utf-8")
    common = dict(url=data["url"], source=SOURCE, observed_at=data["observed_at"],
                  sha256=digest, artifact=str(snapshot), attribution=ATTRIBUTION,
                  category="Imported browser observation", kind="browser_dom", status="candidate; imported browser observation")
    state = "partial" if data["text_truncated"] or data["items"]["total"] > len(data["items"]["items"]) else "ok"
    blocked = re.search(r"\b(captcha|just a moment|access denied|verify you are human|security verification)\b",
                        data["title"], re.I)
    web, findings = [], []
    if blocked:
        state = "blocked"
    elif data["text"].strip() or data["items"]["items"]:
        web.append({**common, "title": data["title"], "snippet": data["text"][:4000], "text": data["text"]})
        for item in data["items"]["items"]:
            findings.append({**common, "kind": "browser_listing", "title": item["title"],
                             "value": json.dumps(item, ensure_ascii=False, allow_nan=False),
                             "linked_url": item["url"], "method": data["items"]["method"]})
    elif state != "partial":
        state = "empty"
    return dict(web=web, findings=findings, errors=[], status=state,
        browser_import=dict(reference=UPSTREAM, reference_commit=COMMIT, status=state,
            extension_version=data["extension_version"], observation_time=data["observed_at"],
            imported_at=datetime.now(timezone.utc).isoformat(), listing_method=data["items"]["method"],
            listing_total=data["items"]["total"], text_truncated=data["text_truncated"]),
        artifacts=[dict(path=str(snapshot), kind="browser_dom_import", sha256=digest,
                        source=SOURCE, url=data["url"], observed_at=data["observed_at"], attribution=ATTRIBUTION),
                   dict(path=str(textfile), kind="browser_text", sha256=hashlib.sha256(textfile.read_bytes()).hexdigest(),
                        source=SOURCE, url=data["url"], observed_at=data["observed_at"], attribution=ATTRIBUTION)],
        statuses=[dict(source=SOURCE, state=state, count=len(web) + len(findings), url=data["url"],
                       method="explicit local file import; no network requests",
                       detail="Challenge page excluded from evidence" if blocked else
                              "Imported user-selected DOM; linked pages not fetched. " +
                              ("Export is truncated." if state == "partial" else ""))])


def collect(paths, output: Path, on_status=None) -> dict:
    """Import only selected files; isolate malformed inputs from other evidence."""
    if not isinstance(paths, (list, tuple)) or len(paths) > 10:
        raise ValueError("Choose at most 10 Chrome crawler exports")
    result = {key: [] for key in ("web", "findings", "artifacts", "statuses", "errors")}
    for index, path in enumerate(dict.fromkeys(str(Path(p).resolve()) for p in paths), 1):
        try:
            data, raw = load(Path(path))
            delta = _delta(data, raw, output)
        except (ValueError, OSError) as exc:
            detail = str(exc) if isinstance(exc, ValueError) else "Could not read or save selected browser export"
            delta = dict(errors=[f"Browser file {index}: {detail}"], statuses=[dict(
                source=f"{SOURCE} / file {index}", state="error", count=0, detail=detail)])
        for key in result:
            result[key].extend(delta.get(key, []))
        if on_status:
            for row in delta["statuses"]:
                on_status(row)
    states = [row["state"] for row in result["statuses"]]
    count = len(result["web"]) + len(result["findings"])
    gaps = any(state in {"partial", "error", "blocked"} for state in states)
    result["status"] = ("partial" if count and gaps else "ok" if count else
                        "error" if "error" in states else "blocked" if "blocked" in states else
                        "partial" if "partial" in states else "empty")
    return result


def import_page(path: Path, output: Path, *, query: str = "") -> dict:
    data, raw = load(path)
    query = _text(query, 500).strip() or data["title"] or data["url"]
    folder = dossier._folder(Path(output) / "dossiers", query)
    delta = _delta(data, raw, folder / "artifacts" / "chrome-crawler")
    result = dict(query=query, kind="query", scope="full", coverage="quick",
        observed_at=datetime.now(timezone.utc).isoformat(),
        sections=dict(web=[], profiles=[], emails=[], findings=[], domain=None),
        source_checks=[], source_events=[], errors=[], artifacts=[],
        settings=dict(capture_pages=-1), report_json=str(folder / "dossier.json"),
        report_csv=str(folder / "dossier.csv"), browser_import=delta["browser_import"])
    dossier.merge_delta(result, delta)
    with Path(result["report_csv"]).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=dossier.CSV_FIELDS)
        writer.writeheader()
        writer.writerows(dossier._report_rows(result))
    dossier.save_relationship_graph(result)
    return result
