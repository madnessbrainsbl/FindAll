"""Run the vendored Parser2GIS engine and retain source-linked business records."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit, urljoin

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "third_party" / "parser-2gis"
EMAIL = re.compile(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}$")
COLUMNS = ("name", "address", "city", "phone", "email", "website", "category", "latitude", "longitude", "url")


def cities() -> list[dict]:
    path = UPSTREAM / "parser_2gis" / "data" / "cities.json"
    if not path.is_file():
        raise RuntimeError("Parser2GIS city catalog is missing. Restore third_party/parser-2gis.")
    return json.loads(path.read_text(encoding="utf-8"))


def search_url(query: str, city: str) -> tuple[str, str]:
    query = query.strip()
    if not 2 <= len(query) <= 200:
        raise ValueError("Enter a business name or category (2–200 characters).")
    wanted = city.strip().casefold()
    place = next((c for c in cities() if wanted in (str(c["code"]).casefold(), str(c["name"]).casefold())), None)
    if place is None:
        raise ValueError(f"Unknown 2GIS city: {city}. Use a city name or code from the city catalog.")
    url = f'https://2gis.{place["domain"]}/{place["code"]}/search/{quote(query, safe="")}/filters/sort=name'
    return url, place["name"]


def validate_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    domains = {f'2gis.{c["domain"]}' for c in cities()} | {"2gis.com"}
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in domains or parsed.username or parsed.password or parsed.port or not re.search(r"/(search|firm|geo)/", parsed.path):
        raise ValueError("Enter an HTTPS 2GIS search, firm, or building URL for a supported country.")
    return url.strip()


def _source_url(item: dict, search_url: str) -> str:
    identifier = str(item.get("id") or "").split("_")[0]
    parts = urlsplit(search_url)
    first = parts.path.strip("/").split("/")[0]
    city = "" if first in {"firm", "geo", "search"} else f"{first}/"
    return f"https://{parts.hostname}/{city}firm/{identifier}" if identifier.isdigit() else ""


def normalize(item: dict, search_url: str) -> dict | None:
    """Convert a 2GIS catalog item to a compact, sourced business record."""
    if not isinstance(item, dict):
        return None
    url = _source_url(item, search_url)
    if not url or item.get("is_deleted"):
        return None
    name_ex = item.get("name_ex") if isinstance(item.get("name_ex"), dict) else {}
    name = str(name_ex.get("primary") or item.get("name") or "").strip()
    if not name:
        return None
    groups = item.get("contact_groups") if isinstance(item.get("contact_groups"), list) else []
    contacts = [c for group in groups if isinstance(group, dict) and isinstance(group.get("contacts"), list)
                for c in group["contacts"] if isinstance(c, dict)]
    def values(kind: str) -> list[str]:
        return list(dict.fromkeys(str(c.get("value") or "").strip() for c in contacts if c.get("type") == kind and c.get("value")))
    emails = [v.lower() for v in values("email") if EMAIL.fullmatch(v)]
    websites = []
    for contact in contacts:
        if contact.get("type") != "website":
            continue
        value = str(contact.get("url") or contact.get("value") or "").strip()
        if value and "://" not in value:
            value = "https://" + value
        try:
            parsed = urlsplit(value)
            parsed.port  # Reject malformed port strings before retaining a URL.
            if parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password:
                websites.append(value)
        except ValueError:
            continue
    websites = list(dict.fromkeys(websites))
    point = item.get("point") if isinstance(item.get("point"), dict) else {}
    rubrics = item.get("rubrics") if isinstance(item.get("rubrics"), list) else []
    return {
        "name": name,
        "address": str(item.get("address_name") or ""),
        "city": str(item.get("city_alias") or ""),
        "phones": values("phone"),
        "emails": list(dict.fromkeys(emails)),
        "websites": websites,
        "categories": [str(r.get("name") or "") for r in rubrics if isinstance(r, dict) and r.get("name")],
        "latitude": point.get("lat"),
        "longitude": point.get("lon"),
        "url": url,
        "source": "2GIS",
    }


class CollectionRows(list):
    """List-compatible result with a visible partial/timeout state for the dossier."""
    def __init__(self, rows, status="ok", detail=""):
        super().__init__(rows)
        self.status, self.detail = status, detail


def _read_raw(path: Path) -> list[dict]:
    """Recover only complete items after a worker stops halfway through its JSON array."""
    if not path.is_file():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
        return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
    except ValueError:
        if not raw.lstrip().startswith("["):
            return []
        decoder, items, offset = json.JSONDecoder(), [], raw.index("[") + 1
        while offset < len(raw):
            while offset < len(raw) and raw[offset] in " \r\n\t,":
                offset += 1
            try:
                item, offset = decoder.raw_decode(raw, offset)
            except ValueError:
                break
            if isinstance(item, dict):
                items.append(item)
        return items


def collect(url: str, raw_path: Path, limit: int, delay_ms: int = 150, timeout: int = 150) -> list[dict]:
    """Run Parser2GIS in its own process; never allow upstream waits to hold the app."""
    url = validate_url(url)
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("2GIS limit must be 1–500")
    if not 1 <= timeout <= 900 or not 0 <= delay_ms <= 10_000:
        raise ValueError("2GIS timeout must be 1–900 seconds; delay must be 0–10000 ms")
    raw_path = Path(raw_path).resolve()
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    status_path = raw_path.with_suffix(".status.json")
    log_path = raw_path.with_suffix(".log")
    raw_path.write_text("[]", encoding="utf-8")
    status_path.write_text(json.dumps({"state": "attempted"}), encoding="utf-8")
    command = [sys.executable, "-m", "jf.two_gis", "--worker", url, str(raw_path), str(limit), str(delay_ms)]
    started, timed_out = time.monotonic(), False
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # The PID belongs to this worker; /T includes only its disposable Chrome tree.
            if os.name == "nt":
                try:
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
            else:
                process.kill()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
    raw = _read_raw(raw_path)
    rows = [normalize(item, url) for item in raw]
    unique = list({row["url"]: row for row in rows if row}.values())[:limit]
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status = {"error": "Worker stopped before writing its final status"}
    state = "timeout" if timed_out else "partial" if process.returncode and unique else "error" if process.returncode else "ok" if unique else "empty"
    detail = status.get("error", "")
    if unique and status.get('state') == 'partial':
        state, detail = 'partial', status.get('detail', '')
    if not unique and status.get('error_type') == 'TimeoutError':
        state = 'timeout'
    if not unique and re.search(r'HTTP (?:401|403|429)', detail):
        state = 'blocked'
    if timed_out:
        detail = f"Stopped at {timeout} seconds; retained {len(unique)} complete business records"
    elif not unique and not detail:
        detail = "2GIS returned no usable business records"
    status_path.write_text(json.dumps({"state": state, "count": len(unique), "detail": detail,
        "elapsed_seconds": round(time.monotonic() - started, 2), "url": url,
        "raw_report": str(raw_path), "log": str(log_path)}, indent=2), encoding="utf-8")
    if not unique:
        raise (TimeoutError if state == 'timeout' else RuntimeError)(f"{detail}. Diagnostics: {status_path}")
    if state != "ok":
        for row in unique:
            row["collection_status"], row["collection_warning"] = state, detail
    return CollectionRows(unique, state, detail)


def _collect_worker(url: str, raw_path: Path, limit: int, delay_ms: int) -> dict:
    def phase(name):
        raw_path.with_suffix('.status.json').write_text(json.dumps({'state':'attempted','phase':name}), encoding='utf-8')
    phase('loading_engine')
    if not UPSTREAM.is_dir():
        raise RuntimeError("Parser2GIS is missing. Restore third_party/parser-2gis.")
    if str(UPSTREAM) not in sys.path:
        sys.path.insert(0, str(UPSTREAM))
    try:
        from parser_2gis.chrome.utils import locate_chrome_path
        from parser_2gis.config import Configuration
        from parser_2gis.logger import logger as upstream_logger
        from parser_2gis.parser import get_parser
        from parser_2gis.writer.writers.json_writer import JSONWriter
    except ImportError as exc:
        raise RuntimeError("Parser2GIS dependencies are missing. Run setup.bat.") from exc
    chrome = locate_chrome_path()
    if not chrome:
        raise RuntimeError("Google Chrome is required for Parser2GIS.")
    config = Configuration()
    upstream_logger.addHandler(logging.NullHandler())
    upstream_logger.propagate = False
    config.chrome.binary_path = Path(chrome)
    config.chrome.headless = True
    import os
    config.chrome.proxy_server = os.environ.get("JOBFIND_ACTIVE_PROXY")
    config.parser.max_records = limit
    config.parser.delay_between_clicks = delay_ms
    config.writer.encoding = "utf-8"
    config.writer.verbose = False
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    class StrictJSONWriter(JSONWriter):
        def write(self, document):
            error = document.get("meta", {}).get("error") if isinstance(document, dict) else None
            if error:
                raise RuntimeError(f"2GIS returned an error: {error.get('message') if isinstance(error, dict) else error}")
            if not isinstance(document, dict) or document.get("meta", {}).get("code") != 200:
                raise RuntimeError("2GIS returned an unexpected catalog response.")
            super().write(document)
            self._file.flush()

    with StrictJSONWriter(str(raw_path), config.writer) as writer:
        phase('starting_browser')
        with get_parser(url, chrome_options=config.chrome, parser_options=config.parser) as parser:
            # Current pages also use fetch(); the upstream XHR counter can stay
            # undefined forever, and firm links no longer always contain stat=.
            def wait_requests():
                phase('waiting_page_requests')
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if parser._chrome_remote.execute_script('window.openHTTPs == undefined || window.openHTTPs == 0'):
                        return
                    time.sleep(0.2)
                raise TimeoutError('2GIS page requests did not finish within 20 seconds')
            def firm_links():
                phase('reading_business_links')
                deadline = time.monotonic() + 10
                while True:
                    tree = parser._chrome_remote.get_document()
                    found = tree.search(lambda node: node.local_name == 'a' and
                        urlsplit(urljoin(url, node.attributes.get('href', ''))).hostname == urlsplit(url).hostname and
                        bool(re.search(r'/(?:firm|station)/\d+(?:[/?#]|$)', node.attributes.get('href', ''))))
                    if found or time.monotonic() >= deadline:
                        return found
                    time.sleep(0.2)
            remote = parser._chrome_remote
            original_responses = remote.get_responses
            def checked_responses(*args, **kwargs):
                phase('reading_page_response')
                responses = original_responses(*args, **kwargs)
                if responses and responses[0].get('status', 0) >= 400:
                    raise RuntimeError('2GIS page returned HTTP ' + str(responses[0]['status']))
                return responses
            remote.get_responses = checked_responses
            original_response = remote.wait_response
            def bounded_response(pattern):
                phase('waiting_catalog_response')
                response = original_response(pattern, timeout=30)
                if not response:
                    raise TimeoutError('2GIS catalog response was not received within 30 seconds')
                if response.get('status', 0) >= 400:
                    raise RuntimeError('2GIS catalog returned HTTP ' + str(response['status']))
                return response
            remote.wait_response = bounded_response
            original_click = remote.perform_click
            def click_current(node, timeout=None):
                phase('opening_business')
                href = node.attributes.get('href', '')
                if not href:
                    return original_click(node, timeout=timeout)
                path = urlsplit(urljoin(url, href)).path
                for _ in range(3):
                    clicked = remote.execute_script('(() => { const link = [...document.querySelectorAll("a[href]")].find(a => '
                        'new URL(a.href).origin === location.origin && new URL(a.href).pathname === ' + json.dumps(path) +
                        '); if (!link) return false; link.click(); return true; })()')
                    if clicked:
                        return
                    time.sleep(0.2)
                raise RuntimeError('2GIS entry changed before it could be opened')
            remote.perform_click = click_current
            parser._wait_requests_finished = wait_requests
            if '/search/' in url:
                parser._get_links = firm_links
            phase('loading_page')
            try:
                parser.parse(writer)
            except (RuntimeError, TimeoutError) as exc:
                # A public search list can remain available when individual
                # cards fail. Retain its observed fields with explicit limits.
                retained = 0
                for response in reversed(original_responses()):
                    endpoint = urlsplit(response.get('url', ''))
                    if response.get('status') != 200 or endpoint.hostname not in {'catalog.api.2gis.ru','catalog.api.2gis.com'} or '/items' not in endpoint.path:
                        continue
                    try:
                        data = json.loads(remote.get_response_body(response, timeout=5))
                        if data.get('meta', {}).get('code') != 200:
                            continue
                        for item in data.get('result', {}).get('items', []):
                            if not isinstance(item, dict) or not normalize(item, url):
                                continue
                            writer.write({'meta':{'code':200}, 'result':{'items':[item]}})
                            retained += 1
                            if retained >= limit:
                                return {'state':'partial', 'detail':'Public search list retained; full business cards unavailable'}
                    except (ValueError, TypeError, KeyError):
                        continue
                if retained:
                    return {'state':'partial', 'detail':'Public search list retained; full business cards unavailable'}
                requests = remote.get_requests()
                endpoints = []
                for request in requests:
                    endpoint = urlsplit(request.get('url', ''))
                    if endpoint.hostname in {'catalog.api.2gis.ru','catalog.api.2gis.com'}:
                        response = request.get('response', {})
                        endpoints.append({'host':endpoint.hostname, 'status':response.get('status'),
                                          'error':response.get('statusText', '')[:120]})
                raw_path.with_suffix('.network.json').write_text(json.dumps(endpoints), encoding='utf-8')
                raise exc
    return {'state':'complete'}


def export(rows: list[dict], prefix: Path) -> tuple[Path, Path, Path]:
    from .report import write_csv
    json_path = prefix.with_suffix(".json")
    json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    flat = [{"name": r["name"], "address": r["address"], "city": r["city"],
             "phone": "; ".join(r["phones"]), "email": "; ".join(r["emails"]),
             "website": "; ".join(r["websites"]), "category": "; ".join(r["categories"]),
             "latitude": r["latitude"], "longitude": r["longitude"], "url": r["url"]} for r in rows]
    def safe_cell(value):
        return "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value
    csv_path = write_csv(prefix.with_suffix(".csv"), [{k: safe_cell(v) for k, v in row.items()} for row in flat], COLUMNS)
    import xlsxwriter
    xlsx_path = prefix.with_suffix(".xlsx")
    with xlsxwriter.Workbook(str(xlsx_path)) as book:
        sheet = book.add_worksheet("2GIS businesses")
        header = book.add_format({"bold": True})
        for col, key in enumerate(COLUMNS):
            sheet.write(0, col, key, header)
        for index, row in enumerate(flat, 1):
            for col, key in enumerate(COLUMNS):
                value = row[key]
                if isinstance(value, str):
                    sheet.write_string(index, col, value)
                else:
                    sheet.write(index, col, value)
        sheet.freeze_panes(1, 0)
        sheet.autofilter(0, 0, len(flat), len(COLUMNS) - 1)
    return json_path, csv_path, xlsx_path


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--worker":
        raw_path = Path(sys.argv[3])
        try:
            status = _collect_worker(validate_url(sys.argv[2]), raw_path, int(sys.argv[4]), int(sys.argv[5]))
        except Exception as exc:
            detail = re.sub(r'https?://[^\s\"<>]+', '[publisher endpoint]', str(exc))
            status = {"state": "error", "error": detail, "error_type": type(exc).__name__}
        raw_path.with_suffix(".status.json").write_text(json.dumps(status), encoding="utf-8")
        raise SystemExit(1 if status.get("error") else 0)
    raise SystemExit("Use FindAll 2GIS search to run this parser")
