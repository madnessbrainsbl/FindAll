"""Isolated public-page research; independent implementation, no extension code."""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from . import ai_agents, diagnostics, dossier, evidence_capture

SOURCE = "Browser research"
REFERENCE = "https://github.com/ir00nman/chrome-crawler"
ATTRIBUTION = "Observed public page content; linked entities, identity and ownership unverified"


def _origin(url):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _link(base, value):
    if not value:
        return ""
    url = urljoin(base, value)
    parsed = urlsplit(url)
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return url if ai_agents._url(url) else ""


def extract(html, url, limit):
    """Retain structured records with their source page, not inferred identities."""
    soup = BeautifulSoup(html, "html.parser")
    items, seen = [], set()

    def add(kind, title, text, linked=""):
        text = " ".join(text.split())[:6000]
        signature = (kind, text, linked)
        if text and signature not in seen and len(items) < limit:
            seen.add(signature)
            items.append(dict(kind=kind, title=title[:500], value=text, linked_url=linked))

    def walk(value, depth=0):
        if depth > 12 or len(items) >= limit:
            return
        if isinstance(value, list):
            for child in value[:100]:
                walk(child, depth + 1)
        elif isinstance(value, dict):
            if value.get("@type") and (value.get("name") or value.get("headline")):
                add("browser_jsonld", str(value.get("name") or value.get("headline")),
                    json.dumps(value, ensure_ascii=False), _link(url, str(value.get("url") or "")))
            for key in ("@graph", "itemListElement", "item"):
                walk(value.get(key), depth + 1)

    for script in soup.select('script[type="application/ld+json"]')[:100]:
        try:
            walk(json.loads(script.get_text()))
        except (ValueError, RecursionError):
            pass
    for table_index, table in enumerate(soup.select("table")[:30], 1):
        headers = [cell.get_text(" ", strip=True) for cell in table.select("tr th")[:50]]
        for row_index, row in enumerate(table.select("tr")[:101], 1):
            cells = [cell.get_text(" ", strip=True) for cell in row.find_all(["th", "td"], recursive=False)[:50]]
            if cells:
                add("browser_table_row", f"Table {table_index} · row {row_index}",
                    json.dumps(dict(table=table_index, row=row_index, columns=headers, cells=cells), ensure_ascii=False))
    for card in soup.select('article, [itemscope], .card, .product, .job, [data-testid*="card"]')[:200]:
        heading = card.select_one("h1,h2,h3,h4,[itemprop=name]")
        anchor = card.select_one("a[href]")
        add("browser_card", heading.get_text(" ", strip=True) if heading else "Page item",
            card.get_text(" ", strip=True), _link(url, anchor["href"]) if anchor else "")
    following = []
    for anchor in soup.select("a[href]"):
        label = anchor.get_text(" ", strip=True).casefold()
        if "next" in anchor.get("rel", []) or re.fullmatch(r"next(?: page)?|следующ(?:ая|ие)(?: страница)?|далее|[›»→]", label):
            target = _link(url, anchor["href"])
            if target and _origin(target) == _origin(url) and target not in following:
                following.append(target)
    return items, following[:8]


def _save_page(delta, html, url, folder, limit, screenshot, selector="", state_dir=None):
    body = html.encode("utf-8")
    page = dict(url=url, html=html, body=body, observed_at=datetime.now(timezone.utc).isoformat(),
                sha256=hashlib.sha256(body).hexdigest())
    evidence = evidence_capture.parse_evidence(page)
    if re.search(r"\b(captcha|just a moment|access denied|verify you are human|security verification)\b", evidence["title"], re.I):
        delta["statuses"].append(dict(source=SOURCE, url=url, state="blocked", count=0,
                                      detail="Challenge page excluded from evidence"))
        return []
    token = hashlib.sha256(url.encode()).hexdigest()[:20]
    raw, preview, textfile, metadata = [folder / (token + suffix) for suffix in (".dom.html", ".preview.html", ".txt", ".json")]
    raw.write_bytes(body)
    preview.write_text(evidence_capture._offline_preview(html), encoding="utf-8")
    textfile.write_text(evidence["text"], encoding="utf-8")
    metadata.write_text(json.dumps(dict(url=url, title=evidence["title"], observed_at=page["observed_at"],
        sha256=page["sha256"], files=[str(raw), str(preview), str(textfile)], raw_html_is_untrusted=True,
        method="Isolated Chromium rendered DOM; source responses fulfilled by pinned public fetcher")), encoding="utf-8")
    for path in (raw, preview, textfile, metadata, screenshot):
        if path and path.is_file():
            delta["artifacts"].append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                source=SOURCE, url=url, observed_at=page["observed_at"]))
    delta["web"].append(dict(url=url, title=evidence["title"], snippet=evidence["text"][:4000],
        source=SOURCE, observed_at=page["observed_at"], html_sha256=page["sha256"],
        artifact=str(preview), metadata=str(metadata), kind="captured_page", attribution=ATTRIBUTION))
    for section in ("emails", "profiles"):
        delta[section].extend(evidence[section])
    items, following = extract(html, url, limit - len(delta["findings"]))
    if selector:
        from . import scrapling_extract
        try:
            remaining = max(0, limit - len(delta["findings"]))
            if not remaining:
                raise ValueError("Structured item limit reached")
            selected, check = scrapling_extract.extract(html, url, selector, state_dir or folder / "selector-state", remaining)
            # Selected observations take priority inside the existing per-run record cap.
            items = (selected + items)[:max(0, limit - len(delta["findings"]))]
            delta["statuses"].append(check)
        except Exception as exc:
            delta["statuses"].append(dict(source=scrapling_extract.SOURCE, url=url, state="limited" if str(exc) == "Structured item limit reached" else "error", count=0,
                detail=f"Scrapling extraction failed ({type(exc).__name__}); page retained"))
    for item in items:
        prior = next((row for row in delta["findings"] if all(row.get(key) == item.get(key)
                     for key in ("kind", "value", "linked_url"))), None)
        if prior is not None:
            prior.setdefault("also_observed_on", []).append(url)
            continue
        delta["findings"].append({"url": url, "source": SOURCE, "observed_at": page["observed_at"],
                                   "sha256": page["sha256"], "attribution": ATTRIBUTION, **item})
    delta["statuses"].append(dict(source=SOURCE, url=url, state="ok" if evidence["text"].strip() or items else "empty",
                                  count=1 + len(items), detail="Rendered DOM and structured observations retained"))
    return following


def _render(url, folder, pages, items, selector="", state_dir=None):
    from playwright.sync_api import sync_playwright
    from .scrapling_extract import validate

    validate(selector)
    url, host, _addresses = evidence_capture.validated_url(url)
    if not ai_agents._url(url):
        raise ValueError("Choose a public source URL without credentials or secret query parameters")
    folder = Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    delta = {key: [] for key in ("web", "findings", "profiles", "emails", "artifacts", "statuses", "errors", "network_events")}
    report = folder / "browser-delta.json"
    temporary = folder / "browser-delta.tmp"
    deadline, requests, gaps, suppressed = time.monotonic() + 90, 0, 0, 0
    queue, visited, allowed_navigation, failures = [url], set(), {url}, {}
    executable = next((path for path in (
        Path(os.environ.get("CHROME_PATH", r"C:\Program Files\Google\Chrome\Application\chrome.exe")),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")) if path.is_file()), None)
    allowed_types = {"text/html", "application/xhtml+xml", "text/plain", "text/css", "application/javascript", "text/javascript", "application/json"}
    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=True, executable_path=str(executable) if executable else None,
            timeout=15000, args=["--disable-background-networking", "--disable-extensions", "--disable-sync", "--disable-quic",
                "--proxy-server=http://127.0.0.1:1", "--proxy-bypass-list=<-loopback>",
                "--host-resolver-rules=MAP * ~NOTFOUND", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
        try:
            context = browser.new_context(accept_downloads=False, service_workers="block", viewport={"width": 1280, "height": 800})
            context.set_default_timeout(5000)
            context.route_web_socket("**/*", lambda socket: socket.close())

            def fulfill(route):
                nonlocal requests, gaps, suppressed
                request = route.request
                meaningful = request.resource_type in {"document", "script", "stylesheet", "xhr", "fetch"}
                if (not meaningful or _origin(request.url) != _origin(url) or request.method != "GET"
                        or requests >= 40 or time.monotonic() >= deadline or request.is_navigation_request() and
                        (request.frame != page.main_frame or request.url.split("#")[0] not in allowed_navigation)):
                    gaps += int(meaningful)
                    suppressed += 1
                    route.abort()
                    return
                started, attempts, outcome = time.monotonic(), 0, "error"
                try:
                    for attempt in range(2):
                        requests += 1
                        attempts += 1
                        try:
                            response = evidence_capture.fetch_public(request.url, timeout=min(8, max(2, deadline - time.monotonic())),
                                max_body=2_000_000, accepted_types=allowed_types, allowed_hosts={host}, allowed_scheme=urlsplit(url).scheme,
                                request_headers={key: value for key, value in request.headers.items() if key.lower() in {"accept", "accept-language"}})
                            break
                        except OSError as exc:
                            if isinstance(exc, ssl.SSLCertVerificationError) or attempt or requests >= 40 or deadline - time.monotonic() < 3:
                                raise
                            time.sleep(.3)
                    if _origin(response["url"]) != _origin(url):
                        raise ValueError("Redirect outside the selected origin")
                    if response["url"] != request.url and request.is_navigation_request():
                        allowed_navigation.add(response["url"])
                        outcome = "ok"
                        route.fulfill(status=302, headers={"location": response["url"]}, body="")
                        return
                    if response["http_status"] >= 400:
                        gaps += 1
                    outcome = "ok"
                    route.fulfill(status=response["http_status"], content_type=response["content_type"], body=response["body"])
                except Exception as exc:
                    gaps += 1
                    failures[request.url] = ("blocked" if re.search(r"HTTP (401|403|429)\b", str(exc)) else
                                             "timeout" if isinstance(exc, TimeoutError) else "error")
                    route.abort()
                finally:
                    delta["network_events"].append(dict(host=host, method="GET", state=outcome,
                        attempts=attempts, retry_count=max(0, attempts - 1), elapsed_seconds=round(time.monotonic() - started, 3)))

            context.route("**/*", fulfill)
            page = context.new_page()
            def page_error(_error):
                nonlocal gaps
                gaps += 1
            page.on("pageerror", page_error)
            context.on("page", lambda popup: popup.close() if popup != page else None)
            while queue and len(visited) < pages and time.monotonic() < deadline and requests < 40:
                target = queue.pop(0)
                if target in visited:
                    continue
                visited.add(target)
                allowed_navigation.add(target)
                started = time.monotonic()
                before = gaps
                try:
                    response = page.goto(target, wait_until="domcontentloaded", timeout=min(20000, max(1000, int((deadline-time.monotonic())*1000))))
                    if response is None or response.status >= 400:
                        state = "blocked" if response and response.status in {401, 403, 429} else "error"
                        delta["statuses"].append(dict(source=SOURCE, url=target, state=state, count=0,
                            detail=f"HTTP {response.status}" if response else "No page response"))
                        continue
                    for _ in range(3):
                        if time.monotonic() >= deadline:
                            break
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(500)
                    html = page.content()
                    if len(html.encode("utf-8")) > 2_000_000:
                        raise ValueError("Rendered page exceeds 2 MB")
                    screenshot = folder / (hashlib.sha256(target.encode()).hexdigest()[:20] + ".png")
                    try:
                        page.screenshot(path=str(screenshot), full_page=False, timeout=3000)
                    except Exception:
                        screenshot = None
                    following = _save_page(delta, html, page.url, folder, items, screenshot, selector, state_dir)
                    queue.extend(link for link in following if link not in visited and link not in queue)
                    if gaps > before and delta["statuses"][-1]["state"] in {"ok", "empty"}:
                        delta["statuses"][-1].update(state="partial", detail="Page retained; some scripts, data requests or navigations were unavailable or outside scope")
                except Exception as exc:
                    delta["statuses"].append(dict(source=SOURCE, url=target, state=failures.get(target) or ("timeout" if "Timeout" in type(exc).__name__ else "error"),
                        count=0, detail=f"Browser page failed ({type(exc).__name__}); retained earlier pages are available"))
                finally:
                    if delta["statuses"]:
                        delta["statuses"][-1]["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    temporary.write_text(json.dumps(delta, ensure_ascii=False), encoding="utf-8")
                    temporary.replace(report)
        finally:
            browser.close()
    delta["statuses"].append(dict(source=SOURCE + "/coverage", state="partial" if queue or gaps or len(delta["findings"]) >= items else "ok",
        count=len(delta["web"]), detail=f"{len(visited)} pages attempted; {requests} resource fetch attempts; {suppressed} requests suppressed. "
        "Same-origin GET only; images, media, frames, forms and external resources excluded. "
        "Only linked next pages are followed; additional content may remain. "
        "Per page: 100,000 text characters; per record: 6,000 characters, table cells: 50."))
    temporary.write_text(json.dumps(delta, ensure_ascii=False), encoding="utf-8")
    temporary.replace(report)
    return delta


def collect(url, output, *, pages=3, items=50, selector="", state_dir=None):
    from .scrapling_extract import validate
    validate(selector)
    if type(pages) is not int or not 1 <= pages <= 8 or type(items) is not int or not 1 <= items <= 100:
        raise ValueError("Choose 1–8 pages and 1–100 structured items")
    url, _host, _addresses = evidence_capture.validated_url(url)
    if not ai_agents._url(url):
        raise ValueError("Choose a public source URL without credentials or secret query parameters")
    folder = Path(output).resolve() / "browser"
    folder.mkdir(parents=True, exist_ok=True)
    from .additional_tools import _run
    command = [sys.executable, "-m", "jf.browser_research", url, folder, pages, items]
    if selector:
        command.extend([selector, state_dir or folder / "selector-state"])
    code, _log = _run(command, Path(__file__).resolve().parents[1], 110)
    report = folder / "browser-delta.json"
    delta = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else dict(statuses=[], errors=[], web=[], findings=[])
    if code:
        delta["statuses"].append(dict(source=SOURCE, url=url, state="timeout" if code == 124 else "error", count=0,
            detail="Browser time budget reached; completed pages retained" if code == 124 else "Browser could not finish. Check Chrome/Edge and Playwright installation (setup.bat)."))
    return delta


@diagnostics.traced_collection
def run(url, output, *, question="", pages=3, items=50, ai=False, provider=None, model=None, selector=""):
    from .scrapling_extract import validate
    validate(selector)
    if not isinstance(question, str) or len(question) > 500:
        raise ValueError("Research question must contain at most 500 characters")
    if type(pages) is not int or not 1 <= pages <= 8 or type(items) is not int or not 1 <= items <= 100:
        raise ValueError("Choose 1–8 pages and 1–100 structured items")
    normalized, host, _addresses = evidence_capture.validated_url(url)
    folder = dossier._folder(Path(output) / "dossiers", question.strip() or host)
    result = dict(query=question.strip() or host, kind="query", scope="full", coverage="quick",
        observed_at=datetime.now(timezone.utc).isoformat(), report_json=str(folder / "dossier.json"), report_csv=str(folder / "dossier.csv"),
        sections=dict(web=[], profiles=[], emails=[], findings=[], domain=None), settings=dict(capture_pages=-1),
        source_checks=[], source_events=[], errors=[], counts={}, artifacts=[],
        browser_research=dict(url=normalized, pages=pages, items=items, reference=REFERENCE, implementation="FindAll independent browser collector"))
    diagnostics.attach(result)
    if selector:
        result["browser_research"].update(selector=selector, extraction_engine="Scrapling 0.5")
    delta = collect(normalized, folder, pages=pages, items=items, **(
        dict(selector=selector, state_dir=Path(output).resolve() / ".research" / "scrapling") if selector else {}))
    for event in delta.pop("network_events", []):
        diagnostics.record_network(event)
    dossier.merge_delta(result, delta)
    states = [row["state"] for row in result["source_checks"] if row["state"] not in {"ok", "empty"}]
    result["browser_research"]["status"] = ("partial" if states and result["sections"]["web"] else
        states[0] if states else "ok" if result["sections"]["web"] else "empty")
    dossier.save_ai_analysis(result, ai_agents.analyze_dossier(result, provider=provider, model=model) if ai else
                            dict(status="skipped", claims=[], answer="", reason="AI analysis was not selected"))
    return result


if __name__ == "__main__":
    _render(sys.argv[1], Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]),
            sys.argv[5] if len(sys.argv) > 5 else "", Path(sys.argv[6]) if len(sys.argv) > 6 else None)
