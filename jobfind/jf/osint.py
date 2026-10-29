"""Поиск открытых публикаций с URL источника и необязательными официальными API."""

from __future__ import annotations

import asyncio
from contextvars import copy_context
import html
import os
import re
import time
from defusedxml import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlsplit

from bs4 import BeautifulSoup

from . import net


ENGINES = ("google", "yandex", "bing", "duckduckgo", "yahoo", "brave", "mojeek")
SOURCES = ENGINES + ("web", "wikipedia", "news", "github", "public")


class SearchRows(list):
    """A list-compatible result with counts before relevance filtering."""
    def __init__(self, rows=(), *, candidates=0, filtered=0, method="", statuses=()):
        super().__init__(rows)
        self.candidates = candidates
        self.filtered = filtered
        self.method = method
        self.statuses = list(statuses)


def _clean(value: object, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", " ", str(value or "")))).strip()[:limit]


def _result(title: object, url: object, snippet: object, source: str, category: str) -> dict | None:
    url = str(url or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    title = _clean(title, 200)
    if not title:
        return None
    return {"title": title, "url": url, "snippet": _clean(snippet),
            "source": source, "category": category}


def _relevant(row: dict, query: str) -> bool:
    # One precise handle/domain should occur in the returned evidence, not just a fuzzy rank.
    alias = query.strip().lstrip("@").casefold()
    if not re.fullmatch(r"[a-z0-9_.-]{6,}", alias):
        if (re.fullmatch(r"[\w\s]+", alias) and len(alias.split()) > 1
                and not re.search(r"\b(?:OR|AND|NOT)\b", query)):
            evidence = unquote(f"{row['title']} {row['snippet']} {row['url']}").casefold().replace("ё", "е")
            def matches(word):
                word = word.replace("ё", "е")
                if word in evidence:
                    return True
                if re.fullmatch(r"[а-я]{3,}[ая]", word):
                    return bool(re.search(r"\b" + re.escape(word[:-1]) + r"(?:а|я|е|ы|и|у|ю|ой|ою|ей|ею)\b", evidence))
                return False
            return all(matches(word) for word in alias.split())
        return True
    if "." in alias and ((urlsplit(row.get("url", "")).hostname or "").casefold() == alias or
                          (urlsplit(row.get("url", "")).hostname or "").casefold().endswith("." + alias)):
        return True
    return bool(re.search(r"(?<![a-z0-9_.-])" + re.escape(alias) + r"(?![a-z0-9_.-])",
                          unquote(f"{row['title']} {row['snippet']} {row['url']}").casefold()))


def _json(url: str, params: dict, source: str) -> dict:
    response = net.get(url, params, retries=1)
    data = response.json(log_errors=False)
    if not isinstance(data, dict):
        raise RuntimeError(f"{source}: {response.error or 'invalid response'}")
    return data


def _web(query: str, limit: int = 10) -> list[dict]:
    response = net.get("https://www.bing.com/search", {"format": "rss", "q": query, "count": limit}, retries=0)
    if not response.body:
        raise RuntimeError(f"Bing: {response.error or 'empty response'}")
    root = ET.fromstring(response.body)
    rows, candidates, filtered = [], 0, 0
    for item in root.findall(".//item")[:limit]:
        row = _result(item.findtext("title"), item.findtext("link"),
                      item.findtext("description"), "Bing RSS", "Web")
        if row:
            candidates += 1
            if _relevant(row, query):
                rows.append(row)
            else:
                filtered += 1
    result = SearchRows(rows, candidates=candidates, filtered=filtered, method="Bing RSS")
    if candidates and not rows:
        result.warning = "Bing returned unrelated entries; the requested query was not confirmed"
    return result


def _engine(query: str, backend: str, limit: int = 10) -> list[dict]:
    """Collect several result pages. One page is about ten links."""
    from . import search_api
    if search_api.configured(backend):
        return search_api.search(query, backend, limit)
    # DDGS silently replaces unavailable backends with "auto". Bing and Yandex
    # are disabled in current DDGS releases; never label another engine as them.
    if backend == "bing":
        return _web(query, limit)
    if backend == "yandex":
        return _engine_html(query, backend, limit)
    try:
        from ddgs import DDGS
        from ddgs.engines import ENGINES as installed_engines
    except ImportError as exc:
        raise RuntimeError("DDGS is not installed: run setup.bat") from exc
    if backend not in installed_engines.get("text", {}):
        return _google_browser(query, limit) if backend == "google" else _engine_html(query, backend, limit)
    region = "ru-ru" if re.search(r"[А-Яа-яЁё]", query) else "us-en"
    client = DDGS(timeout=12, proxy=os.environ.get("JOBFIND_ACTIVE_PROXY"))
    rows: list[dict] = []
    seen: set[str] = set()
    failure: Exception | None = None
    candidates, filtered = 0, 0
    for page in range(1, max(1, (limit + 9) // 10) + 1):
        try:
            found = client.text(query, backend=backend, region=region, max_results=10, page=page)
        except Exception as exc:
            failure = exc
            break
        added = 0
        for item in found or []:
            if not isinstance(item, dict):
                continue
            row = _result(item.get("title"), item.get("href"), item.get("body"),
                          backend.capitalize(), "Web")
            if not row or row["url"] in seen:
                continue
            candidates += 1
            if not _relevant(row, query):
                filtered += 1
                continue
            seen.add(row["url"])
            rows.append(row)
            added += 1
            if len(rows) >= limit:
                return SearchRows(rows, candidates=candidates, filtered=filtered, method="DDGS exact backend")
        if added == 0:
            break
    if rows:
        result = SearchRows(rows, candidates=candidates, filtered=filtered, method="DDGS exact backend")
        if failure:
            rows[0]["_source_warning"] = f"Later search page failed: {failure}"
        return result
    if candidates:
        return SearchRows(candidates=candidates, filtered=filtered, method="DDGS exact backend")
    if backend == "google":
        # DDGS 9.x still uses Google's obsolete Nokia/WML endpoint. The normal
        # browser search stays Google, with no substitute provider or CAPTCHA bypass.
        return _google_browser(query, limit)
    # "No results found" in DDGS also means HTTP 403/429, a CAPTCHA or a
    # changed parser. Confirm against that same engine's public search page.
    return _engine_html(query, backend, limit)


def _search_challenge(document: str, url: str = "") -> bool:
    soup = BeautifulSoup(document or "", "html.parser")
    text = soup.get_text(" ", strip=True).casefold()
    title = soup.title.get_text(" ", strip=True).casefold() if soup.title else ""
    return (_google_blocked(document, url) or "captcha" in title or
            bool(soup.select('form[action*="anomaly"], form[action*="checkcaptcha"], iframe[src*="hcaptcha"], #challenge-form')) or
            any(message in text for message in ("javascript is required to complete this challenge",
                "confirm you are not a robot", "please complete the following challenge", "unfortunately, bots use duckduckgo too")))


def _engine_html_rows(document: str, backend: str, query: str, limit: int) -> SearchRows:
    soup = BeautifulSoup(document or "", "html.parser")
    selectors = {
        "duckduckgo": "a.result__a, a.result-link",
        "brave": '[data-type="web"] a[href]:has(h3), [data-type="web"] a[href]:has(.title), .snippet a[href]:has(.title)',
        "mojeek": "ul.results h2 a[href]",
        "yandex": '.serp-item h2 a[href], .serp-item h3 a[href], .OrganicTitle-Link[href]',
    }
    if backend not in selectors:
        raise RuntimeError(f"No exact-source HTML adapter for {backend}")
    bases = {"duckduckgo": "https://html.duckduckgo.com", "brave": "https://search.brave.com",
             "mojeek": "https://www.mojeek.com", "yandex": "https://yandex.com"}
    rows, seen, candidates, filtered = [], set(), 0, 0
    for anchor in soup.select(selectors[backend]):
        url = urljoin(bases[backend], str(anchor.get("href", "")))
        if backend == "duckduckgo":
            url = parse_qs(urlsplit(url).query).get("uddg", [url])[0]
        if (urlsplit(url).hostname or "").lower() == urlsplit(bases[backend]).hostname:
            continue
        block = (anchor.find_parent(["li", "article"]) or
                 anchor.find_parent(class_=re.compile(r"(?:^|\s)(?:result|snippet|serp-item)(?:\s|$)")) or anchor.parent)
        row = _result(anchor.get_text(" ", strip=True), url, block.get_text(" ", strip=True), backend.capitalize(), "Web")
        if not row or url in seen:
            continue
        seen.add(url)
        candidates += 1
        if not _relevant(row, query):
            filtered += 1
            continue
        rows.append(row)
        if len(rows) >= limit:
            break
    return SearchRows(rows, candidates=candidates, filtered=filtered, method="same-engine public HTML")


def _engine_html(query: str, backend: str, limit: int = 10) -> list[dict]:
    from .evidence_capture import fetch_public
    endpoints = {"duckduckgo": "https://html.duckduckgo.com/html/?q=", "brave": "https://search.brave.com/search?q=",
                 "mojeek": "https://www.mojeek.com/search?q=", "yandex": "https://yandex.com/search/?text="}
    if backend not in endpoints:
        raise RuntimeError(f"Search backend {backend} is unavailable; no substitute provider was used")
    url = endpoints[backend] + quote_plus(query)
    document = fetch_public(url, timeout=12, max_body=3_000_000)
    if _search_challenge(document["html"], document["url"]):
        raise RuntimeError("CAPTCHA/human verification required; automated search stopped")
    rows = _engine_html_rows(document["html"], backend, query, limit)
    if rows.candidates:
        return rows
    text = BeautifulSoup(document["html"], "html.parser").get_text(" ", strip=True).casefold()
    if any(message in text for message in ("no results found", "no results were found", "did not match any documents",
            "no results.", "ничего не найдено", "по вашему запросу ничего не нашлось")):
        return rows
    raise RuntimeError(f"HTTP {document['http_status']} search page contained no recognized results; parser or access restriction, not confirmed empty")


def _google_rows(document: str, query: str, limit: int = 10) -> list[dict]:
    """Parse modern desktop and mobile Google results without CSS class names."""
    soup = BeautifulSoup(document or "", "html.parser")
    rows, seen = [], set()
    for heading in soup.select("h3"):
        anchor = heading.find_parent("a", href=True) or heading.find("a", href=True)
        if anchor is None:
            continue
        url = urljoin("https://www.google.com", str(anchor.get("href", "")))
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        if host in {"www.google.com", "google.com"} and parsed.path == "/url":
            params = parse_qs(parsed.query)
            url = (params.get("q") or params.get("url") or [""])[0]
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or not host:
            continue
        if host in {"www.google.com", "google.com", "accounts.google.com", "consent.google.com"} and parsed.path in {"/search", "/url", "/preferences", "/setprefs", "/advanced_search", "/sorry/index"}:
            continue
        block = anchor
        # Class names rotate. The smallest ancestor carrying text beyond the
        # title generally contains the displayed description.
        for _ in range(4):
            if block.parent is None or len(block.parent.select("h3")) > 1:
                break
            block = block.parent
            text = block.get_text(" ", strip=True)
            if len(text) > len(heading.get_text(" ", strip=True)) + 70:
                break
        row = _result(heading.get_text(" ", strip=True), url, block.get_text(" ", strip=True), "Google", "Web")
        if row and row["url"] not in seen and _relevant(row, query):
            seen.add(row["url"])
            rows.append(row)
            if len(rows) >= limit:
                break
    return rows


def _google_blocked(document: str, url: str = "") -> bool:
    soup = BeautifulSoup(document or "", "html.parser")
    text = soup.get_text(" ", strip=True).casefold()
    return ("/sorry/" in urlsplit(url).path or bool(soup.select('form[action*="sorry"], iframe[src*="recaptcha"], .g-recaptcha')) or
            any(message in text for message in ("unusual traffic from your computer network", "our systems have detected unusual traffic", "verify you are human", "complete the captcha")))


def _google_browser(query: str, limit: int = 10) -> list[dict]:
    """Normal Google Chrome search, bounded and routed through public pinned DNS."""
    from .evidence_capture import fetch_public
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Google browser fallback requires Playwright: run setup.bat") from exc
    limit = max(1, min(int(limit), 100))
    deadline = time.monotonic() + 45
    allowed_hosts = {"www.google.com", "google.com", "consent.google.com", "www.gstatic.com"}
    mime_types = {"text/html", "application/xhtml+xml", "application/javascript", "text/javascript", "text/css", "text/plain", "application/json"}
    executable = next((path for path in (
        Path(os.environ.get("CHROME_PATH", r"C:\Program Files\Google\Chrome\Application\chrome.exe")),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")) if path.is_file()), None)
    fetched, failures, rows, seen, candidates, filtered = 0, [], [], set(), 0, 0
    language = "ru" if re.search(r"[А-Яа-яЁё]", query) else "en"
    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=True, executable_path=str(executable) if executable else None, timeout=15000,
                                         args=["--disable-background-networking", "--disable-extensions", "--disable-sync", "--disable-quic"])
        try:
            context = browser.new_context(accept_downloads=False, service_workers="block", locale=language)
            if hasattr(context, "route_web_socket"):
                context.route_web_socket("**/*", lambda socket: socket.close())
            def fulfill(route):
                nonlocal fetched
                request = route.request
                target = urlsplit(request.url)
                if (target.scheme != "https" or target.hostname not in allowed_hosts or request.resource_type not in {"document", "script", "stylesheet", "xhr", "fetch"}
                        or request.method not in {"GET", "POST"} or fetched >= 40 or time.monotonic() >= deadline):
                    route.abort()
                    return
                fetched += 1
                try:
                    document = fetch_public(request.url, method=request.method, data=request.post_data_buffer,
                                            timeout=min(10, max(2, deadline-time.monotonic())), max_body=2_000_000 if request.resource_type == "document" else 1_000_000,
                                            accepted_types=mime_types,
                                            request_headers={key: value for key, value in request.headers.items() if key in {"user-agent", "accept", "accept-language"}})
                    if urlsplit(document["url"]).hostname not in allowed_hosts:
                        raise ValueError("Google browser redirected outside its public source hosts")
                    route.fulfill(status=document["http_status"], content_type=document["content_type"], body=document["body"])
                except Exception as exc:
                    failures.append(f"{target.path}: {exc}"[:300])
                    route.abort()
            context.route("**/*", fulfill)
            page = context.new_page()
            for number in range(max(1, (limit + 9)//10)):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Google browser search reached its 45-second limit")
                page.set_default_timeout(max(1000, int(remaining*1000)))
                url = f"https://www.google.com/search?q={quote_plus(query)}&num=10&hl={language}&start={number*10}"
                page.goto(url, wait_until="domcontentloaded")
                document = page.content()
                if _google_blocked(document, page.url):
                    raise RuntimeError("Google requires CAPTCHA/human verification; automated search stopped")
                if "consent.google.com" in page.url or page.locator('form[action*="consent"]').count():
                    raise RuntimeError("Google requires a consent choice; open Google manually to choose it")
                parsed_rows = _google_rows(document, "", 10)
                if not parsed_rows:
                    # A normal response may construct results after DOMContentLoaded.
                    try:
                        page.locator("h3").first.wait_for(timeout=min(5000, max(1000, int((deadline-time.monotonic())*1000))))
                    except Exception:
                        pass
                    document = page.content()
                    if _google_blocked(document, page.url):
                        raise RuntimeError("Google requires CAPTCHA/human verification; automated search stopped")
                    parsed_rows = _google_rows(document, "", 10)
                if not parsed_rows:
                    visible = BeautifulSoup(document, "html.parser").get_text(" ", strip=True).casefold()
                    if any(message in visible for message in ("did not match any documents", "no results found for", "не найдено ни одного документа", "ничего не найдено")):
                        break
                    raise RuntimeError("Google returned no parseable results from its ordinary browser page" + ("; " + "; ".join(failures[-2:]) if failures else ""))
                candidates += len(parsed_rows)
                found = [row for row in parsed_rows if _relevant(row, query)]
                filtered += len(parsed_rows) - len(found)
                additions = [row for row in found if row["url"] not in seen]
                rows.extend(additions)
                seen.update(row["url"] for row in additions)
                if len(rows) >= limit or not additions:
                    break
            return SearchRows(rows[:limit], candidates=candidates, filtered=filtered, method="Google public browser search")
        except Exception as exc:
            detail = "; ".join(failures[-2:])
            status = re.search(r"HTTP (202|403|429)", detail)
            if status:
                reason = "rate limited" if status.group(1) == "429" else "access restricted"
                message = f"Google returned HTTP {status.group(1)} ({reason}); automated search stopped"
            else:
                reason = re.sub(r"https?://\S+", "[source URL]", str(exc)).split("Call log:")[0]
                message = f"Google browser: {_clean(reason, 350)}" + (f"; source fetch: {detail}" if detail else "")
            if rows:
                rows[0]["_source_warning"] = message[:700]
                return SearchRows(rows, candidates=candidates, filtered=filtered, method="Google public browser search")
            raise RuntimeError(message) from exc
        finally:
            browser.close()


def _wikipedia(query: str, limit: int = 10) -> list[dict]:
    # Encyclopedias provide a few contextual references, not an 80-page dossier
    # of loosely related full-text hits. Keep the requested source cap too.
    limit = max(1, min(int(limit), 20))
    lang = "ru" if re.search(r"[А-Яа-яЁё]", query) else "en"
    rows, seen, offset, candidates, filtered = [], set(), 0, 0, 0
    words = re.findall(r"[^\W_]{2,}", query.casefold().replace("ё", "е"))
    while len(rows) < limit and offset < min(40, limit * 2):
        batch = min(20, limit - len(rows))
        data = _json(f"https://{lang}.wikipedia.org/w/api.php",
                     {"action": "query", "list": "search", "srsearch": query,
                      "srlimit": batch, "sroffset": offset, "format": "json"}, "Wikipedia")
        items = data.get("query", {}).get("search")
        if not isinstance(items, list):
            if rows:
                break
            raise RuntimeError("Wikipedia: invalid result list")
        added = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            row = _result(item.get("title"), f"https://{lang}.wikipedia.org/?curid={item.get('pageid')}",
                          item.get("snippet"), "Wikipedia", "Encyclopedia")
            if not row or row["url"] in seen:
                continue
            seen.add(row["url"])
            candidates += 1
            evidence = f"{row['title']} {row['snippet']}".casefold().replace("ё", "е")
            # Unlike general web search, Wikipedia is context and must mention
            # the actual target words. The API otherwise returns nearby topics.
            if not _relevant(row, query) or words and not all(word in evidence for word in words):
                filtered += 1
                continue
            rows.append(row)
            added += 1
        if added == 0 or len(items) < batch:
            break
        offset += len(items)
    return SearchRows(rows[:limit], candidates=candidates, filtered=filtered, method="Wikipedia search API")


def _news(query: str, limit: int = 10) -> list[dict]:
    try:
        data = _json("https://api.gdeltproject.org/api/v2/doc/doc",
                     {"query": query, "mode": "artlist", "format": "json", "maxrecords": min(limit, 75)}, "GDELT")
        if not isinstance(data.get("articles"), list):
            raise RuntimeError("GDELT: invalid news list")
        rows = [row for item in data.get("articles", [])
                if isinstance(item, dict) and (row := _result(
                    item.get("title"), item.get("url"),
                    f"{item.get('domain', '')} · {item.get('seendate', '')}",
                    "GDELT", "News"))]
        if rows:
            return rows
    except RuntimeError:
        pass
    response = net.get("https://www.bing.com/news/search",
                       {"q": query, "format": "rss"}, retries=0)
    if not response.body:
        raise RuntimeError(f"Bing News: {response.error or 'empty response'}")
    root = ET.fromstring(response.body)
    rows = []
    for item in root.findall(".//item")[:limit]:
        link = item.findtext("link") or ""
        if urlsplit(link).path.endswith("/apiclick.aspx"):
            link = parse_qs(urlsplit(link).query).get("url", [link])[0]
        row = _result(item.findtext("title"), link, item.findtext("description"),
                      "Bing News", "News")
        if row:
            rows.append(row)
    return rows


def _github(query: str, limit: int = 10) -> list[dict]:
    data = _json("https://api.github.com/search/repositories",
                 {"q": query, "per_page": min(limit, 100)}, "GitHub")
    if not isinstance(data.get("items"), list):
        raise RuntimeError("GitHub: invalid repository list")
    exact_name = query.casefold() if re.fullmatch(r"[a-zA-Z0-9_.-]{2,39}", query) else ""
    return [row for item in data.get("items", [])
            if isinstance(item, dict)
            and (not exact_name or str((item.get("owner") or {}).get("login") or "").casefold() == exact_name
                 or str(item.get("name") or "").casefold() == exact_name)
            and (row := _result(
                item.get("full_name"), item.get("html_url"), item.get("description"),
                "GitHub", "Repositories"))]


def _public(query: str, limit: int = 10) -> list[dict]:
    from . import extra_osint
    # shortcut: caps apply per platform/channel, use pagination when wider coverage is needed.
    data = extra_osint.public_pages(query)
    rows = SearchRows(data["web"], candidates=len(data["web"]),
                      method="Public-site discovery and Telegram public web", statuses=data.get("statuses", []))
    if data.get("errors"):
        error = "; ".join(data["errors"])[:1000]
        if rows:
            rows[0]["_source_warning"] = error
        else:
            # Retain the per-site ledger even if every site failed.
            rows.warning = error
    return rows


SEARCHERS = {"web": _web, "wikipedia": _wikipedia, "news": _news,
             "github": _github, "public": _public}


def _fetch_source(query, source, limit):
    started = time.monotonic()
    try:
        found = _engine(query, source, limit) if source in ENGINES else SEARCHERS[source](query, limit)
        warning = next((row.pop("_source_warning") for row in found if row.get("_source_warning")), getattr(found, "warning", ""))
    except Exception as exc:
        found, warning = [], str(exc)
        if source in ENGINES and warning.strip().rstrip(".").casefold() == "no results found":
            warning = f"{source}: unconfirmed empty response; the search library supplied no HTTP/parse diagnosis"
    return found, warning, round(time.monotonic() - started, 3)


def _combine_search(enabled, completed):
    rows, errors, statuses, by_url = [], [], [], {}
    for source in enabled:
        found, error, elapsed = completed[source]
        filtered = getattr(found, "filtered", 0)
        detail = error or (f"{len(found)} relevant results; {filtered} unrelated candidates excluded" if filtered else f"{len(found)} result(s)")
        lower = error.casefold()
        state = ("partial" if error and found else "blocked" if any(word in lower for word in ("http 403", "http 429", "http 202", "captcha", "human verification", "consent choice"))
                 else "timeout" if "timeout" in lower or "timed out" in lower else "error" if error else "ok" if found else "empty")
        statuses.append({"source": source, "count": len(found), "error": error, "state": state,
                         "detail": detail, "filtered_count": filtered, "elapsed_seconds": elapsed,
                         "candidate_count": getattr(found, "candidates", len(found)), "method": getattr(found, "method", "")})
        statuses.extend(getattr(found, "statuses", []))
        if error:
            errors.append(f"{source}: {error}")
        for row in found:
            old = by_url.get(row["url"])
            if old:
                if row["source"] not in old["source"].split(", "):
                    old["source"] += f", {row['source']}"
            else:
                rows.append(row)
                by_url[row["url"]] = row
    return rows, errors, statuses


async def search_async(query: str, enabled: list[str], on_source=None, limit: int = 10):
    """Run up to four blocking source adapters without blocking the event loop.

    Cancellation stops queued work; already running adapters finish within their
    own transport timeouts. Callback updates run on the caller's event loop.
    """
    enabled = list(dict.fromkeys(enabled))
    limit = max(1, min(int(limit), 100))
    semaphore = asyncio.Semaphore(4)
    async def fetch(source):
        async with semaphore:
            return source, await asyncio.to_thread(_fetch_source, query, source, limit)
    tasks = [asyncio.create_task(fetch(source)) for source in enabled]
    completed = {}
    try:
        for task in asyncio.as_completed(tasks):
            source, outcome = await task
            completed[source] = outcome
            if on_source:
                on_source(source, len(outcome[0]), outcome[1])
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return _combine_search(enabled, completed)


def search(query: str, enabled: list[str], on_source=None, limit: int = 10) -> tuple[list[dict], list[str], list[dict]]:
    """Synchronous UI/CLI entry point; limit is per source."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(search_async(query, enabled, on_source, limit))
    # Keep synchronous callers inside an existing event loop compatible;
    # async callers should await search_async to avoid blocking that loop.
    enabled = list(dict.fromkeys(enabled))
    limit = max(1, min(int(limit), 100))
    with ThreadPoolExecutor(max_workers=max(1, min(4, len(enabled)))) as pool:
        futures = {pool.submit(copy_context().run, _fetch_source, query, source, limit): source for source in enabled}
        completed = {}
        for future in as_completed(futures):
            source = futures[future]
            completed[source] = future.result()
            if on_source:
                found, error, _ = completed[source]
                on_source(source, len(found), error)
    return _combine_search(enabled, completed)


def archived_homepage(domain: str) -> dict | None:
    data = _json("https://archive.org/wayback/available",
                 {"url": f"https://{domain}/"}, "Internet Archive")
    closest = data.get("archived_snapshots", {}).get("closest", {})
    if not isinstance(closest, dict) or not closest.get("available"):
        return None
    return _result(f"Archived home page of {domain}", closest.get("url"),
                   f"Snapshot {closest.get('timestamp', '')} · HTTP {closest.get('status', '')}",
                   "Internet Archive", "Archive")


def breach_catalogue(domain: str) -> list[dict]:
    """Public incident notices only; no leaked accounts or personal records."""
    response = net.get("https://haveibeenpwned.com/api/v3/breaches",
                       {"domain": domain}, retries=0)
    data = response.json(log_errors=False)
    if not isinstance(data, list):
        raise RuntimeError(f"HIBP: {response.error or 'invalid response'}")
    rows = []
    for item in data:
        if not isinstance(item, dict) or item.get("Domain", "").casefold() != domain.casefold():
            continue
        name = item.get("Name", "")
        row = _result(f"Public breach notice: {item.get('Title') or name}",
                      f"https://haveibeenpwned.com/PwnedWebsites#{quote_plus(name)}",
                      f"Date: {item.get('BreachDate', '')} · Records: {item.get('PwnCount', '')}",
                      "Have I Been Pwned", "Breach notices")
        if row:
            rows.append(row)
    return rows


def manual_links(query: str) -> list[dict]:
    encoded = quote_plus(query)
    return [
        {"label": "Google", "url": f"https://www.google.com/search?q={encoded}"},
        {"label": "Yandex", "url": f"https://yandex.ru/search/?text={encoded}"},
        {"label": "Bing", "url": f"https://www.bing.com/search?q={encoded}"},
        {"label": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={encoded}"},
        {"label": "Brave", "url": f"https://search.brave.com/search?q={encoded}"},
        {"label": "Ahmia · onion index", "url": f"https://ahmia.fi/search/?q={encoded}"},
        {"label": "Public Telegram posts · Google CSE", "url":
         f"https://cse.google.com/cse?cx=006368593537057042503%3Aefxu7xprihg#gsc.tab=0&gsc.q={encoded}"},
        {"label": "OpenStreetMap", "url": f"https://www.openstreetmap.org/search?query={encoded}"},
    ]


if __name__ == "__main__":
    assert _result("<b>Title</b>", "javascript:alert(1)", "x", "web", "Веб") is None
    assert _clean("<b>A</b> &amp; B") == "A & B"
