"""Bounded native public searches, independent of general search-engine access."""
import json
import re
from urllib.parse import parse_qs, urlencode, urlsplit

from bs4 import BeautifulSoup
from defusedxml import ElementTree as ET

from . import osint
from .evidence_capture import fetch_public


def _excerpt(text, query):
    text = osint._clean(text, 100_000)
    position = text.casefold().find(query.casefold())
    if position < 0:
        word = query.split()[-1].casefold().rstrip("ая")
        position = text.casefold().find(word)
    return text[max(0, position - 100):max(0, position - 100) + 500]


def rss_rows(document, site, query):
    root = ET.fromstring(document)
    atom = "{http://www.w3.org/2005/Atom}"
    if root.tag not in {"rss", atom + "feed"}:
        raise RuntimeError("Public feed returned an unrecognized document")
    items = root.findall(".//item") if root.tag == "rss" else root.findall(atom + "entry")
    rows, seen = [], set()
    for item in items[:50]:
        link = item.findtext("link") or next((a.get("href", "") for a in item.findall(atom + "link") if a.get("rel", "alternate") == "alternate"), "")
        host = (urlsplit(link).hostname or "").lower()
        if host != site and not host.endswith("." + site):
            continue
        description = item.findtext("description") or item.findtext(atom + "content") or ""
        row = osint._result(item.findtext("title") or item.findtext(atom + "title"), link,
                            _excerpt(description, query), f"{site} public search RSS", "Public post")
        if row and link not in seen and osint._relevant(row, query):
            row["published_at"] = item.findtext("pubDate") or item.findtext(atom + "published") or item.findtext(atom + "updated") or ""
            rows.append(row)
            seen.add(link)
    return osint.SearchRows(rows[:8], candidates=len(items[:50]), filtered=max(0, len(items[:50]) - len(rows)), method=f"{site} native public RSS search")


def youtube_rows(document, query):
    marker = re.search(r'(?:var\s+ytInitialData|window\["ytInitialData"\]|ytInitialData)\s*=\s*', document)
    if not marker:
        raise RuntimeError("YouTube search returned no recognized result data")
    try:
        payload, _ = json.JSONDecoder().raw_decode(document[marker.end():].lstrip())
        primary = payload["contents"]["twoColumnSearchResultsRenderer"]["primaryContents"]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("YouTube search returned invalid result data") from exc
    def text(value):
        if not isinstance(value, dict):
            return ""
        return value.get("simpleText") or "".join(str(run.get("text", "")) for run in value.get("runs", []) if isinstance(run, dict))
    stack, rows, seen, candidates = [primary], [], set(), 0
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
        elif isinstance(node, dict):
            video = node.get("videoRenderer")
            if isinstance(video, dict):
                identifier = video.get("videoId", "")
                if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{11}", identifier) or identifier in seen:
                    continue
                seen.add(identifier)
                candidates += 1
                snippet = text(video.get("descriptionSnippet")) or " ".join(text(item.get("snippetText")) for item in video.get("detailedMetadataSnippets", []) if isinstance(item, dict))
                row = osint._result(text(video.get("title")), "https://www.youtube.com/watch?v=" + identifier,
                                    snippet, "YouTube public search", "Public video")
                if row and osint._relevant(row, query):
                    rows.append(row)
            else:
                stack.extend(value for key, value in node.items() if key not in {"adSlotRenderer", "promotedSparklesWebRenderer"})
    return osint.SearchRows(rows[:8], candidates=candidates, filtered=candidates - len(rows), method="YouTube native public search")


def telegram_directory_rows(document, query):
    soup = BeautifulSoup(document, "html.parser")
    rows = []
    for anchor in soup.select('.tg-channel__link a[href]'):
        path = urlsplit(anchor.get("href", "")).path
        if not re.fullmatch(r"/join/\d+", path):
            continue
        card = anchor.find_parent(class_="tg-channel") or anchor.parent.parent
        row = osint._result(anchor.get_text(" ", strip=True), "https://tgramsearch.com" + path,
                            card.get_text(" ", strip=True), "TgramSearch public directory", "Public channel candidate")
        if row and osint._relevant(row, query):
            rows.append(row)
    if not rows and not soup.select('.tg-channel__link') and not re.search(r"ничего не найдено|не найдено|каналы не найдены", soup.get_text(" ", strip=True), re.I):
        raise RuntimeError("Telegram directory returned no recognized result list")
    return rows[:3]


def search(query, site):
    endpoints = {"youtube.com": "https://www.youtube.com/results?" + urlencode({"search_query": query}),
                 "habr.com": "https://habr.com/ru/rss/search/?" + urlencode({"q": query}),
                 "reddit.com": "https://www.reddit.com/search.rss?" + urlencode({"q": query}),
                 "t.me": "https://tgramsearch.com/search?" + urlencode({"query": query})}
    if site not in endpoints:
        return None
    page = fetch_public(endpoints[site], timeout=15, accepted_types={"text/html", "application/xhtml+xml", "text/xml", "application/xml", "application/rss+xml", "application/atom+xml"})
    if site in {"youtube.com", "t.me"} and osint._search_challenge(page["html"], page["url"]):
        raise RuntimeError("Public search requires CAPTCHA/human verification")
    if site == "youtube.com":
        rows = youtube_rows(page["html"], query)
    elif site != "t.me":
        rows = rss_rows(page["body"], site, query)
    else:
        candidates = telegram_directory_rows(page["html"], query)
        rows = osint.SearchRows(candidates=len(candidates), method="TgramSearch public channel discovery")
        failures = []
        for candidate in candidates:
            try:
                detail = fetch_public(candidate["url"], timeout=10, allowed_hosts={"tgramsearch.com"})
                soup = BeautifulSoup(detail["html"], "html.parser")
                names = []
                for anchor in soup.select('a[href^="tg://resolve?"]'):
                    name = parse_qs(urlsplit(anchor["href"]).query).get("domain", [""])[0]
                    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", name) and name not in names:
                        names.append(name)
                if len(names) != 1:
                    raise RuntimeError("Directory entry has no unique public Telegram username")
                rows.append({**candidate, "url": "https://t.me/" + names[0], "discovery_url": candidate["url"],
                             "discovery_source": "TgramSearch public directory"})
            except Exception as exc:
                failures.append(f"Telegram directory entry: {type(exc).__name__}")
        if failures:
            rows.warning = "; ".join(failures)
    for row in rows:
        row.update(observed_at=page["observed_at"], html_sha256=page["sha256"])
    return rows
