"""Free, passive email discovery from a company's public website.

The only addresses marked published are those present in fetched public pages.
Name-based patterns are returned as guesses and are never SMTP-probed.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import socket
import zlib
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser

from . import contacts, net

MAX_PAGES = 20
MAX_REDIRECTS = 5
PATHS = ("/", "/contact", "/contacts", "/careers", "/jobs", "/about", "/team", "/company",
         "/.well-known/security.txt", "/security.txt", "/privacy")
DOMAIN_RE = re.compile(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")

SOCIAL_PATTERNS = {
    "linkedin": re.compile(r"^https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|in|school)/[A-Za-z0-9_\-\.%]+", re.I),
    "github": re.compile(r"^https?://(?:www\.)?github\.com/[A-Za-z0-9_\-\.]+", re.I),
    "twitter": re.compile(r"^https?://(?:www\.)?(?:twitter\.com|x\.com)/[A-Za-z0-9_]{1,30}", re.I),
    "telegram": re.compile(r"^https?://(?:t\.me|telegram\.me)/[A-Za-z0-9_]{4,32}", re.I),
    "youtube": re.compile(r"^https?://(?:www\.)?youtube\.com/(?:@[A-Za-z0-9_\-\.]+|c/[A-Za-z0-9_\-\.]+|channel/[A-Za-z0-9_\-]+)", re.I),
}


def extract_socials(meta: dict[str, str], json_ld_texts: list[str], hrefs: list[str]) -> dict[str, list[str]]:
    """Извлекает официальные социальные профили компании из OpenGraph, Twitter Cards, Schema.org и ссылок."""
    candidates = set()
    for prop, val in meta.items():
        if not val:
            continue
        if prop in ("twitter:site", "twitter:creator"):
            handle = val.strip().lstrip("@")
            if handle and re.fullmatch(r"[A-Za-z0-9_]{1,30}", handle):
                candidates.add(f"https://x.com/{handle}")
        elif "sameas" in prop or "see_also" in prop:
            candidates.add(val.strip())
        elif prop == "og:url" and any(k in val.lower() for k in SOCIAL_PATTERNS):
            candidates.add(val.strip())

    for raw in json_ld_texts:
        try:
            parsed = json.loads(raw)
        except Exception:
            continue

        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower() == "sameas":
                        if isinstance(v, list):
                            candidates.update(str(x).strip() for x in v if x)
                        elif isinstance(v, str):
                            candidates.add(v.strip())
                    elif k.lower() == "url" and isinstance(v, str) and any(net_name in v.lower() for net_name in SOCIAL_PATTERNS):
                        candidates.add(v.strip())
                    else:
                        walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(parsed)

    for h in hrefs:
        if h and any(k in h.lower() for k in ("linkedin.com", "github.com", "twitter.com", "x.com", "t.me", "youtube.com")):
            candidates.add(h.strip())

    result: dict[str, list[str]] = {k: [] for k in SOCIAL_PATTERNS}
    ignore_tokens = ("sharearticle", "intent/tweet", "share?url", "sharer.php", "login", "signup", "terms", "privacy", "hashtag")
    for cand in sorted(candidates):
        cand_clean = cand.split("?")[0].rstrip("/")
        if any(ign in cand.lower() for ign in ignore_tokens):
            continue
        for network, pat in SOCIAL_PATTERNS.items():
            if pat.search(cand_clean) and cand_clean not in result[network]:
                result[network].append(cand_clean)
                break
    return {k: v for k, v in result.items() if v}


def _public_host(host: str) -> bool:
    if not DOMAIN_RE.fullmatch(host) or host.lower() in {"localhost"}:
        return False
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)
    except (OSError, ValueError):
        return False


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, host: str):
        bare = host.casefold().removeprefix("www.")
        self.hosts = {bare, f"www.{bare}"}
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        target = urllib.parse.urlsplit(newurl)
        target_host = (target.hostname or "").casefold()
        if (self.count > MAX_REDIRECTS or target.scheme != "https" or
                target_host not in self.hosts or not _public_host(target_host)):
            return None
        newurl = urllib.parse.quote(newurl, safe=":/?#[]@!$&'()*+,;=%")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


class _VisiblePage(_Links):
    def __init__(self):
        super().__init__()
        self.text: list[str] = []
        self.mailto: list[str] = []
        self.title: list[str] = []
        self.scripts: list[str] = []
        self.meta: dict[str, str] = {}
        self.json_ld: list[str] = []
        self.hidden = 0
        self.in_title = False
        self.in_json_ld = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        super().handle_starttag(tag, attrs)
        tag_lower = tag.casefold()
        attr_dict = dict(attrs)
        if tag_lower in {"script", "style", "noscript"}:
            self.hidden += 1
        if tag_lower == "script":
            if attr_dict.get("src"):
                self.scripts.append(attr_dict["src"])
            stype = (attr_dict.get("type") or "").strip().lower()
            if stype in ("application/ld+json", "application/json"):
                self.in_json_ld = True
        if tag_lower == "meta":
            prop = (attr_dict.get("property") or attr_dict.get("name") or "").strip().lower()
            content = (attr_dict.get("content") or "").strip()
            if prop and content:
                self.meta[prop] = content
        if tag_lower == "title":
            self.in_title = True
        if tag_lower == "a":
            href = attr_dict.get("href") or ""
            if href.lower().startswith("mailto:"):
                self.mailto.append(urllib.parse.unquote(href[7:].split("?", 1)[0]))

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.casefold()
        if tag_lower in {"script", "style", "noscript"}:
            self.hidden = max(0, self.hidden - 1)
        if tag_lower == "script":
            self.in_json_ld = False
        if tag_lower == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title.append(data)
        if self.in_json_ld:
            self.json_ld.append(data)
        if not self.hidden:
            self.text.append(data)


def parse_public_page(url: str, capture_html: bool = False) -> dict:
    """Parse one user-selected public HTTPS page and retain its URL as evidence."""
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        host = (parsed.hostname or "").lower()
        valid = parsed.scheme == "https" and parsed.port in (None, 443) and _public_host(host)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Enter a public HTTPS page")
    robots_url, robots_text = _get(f"https://{host}/robots.txt", host)
    robots = urllib.robotparser.RobotFileParser()
    robots.set_url(robots_url or f"https://{host}/robots.txt")
    robots.parse(robots_text.splitlines())
    if not robots.can_fetch(net.USER_AGENT, url):
        raise ValueError("The page is disallowed by robots.txt")
    net._polite_wait(host)
    final_url, page = _get(url, host)
    if not final_url:
        raise RuntimeError("The page is unavailable or redirects to another domain")
    if "\x00" in page:
        raise ValueError("The source is not an HTML page")
    parser = _VisiblePage()
    parser.feed(page)
    visible = " ".join(parser.text)
    socials = extract_socials(parser.meta, parser.json_ld, parser.hrefs)
    result = {"url": final_url,
            "title": " ".join(" ".join(parser.title).split())[:200],
            "excerpt": " ".join(visible.split())[:600],
            "emails": contacts.extract_emails(visible + " " + " ".join(parser.mailto)),
            "socials": socials,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "html_sha256": hashlib.sha256(page.encode("utf-8")).hexdigest(),
            "scripts": sorted({absolute for src in parser.scripts
                               if (absolute := urllib.parse.urljoin(final_url, src)).startswith("https://")
                               and urllib.parse.urlsplit(absolute).hostname in {host, urllib.parse.urlsplit(final_url).hostname}})}
    if capture_html:
        result["_snapshot_html"] = page
    return result


def _get(url: str, host: str, errors: list[str] | None = None) -> tuple[str, str]:
    opener = urllib.request.build_opener(_SameHostRedirect(host))
    url = urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%")
    request = urllib.request.Request(url, headers={"User-Agent": net.USER_AGENT, "Accept": "text/html,*/*;q=0.8", "Accept-Encoding": "identity"})
    try:
        with opener.open(request, timeout=net.TIMEOUT) as response:
            if (not url.endswith("/robots.txt") and response.headers.get_content_type()
                    not in {"text/html", "application/xhtml+xml", "text/plain"}):
                return "", ""
            body = response.read(1_000_000)
            encoding = (response.headers.get('Content-Encoding') or '').lower().strip()
            if encoding in {'gzip', 'x-gzip', 'deflate'}:
                decoder = zlib.decompressobj(zlib.MAX_WBITS + 16 if encoding in {'gzip','x-gzip'} else zlib.MAX_WBITS)
                body = decoder.decompress(body, 1_000_001)
                if len(body) > 1_000_000 or decoder.unconsumed_tail or not decoder.eof:
                    raise ValueError('Encoded page is incomplete or exceeds the decompressed size limit')
            return response.geturl(), body.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError, ValueError, zlib.error) as exc:
        if errors is not None:
            reason = "TLS certificate verification failed" if "CERTIFICATE_VERIFY_FAILED" in str(exc) else str(exc)[:180]
            errors.append(f"{url}: {reason}")
        return "", ""


def _name_patterns(full_name: str, domain: str) -> list[str]:
    words = re.findall(r"[a-zA-Z]+", full_name.lower())
    if not words:
        return []
    first, last = words[0], words[-1] if len(words) > 1 else ""
    locals_ = {first, f"{first}.{last}" if last else "", f"{first[0]}.{last}" if last else "",
               f"{first}{last}" if last else "", f"{first[0]}{last}" if last else "",
               f"{last}.{first}" if last else ""}
    return [f"{local}@{domain}" for local in sorted(locals_) if local]


def find_public_emails(company: str, domain: str, full_name: str = "") -> list[dict]:
    """Crawl up to 15 public HTTPS pages, respecting robots.txt and same-host links."""
    host = domain.strip().lower().rstrip(".")
    if not _public_host(host):
        raise ValueError("Enter a public company domain (for example, example.com).")
    origin = f"https://{host}"
    allowed_hosts = {host.removeprefix("www."), f"www.{host.removeprefix('www.')}"}
    errors: list[str] = []
    robots_url, robots_text = _get(f"{origin}/robots.txt", host, errors)
    if errors and "TLS certificate verification failed" in errors[0]:
        raise RuntimeError(f"Could not read {host}: {errors[0]}")
    robots = urllib.robotparser.RobotFileParser()
    robots.set_url(robots_url or f"{origin}/robots.txt")
    robots.parse(robots_text.splitlines())

    queue = deque(f"{origin}{path}" for path in PATHS)
    visited: set[str] = set()
    found: dict[str, dict] = {}
    site_socials: dict[str, set[str]] = {k: set() for k in SOCIAL_PATTERNS}
    loaded = 0
    while queue and len(visited) < MAX_PAGES:
        url = queue.popleft()
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or (parsed.hostname or "").lower() not in allowed_hosts or parsed.query or parsed.fragment or
                url in visited or not robots.can_fetch(net.USER_AGENT, url)):
            continue
        visited.add(url)
        net._polite_wait(host)
        final_url, page = _get(url, host, errors)
        if not final_url:
            continue
        loaded += 1
        parser = _VisiblePage()
        try:
            parser.feed(page)
        except ValueError:
            continue
        page_socials = extract_socials(parser.meta, parser.json_ld, parser.hrefs)
        for net_name, urls in page_socials.items():
            site_socials[net_name].update(urls)
        for email in contacts.extract_emails(" ".join(parser.text + parser.mailto)):
            local = email.split("@", 1)[0]
            if local in {"subscribe", "unsubscribe"} or local.endswith(("-subscribe", "-unsubscribe", "-help")):
                continue
            found.setdefault(email, {"email": email, "company": company, "domain": host,
                                     "full_name": "", "position": "", "department": "",
                                     "confidence": 0, "verification": "published",
                                     "evidence": [final_url], "source": "Public company website",
                                     "socials": {k: sorted(v) for k, v in site_socials.items() if v}})
        for href in parser.hrefs:
            candidate = urllib.parse.urljoin(final_url, href)
            p = urllib.parse.urlsplit(candidate)
            if p.scheme == "https" and p.hostname in allowed_hosts and not p.query and not p.fragment:
                path_url = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", ""))
                if path_url not in visited and path_url not in queue and robots.can_fetch(net.USER_AGENT, path_url):
                    queue.append(path_url)
        if len(found) >= 100:
            break

    if loaded == 0:
        raise RuntimeError(f"Could not read {host}: {errors[0] if errors else 'pages unavailable or blocked by robots.txt'}")

    clean_socials = {k: sorted(v) for k, v in site_socials.items() if v}
    for item in found.values():
        if item.get("verification") == "published":
            item["socials"] = clean_socials

    if full_name.strip():
        for email in _name_patterns(full_name.strip(), host):
            if email not in found:
                found[email] = {"email": email, "company": company, "domain": host,
                                "full_name": full_name.strip(), "position": "", "department": "",
                                "confidence": 0, "verification": "guess", "evidence": [],
                                "source": "Name pattern guess; not verified"}
    return list(found.values())


if __name__ == "__main__":
    page = _VisiblePage()
    page.feed("<title>Контакты</title><script>hidden@apache.org</script>"
              "<p>Пишите на <a href='mailto:jobs@apache.org'>jobs@apache.org</a></p>")
    assert contacts.extract_emails(" ".join(page.text)) == ["jobs@apache.org"]
    assert page.mailto == ["jobs@apache.org"]
