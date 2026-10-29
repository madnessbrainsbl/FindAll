"""Bounded public HTML/text evidence capture, including public Telegram posts.

DNS answers are validated and the connection uses a pinned public address. Raw
HTML is evidence; the separate offline preview strips executable/remote content.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from .contacts import extract_emails

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 2_000_000
ONION_HOST = re.compile(r"[a-z2-7]{56}\.onion$", re.I)
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def validated_url(url: str, include_onion: bool = False) -> tuple[str, str, list[str]]:
    """Return normalized URL, host, public DNS addresses; reject IPs/credentials."""
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("Invalid public URL")
    parsed = urlsplit(url.strip())
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    if parsed.scheme not in {"https", "http"} or parsed.username is not None or parsed.password is not None:
        raise ValueError("Only public HTTP(S) URLs without credentials are accepted")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port != (443 if parsed.scheme == "https" else 80):
        raise ValueError("Only the default HTTP(S) port is accepted")
    # HTTP request targets are ASCII; preserve existing escapes and URL delimiters.
    normalized = urlunsplit((parsed.scheme, host, quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                            quote(parsed.query, safe="%/?@!$&'()*+,;=:-._~"), ""))
    if host.endswith(".onion"):
        if not include_onion or not ONION_HOST.fullmatch(host):
            raise ValueError("Onion capture requires enabled Tor and a v3 hidden-service address")
        return normalized, host, []
    if not DOMAIN.fullmatch(host) or host.endswith((".local", ".localhost", ".internal", ".test", ".invalid")):
        raise ValueError("A public DNS hostname is required; IP addresses and local names are blocked")
    answers = sorted({answer[4][0] for answer in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not answers or any(not ipaddress.ip_address(address).is_global or ipaddress.ip_address(address).is_multicast for address in answers):
        raise ValueError("Private, reserved, and mixed public/private DNS answers are blocked")
    return normalized, host, answers


class _PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, addresses: list[str], timeout: float, tls: bool):
        super().__init__(host, port, timeout=timeout)
        self.addresses, self.tls = addresses, tls

    def connect(self) -> None:
        route = urlsplit(os.environ.get("JOBFIND_ACTIVE_PROXY", ""))
        proxied = route.scheme == "http" and route.hostname in {"127.0.0.1", "localhost"} and route.port
        deadline = time.monotonic() + self.timeout
        for index, address in enumerate(self.addresses):
            self.timeout = deadline - time.monotonic()
            if self.timeout <= 0:
                raise TimeoutError("Public connection exceeded its time limit")
            try:
                if proxied:
                    self.set_tunnel(address, self.port)
                    self.sock = socket.create_connection(("127.0.0.1", route.port), self.timeout)
                    self._tunnel()
                else:
                    self.sock = socket.create_connection((address, self.port), self.timeout)
                if self.tls:
                    self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
                return
            except OSError as exc:
                proxy_closed = proxied and self.sock is None
                # HTTPConnection.close() would reset a request already waiting for connect().
                if self.sock:
                    self.sock.close()
                    self.sock = None
                if proxy_closed or isinstance(exc, ssl.SSLCertVerificationError) or index == len(self.addresses) - 1:
                    raise


def fetch_public(url: str, *, include_onion: bool = False, tor_proxy: str = "",
                 timeout: float = 20, max_body: int = MAX_BODY, method: str = "GET", data: bytes | None = None,
                 accepted_types: set[str] | None = None, request_headers: dict[str, str] | None = None,
                 allowed_hosts: set[str] | None = None, allowed_scheme: str | None = None) -> dict:
    """Fetch one text page, with revalidated redirects and bounded decoded body."""
    timeout = max(2, min(float(timeout), 45))
    max_body = max(1024, min(int(max_body), MAX_BODY))
    deadline = time.monotonic() + timeout
    original = url
    if method not in {"GET", "POST"} or (data is not None and len(data) > 4096):
        raise ValueError("Unsupported index request")
    for hop in range(4):
        if allowed_scheme is not None and urlsplit(url).scheme != allowed_scheme:
            raise ValueError("Request or redirect left the permitted protocol")
        if allowed_hosts is not None and (urlsplit(url).hostname or "").lower() not in allowed_hosts:
            raise ValueError("Archive request or redirect left the permitted source hosts")
        url, host, answers = validated_url(url, include_onion)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Page capture exceeded its time limit")
        headers = {"User-Agent": "FindAll/1.0 public-source evidence capture", "Accept": "text/html,text/plain,application/xhtml+xml", "Accept-Encoding": "identity"}
        allowed_headers = {"user-agent": "User-Agent", "accept": "Accept", "accept-language": "Accept-Language"}
        for key, value in (request_headers or {}).items():
            if key.lower() not in allowed_headers or not isinstance(value, str) or len(value) > 1024 or any(ord(char) < 32 for char in value):
                raise ValueError("Unsupported browser request header")
            headers[allowed_headers[key.lower()]] = value
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection = response = None
        try:
            if host.endswith(".onion"):
                if not re.fullmatch(r"127\.0\.0\.1:(?:9050|9150)", tor_proxy):
                    raise ValueError("A verified local Tor SOCKS proxy is required")
                session = requests.Session()
                session.trust_env = False
                try:
                    response = session.request(method, url, data=data, headers=headers, allow_redirects=False, stream=True,
                                           timeout=(min(remaining, 10), min(remaining, 10)),
                                           proxies={"http": f"socks5h://{tor_proxy}", "https": f"socks5h://{tor_proxy}"})
                    status, reply_headers = response.status_code, response.headers
                    if status in {301, 302, 303, 307, 308}:
                        target = urljoin(url, reply_headers.get("Location", ""))
                        # Hidden-service redirects cannot silently send the query to clearnet.
                        if urlsplit(target).hostname != host:
                            raise ValueError("Cross-host onion redirects are blocked")
                        url = target
                        method, data = "GET", None
                        continue
                    _check_response(status, reply_headers, max_body, accepted_types)
                    chunks, total = [], 0
                    for chunk in response.iter_content(65536):
                        total += len(chunk)
                        if total > max_body or time.monotonic() > deadline:
                            raise ValueError("Page exceeded the capture size or time limit")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                finally:
                    if response is not None:
                        response.close()
                    session.close()
            else:
                parsed = urlsplit(url)
                connection = _PinnedConnection(host, 443 if parsed.scheme == "https" else 80, answers, remaining, parsed.scheme == "https")
                connection.request(method, urlunsplit(("", "", parsed.path, parsed.query, "")), body=data, headers=headers)
                response = connection.getresponse()
                status, reply_headers = response.status, dict(response.getheaders())
                reply_headers = {key.lower(): value for key, value in reply_headers.items()}
                if status in {301, 302, 303, 307, 308}:
                    target = urljoin(url, reply_headers.get("location", ""))
                    if allowed_hosts is not None and (urlsplit(target).hostname or "").lower() not in allowed_hosts:
                        raise ValueError("Archive redirect left the permitted source hosts")
                    validated_url(target, include_onion)
                    url = target
                    method, data = "GET", None
                    continue
                _check_response(status, reply_headers, max_body, accepted_types)
                chunks, total = [], 0
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("Page capture exceeded its time limit")
                    if connection.sock:
                        connection.sock.settimeout(max(.1, deadline - time.monotonic()))
                    chunk = response.read(min(65536, max_body + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_body:
                        raise ValueError("Page exceeded the capture size limit")
                    chunks.append(chunk)
                body = b"".join(chunks)
            content_type = reply_headers.get("content-type", reply_headers.get("Content-Type", ""))
            encoding = re.search(r"charset=([^;\s]+)", content_type, re.I)
            try:
                text = body.decode(encoding.group(1).strip('"') if encoding else "utf-8", "replace")
            except LookupError:
                text = body.decode("utf-8", "replace")
            if b"\x00" in body:
                raise ValueError("Binary content is not captured")
            return {"requested_url": original, "url": url, "body": body, "html": text, "http_status": status,
                    "content_type": content_type, "last_modified": reply_headers.get("last-modified", reply_headers.get("Last-Modified", "")),
                    "observed_at": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(body).hexdigest()}
        finally:
            if connection is not None:
                connection.close()
    raise ValueError("Too many redirects")


def _check_response(status: int, headers: dict, max_body: int, accepted_types: set[str] | None = None) -> None:
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    content_type = headers.get("content-type", headers.get("Content-Type", "")).split(";", 1)[0].lower()
    if content_type not in (accepted_types or {"text/html", "text/plain", "application/xhtml+xml", "application/json"}):
        raise ValueError("Only HTML, text, or index JSON is accepted")
    if int(headers.get("content-length", headers.get("Content-Length", "0")) or "0") > max_body:
        raise ValueError("Page exceeded the capture size limit")
    if headers.get("content-encoding", headers.get("Content-Encoding", "identity")) not in {"", "identity"}:
        raise ValueError("Compressed responses are not accepted for bounded evidence capture")


def telegram_url(url: str) -> str:
    """Convert public channel/post links to Telegram's unauthenticated web view."""
    parsed = urlsplit(url)
    if (parsed.hostname or "").lower() not in {"t.me", "www.t.me", "telegram.me", "www.telegram.me"}:
        return url
    parts = parsed.path.strip("/").split("/")
    if parts and parts[0] == "s":
        parts = parts[1:]
    if (not parts or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", parts[0]) or
            parts[0].lower() in {"joinchat", "share", "proxy", "login", "addstickers", "iv", "c"} or
            len(parts) > 2 or (len(parts) == 2 and not parts[1].isdigit())):
        raise ValueError("Only public Telegram channel or post URLs are captured")
    return "https://t.me/s/" + "/".join(parts)


def parse_evidence(page: dict) -> dict:
    soup = BeautifulSoup(page["html"], "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else page["url"]
    for tag in soup.select("script,style,noscript,template"):
        tag.decompose()
    visible = " ".join(soup.get_text(" ", strip=True).split())[:100_000]
    mailto = " ".join(unquote(str(a.get("href", ""))[7:].split("?", 1)[0]) for a in soup.select('a[href^="mailto:"]'))
    emails = []
    for email in extract_emails(visible + " " + mailto):
        position = visible.casefold().find(email.casefold())
        emails.append({"email": email, "url": page["url"], "source": "Public page capture", "published": True,
                       "context": visible[max(0, position - 120):position + len(email) + 180] if position >= 0 else "Published mailto link",
                       "observed_at": page["observed_at"], "html_sha256": page["sha256"]})
    posts = []
    for post in soup.select(".tgme_widget_message[data-post]")[:40]:
        identifier = post.get("data-post", "")
        text = post.select_one(".tgme_widget_message_text")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}/\d+", identifier) or text is None:
            continue
        date = post.select_one("time[datetime]")
        posts.append({"url": "https://t.me/" + identifier, "title": title[:200],
                      "snippet": text.get_text(" ", strip=True)[:4000], "source": "Telegram public web",
                      "published_at": date.get("datetime", "") if date else "", "observed_at": page["observed_at"],
                      "html_sha256": page["sha256"], "kind": "public_post"})
    profiles = []
    channel_title = soup.select_one(".tgme_channel_info_header_title")
    if urlsplit(page["url"]).hostname == "t.me" and channel_title is not None:
        parts = urlsplit(page["url"]).path.strip("/").split("/")
        username = parts[1] if len(parts) > 1 and parts[0] == "s" else ""
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", username):
            description = soup.select_one(".tgme_channel_info_description")
            profiles.append({"site": "Telegram public channel", "username": username, "url": "https://t.me/"+username,
                             "title": channel_title.get_text(" ", strip=True)[:250],
                             "snippet": description.get_text(" ", strip=True)[:1500] if description else "",
                             "source": "Telegram public web", "kind": "public_channel", "observed_at": page["observed_at"], "html_sha256": page["sha256"]})
    return {"title": title[:250], "text": visible, "emails": emails, "posts": posts, "profiles": profiles}


def _offline_preview(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.select("script,style,link,iframe,frame,object,embed,base,form,meta[http-equiv],svg,math"):
        tag.decompose()
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr.lower().startswith("on") or attr.lower() in {"src", "srcset", "poster", "background", "style", "ping", "action", "formaction", "srcdoc", "xlink:href"}:
                del tag.attrs[attr]
        if "href" in tag.attrs:
            href = str(tag.attrs["href"])
            if urlsplit(href).scheme not in {"http", "https", "mailto"}:
                del tag.attrs["href"]
    return str(soup)


def _singlefile(snapshot: Path, destination: Path, timeout: float = 40) -> dict:
    node = shutil.which("node")
    package = ROOT / "third_party" / "single-file-cli"
    entries = [package / "single-file-node.js", package / "single-file.js"]
    if (package / "package.json").is_file():
        metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
        entry = metadata.get("bin", {})
        if isinstance(entry, dict) and entry.get("single-file"):
            entries.insert(0, package / entry["single-file"])
        elif isinstance(entry, str):
            entries.insert(0, package / entry)
    entrypoint = next((entry for entry in entries if entry.is_file()), None)
    standalone = package / "single-file.exe"
    if not standalone.is_file() and (not node or not entrypoint):
        return {"name": "singlefile", "state": "skipped", "count": 0, "detail": "SingleFile CLI is not installed", "url": snapshot.as_uri()}
    launcher = [str(standalone)] if standalone.is_file() else [node, str(entrypoint)]
    command = [*launcher, snapshot.as_uri(), str(destination), "--blocked-url-pattern=^https?://", "--block-scripts=true", "--remove-frames=true", "--load-deferred-content=false",
               "--browser-load-max-time=15000", "--browser-capture-max-time=15000", "--browser-wait-until=load",
               '--browser-args=["--proxy-server=http://127.0.0.1:1","--proxy-bypass-list=<-loopback>","--host-resolver-rules=MAP * ~NOTFOUND"]']
    chrome = Path(os.environ.get("CHROME_PATH", r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
    if chrome.is_file():
        command.append("--browser-executable-path=" + str(chrome))
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=max(1, min(float(timeout), 40)),
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    if result.returncode or not destination.is_file():
        raise RuntimeError("SingleFile offline snapshot capture failed: " + (result.stderr or result.stdout)[-350:])
    return {"name": "singlefile", "state": "ok", "count": 1, "detail": "Rendered offline evidence snapshot; scripts and remote resources blocked", "artifact": str(destination),
            "source": "gildas-lormeau/single-file-cli", "engine_artifact": str(launcher[-1]),
            "engine_sha256": hashlib.sha256(Path(launcher[-1]).read_bytes()).hexdigest(),
            "observed_at": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


def _select_pages(rows: list[dict], limit: int, include_onion: bool) -> tuple[list[dict], dict]:
    """Select unique text URLs across hosts before doing DNS or network work."""
    groups, seen = {}, set()
    summary = {"input": len(rows), "duplicates": 0, "unsupported": 0}
    for row in rows:
        if not isinstance(row, dict):
            summary["unsupported"] += 1
            continue
        try:
            url = telegram_url(str(row.get("url") or row.get("source_url") or ""))
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            if (parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password
                    or parsed.port not in {None, 443 if parsed.scheme == "https" else 80}
                    or (host.endswith(".onion") and not include_onion)
                    or re.search(r"\.(?:pdf|zip|exe|png|jpe?g|gif|mp4|mp3|xlsx?|docx?)(?:$|/)", parsed.path, re.I)):
                summary["unsupported"] += 1
                continue
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
            if url in seen:
                summary["duplicates"] += 1
                continue
            seen.add(url)
            groups.setdefault(host.casefold(), deque()).append({**row, "url": url})
        except (ValueError, UnicodeError):
            summary["unsupported"] += 1
    selected = []
    while len(selected) < limit and any(groups.values()):
        for group in groups.values():
            if group and len(selected) < limit:
                selected.append(group.popleft())
    summary.update(eligible=len(seen), selected=len(selected), limit=limit,
                   unselected=max(0, len(seen) - len(selected)))
    return selected, summary


def capture_results(rows: list[dict], output: Path, limit: int = 12, include_onion: bool = False,
                    on_status=None, singlefile: bool | None = None, time_budget: float = 180) -> dict:
    """Capture a diverse bounded selection; unselected rows are one limit notice."""
    limit = max(0, min(int(limit), 100))
    output = Path(output).resolve() / "evidence"
    output.mkdir(parents=True, exist_ok=True)
    result = {key: [] for key in ("web", "profiles", "emails", "findings", "statuses", "errors", "artifacts")}
    selected, selection = _select_pages(rows, limit, include_onion)
    result["selection"] = selection
    tor_proxy, tor_error = "", ""
    deadline = time.monotonic() + max(20, min(float(time_budget), 600))
    render_setting = os.environ.get("FINDALL_SINGLEFILE", "auto").lower()
    render = singlefile if singlefile is not None else (render_setting in {"1", "true", "yes"} or
        render_setting == "auto" and (ROOT / "third_party" / "single-file-cli" / "single-file.exe").is_file())

    def status(item: dict) -> None:
        result["statuses"].append(item)
        if on_status:
            on_status(item)

    for index, row in enumerate(selected):
        row = row if isinstance(row, dict) else {}
        url = str(row.get("url") or row.get("source_url") or "")
        record = {"name": f"capture:{index + 1}", "url": url, "count": 0}
        remaining = deadline - time.monotonic()
        if remaining < 2:
            status({"name": "capture-budget", "state": "limited", "count": 0,
                    "detail": f"Capture time budget reached; {len(selected) - index} selected pages were not attempted"})
            selection["not_attempted"] = len(selected) - index
            break
        if on_status:
            on_status({**record, "state": "attempted", "detail": f"Downloading {url}"})
        try:
            url = telegram_url(url)
            normalized, host, _addresses = validated_url(url, include_onion)
            if host.endswith(".onion"):
                if tor_error:
                    raise RuntimeError(tor_error)
                if not tor_proxy:
                    from .github_tools import _tor_proxy
                    try:
                        tor_proxy = _tor_proxy(output)
                    except Exception as exc:
                        tor_error = str(exc)
                        raise
            page = fetch_public(normalized, include_onion=include_onion, tor_proxy=tor_proxy,
                                timeout=min(20, max(2, deadline - time.monotonic())))
            if page["content_type"].split(";", 1)[0].lower() == "application/json":
                raise ValueError("Evidence capture accepts only HTML/text pages")
            evidence = parse_evidence(page)
            if re.search(r"(?:^|\b)(?:captcha|just a moment|access denied|verify you are human|security verification)(?:\b|$)", evidence["title"], re.I):
                raise RuntimeError("Access blocked by a challenge page; content was not added as evidence")
            token = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + "-" + str(time.time_ns())
            raw, preview, textfile, metadata = [output / f"{token}{suffix}" for suffix in (".source.html", ".preview.html", ".txt", ".json")]
            raw.write_bytes(page["body"])
            preview.write_text(_offline_preview(page["html"]), encoding="utf-8")
            textfile.write_text(evidence["text"], encoding="utf-8")
            saved = {key: value for key, value in page.items() if key not in {"body", "html"}}
            saved.update({"title": evidence["title"], "source": row.get("source", ""), "files": [str(raw), str(preview), str(textfile)], "raw_html_is_untrusted": True})
            metadata.write_text(json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8")
            result["artifacts"].extend(str(path) for path in (raw, preview, textfile, metadata))
            result["web"].append({"url": page["url"], "title": evidence["title"], "snippet": evidence["text"][:4000], "source": "Captured public page",
                                  "observed_at": page["observed_at"], "html_sha256": page["sha256"], "artifact": str(preview), "metadata": str(metadata), "kind": "captured_page"})
            result["web"].extend(evidence["posts"])
            result["profiles"].extend(evidence["profiles"])
            result["emails"].extend(evidence["emails"])
            result["findings"].append({"title": evidence["title"], "value": evidence["text"][:4000], "url": page["url"], "source": "HTML evidence capture", "kind": "page_text", "observed_at": page["observed_at"]})
            status({**record, "state": "ok", "count": 1, "detail": f"Captured {len(page['body'])} bytes; {len(evidence['emails'])} published emails; {len(evidence['posts'])} public posts", "artifact": str(metadata)})
            if render:
                try:
                    if deadline - time.monotonic() < 1:
                        status({"name": "singlefile", "url": url, "state": "limited", "count": 0,
                                "detail": "Capture budget reached; raw HTML/text evidence was retained"})
                        continue
                    rendered = _singlefile(preview, output / f"{token}.singlefile.html", timeout=deadline - time.monotonic())
                    status(rendered)
                    if rendered.get("artifact"):
                        result["artifacts"].append({"path": rendered["artifact"], "kind": "singlefile_preview",
                            "source": rendered.get("source", "SingleFile"), "sha256": rendered.get("sha256", ""),
                            "engine_sha256": rendered.get("engine_sha256", ""),
                            "engine_artifact": rendered.get("engine_artifact", ""),
                            "observed_at": rendered.get("observed_at", ""), "url": url})
                except Exception as exc:
                    result["errors"].append(f"SingleFile {url}: {exc}")
                    status({"name": "singlefile", "url": url, "state": "error", "count": 0, "detail": str(exc)[:500]})
        except Exception as exc:
            detail = str(exc)[:500]
            result["errors"].append(f"Capture {url}: {detail}")
            status({**record, "state": "error", "detail": detail})
    if selection["unselected"] or selection["duplicates"] or selection["unsupported"]:
        status({"name": "capture-selection", "state": "limited" if selection["unselected"] else "skipped", "count": 0,
                "detail": f"Selected {selection['selected']} of {selection['eligible']} eligible pages across hosts; "
                          f"{selection['unselected']} outside page limit, {selection['duplicates']} duplicates, "
                          f"{selection['unsupported']} unsupported URLs. Unselected pages were not requested."})
    return result
