"""Apex subscription parsing and process-scoped Xray routing for FindAll."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "third_party" / "apex-parser"
CORE = ROOT / "third_party" / "xray"
UPSTREAM_COMMIT = "20896bbb4b234d6ddb9e9f6d4d86c445d40aba32"
BASE = "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs"
FEEDS = {"full": f"{BASE}/main/alive_plain_full.txt",
         "wl": f"{BASE}/main/alive_plain_bs.txt",
         "bl": f"{BASE}/main/alive_plain_bl.txt",
         "ai": f"{BASE}/other/alive_plain_AI.txt",
         "torrent": f"{BASE}/other/alive_plain_torrent.txt"}
PROBES = ("https://www.gstatic.com/generate_204", "https://api.github.com/zen")
MAX_DOWNLOAD = 100_000_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@lru_cache(maxsize=2048)
def _public(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)
    except (OSError, ValueError):
        return False


def _url(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or not _public(parsed.hostname)):
        raise ValueError("Subscription and probe URLs must use public HTTPS hosts on port 443")
    return url


def _display_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class _PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, limit: int = MAX_DOWNLOAD) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PublicRedirect())
    with opener.open(urllib.request.Request(_url(url), headers={"User-Agent": "FindAll/1.0"}), timeout=25) as response:
        content = response.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Download exceeds the size limit")
    return content


def _modules():
    if str(VENDOR) not in sys.path:
        sys.path.insert(0, str(VENDOR))
    from apex import config, fetch, parse, xray
    # The upstream defaults disable certificate verification. FindAll verifies TLS.
    config.SSL_CONTEXT.check_hostname = True
    config.SSL_CONTEXT.verify_mode = ssl.CERT_REQUIRED
    return fetch, parse, xray


def load(path: Path) -> dict:
    if not path.exists():
        return {"enabled": False, "selected": "", "rows": [], "sources": [], "updated": ""}
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or not isinstance(data.get("rows"), list)
            or not isinstance(data.get("enabled"), bool)):
        raise ValueError("Invalid Apex network state")
    return data


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix="apex-", suffix=".tmp", delete=False) as temporary:
        name = temporary.name
        json.dump(data, temporary, ensure_ascii=False, indent=2)
    try:
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def executable() -> Path | None:
    local = CORE / ("xray.exe" if os.name == "nt" else "xray")
    found = os.environ.get("JOBFIND_XRAY") or (str(local) if local.is_file() else shutil.which("xray"))
    return Path(found) if found and Path(found).is_file() else None


def install_core() -> dict:
    if executable():
        return {"core": str(executable()), "installed": True}
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64", "arm64", "aarch64"}:
        raise RuntimeError("Xray automatic setup supports x64 and arm64")
    if sys.platform == "win32":
        name = "Xray-windows-arm64-v8a.zip" if machine in {"arm64", "aarch64"} else "Xray-windows-64.zip"
    elif sys.platform == "linux":
        name = "Xray-linux-arm64-v8a.zip" if machine in {"arm64", "aarch64"} else "Xray-linux-64.zip"
    else:
        raise RuntimeError("Install Xray manually and set JOBFIND_XRAY on this platform")
    page = _download("https://github.com/XTLS/Xray-core/releases/latest", 4_000_000).decode("utf-8")
    version = re.search(r"/XTLS/Xray-core/releases/tag/(v[0-9][A-Za-z0-9._-]*)", page)
    if not version:
        raise RuntimeError("Could not identify the official Xray release")
    version = version.group(1)
    source = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{name}"
    sums = _download(source + ".dgst", 16_000).decode("ascii")
    digest = re.search(r"(?:SHA256|SHA2-256)[^\n=]*=\s*([0-9a-fA-F]{64})", sums)
    if not digest:
        raise RuntimeError("Official Xray SHA256 checksum is missing")
    digest = digest.group(1).lower()
    archive = _download(source)
    if hashlib.sha256(archive).hexdigest() != digest:
        raise RuntimeError("Xray archive SHA256 verification failed")
    import io
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        # Extract only the executable and its license, never archive-supplied paths.
        binary = "xray.exe" if os.name == "nt" else "xray"
        if binary not in bundle.namelist() or bundle.getinfo(binary).file_size > MAX_DOWNLOAD:
            raise RuntimeError("Invalid Xray archive")
        CORE.mkdir(parents=True, exist_ok=True)
        target = CORE / binary
        with tempfile.NamedTemporaryFile(dir=CORE, delete=False) as temporary:
            temporary.write(bundle.read(binary))
            temporary_name = temporary.name
        try:
            os.replace(temporary_name, target)
        finally:
            Path(temporary_name).unlink(missing_ok=True)
        target.chmod(0o700)
        for name in ("LICENSE", "LICENSE.txt"):
            if name in bundle.namelist():
                (CORE / name).write_bytes(bundle.read(name))
    metadata = {"version": version, "sha256": digest, "source": source}
    (CORE / "origin.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {"core": str(target), "installed": True, **metadata}


def _outbound(link: str) -> dict:
    _, parse, xray = _modules()
    outbound = xray.link_to_xray_outbound(link)
    host, port, _ = parse.parse_host_port_and_name(link)
    if not outbound or not host or not port or not 1 <= port <= 65535:
        raise ValueError("Invalid proxy configuration")
    if not _public(host.strip("[]")):
        raise ValueError("Proxy endpoint must resolve to public addresses")
    stream = outbound.get("streamSettings", {})
    if stream.get("tlsSettings", {}).get("allowInsecure"):
        raise ValueError("Proxy configuration disables TLS verification")
    # Xray expects bare IPv6 addresses, upstream retains URI brackets.
    settings = outbound["settings"]
    for server in settings.get("vnext", []) + settings.get("servers", []):
        server["address"] = server["address"].strip("[]")
    if "address" in settings:
        settings["address"] = settings["address"].strip("[]")
    return outbound


def refresh(path: Path, group: str = "full", country: str = "", urls: list[str] | None = None,
            limit: int = 300) -> dict:
    if not 1 <= limit <= 2000:
        raise ValueError("Node limit must be between 1 and 2000")
    if country:
        if not re.fullmatch(r"[A-Za-z]{2}", country):
            raise ValueError("Country must be a two-letter code")
        cc = country.upper()
        selected_urls = [f"{BASE}/other/countries/{cc}/alive_plain_{cc}.txt"]
    else:
        selected_urls = [FEEDS[group]]
    selected_urls = urls or selected_urls
    if len(selected_urls) > 20:
        raise ValueError("At most 20 subscriptions per update")
    fetch, parse, _ = _modules()
    old = load(path)
    previous = {row["id"]: row for row in old["rows"]}
    rows, seen, sources = [], set(), []
    for url in selected_urls:
        _url(url)
        # Reuse upstream's plain/Base64/JSON decoder with a bounded verified download.
        body = _download(url, 8_000_000).decode("utf-8", errors="replace")
        details = fetch.parse_subscription(body)
        if details["is_expired"]:
            sources.append({"url": _display_url(url), "status": "expired", "count": 0})
            continue
        accepted = 0
        for link in details["configs"]:
            try:
                outbound = _outbound(link)
            except (ValueError, TypeError, KeyError):
                continue
            canonical = json.dumps(outbound, sort_keys=True, separators=(",", ":"))
            node_id = hashlib.sha256(canonical.encode()).hexdigest()[:24]
            if node_id in seen:
                continue
            seen.add(node_id)
            host, port, name = parse.parse_host_port_and_name(link)
            prev = previous.get(node_id, {})
            rows.append({"id": node_id, "name": name[:160], "host": host, "port": port,
                         "protocol": link.split(":", 1)[0], "link": link,
                         "source": _display_url(url), "status": prev.get("status", "untested"),
                         "latency_ms": prev.get("latency_ms"), "checked": prev.get("checked", "")})
            accepted += 1
            if len(rows) >= limit:
                break
        sources.append({"url": _display_url(url), "status": "ok", "count": accepted})
        if len(rows) >= limit:
            break
    if not rows:
        raise RuntimeError("Subscriptions returned no usable configurations; previous state preserved")
    old.update(rows=rows, sources=sources, updated=_now(), group=group, country=country.upper())
    if old["selected"] not in seen:
        old.update(selected="", enabled=False)
    _save(path, old)
    return status(path)


@contextlib.contextmanager
def tunnel(link: str):
    core = executable()
    if not core:
        raise RuntimeError("Xray is missing: run network install or use Install Xray in Network")
    outbound = _outbound(link)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    payload = {"log": {"loglevel": "none"},
               "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}}],
               "outbounds": [outbound]}
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen([str(core), "run", "-c", "stdin:"], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
    try:
        process.stdin.write(json.dumps(payload).encode())
        process.stdin.close()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Xray rejected this configuration")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Xray listener did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def probe(proxy: str, urls: tuple[str, ...] = PROBES) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    start = time.monotonic()
    for url in urls:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "FindAll/1.0"}), timeout=6) as response:
            response.read(4096)
            if response.status not in (200, 204):
                raise RuntimeError("HTTPS connectivity probe failed")
    return round((time.monotonic() - start) * 1000 / len(urls))


def check(path: Path, limit: int = 12, node_id: str = "", test_url: str = "") -> dict:
    if not 1 <= limit <= 100:
        raise ValueError("Check limit must be between 1 and 100")
    if not executable():
        raise RuntimeError("Install Xray before checking nodes")
    data = load(path)
    candidates = [row for row in data["rows"] if not node_id or row["id"] == node_id][:limit]
    if not candidates:
        raise ValueError("No nodes to check; update subscriptions first")
    probes = (_url(test_url),) if test_url else PROBES
    for row in candidates:
        try:
            with tunnel(row["link"]) as proxy:
                row.update(status="ok", latency_ms=probe(proxy, probes))
        except (OSError, RuntimeError, ValueError) as exc:
            row.update(status="failed", latency_ms=None, error=type(exc).__name__)
        row["checked"] = _now()
    healthy = sorted((row for row in data["rows"] if row["status"] == "ok"), key=lambda row: row["latency_ms"])
    selected = next((row for row in data["rows"] if row["id"] == data["selected"]), None)
    if not selected or selected["status"] != "ok":
        data["selected"] = healthy[0]["id"] if healthy else ""
    if not healthy:
        data["enabled"] = False
    _save(path, data)
    return status(path)


def configure(path: Path, enabled: bool, node_id: str = "") -> dict:
    data = load(path)
    if enabled:
        selected = node_id or data["selected"]
        if not any(row["id"] == selected and row["status"] == "ok" for row in data["rows"]):
            raise ValueError("Select a node that passed the HTTPS check")
        if not executable():
            raise RuntimeError("Install Xray first")
        data["selected"] = selected
    data["enabled"] = enabled
    _save(path, data)
    return status(path)


def status(path: Path) -> dict:
    data = load(path)
    return {**data, "rows": [{k: v for k, v in row.items() if k != "link"} for row in data["rows"]],
            "core": str(executable() or ""), "state_path": str(path), "upstream_commit": UPSTREAM_COMMIT,
            "coverage": "Jobs, web search, GitHub, public pages, domain APIs, AI HTTP APIs, Maigret, TikTok, 2GIS, SpiderFoot, and Tor when the route is on",
            "separate_routes": "Web-Check server, external AI CLIs and browser links use their own transports. Tor uses the Apex HTTP proxy when Apex is enabled."}


@contextlib.contextmanager
def _environment(proxy: str | None):
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
            "NO_PROXY", "no_proxy", "JOBFIND_ACTIVE_PROXY", "DDGS_PROXY")
    before = {key: os.environ.get(key) for key in keys}
    old_opener = urllib.request._opener
    try:
        if proxy:
            for key in keys[:6]:
                os.environ[key] = proxy
            os.environ["JOBFIND_ACTIVE_PROXY"] = proxy
            os.environ["DDGS_PROXY"] = proxy
            bypass = "localhost,127.0.0.1,::1"
            os.environ["NO_PROXY"] = os.environ["no_proxy"] = bypass
        else:
            for key in keys:
                os.environ.pop(key, None)
            # A nonempty bypass map also prevents requests from inheriting Windows registry proxies.
            os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})
        urllib.request.install_opener(urllib.request.build_opener(handler))
        yield
    finally:
        urllib.request._opener = old_opener
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextlib.contextmanager
def route(path: Path, mode: str = "saved"):
    data = load(path) if mode != "direct" else None
    if mode == "saved" and not data["enabled"]:
        yield
        return
    if mode == "direct":
        with _environment(None):
            yield
        return
    rows = sorted((row for row in data["rows"] if row["status"] == "ok"),
                  key=lambda row: (row["id"] != data["selected"], row["latency_ms"] or 0))
    # ponytail: retry up to three known healthy nodes at command start; no mid-request replay.
    for row in rows[:3]:
        stack = contextlib.ExitStack()
        try:
            proxy = stack.enter_context(tunnel(row["link"]))
            probe(proxy)
        except (OSError, RuntimeError, ValueError):
            stack.close()
            continue
        with stack, _environment(proxy):
            print(f"Apex route: {row['protocol']} {row['host']}:{row['port']}", file=sys.stderr)
            yield
        return
    raise RuntimeError("No checked Apex node is reachable. Refresh/check nodes or choose direct mode.")
