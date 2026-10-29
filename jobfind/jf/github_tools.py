"""Local adapters for the GitHub OSINT tools bundled with FindAll."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import re
import shutil
import csv
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import requests
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path

from .osint_contacts import _public_host


ROOT = Path(__file__).resolve().parents[1]
ARSENAL = ROOT / "third_party" / "awesome-osint-arsenal" / "tools.json"
WEB_CHECK = ROOT / "third_party" / "web-check"
WEB_CHECK_PORT = 3031
TOR = ROOT / "third_party" / "tor"


def catalog(query: str = "", limit: int = 100, offset: int = 0) -> dict:
    """Search Arsenal and mark entries executable through FindAll adapters."""
    tools = json.loads(ARSENAL.read_text(encoding="utf-8"))
    words = query.casefold().split()
    matched = [item for item in tools if not item.get("archived") and all(
        word in " ".join(str(item.get(key, "")) for key in
                        ("name", "description", "category", "url", "tags")).casefold()
        for word in words)]
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    actions = {"maigret": "maigret", "web-check": "web-check", "onionsearch": "onion-search",
               "shodan": "domain-recon", "shodan-iot": "domain-recon", "tiktok-scraper": "tiktok-profile"}
    rows = [{"id": item["id"], "name": item["name"],
             "description": item.get("description", ""),
             "category": item.get("category", ""), "url": item.get("url", ""),
             "method": item.get("install", {}).get("method", "manual"),
             "action": actions.get(item["id"], "")}
            for item in matched[offset:offset + limit]]
    return {"query": query, "total": len(tools), "matched": len(matched),
            "offset": offset, "rows": rows,
            "source": "rawfilejson/awesome-osint-arsenal"}


def _health(port: int | None = None) -> dict | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port or WEB_CHECK_PORT}/healthz", timeout=2) as res:
            data = json.load(res)
        version = json.loads((WEB_CHECK / "package.json").read_text(encoding="utf-8"))["version"]
        return data if data.get("status") == "ok" and data.get("version") == version else None
    except (OSError, ValueError, urllib.error.URLError):
        return None


def _start_web_check(output: Path, *, port: int | None = None, proxy: str = ""):
    port = port or WEB_CHECK_PORT
    if _health(port):
        return
    node = shutil.which("node")
    if not node or not (WEB_CHECK / "node_modules" / "express").exists():
        raise RuntimeError("Web-Check is not installed: run setup-webcheck.bat")
    output.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PORT": str(port), "WC_HOST": "127.0.0.1"}
    # A persistent UI server must not keep an Apex port which closes after the
    # calling command. Routed API requests get their own owned server below.
    if os.environ.get("JOBFIND_ACTIVE_PROXY"):
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "JOBFIND_ACTIVE_PROXY", "DDGS_PROXY"):
            env.pop(name, None)
    if proxy:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[name] = proxy
        env["CHROMIUM_ARGS"] = (env.get("CHROMIUM_ARGS") or "--headless --no-sandbox --disable-gpu --disable-extensions") + " --proxy-server=" + proxy
    from .domain_recon import configured_keys
    shodan_key = configured_keys()["SHODAN_API_KEY"]
    if shodan_key:
        env["SHODAN_API_KEY"] = shodan_key
    chrome = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    if chrome.exists():
        env["CHROME_PATH"] = str(chrome)
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    # The server outlives a scan. Its open log cannot live in a disposable report folder on Windows.
    runtime = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "JobFind" / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    log_path = runtime / "webcheck-server.log"
    log = log_path.open("ab")
    try:
        process = subprocess.Popen([node, "server.js"], cwd=WEB_CHECK, env=env,
                         stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
    finally:
        log.close()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        health = _health(port)
        if health and health.get("ready"):
            return process
        time.sleep(0.25)
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    raise RuntimeError(f"Web-Check did not start; log: {log_path}")


@contextlib.contextmanager
def web_check_api(output: Path):
    proxy = os.environ.get("JOBFIND_ACTIVE_PROXY", "")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = _start_web_check(output, port=port, proxy=proxy)
    try:
        yield f"http://127.0.0.1:{port}/api"
    finally:
        if process is not None and process.poll() is None:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                process.terminate()
            process.wait(timeout=5)


def web_check(domain: str, output: Path) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not _public_host(domain):
        raise ValueError("Enter a public domain")
    query = urllib.parse.urlencode({"url": f"https://{domain}"})
    with web_check_api(output) as endpoint:
        with urllib.request.urlopen(endpoint + "?" + query, timeout=110) as res:
            data = json.loads(res.read(32_000_000))
    if not isinstance(data, dict):
        raise RuntimeError("Web-Check returned invalid JSON")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report = output / f"webcheck_{domain}_{stamp}.json"
    report.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    _start_web_check(output)
    modules = []
    for name, value in sorted(data.items()):
        status = ("error" if isinstance(value, dict) and value.get("error") else
                  "skipped" if isinstance(value, dict) and value.get("skipped") else "ok")
        detail = value.get("error") or value.get("skipped") or "" if isinstance(value, dict) else ""
        modules.append({"name": name, "status": status, "detail": str(detail)[:250]})
    return {"domain": domain, "modules": modules, "report": str(report),
            "url": f"http://127.0.0.1:{WEB_CHECK_PORT}/check/{domain}",
            "data": data, "counts": {kind: sum(item["status"] == kind for item in modules)
                       for kind in ("ok", "skipped", "error")}}


def maigret_search(username: str, output: Path, top_sites: int = 100) -> dict:
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,64}", username):
        raise ValueError("Username must contain 2–64 Latin letters, digits, dots, underscores, or hyphens")
    executable = ROOT / ".venv" / "Scripts" / "maigret.exe"
    if not executable.exists():
        raise RuntimeError("Maigret is not installed: run setup.bat")
    folder = output / "maigret" / f"{username}_{datetime.now():%Y%m%d-%H%M%S}"
    folder.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    command = [str(executable), username, "--top-sites", str(max(10, min(top_sites, 500))),
               "--timeout", "10", "--no-recursion", "--no-autoupdate", "--no-color",
               "--no-progressbar", "--print-errors", "--json", "simple", "--folderoutput", str(folder)]
    if os.environ.get("JOBFIND_ACTIVE_PROXY"):
        command.extend(["--proxy", os.environ["JOBFIND_ACTIVE_PROXY"]])
        # Maigret combines an explicit ProxyConnector with trust_env=True.
        # Inheriting HTTP_PROXY as well sends CONNECT through the proxy twice.
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)
    if sys.platform == "win32":
        command.extend(["--dns-resolver", "threaded"])
    completed = subprocess.run(command, env=env, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=300 if top_sites > 100 else 150, check=False)
    report = folder / f"report_{username}_simple.json"
    if completed.returncode != 0 or not report.exists():
        raise RuntimeError(f"Maigret: {completed.stderr[-700:] or completed.stdout[-700:]}")
    data = json.loads(report.read_text(encoding="utf-8"))
    rows = [{"site": site, "url": entry.get("url_user", "")}
            for site, entry in data.items() if isinstance(entry, dict) and entry.get("url_user")]
    warnings = [line.strip() for line in (completed.stdout + "\n" + completed.stderr).splitlines()
                if "too many errors" in line.lower()][:8]
    checked = re.search(r'Starting a search on top (\d+) sites', completed.stdout)
    return {"username": username, "rows": rows, "warnings": warnings,
            "report": str(report), "checked": int(checked.group(1)) if checked else max(10, min(top_sites, 500)),
            "requested_sites": max(10, min(top_sites, 500)),
            "status": "partial" if rows and warnings else "error" if warnings else "ok" if rows else "empty"}


def github_email(username: str, output: Path, max_repos: int = 10,
                 max_commit_pages: int = 2) -> dict:
    """Run the bundled GitHub Email Hunter on commits linked to one GitHub account."""
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", username):
        raise ValueError("Enter a valid GitHub username (1–39 characters)")
    if not 1 <= max_repos <= 100 or not 1 <= max_commit_pages <= 5:
        raise ValueError("max-repos: 1–100; max-commit-pages: 1–5")
    vendor = ROOT / "third_party" / "github-email-hunter"
    if not (vendor / "ghmail" / "cli.py").is_file():
        raise RuntimeError("GitHub Email Hunter was not found in third_party")
    if str(vendor) not in sys.path:
        sys.path.insert(0, str(vendor))
    try:
        from ghmail.cli import GithubEmailHunter
        import requests
    except ImportError as exc:
        raise RuntimeError("GitHub Email Hunter dependencies are missing: run setup.bat") from exc
    from .domain_recon import configured_keys
    events = []
    def log(level: str, message: str) -> None:
        if level != "debug":
            events.append({"level": level, "message": message})
    hunter = GithubEmailHunter(token=configured_keys()["GITHUB_TOKEN"] or None,
                               timeout=15, logger=log)
    try:
        found = hunter.find_email(username, max_repos=max_repos,
                                  max_commit_pages=max_commit_pages)
    except requests.RequestException as exc:
        raise RuntimeError(f"GitHub is unavailable: {exc}") from exc
    finally:
        hunter.session.close()
    errors = [event["message"] for event in events if event["level"] in ("warn", "error")]
    status = "found" if found else "source_error" if any(event["level"] == "warn" or
        "rate limit" in event["message"].lower() or "HTTP " in event["message"]
        for event in events) else "not_found"
    output.mkdir(parents=True, exist_ok=True)
    result = {"username": username, "status": status,
              "email": found.email if found else "",
              "repository": found.repository if found else "",
              "commit_sha": found.commit_sha if found else "",
              "source_url": found.source_url if found else "",
              "errors": errors, "max_repos": max_repos,
              "max_commit_pages": max_commit_pages}
    report = output / f"github_email_{username}_{datetime.now():%Y%m%d-%H%M%S-%f}.json"
    result["report"] = str(report)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def tiktok_profile(username: str, output: Path) -> dict:
    """Read a public TikTok profile through the bundled scraper's profile parser."""
    username = username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._]{2,24}", username):
        raise ValueError("Enter a TikTok username (2–24 characters)")
    vendor = ROOT / "third_party" / "tiktok-scraper"
    if not (vendor / "build" / "index.js").is_file():
        raise RuntimeError("TikTok Scraper is not built: run setup-tiktok.bat")
    node = shutil.which("node")
    if not node:
        raise RuntimeError("TikTok Scraper requires Node.js")
    script = (
        "const scraper=require('./build');"
        "scraper.getUserProfileInfo(process.argv[1],{proxy:(process.env.JOBFIND_ACTIVE_PROXY||'').replace(/^http:\/\//,'')}).then(({user,stats})=>"
        "process.stdout.write(JSON.stringify({username:user.uniqueId,"
        "name:user.nickname||'',bio:user.signature||'',stats:stats||{}})))"
        ".catch(e=>{console.error(String(e));process.exitCode=1})"
    )
    completed = subprocess.run([node, "-e", script, username], cwd=vendor,
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=35, check=False)
    if completed.returncode == 0:
        try:
            profile = json.loads(completed.stdout)
        except ValueError as exc:
            raise RuntimeError("TikTok Scraper returned invalid JSON") from exc
        source = "TikTok Scraper"
    else:
        import requests
        url = f"https://www.tiktok.com/@{username}"
        response = requests.get("https://www.tiktok.com/oembed", params={"url": url}, timeout=12)
        if response.status_code != 200:
            raise RuntimeError(f"TikTok Scraper: {(completed.stderr or completed.stdout)[-250:].strip()}; oEmbed HTTP {response.status_code}")
        data = response.json()
        if data.get("author_url", "").rstrip("/").casefold() != url.casefold():
            raise RuntimeError("TikTok oEmbed returned a different profile")
        profile = {"username": username, "name": data.get("author_name", ""),
                   "bio": "", "stats": {}}
        source = "TikTok oEmbed"
    if profile.get("username", "").casefold() != username.casefold():
        raise RuntimeError("TikTok returned another account's profile")
    output.mkdir(parents=True, exist_ok=True)
    result = {"username": username, "name": profile.get("name", ""),
              "bio": profile.get("bio", ""), "stats": profile.get("stats", {}),
              "url": f"https://www.tiktok.com/@{username}", "source": source}
    report = output / f"tiktok_{username}_{datetime.now():%Y%m%d-%H%M%S-%f}.json"
    result["report"] = str(report)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def tor_https_proxy() -> str:
    """Local Apex HTTP proxy, as host:port, when Tor should use it as an upstream."""
    parsed = urllib.parse.urlsplit(os.environ.get("JOBFIND_ACTIVE_PROXY", "").strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host in {"127.0.0.1", "localhost"} and parsed.port:
        return f"{host}:{parsed.port}"
    return ""


def _lyrebird_copy(source: Path) -> Path:
    """Tor splits a transport path on spaces. The project directory contains one.

    The copy is keyed by the source path so a unit-test fixture cannot replace
    the real lyrebird binary.
    """
    digest = hashlib.sha256(str(source.resolve()).encode("utf-8")).hexdigest()[:16]
    folder = Path(tempfile.gettempdir()) / "jobfind-tor" / digest
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / "lyrebird.exe"
    if not dest.is_file() or dest.stat().st_size != source.stat().st_size:
        shutil.copy2(source, dest)
    return dest


def _transport_plugin(kind: str, lyrebird: Path) -> str:
    name = kind.lower().replace("-", "_")
    if name == "snowflake":
        token = "snowflake"
    elif name in {"meek", "meek_lite", "meek_azure"}:
        token = "meek_lite"
    elif "webtunnel" in name:
        token = "webtunnel"
    else:
        token = "obfs4"
    return f"{token} exec {lyrebird}"


def _bridge_argv(kind: str, lines: list[str], lyrebird: Path) -> list[str]:
    """One snowflake line. Two lines share one transport and the peer then drops."""
    if kind.lower().replace("-", "_") == "snowflake":
        lines = lines[:1]
    args = ["--UseBridges", "1", "--ClientTransportPlugin", _transport_plugin(kind, lyrebird)]
    for line in lines:
        args.extend(["--Bridge", line])
    return args


def _bridge_line_key(args: list[str]) -> tuple[str, ...]:
    lines = []
    tokens = iter(args)
    for token in tokens:
        if token == "--Bridge":
            lines.append(next(tokens, ""))
    return tuple(lines)


def local_bridge_sets(executable: Path) -> list[tuple[str, list[str]]]:
    """Bundled transports, in the order this network can use them."""
    base = executable.resolve().parent / "pluggable_transports"
    lyrebird = base / "lyrebird.exe"
    config = base / "pt_config.json"
    if not lyrebird.is_file() or not config.is_file():
        return []
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    bridges = data.get("bridges") or {}
    if not isinstance(bridges, dict):
        return []
    transport = _lyrebird_copy(lyrebird)
    sets = []
    for key, kind, label in (("obfs4", "obfs4", "obfs4"), ("snowflake", "snowflake", "snowflake"),
                             ("meek", "meek_lite", "meek")):
        lines = [" ".join(str(line).split()) for line in bridges.get(key) or [] if str(line).strip()]
        if lines:
            sets.append((label, _bridge_argv(kind, lines, transport)))
    return sets


def tor_bridge_args(executable: Path) -> list[str]:
    """obfs4 bridges shipped with this Tor build. Other transports are fallbacks."""
    for label, args in local_bridge_sets(executable):
        if label == "obfs4":
            return args
    sets = local_bridge_sets(executable)
    return sets[0][1] if sets else []


def moat_bridge_sets(payload: dict, lyrebird: Path) -> list[tuple[str, list[str]]]:
    """Fresh built-in bridges from Tor's moat settings response. No captcha."""
    settings = payload.get("settings") if isinstance(payload, dict) else None
    if not isinstance(settings, list) or not lyrebird.is_file():
        return []
    transport = _lyrebird_copy(lyrebird)
    found = []
    for item in settings:
        if not isinstance(item, dict):
            continue
        block = item.get("bridges") or {}
        if not isinstance(block, dict):
            continue
        kind = str(block.get("type") or "obfs4").strip().lower() or "obfs4"
        lines = [" ".join(str(line).split()) for line in block.get("bridge_strings") or [] if str(line).strip()]
        if not lines:
            continue
        label = "moat-" + re.sub(r"[^a-z0-9]+", "-", kind).strip("-")[:24]
        found.append((label or "moat", _bridge_argv(kind, lines, transport)))
    return found


def moat_settings(lyrebird: Path) -> list[tuple[str, list[str]]]:
    """Ask Tor which built-in bridges to use from this network. Fails open."""
    try:
        request = urllib.request.Request(
            "https://bridges.torproject.org/moat/circumvention/settings",
            data=b"{}",
            headers={"User-Agent": "FindAll/1.0", "Content-Type": "application/json",
                     "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read(200_000).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return []
    return moat_bridge_sets(payload if isinstance(payload, dict) else {}, lyrebird)


def tor_command(executable: Path, data_dir: Path, proxy: str = "",
                bridge_args: list[str] | None = None) -> list[str]:
    """Absolute data and GeoIP paths. A dossier scratch folder must not own this state."""
    data_root = executable.resolve().parent.parent / "data"
    command = [str(executable),
               "--SocksPort", "127.0.0.1:9050",
               "--DataDirectory", str(Path(data_dir).resolve()),
               "--GeoIPFile", str((data_root / "geoip").resolve()),
               "--GeoIPv6File", str((data_root / "geoip6").resolve()),
               "--ClientUseIPv6", "1" if proxy else "0"]
    bridge_args = tor_bridge_args(executable) if bridge_args is None else bridge_args
    command.extend(bridge_args)
    if proxy:
        command.extend(["--HTTPSProxy", proxy])
        if not bridge_args:
            command.extend(["--ReachableORAddresses", "*:443", "--ClientPreferIPv6ORPort", "1"])
    return command


def _stop_our_tor() -> bool:
    """Stop our own tor.exe when port 9050 is open and the circuit is not usable."""
    try:
        import psutil
        connections = psutil.net_connections(kind="tcp")
    except Exception:
        return False
    root = TOR.resolve()
    stopped = False
    for conn in connections:
        if not conn.pid or not conn.laddr or conn.laddr.port != 9050 or conn.status != psutil.CONN_LISTEN:
            continue
        try:
            proc = psutil.Process(conn.pid)
            Path(proc.exe()).resolve().relative_to(root)
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except psutil.TimeoutExpired:
                proc.kill()
            stopped = True
        except (psutil.Error, OSError, ValueError):
            continue
    return stopped


def _tor_proxy(output: Path) -> str:
    del output  # onion CSV uses this folder; Tor state stays under jobfind_out
    state = ROOT / "jobfind_out"
    data_dir = state / "tor-data"
    log_path = state / "tor.log"

    def ready(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                conn.settimeout(2)
                conn.sendall(b"\x05\x01\x00")
                return conn.recv(2) == b"\x05\x00"
        except OSError:
            return False

    def working(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
                conn.settimeout(5)
                conn.sendall(b"\x05\x01\x00")
                if conn.recv(2) != b"\x05\x00":
                    return False
                host = b"example.com"
                conn.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x01\xbb")
                return conn.recv(2) == b"\x05\x00"
        except OSError:
            return False

    def wait_until(port: int, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if working(port):
                return True
            time.sleep(2)
        return False

    proxy = tor_https_proxy()
    for port in (9050, 9150):
        if not ready(port):
            continue
        if working(port) or wait_until(port, 20):
            return f"127.0.0.1:{port}"
        if port == 9050:
            _stop_our_tor()
    if ready(9050):
        if proxy:
            raise RuntimeError(
                "Tor SOCKS port 9050 is open, but the circuit is not up. "
                "That Tor is not using the Apex HTTP proxy, and it could not be restarted. "
                "Stop that Tor process, then search again.")
        raise RuntimeError(
            "Tor SOCKS port 9050 is open, but the circuit is not up. "
            "Direct Tor connections failed on this network before. "
            "Turn on the Apex route and search again so Tor uses that local HTTP proxy.")
    tor = next(TOR.rglob("tor.exe"), None) if TOR.exists() else None
    if tor is None:
        raise RuntimeError("Tor SOCKS is unavailable. Start Tor Browser or run setup-tor.ps1")
    attempts = local_bridge_sets(tor)
    if proxy:
        # A checked upstream can reach relays directly; bridge transports may not use it.
        attempts = [(label, args) for label, args in attempts if "snowflake" not in label]
        attempts.insert(0, ("upstream", []))
    elif not attempts:
        attempts = [("", [])]
    lyrebird = tor.resolve().parent / "pluggable_transports" / "lyrebird.exe"
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    tried: list[str] = []
    seen = {_bridge_line_key(args) for _label, args in attempts}
    asked_moat = False
    index = 0
    startup_deadline = time.monotonic() + 360
    while index < len(attempts) and len(tried) < 4 and time.monotonic() < startup_deadline:
        label, bridge_args = attempts[index]
        index += 1
        tried.append(label or "direct")
        folder = state / ("tor-upstream" if proxy and not bridge_args else "tor-data" if not bridge_args else f"tor-{re.sub(r'[^a-z0-9-]+', '-', label.lower()).strip('-')}")
        folder.mkdir(parents=True, exist_ok=True)
        start = log_path.stat().st_size if log_path.exists() else 0
        log = log_path.open("ab")
        try:
            process = subprocess.Popen(tor_command(tor, folder, proxy, bridge_args), cwd=tor.parent,
                                       stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        finally:
            log.close()
        opened = time.monotonic()
        last_change = opened
        last_percent = -1
        limit = 240 if bridge_args else 180 if proxy else 60
        while time.monotonic() < min(opened + limit, startup_deadline) and process.poll() is None:
            if ready(9050) and working(9050):
                return "127.0.0.1:9050"
            percent = -1
            try:
                text = log_path.read_bytes()[start:].decode("utf-8", "replace")
            except OSError:
                text = ""
            for line in text.splitlines():
                match = re.search(r"Bootstrapped (\d+)%", line)
                if match:
                    percent = int(match.group(1))
            if percent != last_percent:
                last_percent = percent
                last_change = time.monotonic()
            elapsed = time.monotonic() - opened
            if bridge_args and elapsed > 25 and 0 <= percent < 15:
                break
            if bridge_args and time.monotonic() - last_change > 40 and percent < 15:
                break
            time.sleep(2)
        if process.poll() is None and ready(9050) and working(9050):
            return "127.0.0.1:9050"
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
        if ready(9050):
            _stop_our_tor()
        if bridge_args and not asked_moat:
            asked_moat = True
            for extra_label, extra_args in moat_settings(lyrebird):
                if proxy and "snowflake" in extra_label:
                    continue
                key = _bridge_line_key(extra_args)
                if key in seen:
                    continue
                seen.add(key)
                attempts.insert(index, (extra_label, extra_args))
    tried_text = ", ".join(tried) or "a direct connection"
    if proxy:
        raise RuntimeError(
            "Tor was started through the Apex HTTP proxy and still did not open a circuit. "
            f"Tried {tried_text}. Log: {log_path}")
    raise RuntimeError(
        f"Tor could not open a circuit. Tried {tried_text}. "
        "A failed set is replaced by Tor's current built-in bridges, without a captcha. "
        f"Log: {log_path}")


_ONION_URL = re.compile(r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", re.IGNORECASE)


def onionland_rows(html: str, limit: int = 15) -> list[dict]:
    """OnionLand's current result blocks. The bundled OnionSearch parser no longer matches them."""
    soup = BeautifulSoup(html or "", "html.parser")
    rows, seen = [], set()
    for block in soup.select("div.result-block"):
        link = block.select_one(".link")
        raw = " ".join(link.get_text(" ", strip=True).split()) if link else ""
        if raw.lower().startswith("ad "):
            continue
        match = _ONION_URL.search(raw)
        if not match:
            continue
        url = match.group(0).rstrip(").,;")
        if url in seen:
            continue
        seen.add(url)
        title_el = block.select_one(".title")
        title = " ".join(title_el.get_text(" ", strip=True).split()) if title_el else url
        rows.append({"engine": "onionland", "title": (title or url)[:180], "url": url,
                     "snippet": block.get_text(" ", strip=True)[:600]})
        if len(rows) >= limit:
            break
    return rows


def _onion_origins() -> dict[str, str]:
    """Read the bundled registry without importing its command-line parser."""
    core = ROOT / ".venv" / "Lib" / "site-packages" / "onionsearch" / "core.py"
    if not core.is_file():
        core = next(iter((ROOT / ".venv").glob("lib/python*/site-packages/onionsearch/core.py")), core)
    try:
        tree = ast.parse(core.read_text(encoding="utf-8", errors="replace"))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "ENGINES" for target in node.targets):
                origins = ast.literal_eval(node.value)
                if isinstance(origins, dict):
                    return {**origins, "ahmia": "https://ahmia.fi"}
    except (OSError, ValueError, SyntaxError):
        pass
    # Ahmia works independently of the optional OnionSearch installation.
    return {"ahmia": "https://ahmia.fi"}


def _onionland_origin() -> str:
    origin = _onion_origins().get("onionland", "")
    if not origin:
        raise RuntimeError("OnionLand address is missing from bundled OnionSearch: run setup.bat")
    return origin


def _onion_link(raw: str) -> str:
    raw = urllib.parse.unquote(urllib.parse.unquote(raw or ""))
    parsed = urllib.parse.urlsplit(raw)
    params = urllib.parse.parse_qs(parsed.query)
    for name in ("redirect_url", "url", "u", "l"):
        if params.get(name):
            raw = params[name][0]
            break
    match = _ONION_URL.search(raw)
    if not match:
        return ""
    url = match.group(0).rstrip(").,;")
    host = urllib.parse.urlsplit(url).hostname or ""
    # Tor no longer supports v2; do not present those dead addresses as usable leads.
    return url if re.fullmatch(r"[a-z2-7]{56}\.onion", host, re.I) else ""


def onion_rows(engine: str, text: str, limit: int = 30) -> list[dict]:
    """Current OnionLand + per-engine selectors ported from OnionSearch 1.3."""
    if engine == "onionland":
        rows = onionland_rows(text, limit)
        if rows:
            return [row for row in rows if _onion_link(row["url"])]
    if engine == "darksearchio":
        payload = json.loads(text)
        return [{"engine": engine, "title": str(item.get("title") or url)[:250], "url": url,
                 "snippet": str(item.get("description") or "")[:600]}
                for item in payload.get("data", []) if isinstance(item, dict)
                and (url := _onion_link(str(item.get("link", ""))))][:limit]
    soup = BeautifulSoup(text or "", "html.parser")
    selectors = {"ahmia": "li.result h4 a", "darksearchenginer": ".table-responsive a",
                 "phobos": ".serp .titles", "onionsearchserver": ".osscmnrdr.ossfieldrdr1 a",
                 "torgle": "ul#page a", "torgle1": "#results a.title", "onionsearchengine": "table a",
                 "tordex": ".container h5 a", "tor66": "b a", "tormax": "#search-results article a.title",
                 "haystack": ".result b a", "multivac": "dl dt a", "evosearch": "#results .title a",
                 "deeplink": "tr td a", "notevil": "p a", "onionland": ".result-block .title a"}
    rows, seen = [], set()
    for anchor in soup.select(selectors.get(engine, "li.result a")):
        raw = str(anchor.get("href", ""))
        url = _onion_link(raw) or _onion_link(anchor.get_text(" ", strip=True))
        if not url or url in seen:
            continue
        seen.add(url)
        parent = anchor.find_parent("li", class_="result") if engine == "ahmia" else anchor.parent
        description = parent.get_text(" ", strip=True) if parent else ""
        rows.append({"engine": engine, "title": anchor.get_text(" ", strip=True)[:250] or url,
                     "url": url, "snippet": description[:600], "source": f"OnionSearch · {engine}"})
        if len(rows) >= limit:
            break
    return rows


def _onion_request(engine: str, origin: str, query: str, page: int) -> tuple[str, str, bytes | None]:
    q = urllib.parse.quote(query)
    paths = {"ahmia": f"/search/?q={q}", "darksearchio": f"/api/search?query={q}&page={page}",
             "onionland": f"/search?q={q}&page={page}", "notevil": f"/index.php?q={q}&hostLimit=20&start={(page-1)*20}&numRows=20&template=0",
             "phobos": f"/search?query={q}&p={page}", "torgle": f"/search.php?term={q}",
             "torgle1": f"/torgle/index-frame.php?query={q}&search=1&engine-ver=2&isframe=0&start={page}",
             "onionsearchengine": f"/search.php?search={q}&submit=Search&page={page}",
             "tordex": f"/search?query={q}&page={page}", "tor66": f"/search?q={q}&sorttype=rel&page={page}",
             "tormax": f"/search?q={q}", "haystack": f"/?q={q}&offset={(page-1)*20}",
             "multivac": f"/?q={q}&page={page}", "evosearch": f"/evo/search.php?query={q}&start={(page-1)*50+1}&search=1&type=and&mark=bold+text&results=50",
             "deeplink": f"/?search={q}&type=verified", "onionsearchserver": "/oss/"}
    if engine == "darksearchenginer":
        return origin, "POST", urllib.parse.urlencode({"search[keyword]": query, "page": page}).encode()
    if engine not in paths:
        raise ValueError(f"Unsupported onion index: {engine}")
    return origin + paths[engine], "GET", None


def _index_blocked(html: str) -> bool:
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
    text = soup.get_text(" ", strip=True).lower()
    return any(word in title for word in ("captcha", "access denied", "just a moment", "security check")) or any(
        word in text for word in ("verify you are human", "complete the captcha", "checking your browser"))


def _verify_ahmia_query(query: str, url: str, html: str) -> None:
    """A successful result page must still belong to the exact submitted query."""
    parameters = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
    if "q" in parameters:
        if parameters["q"] != [query]:
            raise RuntimeError("Ahmia returned a page for a different or truncated query")
        return
    field = BeautifulSoup(html or "", "html.parser").select_one('input[name="q"]')
    if field is None or field.get("value") != query:
        raise RuntimeError("Ahmia result page did not confirm the submitted query")


def _ahmia_browser(query: str, timeout: float = 30, page_number: int = 1) -> dict:
    """Submit Ahmia's public browser form; scripts produce its normal form token.

    Every network request is fulfilled via the pinned same-host fetcher. No
    CAPTCHA, login, or external-resource requests are automated.
    """
    from .evidence_capture import fetch_public
    if not isinstance(query, str) or not 2 <= len(query) <= 200:
        raise ValueError("Query must contain 2–200 characters")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Ahmia requires a browser form; Playwright is missing: run setup.bat") from exc
    executable = next((path for path in (
        Path(os.environ.get("CHROME_PATH", r"C:\Program Files\Google\Chrome\Application\chrome.exe")),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")) if path.is_file()), None)
    deadline = time.monotonic() + max(10, min(timeout, 45))
    requests_count, errors = 0, []
    allowed_types = {"text/html", "application/xhtml+xml", "application/javascript", "text/javascript", "text/css", "text/plain", "application/json"}
    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=True, executable_path=str(executable) if executable else None,
                                         timeout=max(1000, int((deadline-time.monotonic())*1000)),
                                         args=["--disable-background-networking", "--disable-extensions", "--disable-sync", "--disable-quic"])
        try:
            context = browser.new_context(accept_downloads=False, service_workers="block")
            context.set_default_timeout(max(1000, int((deadline-time.monotonic())*1000)))
            if hasattr(context, "route_web_socket"):
                context.route_web_socket("**/*", lambda socket: socket.close())
            def fulfill(route):
                nonlocal requests_count
                request = route.request
                target = urllib.parse.urlsplit(request.url)
                if (target.scheme != "https" or target.hostname != "ahmia.fi" or request.resource_type not in {"document", "script", "stylesheet", "xhr", "fetch"}
                        or request.method not in {"GET", "POST"} or requests_count >= 12 or time.monotonic() >= deadline):
                    route.abort()
                    return
                requests_count += 1
                try:
                    document = fetch_public(request.url, method=request.method, data=request.post_data_buffer,
                                            timeout=min(10, max(2, deadline-time.monotonic())), max_body=2_000_000 if request.resource_type == "document" else 1_000_000, accepted_types=allowed_types)
                    if urllib.parse.urlsplit(document["url"]).hostname != "ahmia.fi":
                        raise ValueError("Cross-host Ahmia redirects are blocked")
                    route.fulfill(status=document["http_status"], content_type=document["content_type"], body=document["body"])
                except Exception as exc:
                    errors.append(f"{target.path}: {exc}"[:250])
                    route.abort()
            context.route("**/*", fulfill)
            page = context.new_page()
            page.goto("https://ahmia.fi/", wait_until="networkidle")
            if _index_blocked(page.content()):
                raise RuntimeError("Ahmia requires a CAPTCHA/human verification; complete it manually")
            field = page.locator('input[name="q"]').first
            field.fill(query)
            if page_number > 1:
                field.evaluate("(element, number) => { let input = element.form.querySelector('input[name=page]'); if (!input) { input = document.createElement('input'); input.type = 'hidden'; input.name = 'page'; element.form.appendChild(input); } input.value = String(number - 1); }", page_number)
            with page.expect_navigation(wait_until="domcontentloaded", timeout=max(1000, int((deadline-time.monotonic())*1000))):
                field.press("Enter")
            html = page.content()
            if _index_blocked(html):
                raise RuntimeError("Ahmia blocked browser search with CAPTCHA/human verification")
            if not page.locator("li.result, .result, #results").count() and "no results" not in page.locator("body").inner_text().lower():
                raise RuntimeError("Ahmia browser form did not return a results page" + (": " + "; ".join(errors[-2:]) if errors else ""))
            _verify_ahmia_query(query, page.url, html)
            return {"html": html, "url": page.url, "observed_at": datetime.utcnow().isoformat()+"Z", "browser_requests": requests_count}
        except Exception as exc:
            detail = "; ".join(errors[-3:])
            raise RuntimeError(f"Ahmia browser: {exc}" + (f"; source fetch: {detail}" if detail else "")) from exc
        finally:
            browser.close()


def onion_search(query: str, output: Path, engines: str = "ahmia,onionland", page_limit: int = 1,
                 result_limit: int = 30, on_status=None, timeout: float = 25) -> dict:
    """Actually query every selected index; source failure never becomes an empty result."""
    from .evidence_capture import fetch_public, validated_url
    from .osint import _relevant
    output = output.resolve()
    query = " ".join(query.split())
    if not 2 <= len(query) <= 200:
        raise ValueError("Query must contain 2–200 characters")
    names = list(dict.fromkeys(name.strip().lower() for name in engines.split(",") if name.strip()))
    allowed = {"ahmia", "darksearchio", "onionland", "notevil", "darksearchenginer", "phobos", "onionsearchserver",
               "torgle", "torgle1", "onionsearchengine", "tordex", "tor66", "tormax", "haystack", "multivac", "evosearch", "deeplink"}
    if not names or len(names) > len(allowed) or set(names) - allowed:
        raise ValueError("Select supported onion search engines")
    if not 1 <= page_limit <= 3 or not 1 <= result_limit <= 100:
        raise ValueError("Onion page-limit: 1–3; result-limit: 1–100 per engine")
    origins, proxy, tor_error = _onion_origins(), "", ""
    rows, statuses, warnings, artifacts = [], [], [], []
    folder = output / "onion"
    folder.mkdir(parents=True, exist_ok=True)
    scan_stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    def emit(status):
        if on_status:
            on_status(status)
    for name in names:
        opened, found, pages, failure, candidates, filtered = time.monotonic(), [], 0, "", 0, 0
        emit({"name": f"onion:{name}", "state": "running", "count": 0, "detail": "Querying index"})
        try:
            origin = origins.get(name, "")
            if not origin:
                raise RuntimeError("Index address is missing from bundled OnionSearch: run setup.bat")
            host = urllib.parse.urlsplit(origin).hostname or ""
            if host.endswith(".onion"):
                if not re.fullmatch(r"[a-z2-7]{56}\.onion", host, re.I):
                    raise ValueError("Bundled index has an obsolete v2 address; Tor no longer supports it")
                if tor_error:
                    raise RuntimeError(tor_error)
                if not proxy:
                    try:
                        proxy = _tor_proxy(output)
                    except Exception as exc:
                        tor_error = str(exc)
                        raise
            for page_number in range(1, page_limit + 1):
                url, method, payload = _onion_request(name, origin, query, page_number)
                document = fetch_public(url, include_onion=True, tor_proxy=proxy, timeout=timeout, method=method, data=payload)
                if _index_blocked(document["html"]):
                    raise RuntimeError("Index requires CAPTCHA/human verification or denies automated access")
                if name == "ahmia" and (urllib.parse.urlsplit(document["url"]).path == "/" or "non-JavaScript version" in document["html"]):
                    emit({"name": "onion:ahmia", "state": "running", "count": 0, "detail": "Submitting public Ahmia browser form"})
                    document = _ahmia_browser(query, timeout, page_number)
                if name == "ahmia":
                    _verify_ahmia_query(query, document["url"], document["html"])
                if name == "onionsearchserver":
                    frame = BeautifulSoup(document["html"], "html.parser").select_one('iframe[src]')
                    if frame is None:
                        raise RuntimeError("Index iframe was not present; parser/source changed")
                    frame_url = urllib.parse.urljoin(url, str(frame["src"]))
                    if urllib.parse.urlsplit(frame_url).hostname != host:
                        raise ValueError("Cross-host index iframe is blocked")
                    frame_url += urllib.parse.quote(query) + f"&page={page_number}"
                    validated_url(frame_url, True)
                    document = fetch_public(frame_url, include_onion=True, tor_proxy=proxy, timeout=timeout)
                pages += 1
                snapshot = folder / f"index_{scan_stamp}_{name}_{page_number}.html"
                snapshot.write_text(document["html"], encoding="utf-8")
                artifacts.append(str(snapshot))
                page_rows = onion_rows(name, document["html"], result_limit)
                candidates += len(page_rows)
                matching = [row for row in page_rows if _relevant({**row, "snippet": row.get("snippet", "")}, query)]
                filtered += len(page_rows) - len(matching)
                seen = {row["url"] for row in found}
                additions = [row for row in matching if row["url"] not in seen]
                for row in additions:
                    row["index_url"] = document["url"]
                    row["observed_at"] = document["observed_at"]
                    row["index_artifact"] = str(snapshot)
                    row["index_sha256"] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                found.extend(additions[:result_limit - len(found)])
                if len(found) >= result_limit or not additions or name in {"torgle", "tormax", "deeplink"}:
                    break
        except Exception as exc:
            failure = str(exc)[:500]
        if candidates and not found and not failure:
            failure = "Index returned unrelated entries; the target was not confirmed in indexed text"
        if failure:
            warnings.append(f"{name}: {failure}")
        # Partial pages remain usable when a later request failed.
        state = "partial" if found and failure else "error" if failure else "ok" if found else "empty"
        status = {"name": f"onion:{name}", "engine": name, "state": state, "status": state, "count": len(found), "pages": pages,
                  "detail": failure or f"{len(found)} indexed onion URLs; {filtered} unrelated candidates excluded",
                  "candidate_count": candidates, "filtered_count": filtered, "elapsed_seconds": round(time.monotonic()-opened, 2)}
        statuses.append(status)
        emit(status)
        rows.extend(found)
    report = folder / f"onion_{scan_stamp}.csv"
    with report.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["engine", "title", "url", "index_url", "observed_at"], extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    manifest = report.with_suffix(".json")
    result = {"query": query, "proxy": proxy, "engines": names, "rows": rows, "statuses": statuses,
              "warnings": warnings, "errors": warnings, "report": str(report), "status_report": str(manifest),
              "page_limit": page_limit, "result_limit": result_limit, "artifacts": artifacts + [str(report), str(manifest)]}
    manifest.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    assert catalog("maigret")["matched"] >= 1
    assert catalog("no-such-osint-tool-xyz")["matched"] == 0
    assert catalog("", 100, 700)["rows"]
