"""Public checks that the main dossier collectors do not already cover.

WhatsMyName, Sherlock, Social Analyzer, and Blackbird look for a public
profile URL. Holehe reports only whether an email is registered; recovery
addresses and phone fragments are discarded. Blackbird runs without its AI
upload and without an Instagram session, and only the profile URL is kept.
Gravatar, urlscan, Subfinder, passive Amass, and public hostname lists add
hostnames. httpx requests the single site that was asked about. A name,
handle, email, or phone also keeps public https pages from a fixed set of
sites, and a name adds Wikidata, a DuckDuckGo instant answer, and a GLEIF
legal-entity record when one is published. A public IP adds reverse DNS and
the RIPE prefix. Phone results come from the numbering plan, not a subscriber
lookup. Leak records, brute force, and port scans are not requested.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from contextvars import copy_context
from pathlib import Path

try:
    import phonenumbers
    from phonenumbers import PhoneNumberType, carrier, geocoder
except ImportError:
    phonenumbers = None
    PhoneNumberType = carrier = geocoder = None

from .net import USER_AGENT


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "jobfind_out" / "cache" / "wmn-data.json"
SUBFINDER = ROOT / "third_party" / "subfinder" / "subfinder.exe"
AMASS = ROOT / "third_party" / "amass" / "amass.exe"
HTTPX = ROOT / "third_party" / "httpx" / "httpx.exe"
BLACKBIRD = ROOT / "third_party" / "blackbird"
SHERLOCK = ROOT / ".venv" / "Scripts" / "sherlock.exe"
SOCIAL = ROOT / ".venv" / "Scripts" / "social-analyzer"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
PASSIVE_HOSTNAME_SOURCES = {"Subfinder", "Amass", "Anubis", "RapidDNS", "HackerTarget",
                             "Common Crawl", "OTX", "Subdomain Center", "Robtex"}
PUBLIC_SITES = (
    ("vk.com", "VK"),
    ("ok.ru", "OK"),
    ("t.me", "Telegram"),
    ("youtube.com", "YouTube"),
    ("reddit.com", "Reddit"),
    ("pikabu.ru", "Pikabu"),
    ("habr.com", "Habr"),
    ("dzen.ru", "Dzen"),
)
_INDEX_LOCK = threading.Lock()
_LEI = re.compile(r"^[A-Z0-9]{20}\Z")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_USER = re.compile(r"^[A-Za-z0-9._-]{2,64}\Z")


def _request(url: str, timeout: float = 8, limit: int = 80_000, headers: dict | None = None) -> tuple[int, str]:
    from . import net
    response = net.get(url, retries=1, timeout=timeout * 2, max_bytes=limit,
                       extra_headers={"Accept": "application/json,text/plain,*/*", **(headers or {})})
    if response.status == 0:
        raise RuntimeError(response.error or "Network request failed")
    return response.status, response.text


def account_found(status: int, body: str, site: dict) -> bool:
    """True when the response matches WhatsMyName's found rule and not its missing rule."""
    try:
        expected = int(site.get("e_code") or 0)
    except (TypeError, ValueError):
        return False
    if status != expected:
        return False
    text = body or ""
    missing = str(site.get("m_string") or "")
    if missing and missing in text:
        return False
    present = str(site.get("e_string") or "")
    return not present or present in text


def profile_url(username: str, site: dict) -> str:
    template = str(site.get("uri_check") or "")
    if site.get("cat") == "archived" or "{account}" not in template or not template.startswith("https://"):
        return ""
    if not _USER.fullmatch(username):
        return ""
    url = template.replace("{account}", urllib.parse.quote(username))
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return ""
    return url


def _wmn_sites(limit: int = 48) -> list[dict]:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    fresh = CACHE.exists() and time.time() - CACHE.stat().st_mtime < 7 * 24 * 3600
    if not fresh:
        status, body = _request(WMN_URL, timeout=25, limit=8_000_000)
        if status == 200 and body.startswith("{"):
            CACHE.write_text(body, encoding="utf-8")
    if not CACHE.exists():
        raise RuntimeError("WhatsMyName list could not be downloaded")
    data = json.loads(CACHE.read_text(encoding="utf-8"))
    sites = [site for site in data.get("sites", []) if isinstance(site, dict)]
    preferred = [site for site in sites if site.get("cat") in {"social", "coding", "business", "tech", "images"}]
    chosen = []
    for site in preferred or sites:
        template = str(site.get("uri_check") or "")
        if site.get("cat") == "archived" or "{account}" not in template or not template.startswith("https://"):
            continue
        chosen.append(site)
        if len(chosen) >= limit:
            break
    return chosen


def whatsmyname(username: str, coverage: str = "quick") -> dict:
    """Check a bounded set of public profile URLs from the WhatsMyName list."""
    if not _USER.fullmatch(username):
        return {"profiles": [], "errors": ["WhatsMyName: username must be 2–64 Latin letters, digits, dots, underscores, or hyphens"]}
    sites = _wmn_sites(250 if coverage == "deep" else 48)
    profiles = []

    def check(site: dict) -> dict | None:
        url = profile_url(username, site)
        if not url:
            return None
        try:
            status, body = _request(url, timeout=6, limit=60_000)
        except (OSError, RuntimeError) as exc:
            return {"error": str(exc)}
        if not account_found(status, body, site):
            return None
        return {"site": str(site.get("name") or urllib.parse.urlsplit(url).hostname),
                "url": url, "username": username, "source": "WhatsMyName",
                "status": "candidate; same handle only, identity unverified"}

    pool = ThreadPoolExecutor(max_workers=12)
    try:
        pending = [pool.submit(check, site) for site in sites]
        done, running = wait(pending, timeout=120 if coverage == "deep" else 30)
        for future in running:
            future.cancel()
        failed = 0
        for future in done:
            row = future.result()
            if row and row.get("error"):
                failed += 1
            elif row:
                profiles.append(row)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    errors = []
    if running:
        errors.append(f"WhatsMyName: timeout; {len(running)} of {len(sites)} checks unfinished")
    if failed:
        errors.append(f"WhatsMyName: {failed} of {len(sites)} requests failed")
    return {"profiles": profiles, "errors": errors, "checked": len(done), "planned": len(sites)}


def gravatar(email: str) -> dict:
    """Public Gravatar profile for an email hash. A missing profile is empty, not an error."""
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
    status, body = _request(f"https://secure.gravatar.com/{digest}.json", timeout=8)
    if status == 404:
        return {"profiles": [], "errors": []}
    if status != 200:
        return {"profiles": [], "errors": [f"Gravatar: HTTP {status}"]}
    try:
        entry = json.loads(body).get("entry") or []
    except ValueError:
        return {"profiles": [], "errors": ["Gravatar: invalid response"]}
    if not entry:
        return {"profiles": [], "errors": []}
    name = str(entry[0].get("displayName") or entry[0].get("preferredUsername") or "Gravatar")
    return {"profiles": [{"site": "Gravatar", "url": f"https://gravatar.com/{digest}",
                          "username": name, "source": "Gravatar",
                          "status": "Public profile for this email hash; identity unverified"}],
            "errors": []}


def urlscan_rows(payload: dict) -> list[dict]:
    rows = []
    for item in (payload.get("results") or [])[:8]:
        if not isinstance(item, dict):
            continue
        page = item.get("page") or {}
        task = item.get("task") or {}
        url = str(page.get("url") or task.get("url") or "")
        if not url.startswith("https://"):
            continue
        rows.append({"title": str(page.get("title") or page.get("domain") or url)[:180],
                     "url": url, "snippet": "Existing public urlscan.io result",
                     "source": "urlscan.io", "category": "Public scan"})
    return rows


def urlscan(domain: str) -> dict:
    query = urllib.parse.urlencode({"q": f"domain:{domain}", "size": 8})
    status, body = _request(f"https://urlscan.io/api/v1/search/?{query}", timeout=15)
    if status != 200:
        return {"web": [], "errors": [f"urlscan.io: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"web": [], "errors": ["urlscan.io: invalid response"]}
    return {"web": urlscan_rows(payload), "errors": []}


def phone_plan(number: str) -> dict:
    """Country, number type, and carrier name from the public numbering plan."""
    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as exc:
        return {"findings": [], "errors": [f"Phone: {exc}"]}
    if not phonenumbers.is_valid_number(parsed):
        return {"findings": [], "errors": ["Phone: not a valid international number"]}
    kind = PhoneNumberType.to_string(phonenumbers.number_type(parsed)).replace("_", " ").lower()
    region = geocoder.description_for_number(parsed, "en") or "unknown region"
    name = carrier.name_for_number(parsed, "en") or "carrier not published"
    return {"findings": [{"event_type": "PHONE_NUMBER", "value": f"{region}; {kind}; {name}",
                          "module": "numbering plan", "url": "", "source_data": ""}],
            "errors": []}


def holehe_profiles(rows: list[dict]) -> list[dict]:
    """Keep the site name only. Drop recovery addresses and phone fragments."""
    profiles = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not row.get("exists") or row.get("rateLimit"):
            continue
        domain = str(row.get("domain") or "").strip().lower().rstrip(".")
        if not _HOST.fullmatch(domain) or domain in seen:
            continue
        seen.add(domain)
        profiles.append({"site": str(row.get("name") or domain), "url": f"https://{domain}",
                         "username": "", "source": "Holehe",
                         "status": "Email is registered on this public service; identity unverified"})
    return profiles


def holehe(email: str) -> dict:
    import httpx
    from holehe.core import get_functions, import_submodules, launch_module

    async def run() -> tuple[list, int, int]:
        found: list = []
        websites = get_functions(import_submodules("holehe.modules"))
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0), follow_redirects=True) as client:
            tasks = [asyncio.create_task(launch_module(site, email, client, found)) for site in websites]
            _done, pending = await asyncio.wait(tasks, timeout=35)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return found, len(websites), len(pending)

    try:
        rows, planned, pending = asyncio.run(run())
    except Exception as exc:
        return {"profiles": [], "errors": [f"Holehe: {exc}"]}
    errors = []
    failed = sum(bool(row.get("rateLimit")) for row in rows)
    if pending:
        errors.append(f"Holehe: time limit; {pending} of {planned} checks unfinished")
    if failed:
        errors.append(f"Holehe: {failed} of {planned} checks blocked or failed")
    return {"profiles": holehe_profiles(rows), "errors": errors, "checked": len(rows), "planned": planned}


def subfinder(domain: str) -> dict:
    executable = SUBFINDER if SUBFINDER.exists() else Path(shutil.which("subfinder") or "")
    if not executable.is_file():
        return {"hostnames": [], "errors": ["Subfinder: binary is not installed"]}
    # -max-time is minutes, not seconds. Keep the process deadline longer
    # than that budget and retain its stdout if an upstream source still hangs.
    out, err, timed = _run([str(executable), "-d", domain, "-silent", "-timeout", "8",
                          "-max-time", "1"], 75)
    hosts = []
    for line in out.splitlines():
        host = line.strip().lower().rstrip(".")
        if _HOST.fullmatch(host) and (host == domain or host.endswith("." + domain)):
            hosts.append(host)
    errors = ["Subfinder: time limit; retained completed hostname observations"] if timed else []
    if not hosts and not timed and err.strip():
        errors.append("Subfinder: " + err.strip().splitlines()[-1][:240])
    return {"hostnames": list(dict.fromkeys(hosts))[:80], "errors": errors}


def github_profile(payload: dict) -> dict:
    """Fields the account holder published on GitHub. Location is that text, not a fix."""
    if not isinstance(payload, dict):
        return {"profiles": [], "web": [], "findings": [], "errors": []}
    url = str(payload.get("html_url") or "")
    login = str(payload.get("login") or "")
    if not url.startswith("https://github.com/") or not login:
        return {"profiles": [], "web": [], "findings": [], "errors": []}
    profiles = [{"site": "GitHub", "url": url, "username": login, "source": "GitHub",
                 "status": "Public GitHub profile; identity unverified"}]
    web = []
    blog = str(payload.get("blog") or "").strip()
    if blog.startswith("https://"):
        web.append({"title": f"{login} published site", "url": blog,
                    "snippet": "Website field on the public GitHub profile",
                    "source": "GitHub", "category": "Public profile"})
    parts = []
    for label, key in (("name", "name"), ("company", "company"), ("location", "location"), ("bio", "bio")):
        text = " ".join(str(payload.get(key) or "").split())
        if text:
            parts.append(f"{label}: {text[:120]}")
    findings = []
    if parts:
        findings.append({"event_type": "ACCOUNT", "value": "; ".join(parts)[:300],
                         "module": "github", "url": url, "source": "GitHub"})
    return {"profiles": profiles, "web": web, "findings": findings, "errors": []}


def github_user(username: str) -> dict:
    if not _USER.fullmatch(username):
        return {"profiles": [], "errors": ["GitHub: username is not supported"]}
    headers = {"Accept": "application/vnd.github+json"}
    token = ""
    try:
        from .domain_recon import configured_keys
        token = configured_keys().get("GITHUB_TOKEN", "")
    except Exception:
        token = ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, body = _request(f"https://api.github.com/users/{urllib.parse.quote(username)}",
                            timeout=12, headers=headers)
    if status == 404:
        return {"profiles": [], "errors": []}
    if status == 403 and not token:
        return {"profiles": [], "errors": ["GitHub: HTTP 403; add GITHUB_TOKEN to osint-keys.env if this repeats"]}
    if status != 200:
        return {"profiles": [], "errors": [f"GitHub: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"profiles": [], "errors": ["GitHub: invalid response"]}
    return github_profile(payload)


def openpgp_published(email: str, status: int, body: str) -> dict:
    """Record that a public key exists. The key block itself is not kept."""
    if status == 404:
        return {"findings": [], "errors": []}
    if status != 200:
        return {"findings": [], "errors": [f"OpenPGP: HTTP {status}"]}
    if "BEGIN PGP PUBLIC KEY BLOCK" not in (body or ""):
        return {"findings": [], "errors": []}
    return {"findings": [{"event_type": "OPENPGP_KEY",
                          "value": "Published public key; key material is not stored",
                          "module": "keys.openpgp.org",
                          "url": f"https://keys.openpgp.org/search?q={urllib.parse.quote(email.strip())}",
                          "source": "OpenPGP"}], "errors": []}


def openpgp(email: str) -> dict:
    quoted = urllib.parse.quote(email.strip())
    status, body = _request(f"https://keys.openpgp.org/vks/v1/by-email/{quoted}", timeout=12, limit=4_000)
    return openpgp_published(email, status, body)


def archive_rows(domain: str, table: list) -> list[dict]:
    """Historical captures for this domain. Off-site URLs are dropped."""
    rows = []
    seen = set()
    domain = domain.lower().rstrip(".")
    for item in table:
        if not isinstance(item, list) or len(item) < 2 or item[0] == "original":
            continue
        original = str(item[0]).strip()
        timestamp = str(item[1]).strip()
        if not timestamp.isdigit() or not 8 <= len(timestamp) <= 14 or original in seen:
            continue
        parsed = urllib.parse.urlsplit(original)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host:
            continue
        if host != domain and not host.endswith("." + domain):
            continue
        seen.add(original)
        rows.append({"title": original[:180],
                     "url": f"https://web.archive.org/web/{timestamp}/{original}",
                     "snippet": "Public Internet Archive capture",
                     "source": "Internet Archive", "category": "Public archive",
                     "original_url": original, "snapshot_at": timestamp, "archived": True})
        if len(rows) == 12:
            break
    return rows


def archive_cdx(domain: str) -> dict:
    query = urllib.parse.urlencode({"url": f"{domain}/*", "output": "json",
                                    "fl": "original,timestamp,statuscode",
                                    "filter": "statuscode:200", "collapse": "urlkey", "limit": "20"})
    status, body = _request(f"https://web.archive.org/cdx/search/cdx?{query}", timeout=20, limit=500_000)
    if status != 200:
        return {"web": [], "errors": [f"Internet Archive: HTTP {status}"]}
    try:
        table = json.loads(body)
    except ValueError:
        return {"web": [], "errors": ["Internet Archive: invalid response"]}
    if not isinstance(table, list):
        return {"web": [], "errors": ["Internet Archive: invalid response"]}
    return {"web": archive_rows(domain, table), "errors": []}


def rdap_summary(payload: dict) -> str:
    if not isinstance(payload, dict):
        return ""
    name = " ".join(str(payload.get("name") or payload.get("handle") or "").split())
    country = " ".join(str(payload.get("country") or "").split())
    cidrs = []
    for item in payload.get("cidr0_cidrs") or []:
        if not isinstance(item, dict):
            continue
        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")
        if prefix and length is not None:
            cidrs.append(f"{prefix}/{length}")
    return "; ".join(part for part in (name, country, ", ".join(cidrs[:3])) if part)[:240]


def _public_address(value: str) -> str:
    text = value.strip()
    try:
        if "/" in text:
            address = ipaddress.ip_network(text, strict=False).network_address
        else:
            address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return str(address) if address.is_global else ""


def ip_registration(value: str) -> dict:
    """RDAP network registration for a public address. Private addresses are not sent."""
    address = _public_address(value)
    if not address:
        return {"findings": [], "errors": ["RDAP: not a public IP address"]}
    url = f"https://rdap.org/ip/{urllib.parse.quote(address)}"
    status, body = _request(url, timeout=15)
    if status == 404:
        return {"findings": [], "errors": []}
    if status != 200:
        return {"findings": [], "errors": [f"RDAP: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"findings": [], "errors": ["RDAP: invalid response"]}
    text = rdap_summary(payload)
    if not text:
        return {"findings": [], "errors": ["RDAP: no registration fields"]}
    return {"findings": [{"event_type": "IP_ADDRESS", "value": text, "module": "rdap",
                          "url": url, "source": "RDAP"}], "errors": []}


def hostname_item(item, default: str = "Subfinder") -> tuple[str, str]:
    """Accept a bare hostname or ``{"name", "source"}`` from a passive tool."""
    if isinstance(item, str):
        return item.strip().lower().rstrip("."), default
    if isinstance(item, dict):
        return (str(item.get("name") or "").strip().lower().rstrip("."),
                str(item.get("source") or default))
    return "", ""


def _proxy() -> str:
    value = os.environ.get("JOBFIND_ACTIVE_PROXY", "").strip()
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme in {"http", "https", "socks5", "socks5h"} and parsed.hostname and parsed.port:
        return value
    return ""


def _python() -> str:
    return str(PYTHON) if PYTHON.is_file() else sys.executable


def _run(command: list[str], timeout: float, cwd: str | None = None,
         env: dict | None = None) -> tuple[str, str, bool]:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, creationflags=flags, cwd=cwd, env=env)
        return completed.stdout or "", completed.stderr or "", False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", errors="replace")
        return out or "", err or "", True
    except OSError as exc:
        return "", str(exc), False


def _https_profile(site: str, url: str, username: str, source: str) -> dict | None:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    return {"site": site or parsed.hostname, "url": url.strip(), "username": username,
            "source": source, "status": "Public profile link; identity unverified"}


def sherlock_profiles(text: str, username: str, limit: int = 40) -> list[dict]:
    """Keep claimed https profiles. Ignore the tool's banner and plain http."""
    profiles = []
    seen = set()
    needle = username.lower()
    for line in _ANSI.sub("", text).splitlines():
        match = re.search(r"\[\+\]\s+([^:\r\n]+):\s+(https://\S+)", line)
        if not match:
            continue
        url = match.group(2).rstrip(".,)")
        if needle not in url.lower() or url in seen:
            continue
        row = _https_profile(match.group(1).strip(), url, username, "Sherlock")
        if not row:
            continue
        seen.add(url)
        profiles.append(row)
        if len(profiles) >= limit:
            break
    return profiles


def sherlock_command(username: str) -> list[str]:
    command = [str(SHERLOCK), username, "--local", "--no-color", "--timeout", "4", "--print-found"]
    proxy = _proxy()
    if proxy:
        command.extend(["--proxy", proxy])
    return command


def sherlock(username: str, coverage: str = "quick") -> dict:
    if not _USER.fullmatch(username):
        return {"profiles": [], "errors": ["Sherlock: username is not supported"]}
    if not SHERLOCK.is_file():
        return {"profiles": [], "errors": ["Sherlock: is not installed"]}
    with tempfile.TemporaryDirectory() as tmp:
        out, err, timed = _run(sherlock_command(username), 180 if coverage == "deep" else 35, cwd=tmp)
    profiles = sherlock_profiles(out, username, 250 if coverage == "deep" else 40)
    errors = []
    if timed:
        errors.append("Sherlock: stopped at the time limit; kept profiles found by then")
    elif not profiles and err.strip():
        errors.append("Sherlock: " + err.strip().splitlines()[-1][:200])
    return {"profiles": profiles, "errors": errors}


def social_analyzer_profiles(payload: dict, username: str, limit: int = 30) -> list[dict]:
    """Detected https links only. Page text, metadata, and extracts are dropped."""
    detected = payload.get("detected") if isinstance(payload, dict) else None
    if not isinstance(detected, list):
        return []
    profiles = []
    seen = set()
    needle = username.lower()
    for item in detected:
        if not isinstance(item, dict):
            continue
        url = str(item.get("link") or "")
        status = str(item.get("status") or "good")
        if status not in {"good", ""} or needle not in url.lower() or url in seen:
            continue
        row = _https_profile(urllib.parse.urlsplit(url).hostname or "", url, username, "Social Analyzer")
        if not row:
            continue
        seen.add(url)
        profiles.append(row)
        if len(profiles) >= limit:
            break
    return profiles


def _json_blob(text: str):
    decoder = json.JSONDecoder()
    found = None
    index = 0
    while True:
        start = text.find("{", index)
        if start < 0:
            return found
        try:
            obj, end = decoder.raw_decode(text[start:])
        except ValueError:
            index = start + 1
            continue
        found = obj
        index = start + max(end, 1)
    return found


def social_command(username: str, coverage: str = "quick") -> list[str]:
    return [_python(), str(SOCIAL), "--username", username, "--top", "150" if coverage == "deep" else "25", "--mode", "fast",
            "--output", "json", "--filter", "good", "--profiles", "detected", "--method", "find"]


def social_analyzer(username: str, coverage: str = "quick") -> dict:
    if not _USER.fullmatch(username):
        return {"profiles": [], "errors": ["Social Analyzer: username is not supported"]}
    if not SOCIAL.is_file():
        return {"profiles": [], "errors": ["Social Analyzer: is not installed"]}
    with tempfile.TemporaryDirectory() as tmp:
        out, err, timed = _run(social_command(username, coverage), 180 if coverage == "deep" else 40, cwd=tmp)
    payload = _json_blob(out) or {}
    profiles = social_analyzer_profiles(payload, username, 150 if coverage == "deep" else 30) if isinstance(payload, dict) else []
    errors = []
    if timed:
        errors.append("Social Analyzer: stopped at the time limit; kept profiles found by then")
    elif not profiles and not payload and err.strip():
        errors.append("Social Analyzer: " + err.strip().splitlines()[-1][:200])
    return {"profiles": profiles, "errors": errors}


def blackbird_profiles(payload, username: str) -> list[dict]:
    """FOUND https URLs only. Metadata, phones, and recovery fields are not copied."""
    rows = payload if isinstance(payload, list) else []
    profiles = []
    seen = set()
    for item in rows:
        if not isinstance(item, dict) or item.get("status") != "FOUND":
            continue
        url = str(item.get("url") or "")
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if "blackbird" in host or host.endswith("whatsmyname.app") or url in seen:
            continue
        row = _https_profile(str(item.get("name") or host), url, username, "Blackbird")
        if not row:
            continue
        seen.add(url)
        profiles.append(row)
        if len(profiles) == 40:
            break
    return profiles


def blackbird_command(value: str, kind: str) -> list[str]:
    flag = "--username" if kind == "username" else "--email"
    command = [_python(), str(BLACKBIRD / "blackbird.py"), flag, value, "--json", "--no-nsfw",
               "--no-update", "--timeout", "4", "--max-concurrent-requests", "20"]
    proxy = _proxy()
    if proxy:
        command.extend(["--proxy", proxy])
    return command


def blackbird(value: str, kind: str) -> dict:
    if kind == "username" and not _USER.fullmatch(value):
        return {"profiles": [], "errors": ["Blackbird: username is not supported"]}
    if kind == "email" and "@" not in value:
        return {"profiles": [], "errors": ["Blackbird: email is not supported"]}
    if not (BLACKBIRD / "blackbird.py").is_file():
        return {"profiles": [], "errors": ["Blackbird: is not installed"]}
    env = os.environ.copy()
    env.pop("INSTAGRAM_SESSION_ID", None)
    env["PYTHONUNBUFFERED"] = "1"
    profiles = []
    planned = None
    # Upstream writes exports relative to its source tree. Isolate the tree so
    # previous exports cannot be read as fresh matches or deleted after a run.
    with tempfile.TemporaryDirectory(prefix="findall-blackbird-") as tmp:
        vendor = Path(tmp)
        shutil.copy2(BLACKBIRD / "blackbird.py", vendor / "blackbird.py")
        for name in ("src", "data", "assets"):
            if (BLACKBIRD / name).is_dir():
                shutil.copytree(BLACKBIRD / name, vendor / name,
                                ignore=shutil.ignore_patterns("__pycache__"))
        wmn = vendor / "data" / "wmn-data.json"
        if kind == "username" and not wmn.exists() and CACHE.exists():
            wmn.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(CACHE, wmn)
        if kind == "username" and wmn.exists():
            data = json.loads(wmn.read_text(encoding="utf-8"))
            sites = [site for site in data.get("sites", []) if isinstance(site, dict)
                     and site.get("cat") in {"social", "coding", "business", "tech", "images"}]
            data["sites"] = sites[:48]
            planned = len(data["sites"])
            wmn.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        command = blackbird_command(value, kind)
        command[1] = str(vendor / "blackbird.py")
        if kind == "username" and not wmn.exists():
            command = [part for part in command if part != "--no-update"]
        out, err, timed = _run(command, 40, cwd=str(vendor), env=env)
        results = vendor / "results"
        if results.exists():
            for path in results.rglob("*.json"):
                try:
                    profiles.extend(blackbird_profiles(json.loads(path.read_text(encoding="utf-8")), value))
                except ValueError:
                    continue
    if not profiles:
        profiles = blackbird_profiles(_found_urls(out, value), value)
    errors = []
    if timed:
        errors.append("Blackbird: stopped at the time limit; kept profiles found by then")
    elif not profiles and err.strip() and "Either --username or --email" not in err:
        errors.append("Blackbird: " + _ANSI.sub("", err).strip().splitlines()[-1][:200])
    return {"profiles": profiles[:40], "errors": errors,
            "planned": planned}


def _found_urls(text: str, needle: str) -> list[dict]:
    """Fallback when Blackbird is stopped before it writes JSON."""
    rows = []
    seen = set()
    clean = re.sub(r"\[/?[a-zA-Z0-9_ ]+\]", "", _ANSI.sub("", text))
    for line in clean.splitlines():
        if needle.lower() not in line.lower():
            continue
        for url in re.findall(r"https://[^\s\]\)\"']+", line):
            url = url.rstrip(".,)")
            if url in seen:
                continue
            seen.add(url)
            rows.append({"name": urllib.parse.urlsplit(url).hostname or "", "url": url, "status": "FOUND"})
    return rows


def hosts_matching(domain: str, values, source: str, limit: int = 40) -> list[dict]:
    domain = domain.lower().rstrip(".")
    hosts = []
    seen = set()
    for item in values:
        host = str(item).strip().lower().rstrip(".")
        if "://" in host or host.startswith("//"):
            host = (urllib.parse.urlsplit(host if "://" in host else "https:" + host).hostname or "")
        host = host.rstrip(".")
        if not _HOST.fullmatch(host) or host in seen:
            continue
        if host != domain and not host.endswith("." + domain):
            continue
        seen.add(host)
        hosts.append({"name": host, "source": source})
        if len(hosts) == limit:
            break
    return hosts


def amass_hosts(domain: str, text: str) -> list[dict]:
    tokens = re.findall(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", _ANSI.sub("", text).lower())
    return hosts_matching(domain, tokens, "Amass", limit=80)


def amass_command(domain: str, directory: str, output: str) -> list[str]:
    return [str(AMASS), "enum", "-passive", "-d", domain, "-nocolor", "-timeout", "1",
            "-dir", directory, "-o", output]


def amass(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "errors": ["Amass: domain is not supported"]}
    if not AMASS.is_file():
        return {"hostnames": [], "errors": ["Amass: binary is not installed"]}
    with tempfile.TemporaryDirectory() as tmp:
        output = str(Path(tmp) / "names.txt")
        out, err, timed = _run(amass_command(domain, tmp, output), 75)
        written = ""
        if Path(output).is_file():
            written = Path(output).read_text(encoding="utf-8", errors="replace")
    hosts = amass_hosts(domain, out + "\n" + written)
    errors = []
    if timed:
        errors.append("Amass: stopped at the time limit; kept hostnames found by then")
    elif not hosts and err.strip():
        errors.append("Amass: " + err.strip().splitlines()[-1][:200])
    return {"hostnames": hosts, "errors": errors}


def httpx_page(domain: str, text: str) -> list[dict]:
    """One homepage row. A different host in the output is ignored."""
    domain = domain.lower().rstrip(".")
    allowed = {domain, "www." + domain}
    for line in _ANSI.sub("", text[:1_000_000]).splitlines()[:20]:
        if line.lstrip().startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            url = str(data.get("url", ""))
            try:
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme != "https" or parsed.hostname not in allowed or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.path not in ("", "/") or parsed.query:
                    continue
            except ValueError:
                continue
            if data.get("failed"):
                continue
            from datetime import datetime, timezone
            stamp = datetime.now(timezone.utc).isoformat()
            code = data.get("status_code")
            headers = data.get("header", data.get("headers", {}))
            useful_headers = {}
            if isinstance(headers, dict):
                for name, value in headers.items():
                    name = str(name).lower().replace("_", "-")
                    if name in {"server", "content-type", "x-powered-by", "strict-transport-security", "content-security-policy", "x-frame-options"}:
                        useful_headers[name] = str(value)[:1500]
            tls = data.get("tls", {})
            tls_fields = {}
            if isinstance(tls, dict):
                for key in ("tls_version", "cipher", "subject_cn", "issuer_cn", "not_before", "not_after", "expired", "self_signed", "mismatched", "fingerprint_hash"):
                    value = tls.get(key)
                    if isinstance(value, (str, int, bool)):
                        tls_fields[key] = value[:1000] if isinstance(value, str) else value
                    elif key == "fingerprint_hash" and isinstance(value, dict):
                        tls_fields[key] = {str(kind)[:20]: str(digest)[:160] for kind, digest in list(value.items())[:3]}
            tech_values = data.get("tech")
            technologies = [value[:150] for value in tech_values[:40] if isinstance(value, str)] if isinstance(tech_values, list) else []
            observation = {"status_code": code if isinstance(code, int) else None,
                "content_type": str(data.get("content_type") or useful_headers.get("content-type", ""))[:200],
                "content_length": data.get("content_length") if isinstance(data.get("content_length"), int) else None,
                "server": str(data.get("webserver") or useful_headers.get("server", ""))[:200],
                "response_time": str(data.get("time", ""))[:100], "headers": useful_headers,
                "tls": tls_fields, "technologies": technologies, "checked_at": stamp,
                "provider_observed_at": str(data.get("timestamp") or "")[:100],
                "limits": "Homepage observations and technology signatures do not prove a version, ownership or vulnerability. httpx DNS resolution has a separate resolver path from the HTTP proxy."}
            title = " ".join(str(data.get("title") or parsed.hostname).split())[:250]
            snippet = f"HTTP {code}" if isinstance(code, int) else "Homepage responded"
            if observation["server"]:
                snippet += "; server " + observation["server"]
            if technologies:
                snippet += "; technology signatures " + ", ".join(technologies)
            return [{"title": title, "url": url, "snippet": snippet[:1000], "source": "httpx",
                     "category": "Public page", "checked_at": stamp, "http_observation": observation,
                     "certainty": "observed"}]
        match = re.search(r"https://([^/\s\]]+)", line)
        if not match:
            continue
        host = match.group(1).lower().rstrip(".").split(":", 1)[0]
        if host not in allowed:
            continue
        codes = re.findall(r"\[(\d{3})\]", line)
        status = codes[0] if codes else ""
        title = ""
        for item in re.findall(r"\[([^\[\]]+)\]", line):
            if item != status and not item.isdigit():
                title = " ".join(item.split())
                break
        snippet = f"HTTP {status}" if status else "Homepage responded"
        if title:
            snippet = f"{snippet}; {title}"[:180]
        return [{"title": title or host, "url": f"https://{host}/", "snippet": snippet,
                 "source": "httpx", "category": "Public page"}]
    return []


def httpx_command(domain: str) -> list[str]:
    command = [str(HTTPX), "-u", f"https://{domain}", "-status-code", "-title", "-silent",
               "-nc", "-timeout", "8", "-threads", "1", "-duc", "-no-stdin", "-nfs",
               "-json", "-irh", "-omit-body", "-server", "-tech-detect", "-tls-grab",
               "-content-type", "-content-length", "-response-time", "-rstr", "1000000", "-retries", "0"]
    proxy = _proxy()
    if proxy:
        command.extend(["-proxy", proxy])
    return command


def httpx_probe(domain: str) -> dict:
    """GET the one https URL the user asked about. No port list and no other hosts."""
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"web": [], "errors": ["httpx: domain is not supported"]}
    if not HTTPX.is_file():
        return {"web": [], "errors": ["httpx: binary is not installed"]}
    out, err, timed = _run(httpx_command(domain), 20)
    rows = httpx_page(domain, out)
    errors = []
    if timed:
        errors.append("httpx: time limit")
    elif not rows and err.strip():
        detail = _ANSI.sub("", err).strip().splitlines()
        errors.append("httpx: " + (detail[-1][:200] if detail else "no response"))
    elif not rows:
        errors.append("httpx: no parseable homepage observation; network, TLS or upstream tool access may have failed")
    observations = [row["http_observation"] for row in rows if "http_observation" in row]
    technologies = [{"name": name, "version": "", "url": row["url"], "source": "httpx signature",
                     "checked_at": row.get("checked_at", ""), "certainty": "candidate"}
                    for row in rows for name in row.get("http_observation", {}).get("technologies", [])]
    for technology in technologies:
        detected = re.fullmatch(r"(.+?):([0-9][A-Za-z0-9.+-]*)", technology["name"])
        if detected:
            technology["name"], technology["version"] = detected.groups()
        technology["limits"] = "Detected signature; product/version is not independently confirmed."
    return {"web": rows, "errors": errors, "http_observations": observations, "technologies": technologies}


def anubis_hosts(domain: str, payload) -> list[dict]:
    values = payload if isinstance(payload, list) else []
    if isinstance(payload, dict):
        values = payload.get("subdomains") or payload.get("hostnames") or []
    return hosts_matching(domain, values, "Anubis")


def anubis(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "errors": ["Anubis: domain is not supported"]}
    status, body = _request(f"https://jldc.me/anubis/subdomains/{urllib.parse.quote(domain)}",
                            timeout=15, limit=400_000)
    if status != 200:
        return {"hostnames": [], "errors": [f"Anubis: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"hostnames": [], "errors": ["Anubis: invalid response"]}
    return {"hostnames": anubis_hosts(domain, payload), "errors": []}


def hackertarget_hosts(domain: str, text: str) -> tuple[list[dict], str]:
    hosts = []
    for line in text.splitlines():
        host = line.split(",")[0].strip()
        if host:
            hosts.append(host)
    rows = hosts_matching(domain, hosts, "HackerTarget", limit=40)
    if rows:
        return rows, ""
    lowered = text.lower()
    if "exceeded" in lowered or lowered.startswith("error") or "invalid" in lowered:
        detail = text.strip().splitlines()
        return [], (detail[0][:180] if detail else "no hostnames")
    return [], ""


def hackertarget(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "errors": ["HackerTarget: domain is not supported"]}
    status, body = _request(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}",
                            timeout=15)
    if status != 200:
        return {"hostnames": [], "errors": [f"HackerTarget: HTTP {status}"]}
    hosts, detail = hackertarget_hosts(domain, body)
    return {"hostnames": hosts, "errors": [f"HackerTarget: {detail}"] if detail else []}


def _child_hosts(domain: str, values, source: str, limit: int = 40) -> list[dict]:
    domain = domain.lower().rstrip(".")
    children = [str(item).strip().lower().rstrip(".") for item in values
                if str(item).strip().lower().rstrip(".").endswith("." + domain)]
    return hosts_matching(domain, children, source, limit)


def subdomaincenter_hosts(domain: str, payload) -> list[dict]:
    values = payload if isinstance(payload, list) else []
    return _child_hosts(domain, values, "Subdomain Center")


def subdomaincenter(domain: str) -> dict:
    """Public hostname list used by theHarvester. No API key."""
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "errors": ["Subdomain Center: domain is not supported"]}
    status, body = _request(f"https://api.subdomain.center/?domain={urllib.parse.quote(domain)}",
                            timeout=15, limit=400_000)
    if status != 200:
        return {"hostnames": [], "errors": [f"Subdomain Center: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"hostnames": [], "errors": ["Subdomain Center: invalid response"]}
    return {"hostnames": subdomaincenter_hosts(domain, payload), "errors": []}


def _robtex_rows(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def robtex_hosts(domain: str, text: str) -> list[dict]:
    names = []
    for row in _robtex_rows(text):
        names.extend(str(row.get(key) or "") for key in ("rrname", "rrdata"))
    return _child_hosts(domain, names, "Robtex")


def robtex_records(domain: str, text: str) -> list[dict]:
    """Published passive-DNS records for this name. The forward API is the apex, not a subdomain list."""
    domain = domain.lower().rstrip(".")
    url = f"https://www.robtex.com/dns-lookup/{urllib.parse.quote(domain)}"
    seen = set()
    findings = []
    for row in _robtex_rows(text):
        rrname = str(row.get("rrname") or "").strip().lower().rstrip(".")
        rrtype = str(row.get("rrtype") or "").strip().upper()
        rrdata = " ".join(str(row.get("rrdata") or "").split())
        if rrname != domain and not rrname.endswith("." + domain):
            continue
        if rrtype not in {"A", "AAAA", "NS", "MX", "CNAME", "TXT"} or not rrdata:
            continue
        key = (rrtype, rrdata.lower())
        if key in seen:
            continue
        seen.add(key)
        kind = "IP_ADDRESS" if rrtype in {"A", "AAAA"} else "INTERNET_NAME"
        findings.append({"event_type": kind, "value": f"{rrtype} {rrdata}"[:180],
                         "module": "passive DNS", "url": url, "source": "Robtex"})
        if len(findings) == 12:
            break
    return findings


def robtex(domain: str) -> dict:
    """Passive DNS from Robtex. SpiderFoot has the same source; this one is not cut off at two minutes."""
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "findings": [], "errors": ["Robtex: domain is not supported"]}
    status, body = _request(f"https://freeapi.robtex.com/pdns/forward/{urllib.parse.quote(domain)}",
                            timeout=15, limit=400_000)
    if status != 200:
        return {"hostnames": [], "findings": [], "errors": [f"Robtex: HTTP {status}"]}
    return {"hostnames": robtex_hosts(domain, body), "findings": robtex_records(domain, body), "errors": []}


def rapiddns_hosts(domain: str, html: str) -> list[dict]:
    return hosts_matching(domain, re.findall(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", html.lower()),
                          "RapidDNS", limit=40)


def rapiddns(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "errors": ["RapidDNS: domain is not supported"]}
    status, body = _request(f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1",
                            timeout=15, limit=300_000)
    if status != 200:
        return {"hostnames": [], "errors": [f"RapidDNS: HTTP {status}"]}
    return {"hostnames": rapiddns_hosts(domain, body), "errors": []}


def commoncrawl_rows(domain: str, text: str) -> tuple[list[dict], list[dict]]:
    web = []
    seen_url = set()
    hosts = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{") and not line.startswith("["):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        records = item if isinstance(item, list) else [item]
        for record in records:
            if not isinstance(record, dict):
                continue
            url = str(record.get("url") or "")
            parsed = urllib.parse.urlsplit(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme != "https" or not _HOST.fullmatch(host) or url in seen_url:
                continue
            if host != domain.lower().rstrip(".") and not host.endswith("." + domain.lower().rstrip(".")):
                continue
            seen_url.add(url)
            web.append({"title": url[:180], "url": url, "snippet": "Public Common Crawl capture URL",
                        "source": "Common Crawl", "category": "Public archive", "original_url": url,
                        "snapshot_at": str(record.get("timestamp") or ""), "archived": True})
            if len(web) == 8:
                break
        if len(web) == 8:
            break
    hosts = hosts_matching(domain, [urllib.parse.urlsplit(row["url"]).hostname or "" for row in web],
                           "Common Crawl", limit=8)
    return web, hosts


def commoncrawl(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"web": [], "hostnames": [], "errors": ["Common Crawl: domain is not supported"]}
    status, body = _request("https://index.commoncrawl.org/collinfo.json", timeout=12, limit=200_000)
    if status != 200:
        return {"web": [], "hostnames": [], "errors": [f"Common Crawl: HTTP {status}"]}
    try:
        indexes = json.loads(body)
    except ValueError:
        return {"web": [], "hostnames": [], "errors": ["Common Crawl: invalid index"]}
    api = ""
    if isinstance(indexes, list):
        for item in indexes:
            if isinstance(item, dict) and str(item.get("cdx-api") or "").startswith("https://"):
                api = item["cdx-api"]
                break
    if not api:
        return {"web": [], "hostnames": [], "errors": ["Common Crawl: no public index"]}
    query = urllib.parse.urlencode({"url": f"*.{domain}", "output": "json", "fl": "url,status,timestamp",
                                    "filter": "status:200", "limit": "12"})
    status, body = _request(f"{api}?{query}", timeout=15, limit=200_000)
    if status != 200:
        return {"web": [], "hostnames": [], "errors": [f"Common Crawl: HTTP {status}"]}
    web, hosts = commoncrawl_rows(domain, body)
    return {"web": web, "hostnames": hosts, "errors": []}


def ip_geo_summary(payload: dict) -> str:
    """Country, region, and city published for an address. Not a device fix."""
    if not isinstance(payload, dict) or payload.get("success") is False:
        return ""
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    asn = connection.get("asn")
    org = " ".join(str(connection.get("org") or "").split())
    network = f"AS{asn} {org}".strip() if asn else org
    parts = [" ".join(str(payload.get(key) or "").split()) for key in ("country", "region", "city")]
    parts.append(network)
    return "; ".join(part for part in parts if part)[:240]


def _unwrap_search_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    host = (parsed.hostname or "").lower()
    if host.endswith(("yandex.ru", "yandex.com", "yandex.kz")):
        for key in ("url", "u", "target"):
            values = urllib.parse.parse_qs(parsed.query).get(key) or []
            if values and values[0].startswith("https://"):
                return values[0]
    return url.strip()


def page_on_site(row: dict, site: str) -> dict | None:
    """Keep one https page whose host is the site that was searched."""
    if not isinstance(row, dict):
        return None
    raw = _unwrap_search_url(str(row.get("url") or ""))
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    site = site.lower()
    if parsed.scheme != "https" or not host or (host != site and not host.endswith("." + site)):
        return None
    title = " ".join(str(row.get("title") or "").split())[:200] or raw[:180]
    snippet = " ".join(str(row.get("snippet") or "").split())[:500]
    discovery = str(row.get("source") or "")
    return {"title": title, "url": raw, "snippet": snippet,
            "source": f"Public page · {site}" + (f" via {discovery}" if discovery else ""),
            "discovery_source": discovery, "category": "Public page"}


def public_page_rows(site: str, rows) -> list[dict]:
    kept, seen = [], set()
    for row in rows or []:
        item = page_on_site(row, site)
        if not item or item["url"] in seen:
            continue
        seen.add(item["url"])
        kept.append(item)
        if len(kept) == 8:
            break
    return kept


def _indexed_site(query: str, site: str, index_blocks=None) -> dict:
    from . import osint, search_api, public_sources
    label = dict(PUBLIC_SITES)[site]
    statuses, errors, blocked = [], [], set()
    index_blocks = {} if index_blocks is None else index_blocks
    try:
        direct = public_sources.search(query, site)
        if direct is not None:
            warning = getattr(direct, "warning", "")
            statuses.append({"source": f"Public pages {site} / native", "count": len(direct),
                "state": "partial" if warning and direct else "error" if warning else "ok" if direct else "empty",
                "detail": warning or f"{len(direct)} relevant results; {direct.filtered} unrelated candidates excluded",
                "method": direct.method, "candidate_count": direct.candidates, "filtered_count": direct.filtered})
            return {"web": direct, "statuses": statuses, "errors": [warning] if warning else []}
    except Exception as exc:
        detail = str(exc)[:250]
        state = "blocked" if any(word in detail.lower() for word in ("http 403", "http 429", "captcha")) else "timeout" if "timed out" in detail.lower() else "error"
        statuses.append({"source": f"Public pages {site} / native", "state": state, "count": 0, "detail": detail})
        errors.append(f"Native public source: {detail}")
    attempts = [("duckduckgo", f"{query} {label}"), ("duckduckgo", f"{query} site:{site}"),
                ("bing", f"{query} site:{site}")]
    attempts.extend((backend, f"{query} site:{site}") for backend in ("brave", "yandex")
                    if search_api.configured(backend))
    attempts.append(("yahoo", f"{query} site:{site}"))
    for backend, text in attempts:
        if backend in blocked:
            continue
        # Keep public-site queries sequential and spaced; do not burst eight requests at one index.
        with _INDEX_LOCK:
            if backend in index_blocks:
                reason = index_blocks[backend]
                statuses.append({"source": f"Public pages {site} / {backend}", "state": "skipped", "count": 0,
                                 "detail": f"Index blocked earlier in this search: {reason}"})
                errors.append(f"{backend}: blocked earlier in this search")
                blocked.add(backend)
                continue
            net_host = {"duckduckgo": "duckduckgo.com", "yahoo": "search.yahoo.com",
                        "brave": "api.search.brave.com", "yandex": "searchapi.api.cloud.yandex.net"}.get(backend, "www.bing.com")
            from . import net
            net._polite_wait(net_host, min_interval=2, deadline=time.monotonic() + 20)
            found, failures, checks = osint.search(text, [backend], limit=10)
            for check in checks:
                if check.get("state") == "blocked":
                    index_blocks[backend] = check.get("error") or check.get("detail") or "access blocked"
        rows = [row for row in public_page_rows(site, found) if osint._relevant(row, query)]
        for check in checks:
            excluded = check.get("filtered_count", 0) + len(found) - len(rows)
            if backend == "bing" and not rows and check.get("candidate_count", 0) and not check.get("error"):
                check = {**check, "state": "error", "error": "Bing returned unrelated entries; the site and target query was not confirmed"}
                failures.append(check["error"])
            statuses.append({**check, "source": f"Public pages {site} / {backend}", "count": len(rows),
                             "state": check["state"] if check.get("error") or check.get("state") not in {"ok", "empty"} else "ok" if rows else "empty",
                             "filtered_count": excluded,
                             "detail": check.get("error") or f"{len(rows)} results on {site}; {excluded} unrelated candidates excluded",
                             "method": check.get("method", "") + " / site and target validation"})
            if check.get("state") == "blocked":
                blocked.add(backend)
        errors.extend(failures)
        if rows:
            return {"web": rows, "statuses": statuses, "errors": []}
    return {"web": [], "statuses": statuses, "errors": errors}


def _telegram_posts(query: str, rows: list[dict]) -> dict:
    from . import osint
    from .evidence_capture import fetch_public, parse_evidence, telegram_url
    urls = []
    for row in rows:
        try:
            url = telegram_url(row["url"])
        except ValueError:
            continue
        channel = url.rsplit("/", 1)[0] if url.rsplit("/", 1)[-1].isdigit() else url
        if channel not in urls:
            urls.append(channel)
        if len(urls) == 3:
            break
    posts, statuses, errors, seen = [], [], [], set()
    for url in urls:
        try:
            page = fetch_public(url + "?" + urllib.parse.urlencode({"q": query}), timeout=12)
            parsed = parse_evidence(page)
            if not parsed["profiles"] and not parsed["posts"]:
                raise RuntimeError("Telegram returned no public channel preview; unavailable or parser error")
            count = 0
            for post in parsed["posts"]:
                # A matching channel name must not turn unrelated advertisements into evidence.
                if post["url"] in seen or not osint._relevant({"title": "", "snippet": post["snippet"], "url": post["url"]}, query):
                    continue
                seen.add(post["url"])
                count += 1
                posts.append({**post, "source": "Telegram public web", "category": "Public post"})
            statuses.append({"source": "Telegram public web", "state": "ok" if count else "empty",
                             "count": count,
                             "url": url, "detail": "Read public channel search; retained matching post text", "method": "Telegram public web"})
        except Exception as exc:
            detail = str(exc)[:250]
            state = "blocked" if "HTTP 403" in detail or "HTTP 429" in detail else "timeout" if "timed out" in detail else "error"
            statuses.append({"source": "Telegram public web", "state": state, "count": 0, "url": url, "detail": detail})
            errors.append(f"Telegram public web: {detail}")
    return {"web": posts, "statuses": statuses, "errors": errors}


def public_pages(query: str, searcher=None) -> dict:
    """Native and indexed public searches on a fixed set of sites."""
    query = " ".join(str(query or "").split())
    if len(query) < 2:
        return {"web": [], "errors": ["Public pages: query is too short"]}
    if searcher is None:
        index_blocks = {}
        searcher = lambda query, site: _indexed_site(query, site, index_blocks)
    sites = [site for site, _label in PUBLIC_SITES]

    def one(site: str):
        try:
            data = searcher(query, site)
            if not isinstance(data, dict):
                data = {"web": public_page_rows(site, data), "errors": [], "statuses": []}
            return data
        except Exception as exc:
            return {"web": [], "errors": [str(exc)], "statuses": []}

    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [pool.submit(copy_context().run, one, site) for site in sites]
        found = [task.result() for task in tasks]
    web, errors, statuses, seen = [], [], [], set()
    for site, data in zip(sites, found):
        rows = data.get("web", [])
        failures = data.get("errors", [])
        errors.extend(f"Public pages {site}: {error}" for error in failures)
        statuses.extend(data.get("statuses", []))
        detail = "; ".join(failures)
        state = "partial" if rows and failures else "blocked" if any(check.get("state") == "blocked" for check in data.get("statuses", [])) and not rows else "error" if failures else "ok" if rows else "empty"
        statuses.append({"source": f"Public pages {site}", "state": state, "count": len(rows), "detail": detail})
        for row in rows:
            if row["url"] not in seen:
                seen.add(row["url"])
                web.append(row)
    telegram = _telegram_posts(query, [row for row in web if urllib.parse.urlsplit(row["url"]).hostname == "t.me"])
    web.extend(telegram["web"])
    errors.extend(telegram["errors"])
    statuses.extend(telegram["statuses"])
    return {"web": web, "errors": errors, "statuses": statuses}


def wikidata_rows(payload) -> tuple[list[dict], list[dict]]:
    web, findings = [], []
    search = payload.get("search") if isinstance(payload, dict) else None
    for item in search or []:
        if not isinstance(item, dict) or not re.fullmatch(r"Q\d+", str(item.get("id") or "")):
            continue
        qid = str(item["id"])
        url = f"https://www.wikidata.org/wiki/{qid}"
        label = " ".join(str(item.get("label") or qid).split())[:200]
        description = " ".join(str(item.get("description") or "").split())
        web.append({"title": label, "url": url, "snippet": description[:500],
                    "source": "Wikidata", "category": "Reference"})
        if description:
            findings.append({"event_type": "WIKIDATA", "value": f"{label}; {description}"[:240],
                             "module": "wikidata", "url": url, "source": "Wikidata"})
        if len(web) == 8:
            break
    return web, findings


def wikidata(query: str) -> dict:
    query = " ".join(str(query or "").split())
    if len(query) < 2:
        return {"web": [], "findings": [], "errors": ["Wikidata: query is too short"]}
    langs = ("ru", "en") if re.search(r"[А-Яа-яЁё]", query) else ("en", "ru")
    web, findings, errors, seen = [], [], [], set()
    for lang in langs:
        url = "https://www.wikidata.org/w/api.php?" + urllib.parse.urlencode({
            "action": "wbsearchentities", "search": query, "language": lang,
            "uselang": lang, "format": "json", "limit": "8", "type": "item"})
        status, body = _request(url, timeout=12, limit=200_000)
        if status != 200:
            errors.append(f"Wikidata: HTTP {status}")
            continue
        try:
            payload = json.loads(body)
        except ValueError:
            errors.append("Wikidata: invalid response")
            continue
        pages, notes = wikidata_rows(payload)
        for row in pages:
            if row["url"] in seen or len(web) == 8:
                continue
            seen.add(row["url"])
            web.append(row)
        for note in notes:
            if note["url"] not in {item["url"] for item in findings}:
                findings.append(note)
        if len(web) == 8:
            break
    return {"web": web, "findings": findings[:8], "errors": errors}


def _https_page(title: str, url: str, snippet: str, source: str, category: str) -> dict | None:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    title = " ".join(str(title or "").split())[:200] or parsed.hostname
    return {"title": title, "url": str(url).strip(), "snippet": " ".join(str(snippet or "").split())[:500],
            "source": source, "category": category}


def duckduckgo_rows(payload) -> tuple[list[dict], list[dict]]:
    if not isinstance(payload, dict):
        return [], []
    web, findings = [], []
    abstract = " ".join(str(payload.get("AbstractText") or "").split())
    heading = " ".join(str(payload.get("Heading") or "").split()) or abstract[:80]
    row = _https_page(heading, str(payload.get("AbstractURL") or ""), abstract,
                      "DuckDuckGo instant", "Instant answer")
    if row and abstract:
        web.append(row)
        findings.append({"event_type": "DESCRIPTION_ABSTRACT", "value": abstract[:240],
                         "module": "duckduckgo", "url": row["url"], "source": "DuckDuckGo instant"})
    topics = []
    for item in payload.get("RelatedTopics") or []:
        if not isinstance(item, dict):
            continue
        nested = item.get("Topics")
        if isinstance(nested, list):
            topics.extend(child for child in nested if isinstance(child, dict))
        else:
            topics.append(item)
    seen = {item["url"] for item in web}
    for item in topics:
        text = " ".join(str(item.get("Text") or "").split())
        title = text.split(" - ")[0][:200]
        row = _https_page(title, str(item.get("FirstURL") or ""), text, "DuckDuckGo instant", "Related")
        if not row or row["url"] in seen:
            continue
        seen.add(row["url"])
        web.append(row)
        if len(web) == 8:
            break
    return web, findings


def duckduckgo_instant(query: str) -> dict:
    query = " ".join(str(query or "").split())
    if len(query) < 2:
        return {"web": [], "findings": [], "errors": ["DuckDuckGo: query is too short"]}
    url = "https://api.duckduckgo.com/?" + urllib.parse.urlencode({
        "q": query, "format": "json", "no_html": "1", "skip_disambig": "0", "no_redirect": "1"})
    status, body = _request(url, timeout=12, limit=200_000)
    if status != 200:
        return {"web": [], "findings": [], "errors": [f"DuckDuckGo: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"web": [], "findings": [], "errors": ["DuckDuckGo: invalid response"]}
    web, findings = duckduckgo_rows(payload)
    return {"web": web, "findings": findings, "errors": []}


def gleif_rows(payload) -> list[dict]:
    data = payload.get("data") if isinstance(payload, dict) else None
    rows = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        name = " ".join(str(attrs.get("value") or "").split())[:200]
        rel = item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
        lei_rel = rel.get("lei-records") if isinstance(rel.get("lei-records"), dict) else {}
        lei_data = lei_rel.get("data") if isinstance(lei_rel.get("data"), dict) else {}
        lei = str(lei_data.get("id") or "").strip().upper()
        if not name or not _LEI.fullmatch(lei):
            continue
        rows.append({"title": name, "url": f"https://search.gleif.org/#/record/{lei}",
                     "snippet": f"LEI {lei}", "source": "GLEIF", "category": "Legal entity"})
        if len(rows) == 5:
            break
    return rows


def gleif(query: str) -> dict:
    query = " ".join(str(query or "").split())
    if len(query) < 2:
        return {"web": [], "errors": ["GLEIF: query is too short"]}
    url = "https://api.gleif.org/api/v1/autocompletions?" + urllib.parse.urlencode({
        "field": "fulltext", "q": query})
    status, body = _request(url, timeout=12, limit=200_000,
                            headers={"Accept": "application/vnd.api+json"})
    if status != 200:
        return {"web": [], "errors": [f"GLEIF: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"web": [], "errors": ["GLEIF: invalid response"]}
    return {"web": gleif_rows(payload), "errors": []}


def _otx_key() -> str:
    key = os.environ.get("OTX_API_KEY", "").strip()
    if key:
        return key
    path = ROOT / "osint-keys.env"
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == "OTX_API_KEY":
            return value.strip().strip("\"'")
    return ""


def otx_hosts(domain: str, payload) -> list[dict]:
    rows = payload.get("passive_dns") if isinstance(payload, dict) else None
    names = [str(item.get("hostname") or "") for item in rows or [] if isinstance(item, dict)]
    return hosts_matching(domain, names, "OTX", limit=40)


def otx_passive(domain: str) -> dict:
    """Passive DNS hostnames. Skipped without a key so a missing key is not an error."""
    domain = domain.strip().lower().rstrip(".")
    if not _HOST.fullmatch(domain):
        return {"hostnames": [], "errors": ["OTX: domain is not supported"]}
    key = _otx_key()
    if not key:
        return {"hostnames": [], "errors": []}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
    status, body = _request(url, timeout=15, limit=400_000, headers={"X-OTX-API-KEY": key})
    if status != 200:
        return {"hostnames": [], "errors": [f"OTX: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"hostnames": [], "errors": ["OTX: invalid response"]}
    return {"hostnames": otx_hosts(domain, payload), "errors": []}


def _single_public_ip(value: str) -> str:
    text = value.strip()
    if "/" in text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return str(address) if address.is_global else ""


def reverse_name_hosts(text: str) -> tuple[list[dict], str]:
    lowered = text.lower()
    if "exceeded" in lowered or lowered.startswith("error") or "invalid" in lowered:
        detail = text.strip().splitlines()
        return [], (detail[0][:180] if detail else "no names")
    hosts, seen = [], set()
    for line in text.splitlines():
        parts = [part.strip().lower().rstrip(".") for part in line.split(",") if part.strip()]
        candidate = parts[-1] if parts else ""
        if not _HOST.fullmatch(candidate) or candidate in seen:
            continue
        seen.add(candidate)
        hosts.append({"name": candidate, "source": "HackerTarget"})
        if len(hosts) == 20:
            break
    return hosts, ""


def ip_names(value: str) -> dict:
    """Published reverse names for one public address. Not a shared-host scan of a range."""
    address = _single_public_ip(value)
    if not address:
        return {"hostnames": [], "errors": []}
    hosts, errors = [], []
    for label in ("reversedns", "reverseiplookup"):
        status, body = _request(f"https://api.hackertarget.com/{label}/?q={urllib.parse.quote(address)}",
                                timeout=12)
        if status != 200:
            errors.append(f"HackerTarget {label}: HTTP {status}")
            continue
        found, detail = reverse_name_hosts(body)
        if detail:
            errors.append(f"HackerTarget {label}: {detail}")
            if "exceeded" in detail.lower():
                break
            continue
        known = {item["name"] for item in hosts}
        for item in found:
            if item["name"] not in known and len(hosts) < 20:
                hosts.append(item)
                known.add(item["name"])
        if len(hosts) == 20:
            break
    return {"hostnames": hosts, "errors": errors}


def ripe_summary(payload: dict) -> str:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return ""
    parts = []
    for item in data.get("asns") or []:
        if not isinstance(item, dict) or item.get("asn") in (None, ""):
            continue
        holder = " ".join(str(item.get("holder") or "").split())
        parts.append(f"AS{item['asn']} {holder}".strip())
        if len(parts) == 3:
            break
    return "; ".join(parts)[:240]


def ripe_prefix(value: str) -> dict:
    """Published prefix and ASN. Private addresses are not sent."""
    address = _public_address(value)
    if not address:
        return {"findings": [], "errors": []}
    url = "https://stat.ripe.net/data/prefix-overview/data.json?resource=" + urllib.parse.quote(address)
    status, body = _request(url, timeout=12, limit=200_000)
    if status != 200:
        return {"findings": [], "errors": [f"RIPE Stat: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"findings": [], "errors": ["RIPE Stat: invalid response"]}
    text = ripe_summary(payload)
    if not text:
        return {"findings": [], "errors": []}
    page = f"https://stat.ripe.net/{urllib.parse.quote(address)}"
    return {"findings": [{"event_type": "BGP_AS_OWNER", "value": text, "module": "ripe",
                          "url": page, "source": "RIPE Stat"}], "errors": []}


def ip_geo(value: str) -> dict:
    """Published network location for a public IP. Private addresses are not sent."""
    address = _public_address(value)
    if not address:
        return {"findings": [], "errors": []}
    url = f"https://ipwho.is/{urllib.parse.quote(address)}"
    status, body = _request(url, timeout=12)
    if status != 200:
        return {"findings": [], "errors": [f"IP geo: HTTP {status}"]}
    try:
        payload = json.loads(body)
    except ValueError:
        return {"findings": [], "errors": ["IP geo: invalid response"]}
    text = ip_geo_summary(payload)
    if not text:
        return {"findings": [], "errors": []}
    return {"findings": [{"event_type": "IP_ADDRESS",
                          "value": f"{text}; published network location, not a device fix",
                          "module": "public geo", "url": url, "source": "Public IP geo"}],
            "errors": []}


def supplement(query: str, kind: str, coverage: str = "quick", on_status=None, *, include_public=True) -> dict:
    """Run the extra public checks that apply to this target type."""
    if coverage not in {"quick", "deep"}:
        raise ValueError("Coverage must be quick or deep")
    profiles, web, findings, hostnames, errors, statuses = [], [], [], [], [], []

    def status(name, state, count=0, detail="", elapsed=0):
        item = {"name": name, "state": state, "count": count, "detail": detail,
                "elapsed_seconds": round(elapsed, 2)}
        if state != "attempted":
            statuses.append(item)
        if on_status:
            on_status(item)

    def take(name: str, getter) -> None:
        started = time.monotonic()
        status(name, "attempted")
        try:
            part = getter()
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            status(name, "timeout" if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)) else "error",
                   detail=str(exc), elapsed=time.monotonic() - started)
            return
        profiles.extend(part.get("profiles") or [])
        web.extend(part.get("web") or [])
        findings.extend(part.get("findings") or [])
        hostnames.extend(part.get("hostnames") or [])
        errors.extend(part.get("errors") or [])
        for item in part.get("statuses") or []:
            statuses.append(item)
            if on_status:
                on_status(item)
        count = sum(len(part.get(field) or []) for field in ("profiles", "web", "findings", "hostnames"))
        detail = "; ".join(part.get("errors") or [])
        state = "timeout" if "time limit" in detail.lower() or "timeout" in detail.lower() else "partial" if detail and count else "error" if detail else "ok" if count else "empty"
        if name == "OTX" and not _otx_key():
            state, detail = "skipped", "missing OTX_API_KEY"
        status(name, state, count, detail, time.monotonic() - started)

    if kind == "person":
        if include_public:
            take("Public pages", lambda: public_pages(query))
        take("Wikidata", lambda: wikidata(query))
        take("DuckDuckGo", lambda: duckduckgo_instant(query))
        take("GLEIF", lambda: gleif(query))
    elif kind == "username":
        take("WhatsMyName", lambda: whatsmyname(query, coverage))
        take("GitHub", lambda: github_user(query))
        take("Sherlock", lambda: sherlock(query, coverage))
        take("Social Analyzer", lambda: social_analyzer(query, coverage))
        take("Blackbird", lambda: blackbird(query, "username"))
        if include_public:
            take("Public pages", lambda: public_pages(query))
    elif kind == "email":
        take("Gravatar", lambda: gravatar(query))
        take("Holehe", lambda: holehe(query))
        take("OpenPGP", lambda: openpgp(query))
        take("Blackbird", lambda: blackbird(query, "email"))
        if include_public:
            take("Public pages", lambda: public_pages(query))
    elif kind == "domain":
        take("urlscan.io", lambda: urlscan(query))
        take("Subfinder", lambda: subfinder(query))
        take("Internet Archive", lambda: archive_cdx(query))
        take("Amass", lambda: amass(query))
        take("httpx", lambda: httpx_probe(query))
        take("Anubis", lambda: anubis(query))
        take("RapidDNS", lambda: rapiddns(query))
        take("HackerTarget", lambda: hackertarget(query))
        take("Subdomain Center", lambda: subdomaincenter(query))
        take("Robtex", lambda: robtex(query))
        take("Common Crawl", lambda: commoncrawl(query))
        take("OTX", lambda: otx_passive(query))
    elif kind == "phone":
        take("Phone", lambda: phone_plan(query))
        if include_public:
            take("Public pages", lambda: public_pages(query))
    elif kind == "ip":
        take("RDAP", lambda: ip_registration(query))
        take("IP geo", lambda: ip_geo(query))
        take("RIPE", lambda: ripe_prefix(query))
        take("Reverse DNS", lambda: ip_names(query))
    return {"profiles": profiles, "web": web, "findings": findings,
            "hostnames": hostnames, "errors": errors, "statuses": statuses}
