"""Run SpiderFoot inside a FindAll search and keep the events in the same dossier.

The engine is the MIT-licensed SpiderFoot tree in third_party/spiderfoot
(commit 0f815a203afebf05c98b605dba5cf0475a0ee5fd). FindAll does not start
its web UI. Passive modules are the default. Password, hash, and card
events are removed from the local SpiderFoot database after the scan.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import sqlite3
import ssl
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "third_party" / "spiderfoot"
USE_CASES = {"passive": "Passive", "footprint": "Footprint", "investigate": "Investigate", "all": "All"}
# The research screen uses this set so a scan can finish inside two minutes.
# Port scans, zone transfers, brute force, leak dumps, and the full account sweep stay out.
DOSSIER_MODULES = [
    "sfp_github",
    "sfp_keybase",
    "sfp_wikipediaedits",
    "sfp_socialprofiles",
    "sfp_gravatar",
    "sfp_pgp",
    "sfp_duckduckgo",
    "sfp_dnsresolve",
    "sfp_crt",
    "sfp_certspotter",
    "sfp_whois",
    "sfp_urlscan",
    "sfp_ripe",
    "sfp_bgpview",
    "sfp_robtex",
]
SECRET_TYPES = {"PASSWORD_COMPROMISED", "HASH_COMPROMISED", "CREDIT_CARD_NUMBER"}
HIDDEN_TYPES = SECRET_TYPES | {"ROOT"}
URL_TYPES = {
    "LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL", "URL_STATIC", "URL_FORM", "URL_PASSWORD",
    "URL_UPLOAD", "URL_JAVASCRIPT", "URL_WEB", "LEAKSITE_URL", "DARKNET_MENTION_URL",
}
PROFILE_TYPES = {
    "SOCIAL_MEDIA", "ACCOUNT_EXTERNAL_OWNED", "SIMILAR_ACCOUNT_EXTERNAL",
    "PUBLIC_CODE_REPO", "APPSTORE_ENTRY",
}
EMAIL_TYPES = {"EMAILADDR", "AFFILIATE_EMAILADDR", "EMAILADDR_GENERIC", "EMAILADDR_COMPROMISED"}
NAME_TYPES = {
    "INTERNET_NAME", "DOMAIN_NAME", "AFFILIATE_DOMAIN_NAME", "AFFILIATE_INTERNET_NAME",
    "CO_HOSTED_SITE", "CO_HOSTED_SITE_DOMAIN", "SIMILARDOMAIN",
}
KEY_OPTIONS = {
    "sfp_shodan": {"api_key": "SHODAN_API_KEY"},
    "sfp_securitytrails": {"api_key": "SECURITY_TRAILS_API_KEY"},
}
_URL = re.compile(r"https?://[^\s<>'\"\\)]+")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_RULES = (
    (_EMAIL, "EMAILADDR"),
    (re.compile(r"^\+[0-9]{8,15}$"), "PHONE_NUMBER"),
    (re.compile(r"^[0-9]+$"), "BGP_AS_OWNER"),
    (re.compile(r"^(([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$", re.I), "INTERNET_NAME"),
)
_state = {"thread": None, "guard": threading.Lock()}
_loaded = None


def publishable(event_type: str) -> bool:
    """Password, hash, and card events stay out of FindAll reports."""
    return event_type not in HIDDEN_TYPES


def _address_type(value: str) -> str:
    """IP and CIDR types. A hex word such as cafe is not an IPv6 address."""
    if ":" not in value and value.count(".") != 3 and "/" not in value:
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return ""
        return "NETBLOCKV6_OWNER" if network.version == 6 else "NETBLOCK_OWNER"
    return "IPV6_ADDRESS" if ":" in value else "IP_ADDRESS"


def prepare_target(value: str, kind: str = "") -> tuple[str, str]:
    """Return the seed value and SpiderFoot seed type."""
    value = " ".join(value.strip().strip('"').split())
    if not value or len(value) > 200:
        raise ValueError("SpiderFoot target must contain 1–200 characters")
    kind = kind.strip().lower()
    if kind == "person":
        return value, "HUMAN_NAME" if " " in value else "USERNAME"
    if kind == "username":
        return value, "USERNAME"
    if kind == "domain":
        return value.lower(), "INTERNET_NAME"
    if kind == "email":
        return value, "EMAILADDR"
    if kind == "ip":
        return value, "NETBLOCK_OWNER" if "/" in value else "IP_ADDRESS"
    if kind == "phone":
        return value, "PHONE_NUMBER"
    if kind == "asn":
        return value, "BGP_AS_OWNER"
    if kind == "bitcoin":
        return value, "BITCOIN_ADDRESS"
    if kind not in ("", "auto"):
        raise ValueError(f"Unknown SpiderFoot target kind: {kind}")
    if " " in value:
        return value, "HUMAN_NAME"
    address = _address_type(value)
    if address:
        return value, address
    for pattern, event_type in _RULES:
        if pattern.fullmatch(value):
            return value, event_type
    return value, "USERNAME"


def select_modules(modules: dict, use_case: str = "passive", only: list[str] | None = None) -> list[str]:
    """Choose SpiderFoot modules the way its CLI use-case flag does, and keep database storage."""
    if use_case not in USE_CASES:
        raise ValueError(f"Use case must be one of: {', '.join(USE_CASES)}")
    if only:
        missing = [name for name in only if name not in modules]
        if missing:
            raise ValueError("Unknown SpiderFoot module: " + ", ".join(missing))
        names = [name for name in only if not name.startswith("sfp__stor")]
    else:
        label = USE_CASES[use_case]
        names = [name for name, meta in sorted(modules.items())
                 if not name.startswith("sfp__stor") and (label == "All" or label in (meta.get("group") or []))]
    if "sfp__stor_db" in modules and "sfp__stor_db" not in names:
        names.append("sfp__stor_db")
    if not any(not name.startswith("sfp__stor") for name in names):
        raise ValueError("No SpiderFoot modules matched this use case")
    return names


def _http_url(text: str) -> str:
    match = _URL.search(text or "")
    if not match:
        return ""
    return match.group(0).rstrip(".,);]")


def _email(text: str) -> str:
    value = (text or "").strip().lower()
    return value if _EMAIL.fullmatch(value) and len(value) <= 200 else ""


def normalize_events(events: list[dict]) -> dict:
    """Split stored events into the dossier sections and linked OSINT rows."""
    web, profiles, emails, names, assets, technologies, findings = [], [], [], [], [], [], []
    rows, notes = [], []
    seen_web, seen_profiles, seen_emails = set(), set(), set()

    def add_web(event: dict, url: str) -> None:
        if url in seen_web or len(web) >= 60:
            return
        seen_web.add(url)
        title = event["type"].replace("_", " ").title()
        snippet = event["data"][:240]
        source = f"SpiderFoot · {event['module']}"
        web.append({"title": title, "url": url, "snippet": snippet, "source": source,
                    "category": event["type"], "status": "SpiderFoot event; identity unverified"})
        rows.append({"title": title, "url": url, "snippet": snippet, "source": source, "category": event["type"]})

    for event in events:
        event_type = event.get("type") or ""
        data = str(event.get("data") or "").strip()
        module = str(event.get("module") or "spiderfoot")
        source_data = str(event.get("source_data") or "")
        if not publishable(event_type) or not data or len(data) > 500:
            continue
        event = {"type": event_type, "data": data, "module": module, "source_data": source_data[:300]}
        url = _http_url(data) or _http_url(source_data)
        if event_type == "ERROR_MESSAGE":
            if len(notes) < 8:
                notes.append(f"{module}: {data[:180]}")
            continue
        if event_type in EMAIL_TYPES:
            email = _email(data)
            if email and url.startswith("https://") and (email, url) not in seen_emails and len(emails) < 40:
                seen_emails.add((email, url))
                emails.append({"email": email, "url": url, "source": f"SpiderFoot · {module}",
                               "attribution": "SpiderFoot event with a public page; mailbox owner unverified"})
            elif email and len(findings) < 80:
                findings.append({"event_type": event_type, "value": email, "module": module, "url": url,
                                 "source_data": "No public page URL; not treated as a published mailbox"})
            continue
        if event_type in PROFILE_TYPES and url.startswith(("https://", "http://")):
            if url not in seen_profiles and len(profiles) < 40:
                seen_profiles.add(url)
                prefix = data.replace(url, "").strip(" :()-")
                profiles.append({"site": prefix or module.removeprefix("sfp_"), "url": url,
                                 "username": "", "source": f"SpiderFoot · {module}",
                                 "status": "candidate; same handle only, identity unverified"})
                rows.append({"title": prefix or module.removeprefix("sfp_"), "url": url,
                             "snippet": "Candidate profile; identity unverified",
                             "source": f"SpiderFoot · {module}", "category": "Public profile candidate"})
            continue
        if event_type in URL_TYPES and url.startswith(("https://", "http://")):
            add_web(event, url)
            continue
        if event_type in NAME_TYPES and _HOST.fullmatch(data) and len(names) < 40:
            names.append(data.lower())
            continue
        if event_type in {"IP_ADDRESS", "IPV6_ADDRESS", "TCP_PORT_OPEN", "UDP_PORT_OPEN"} and len(assets) < 40:
            ip, port = _endpoint(event)
            if ip:
                assets.append({"ip": ip, "port": port, "product": event_type, "url": url,
                               "provider": f"SpiderFoot · {module}"})
                continue
        if event_type == "WEBSERVER_TECHNOLOGY" and len(technologies) < 30:
            technologies.append({"name": data[:120], "version": "", "confidence": 0, "provider": module})
            continue
        if len(findings) < 80 and not event_type.startswith("RAW_"):
            findings.append({"event_type": event_type, "value": data[:300], "module": module,
                             "url": url, "source_data": source_data[:200]})
    return {"web": web, "profiles": profiles, "emails": emails, "names": list(dict.fromkeys(names)),
            "assets": assets, "technologies": technologies, "findings": findings,
            "rows": rows, "notes": notes}


def _endpoint(event: dict) -> tuple[str, str]:
    data = event["data"]
    source = event["source_data"]
    paired = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", data)
    if paired:
        return paired.group(1), paired.group(2)
    if data.isdigit() and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", source):
        return source, data
    if event["type"] in {"IP_ADDRESS", "IPV6_ADDRESS"} and " " not in data:
        return data, ""
    return "", ""


def merge_dossier(sections: dict, report: dict, observed_at: str) -> None:
    """Copy a finished scan into the open dossier sections."""
    if report.get("status") in (None, "skipped"):
        return
    normalized = normalize_events(report.get("events") or [])
    known_urls = {row.get("url") for row in sections["web"]}
    for row in normalized["web"]:
        if row["url"] not in known_urls:
            sections["web"].append({**row, "observed_at": observed_at})
            known_urls.add(row["url"])
    known_profiles = {row.get("url") for row in sections["profiles"]}
    for row in normalized["profiles"]:
        if row["url"] not in known_profiles:
            sections["profiles"].append({**row, "observed_at": observed_at})
    known_emails = {(row.get("email"), row.get("url")) for row in sections["emails"]}
    for row in normalized["emails"]:
        if (row["email"], row["url"]) not in known_emails:
            sections["emails"].append({**row, "observed_at": observed_at})
    domain = sections.get("domain")
    extra = []
    if isinstance(domain, dict):
        have = {item.get("name") for item in domain.get("subdomains", [])}
        for name in normalized["names"]:
            if name not in have:
                domain.setdefault("subdomains", []).append(
                    {"name": name, "ips": [], "sources": ["SpiderFoot"]})
        domain.setdefault("assets", []).extend(normalized["assets"])
        domain.setdefault("technologies", []).extend(normalized["technologies"])
    else:
        extra.extend({"event_type": "INTERNET_NAME", "value": name, "module": "spiderfoot",
                      "url": "", "source_data": ""} for name in normalized["names"])
        extra.extend({"event_type": asset["product"], "value": asset["ip"] + (f":{asset['port']}" if asset["port"] else ""),
                      "module": asset["provider"], "url": asset.get("url", ""), "source_data": ""}
                     for asset in normalized["assets"])
    sections.setdefault("findings", []).extend(
        {**row, "observed_at": observed_at}
        for row in (extra + normalized["findings"])[:80])
    sections["spiderfoot"] = {
        "status": report.get("status", ""),
        "use_case": report.get("use_case", "passive"),
        "modules": report.get("modules", 0),
        "event_count": report.get("event_count", 0),
        "scan_id": report.get("scan_id", ""),
        "database": report.get("database", ""),
        "target_type": report.get("target_type", ""),
        "timed_out": bool(report.get("timed_out")),
    }


def _apply_keys(modules: dict) -> None:
    from .domain_recon import configured_keys
    keys = configured_keys()
    for module, options in KEY_OPTIONS.items():
        meta = modules.get(module)
        if not meta:
            continue
        for option, name in options.items():
            if keys.get(name):
                meta["opts"][option] = keys[name]


def _proxy_config(config: dict) -> None:
    proxy = os.environ.get("JOBFIND_ACTIVE_PROXY", "")
    parsed = urlsplit(proxy)
    if parsed.scheme == "http" and parsed.hostname and parsed.port:
        config["_socks1type"] = "HTTP"
        config["_socks2addr"] = parsed.hostname
        config["_socks3port"] = str(parsed.port)


def _load():
    global _loaded
    if _loaded is not None:
        return _loaded
    if not (VENDOR / "sfscan.py").is_file():
        raise RuntimeError("SpiderFoot is missing. Restore third_party/spiderfoot.")
    vendor = str(VENDOR)
    if vendor not in sys.path:
        sys.path.insert(0, vendor)
    logging.getLogger("spiderfoot").setLevel(logging.ERROR)
    from sfscan import SpiderFootScanner
    from spiderfoot import SpiderFootCorrelator, SpiderFootDb, SpiderFootHelpers
    modules = SpiderFootHelpers.loadModulesAsDict(str(VENDOR / "modules") + os.sep, ["sfp_template.py"])
    _apply_keys(modules)
    _loaded = {"modules": modules, "helpers": SpiderFootHelpers, "db": SpiderFootDb,
               "scanner": SpiderFootScanner, "correlator": SpiderFootCorrelator}
    return _loaded


def _read_events(database: Path, scan_id: str) -> tuple[list[dict], int]:
    if not database.is_file():
        return [], 0
    with sqlite3.connect(database) as conn:
        conn.execute(
            "DELETE FROM tbl_scan_results WHERE scan_instance_id=? AND type IN (?,?,?)",
            (scan_id, *sorted(SECRET_TYPES)),
        )
        fetched = conn.execute(
            "SELECT c.type, c.data, c.module, COALESCE(s.data, ''), c.false_positive "
            "FROM tbl_scan_results c LEFT JOIN tbl_scan_results s "
            "ON s.scan_instance_id=c.scan_instance_id AND s.hash=c.source_event_hash "
            "WHERE c.scan_instance_id=?",
            (scan_id,),
        ).fetchall()
    events, count = [], 0
    for event_type, data, module, source_data, false_positive in fetched:
        if false_positive or not publishable(event_type):
            continue
        count += 1
        if len(events) < 2000 and not str(event_type).startswith("RAW_"):
            events.append({"type": event_type, "data": str(data or "")[:500],
                           "module": module, "source_data": str(source_data or "")[:300]})
    return events, count


def _event_count(database: Path, scan_id: str) -> int:
    if not database.is_file():
        return 0
    try:
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM tbl_scan_results WHERE scan_instance_id=? AND type!='ROOT'",
                (scan_id,),
            ).fetchone()
        return int(row[0] if row else 0)
    except sqlite3.Error:
        return 0


def scan(target: str, work_dir: Path, *, kind: str = "", use_case: str = "passive",
         modules: list[str] | None = None, timeout: int = 120, on_status=None) -> dict:
    """Run one SpiderFoot scan and return events already mapped for FindAll."""
    if not isinstance(timeout, int) or timeout < 0:
        raise ValueError("SpiderFoot timeout must be a positive number of seconds, or 0 for no limit")
    target, target_type = prepare_target(target, kind)
    with _state["guard"]:
        running = _state["thread"]
        if running is not None and running.is_alive():
            raise RuntimeError("A SpiderFoot scan is already running")
    engine = _load()
    chosen = select_modules(engine["modules"], use_case, modules)
    work_dir.mkdir(parents=True, exist_ok=True)
    database = work_dir / "spiderfoot.db"
    os.environ["SPIDERFOOT_DATA"] = str(work_dir)
    os.environ["SPIDERFOOT_CACHE"] = str(work_dir / "cache")
    os.environ["SPIDERFOOT_LOGS"] = str(work_dir / "logs")
    try:
        generic = ",".join(sorted(engine["helpers"].usernamesFromWordlists(["generic-usernames"])))
    except OSError:
        generic = "admin,administrator,webmaster,hostmaster,postmaster,info"
    config = {
        "_debug": False,
        "_maxthreads": 3,
        "__logging": True,
        "__outputfilter": None,
        "_useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "_dnsserver": "",
        "_fetchtimeout": 5,
        "_internettlds": "https://publicsuffix.org/list/effective_tld_names.dat",
        "_internettlds_cache": 72,
        "_genericusers": generic,
        "__database": str(database),
        "__modules__": engine["modules"],
        "__correlationrules__": [],
        "_socks1type": "",
        "_socks2addr": "",
        "_socks3port": "",
        "_socks4user": "",
        "_socks5pwd": "",
    }
    # The installed publicsuffixlist dependency bundles the same Mozilla list.
    # Initialization must not wait indefinitely on a blocked list download.
    import publicsuffixlist
    suffix_list = Path(publicsuffixlist.__file__).parent / "public_suffix_list.dat"
    if suffix_list.is_file():
        config["_internettlds"] = suffix_list.read_text(encoding="utf-8")
    _proxy_config(config)
    rules = {}
    try:
        handle = engine["db"](config, init=True)
        try:
            rules = engine["helpers"].loadCorrelationRulesRaw(str(VENDOR / "correlations") + os.sep, ["template.yaml"])
            config["__correlationrules__"] = engine["correlator"](handle, rules).get_ruleset()
        except (OSError, SyntaxError, TypeError, ValueError):
            config["__correlationrules__"] = []
        finally:
            handle.close()
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError(f"SpiderFoot database could not be opened: {exc}") from exc
    scan_id = engine["helpers"].genScanInstanceId()
    if on_status:
        on_status(f"Running {len(chosen) - 1} SpiderFoot {use_case} modules")
    previous_ssl = ssl._create_default_https_context
    holder = {"error": ""}

    def run() -> None:
        try:
            engine["scanner"](target, scan_id, target, target_type, chosen, config, start=True)
        except Exception as exc:
            holder["error"] = str(exc)

    worker = threading.Thread(target=run, name="findall-spiderfoot", daemon=True)
    with _state["guard"]:
        _state["thread"] = worker
    worker.start()
    timed_out = False
    deadline = time.monotonic() + timeout if timeout else None
    try:
        while worker.is_alive():
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                try:
                    stopper = engine["db"](config)
                    try:
                        stopper.scanInstanceSet(scan_id, None, None, "ABORT-REQUESTED")
                    finally:
                        stopper.close()
                except (OSError, TypeError, ValueError):
                    pass
                worker.join(45)
                break
            wait = 2 if deadline is None else max(0.2, min(2, deadline - time.monotonic()))
            worker.join(wait)
            if on_status and worker.is_alive():
                on_status(f"SpiderFoot {use_case} scan · {_event_count(database, scan_id)} events")
    finally:
        ssl._create_default_https_context = previous_ssl
        try:
            import dns.resolver
            dns.resolver.restore_system_resolver()
        except Exception:
            pass
        with _state["guard"]:
            if _state["thread"] is worker and not worker.is_alive():
                _state["thread"] = None
    events, event_count = _read_events(database, scan_id)
    normalized = normalize_events(events)
    useful = any(event.get("module") not in ("SpiderFoot UI", "", None) for event in events)
    status = ("partial" if useful else "error") if holder["error"] or normalized["notes"] else \
        ("partial" if useful else "timeout") if timed_out or worker.is_alive() else "ok" if useful else "empty"
    return {"status": status, "error": holder["error"], "errors": normalized["notes"],
            "target": target, "target_type": target_type, "use_case": use_case,
            "modules": len(chosen) - 1, "scan_id": scan_id, "database": str(database),
            "timed_out": timed_out or worker.is_alive(), "event_count": event_count,
            "events": events, "rows": normalized["rows"], "emails": normalized["emails"]}
