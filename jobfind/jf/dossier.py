"""One evidence-backed export for a public name, handle, or domain search."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import diagnostics, domain_recon, extra_osint, github_tools, osint, osint_contacts, spiderfoot_scan, two_gis
from .osint_contacts import DOMAIN_RE


KINDS = ("auto", "person", "username", "domain", "email", "ip", "phone")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_PHONE = re.compile(r"^\+[0-9]{8,15}\Z")
SCOPES = ("full", "email", "domain", "profiles")
_USERNAME = re.compile(r"[A-Za-z0-9._-]{2,64}\Z")
CSV_FIELDS = ("section", "kind", "title", "value", "url", "source", "observed_at",
              "status", "details", "error")


def _folder(output: Path, query: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in query)[:48].strip("._-") or "query"
    if safe.upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        safe = "_" + safe
    folder = output.resolve() / safe / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _status(item: dict) -> dict:
    state = item.get("state", item.get("status", "empty"))
    state = {"completed": "ok", "complete": "ok", "success": "ok"}.get(state, state)
    detail = str(item.get("detail", item.get("error", "")))[:1000]
    if state == "error":
        lowered = detail.casefold()
        if re.search(r"http\s*[:=]?\s*(?:403|429)\b", lowered) or any(
                marker in lowered for marker in ("captcha", "access denied", "rate limit", "challenge page")):
            state = "blocked"
        elif any(marker in lowered for marker in ("timed out", "timeout", "time limit")):
            state = "timeout"
    return {"source": str(item.get("source", item.get("name", "source"))),
            "state": state, "count": int(item.get("count") or 0),
            "detail": detail,
            **{key: item[key] for key in ("method", "filtered_count", "candidate_count") if key in item},
            **({"url": item["url"]} if item.get("url") else {}),
            **({"elapsed_seconds": item["elapsed_seconds"]} if "elapsed_seconds" in item else {})}


def _record_check(result: dict, item: dict) -> dict:
    """Retain transitions separately; the source ledger holds the latest outcome."""
    row = _status(item)
    diagnostics.record_source(row)
    checks = result.setdefault("source_checks", [])
    key = (row["source"], row.get("url", ""))
    previous = next((entry for entry in checks if
                     (entry.get("source"), entry.get("url", "")) == key), None)
    if previous == row:
        return row
    if previous is not None:
        checks.remove(previous)
    checks.append(row)
    result.setdefault("source_events", []).append(dict(row))
    return row


def merge_delta(result: dict, delta: dict) -> dict:
    """Merge source-linked tool output into the one dossier, retaining all artifacts and errors."""
    sections = result["sections"]
    part = delta.get("sections") or delta
    if isinstance(part.get("wireless"), dict):
        sections["wireless"] = part["wireless"]
    if isinstance(part.get("archives"), dict):
        sections["archives"] = part["archives"]
    for field in ("web", "profiles", "emails", "findings", "businesses", "jobs", "careers", "webcheck_modules", "enrichments"):
        target = sections.setdefault(field, [])
        known = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in target}
        for row in part.get(field) or []:
            if not isinstance(row, dict):
                continue
            row = {**row, "observed_at": row.get("observed_at", result["observed_at"])}
            if field == "profiles":
                row.setdefault("username", result["query"])
                row.setdefault("status", "candidate; same handle only, identity unverified")
            elif field == "web":
                row.setdefault("status", "candidate; identity unverified")
            elif field == "findings":
                row.setdefault("source", row.get("module", "Public source"))
            key = json.dumps(row, sort_keys=True, ensure_ascii=False)
            if key not in known:
                if field in {"web", "profiles", "businesses", "jobs", "careers"} and row.get("url"):
                    def archive_key(entry):
                        from .dossier_history import _archived
                        return (_archived(entry), entry.get("snapshot_at") or entry.get("timestamp") or entry.get("capture_timestamp") or "")
                    existing = next((entry for entry in target if entry.get("url") == row["url"]
                                     and (field != "web" or archive_key(entry) == archive_key(row))), None)
                    if existing is not None:
                        sources = list(dict.fromkeys([*(existing.get("sources") or []),
                            existing.get("source", ""), row.get("source", "")]))
                        source = existing.get("source") or row.get("source")
                        existing.update(row)
                        existing["source"] = source
                        existing["sources"] = [item for item in sources if item]
                        continue
                target.append(row)
                known.add(key)
    if isinstance(part.get("domain"), dict):
        target = sections.get("domain") or {}
        for field, value in part["domain"].items():
            if isinstance(value, list):
                combined = target.setdefault(field, [])
                for row in value:
                    if row not in combined:
                        combined.append(row)
            elif isinstance(value, dict):
                target.setdefault(field, {}).update(value)
            else:
                target[field] = value
        sections["domain"] = target
    for error in delta.get("errors") or []:
        if str(error) not in result["errors"]:
            result["errors"].append(str(error))
    for item in delta.get("source_checks", delta.get("statuses", [])) or []:
        _record_check(result, item)
    for artifact in delta.get("artifacts") or []:
        if artifact not in result.setdefault("artifacts", []):
            result["artifacts"].append(artifact)
    if isinstance(delta.get("selection"), dict):
        result.setdefault("capture_runs", []).append(dict(delta["selection"]))
    if isinstance(delta.get("limits"), dict) and (delta.get("careers") is not None or delta.get("ats_links") is not None):
        result.setdefault("career_discovery", []).append({
            "observed_at": result["observed_at"], "limits": dict(delta["limits"]),
            "ats_links": delta.get("ats_links") or [], "js_candidates": delta.get("js_candidates") or []})
    return result


def run_tool(result: dict, tool: str, parameters: dict, progress=None) -> dict:
    """The same bounded collectors serve the main workflow and AI tool requests."""
    query, kind = result["query"], result["kind"]
    if parameters.get("target", query) != query:
        raise ValueError("Tool target must match the dossier query")
    settings = result.get("settings") or {}
    coverage = result.get("coverage", "quick")
    requested_limit = parameters.get("limit")
    if requested_limit is not None and (type(requested_limit) is not int or not 1 <= requested_limit <= 100):
        raise ValueError("Tool result limit must be 1–100")
    output = Path(result["report_json"]).parent / "artifacts"
    output.mkdir(parents=True, exist_ok=True)
    delta = {"errors": [], "statuses": [], "artifacts": []}
    def status(state, count=0, detail=""):
        row = {"name": tool, "state": state, "count": count, "detail": detail}
        delta["statuses"].append(row)
        if progress:
            progress(row)
    if progress:
        progress({"name": tool, "state": "attempted", "detail": ""})
    try:
        if tool == "archive_search":
            if kind != "domain" or not settings.get("include_archives", True):
                status("skipped", detail="Archive collection requires an enabled domain search")
                return delta
            from . import archives
            options = dict(settings.get("archive_options") or {})
            options = {key:value for key,value in options.items() if key in {
                "providers", "subs", "from_date", "to_date", "category", "status_codes", "mime", "collapse_parameters"}}
            if "include_subdomains" in (settings.get("archive_options") or {}):
                options["subs"] = settings["archive_options"]["include_subdomains"]
            delta = archives.delta(archives.collect(query, output,
                limit=min(requested_limit or (1000 if coverage == "deep" else 300), 1000),
                captures=0, time_budget=150 if coverage == "deep" else 75,
                on_status=progress, **options))
        elif tool == "careers":
            if kind != "domain" or not settings.get("include_careers", True):
                status("skipped", detail="Careers discovery requires an enabled domain search")
                return delta
            from . import careers
            delta = careers.collect(query, max_pages=30 if coverage == "deep" else 12,
                                    time_budget=120 if coverage == "deep" else 45, on_status=progress)
        elif tool == "domain_card":
            if kind != "domain":
                status("skipped", detail="DNS and registration require a domain")
                return delta
            from . import domain_enrichment
            current = result["sections"].get("domain") or {}
            card = domain_enrichment.collect(query, webcheck={"data": {
                row.get("name"): row.get("data")
                for row in result["sections"].get("webcheck_modules", []) if row.get("status") in ("ok", "partial", "success")}},
                existing_card=current.get("dns"), include_dnsdumpster=False,
                known_hosts=[row.get("name", "") for row in current.get("subdomains", [])])
            delta = {"domain": {"domain_card": card["domain_card"],
                     "technologies": card.get("technologies", []), "subdomains": card.get("subdomains", [])},
                     "findings": card.get("findings", []), "statuses": card.get("statuses", []), "errors": card.get("errors", [])}
        elif tool == "dns_history":
            if kind != "domain":
                status("skipped", detail="Historical DNS requires a domain")
                return delta
            from . import dossier_history
            history = dossier_history.get_securitytrails_history(query)
            delta = history
        elif tool == "webcheck":
            if kind != "domain":
                status("skipped", detail="Web-Check requires a domain")
                return delta
            data = github_tools.web_check(query, output)
            raw = data.get("data")
            if raw is None:
                raw = json.loads(Path(data["report"]).read_text(encoding="utf-8"))
            delta["webcheck_modules"] = [{**item, "data": raw.get(item["name"]),
                "url": f"https://{query}/"} for item in data.get("modules", [])]
            delta["artifacts"].append({"path": data["report"], "source": "Web-Check", "kind": "raw_json"})
            for item in data.get("modules", []):
                row = {"name": f"Web-Check/{item['name']}", "state": item["status"], "detail": item.get("detail", "")}
                delta["statuses"].append(row)
                if progress:
                    progress(row)
                if item["status"] == "error":
                    delta["errors"].append(f"Web-Check/{item['name']}: {item.get('detail', '')}")
        elif tool == "businesses":
            if not settings.get("city"):
                status("skipped", detail="Set a 2GIS city before business collection")
                return delta
            url, city = two_gis.search_url(settings.get("business_query") or query, settings["city"])
            raw = Path(tempfile.mkdtemp(prefix="2gis-", dir=output)) / "2gis-raw.json"
            limit = int(settings.get("two_gis_limit", 25))
            rows = two_gis.collect(url, raw, min(limit, requested_limit) if requested_limit else limit,
                                   timeout=300 if coverage == "deep" else 120)
            if getattr(rows, "status", "ok") != "ok":
                status(getattr(rows, "status", "partial"), len(rows), getattr(rows, "detail", ""))
                delta["errors"].append("2GIS: " + getattr(rows, "detail", "Partial collection"))
            delta["businesses"] = rows
            delta["artifacts"].append({"path": str(raw), "source": "2GIS", "kind": "raw_json"})
            delta["web"] = [{"title": row["name"], "url": row["url"], "source": "2GIS",
                "snippet": row.get("address", "") + " · " + city} for row in rows]
            delta["emails"] = [{"email": email, "url": row["url"], "source": "2GIS",
                "attribution": "Published business contact"} for row in rows for email in row.get("emails", [])]
        elif tool == "additional":
            from . import additional_tools
            if not settings.get("include_extra_tools", True):
                status("skipped", detail="Additional engines disabled in search settings")
                return delta
            delta = additional_tools.supplement(query, kind, output, coverage=coverage)
        elif tool == "maps":
            from . import additional_tools
            if not settings.get("map_location"):
                status("skipped", detail="Set a map location before map collection")
                return delta
            delta = additional_tools.map_search(query, settings["map_location"], output)
        elif tool == "wireless":
            from . import wireless
            if not settings.get("wireless_files"):
                status("skipped", detail="Choose local telemetry files before wireless import")
                return delta
            data = wireless.collect(output, files=settings["wireless_files"], on_status=progress)
            delta = wireless.delta(data)
        elif tool == "browser_import":
            from . import chrome_crawler
            delta = chrome_crawler.collect(settings.get("browser_files") or [], output / "chrome-crawler", on_status=progress)
        elif tool == "metadata":
            from . import additional_tools
            if not settings.get("metadata_files"):
                status("skipped", detail="Choose local files before metadata collection")
                return delta
            delta = additional_tools.local_metadata(settings["metadata_files"], output)
        elif tool == "page_capture":
            from . import evidence_capture
            limit = settings.get("capture_pages", 0)
            if limit == -1:
                status("skipped", detail="Page capture disabled")
                return delta
            limit = limit or (40 if coverage == "deep" else 12)
            if requested_limit:
                limit = min(limit, requested_limit)
            rows = result["sections"].get("profiles", []) + result["sections"].get("web", [])
            if parameters.get("source_url"):
                rows = [row for row in rows if row.get("url") == parameters["source_url"]]
            delta = evidence_capture.capture_results(rows, output, limit=limit,
                include_onion=result.get("include_onion", False), on_status=progress,
                time_budget=420 if coverage == "deep" else 150)
        elif tool in {"profiles", "telegram"}:
            if tool == "profiles" and (kind != "username" and not _USERNAME.fullmatch(query)):
                status("skipped", detail="Profile collectors require a Latin username")
                return delta
            delta = (extra_osint.supplement(query, "username", coverage, on_status=progress)
                     if tool == "profiles" else extra_osint.public_pages(query))
        elif tool == "web_search":
            found, errors, statuses = osint.search(query, ["google", "yandex", "bing", "duckduckgo", "brave", "yahoo"],
                limit=min(int(parameters.get("limit", 20)), 80))
            delta = {"web": found, "errors": errors, "statuses": statuses}
        elif tool == "domain":
            if kind != "domain":
                status("skipped", detail="Domain research requires a domain")
                return delta
            data = domain_recon.investigate(query, output, max_hosts=200 if coverage == "deep" else 30,
                max_ips=20 if coverage == "deep" else 3, on_status=progress)
            delta = {"domain": {k: v for k, v in data.items() if k not in ("report", "csv")},
                     "web": data.get("web_results", []), "statuses": data.get("statuses", [])}
        elif tool == "emails":
            if kind == "domain":
                rows = osint_contacts.find_public_emails(query, query)
                delta["emails"] = [{"email": row["email"], "url": url, "source": "Public website",
                    "attribution": "Published on domain page; mailbox owner unverified"}
                    for row in rows if row.get("verification") == "published" for url in row.get("evidence", [])]
            elif kind == "username":
                data = github_tools.github_email(query, output, max_repos=30 if coverage == "deep" else 5,
                                                  max_commit_pages=5 if coverage == "deep" else 1)
                if data.get("email"):
                    delta["emails"] = [{"email": data["email"], "url": data.get("source_url", ""), "source": "GitHub commit"}]
                delta["errors"] = data.get("errors", [])
            else:
                delta = extra_osint.supplement(query, kind, coverage, on_status=progress)
        else:
            raise ValueError(f"Unknown research tool: {tool}")
        if requested_limit:
            for field in ("web", "profiles", "emails", "findings", "businesses", "jobs", "careers"):
                if isinstance(delta.get(field), list):
                    delta[field] = delta[field][:requested_limit]
        count = sum(len(delta.get(field) or []) for field in ("web", "profiles", "emails", "findings", "businesses", "jobs", "careers", "webcheck_modules"))
        errors = delta.get("errors") or []
        child_states = [_status(item)["state"] for item in delta.get("statuses", [])]
        state = ("partial" if errors and count else
                 "blocked" if errors and child_states and all(value == "blocked" for value in child_states) else
                 "error" if errors else "ok" if count else
                 "skipped" if child_states and all(value == "skipped" for value in child_states) else
                 "limited" if "limited" in child_states else "empty")
        if tool == "wireless" and isinstance(delta.get("wireless"), dict):
            state = delta["wireless"]["status"]
        if tool == "archive_search" and isinstance(delta.get("archives"), dict):
            state = delta["archives"]["status"]
        if tool == "browser_import":
            state = delta["status"]
        row = {"name": tool, "state": state, "count": count,
               "detail": f"{count} evidence records; {len(errors)} source issue(s)"}
        delta.setdefault("statuses", []).append(row)
        delta["status"] = state
        delta["message"] = row["detail"]
        if progress:
            progress(row)
        return delta
    except Exception as exc:
        delta["errors"].append(f"{tool}: {exc}")
        status("timeout" if isinstance(exc, TimeoutError) else "error", detail=str(exc))
        return delta


def identify(query: str, kind: str = "auto") -> tuple[str, str]:
    """Return the normalized search value and the selected target type."""
    query = " ".join(query.strip().split())
    if not 2 <= len(query) <= 200:
        raise ValueError("Query must contain 2–200 characters")
    if kind not in KINDS:
        raise ValueError(f"Kind must be one of: {', '.join(KINDS)}")
    if query.startswith(("https://", "http://")):
        parsed = urlsplit(query)
        if not parsed.hostname or parsed.username or parsed.password or parsed.port:
            raise ValueError("Enter a public website URL without credentials or a port")
        if kind not in ("auto", "domain"):
            raise ValueError("A website URL requires the domain target type")
        query, kind = parsed.hostname.lower(), "domain"
    if kind == "auto":
        lowered = query.lower()
        if _EMAIL.fullmatch(query):
            kind = "email"
        elif _PHONE.fullmatch(query):
            kind = "phone"
        elif _network_target(lowered):
            kind = "ip"
        elif DOMAIN_RE.fullmatch(lowered):
            kind = "domain"
        elif query.startswith("@"):
            kind = "username"
        else:
            kind = "person"
    if kind == "email" and not _EMAIL.fullmatch(query):
        raise ValueError("Enter an email address, for example name@example.org")
    if kind == "phone" and not _PHONE.fullmatch(query):
        raise ValueError("Enter a phone number in international format, for example +14155552671")
    if kind == "ip" and not _network_target(query.lower()):
        raise ValueError("Enter a public IPv4 or IPv6 address")
    if kind == "domain":
        query = query.lower().rstrip(".")
        if (not DOMAIN_RE.fullmatch(query) or
                query.endswith((".local", ".internal", ".test", ".onion"))):
            raise ValueError("Enter a public domain, for example example.org")
    elif kind == "username":
        query = query.lstrip("@")
        if not _USERNAME.fullmatch(query):
            raise ValueError("Username must have 2–64 Latin letters, digits, dots, underscores, or hyphens")
    return query, kind


def _network_target(value: str) -> bool:
    """True for an IP address or CIDR. Hex words such as cafe are names, not IPv6."""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        elif ":" in value or value.count(".") == 3:
            ipaddress.ip_address(value)
        else:
            return False
    except ValueError:
        return False
    return True


def _entry(section: str, kind: str, title: str, value: object, url: str,
           source: str, observed_at: str, status: str = "observed", details: str = "",
           error: str = "") -> dict:
    return {"section": section, "kind": kind, "title": title, "value": str(value) if value is not None else "",
            "url": url, "source": source, "observed_at": observed_at,
            "status": status, "details": details, "error": error}


def _report_rows(result: dict) -> list[dict]:
    rows = _flat_rows(result["sections"], result["errors"], result["observed_at"])
    for item in result.get("source_checks", []):
        item = _status(item)
        rows.append(_entry("source_checks", "source_check", item["source"], item["count"], item.get("url", ""),
                           item["source"], result["observed_at"], item["state"], item["detail"]))
    for item in result.get("artifacts", []):
        item = item if isinstance(item, dict) else {"path": str(item)}
        path = str(item.get("path", ""))
        digest = str(item.get("sha256", ""))
        rows.append(_entry("artifacts", item.get("kind", "file"), item.get("name") or Path(path).name,
                           digest, "artifact:sha256:" + digest if digest else "", item.get("source", "Collector"),
                           result["observed_at"], "retained", path))
    for event in (result.get("history") or {}).get("timeline", []):
        rows.append(_entry("history", event.get("event", "observation"), event.get("label", ""),
            event.get("date", ""), event.get("url", ""), event.get("source", ""), event.get("collected_at", ""),
            "archived" if event.get("archived") else "observed"))
    comparison = (result.get("history") or {}).get("comparison") or {}
    for field in ("added", "missing"):
        for item in comparison.get(field, []):
            rows.append(_entry("comparison", item.get("section", ""), item.get("value", ""),
                item.get("change", ""), item.get("url", ""), item.get("source", ""), result["observed_at"],
                comparison.get("status", "partial"), item.get("meaning", "")))
    return rows


def _flat_rows(sections: dict, errors: list[str], observed_at: str) -> list[dict]:
    rows = []
    for item in sections.get("statistics") or []:
        rows.append(_entry("statistics", "sample_calculation", item.get("title", ""), item.get("text", ""),
            "artifact:sha256:" + item.get("sha256", ""), item.get("source", ""),
            item.get("observed_at", observed_at), item.get("status", ""), item.get("attribution", "")))
    for item in sections.get("enrichments") or []:
        rows.append(_entry("enrichments", item.get("relation", ""), item.get("input", {}).get("value", ""),
            item.get("output", {}).get("value", ""), item.get("url", ""), item.get("source", ""),
            item.get("observed_at", observed_at), item.get("certainty", "candidate"), item.get("attribution", "")))
    for section in ("jobs", "careers"):
        for item in sections.get(section) or []:
            rows.append(_entry(section, "published_job" if section == "jobs" else "career_link",
                item.get("title", item.get("provider", "Career page")), item.get("description", item.get("tenant", "")),
                item.get("url", ""), item.get("source", "Company website"), item.get("observed_at", observed_at),
                item.get("status", "published"), json.dumps({key: item[key] for key in ("company", "location", "company_source_url", "association", "source_url") if key in item}, ensure_ascii=False)))
    card = (sections.get("domain") or {}).get("domain_card") or {}
    if card:
        rows.append(_entry("domain", "dns_registration_card", card.get("domain", ""),
            json.dumps(card, ensure_ascii=False), f"https://{card.get('domain', '')}/", "DNS/RDAP", observed_at))
        for kind, entry in (card.get("records") or {}).items():
            if not isinstance(entry, dict):
                continue
            values = entry.get("records") or []
            for item in values or [{}]:
                rows.append(_entry("domain", "dns_record", kind, item.get("value", ""), entry.get("url", ""),
                    entry.get("source", "DNS"), entry.get("checked_at", observed_at), entry.get("state", "unknown"),
                    json.dumps({key: item[key] for key in ("ttl", "name") if key in item}, ensure_ascii=False)))
        registration = card.get("registration") or {}
        rows.append(_entry("domain", "registration", card.get("domain", ""), json.dumps(registration, ensure_ascii=False),
            registration.get("url", ""), registration.get("source", "RDAP"), registration.get("checked_at", observed_at),
            registration.get("state", "unknown")))
    for item in sections["web"]:
        rows.append(_entry("web", "candidate_page", item.get("title", ""),
                           item.get("snippet", ""), item.get("url", ""),
                           item.get("source", ""), item.get("observed_at", observed_at),
                           "candidate", "Search match; identity and claims unverified"))
    for item in sections["profiles"]:
        rows.append(_entry("profiles", "candidate_profile", item.get("site", ""),
                           item.get("username", ""), item.get("url", ""),
                           item.get("source", "Maigret"), item.get("observed_at", observed_at),
                           "candidate", "Same handle; account ownership unverified"))
    for item in sections["emails"]:
        rows.append(_entry("emails", "candidate_email" if item.get("verification") in {"hypothesis", "candidate", "unknown"}
                           else "published_email", item.get("email", ""), "",
                           item.get("url", ""), item.get("source", ""),
                           item.get("observed_at", observed_at), item.get("verification", "published"),
                           item.get("attribution", "")))
    domain = sections["domain"]
    if domain:
        name = domain["domain"]
        for field, value in domain.get("dns", {}).items():
            if field in {"domain", "records", "registration", "domain_card", "limits"} or value is None:
                continue
            source = (f"https://rdap.org/domain/{quote(name)}" if field == "age_years" else
                      f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={quote(field.upper())}"
                      if field.lower() in {"a", "aaaa", "mx", "ns", "txt", "cname", "soa", "srv", "ptr", "caa"} else "")
            rows.append(_entry("domain", "dns", field, json.dumps(value, ensure_ascii=False),
                               source, "DNS/RDAP", observed_at))
        for item in domain.get("subdomains", []):
            providers = item.get("sources", [])
            evidence = (f"https://crt.sh/?q=%25.{quote(name)}" if "crt.sh" in providers else
                        f"https://api.certspotter.com/v1/issuances?domain={quote(name)}&include_subdomains=true"
                        if "CertSpotter" in providers else "")
            rows.append(_entry("domain", "subdomain", item.get("name", ""),
                               ", ".join(item.get("ips", [])), evidence, ", ".join(providers),
                               observed_at, details=(f"Passive hostname from {', '.join(providers)}; ownership unverified"
                                                      if providers and set(providers) <= extra_osint.PASSIVE_HOSTNAME_SOURCES else
                                                      "Observed DNS/certificate name; ownership unverified")))
        for item in domain.get("assets", []):
            rows.append(_entry("domain", "resolved_ip_service", item.get("ip", ""),
                               f"port {item.get('port', '')} {item.get('product', '')}".strip(),
                               item.get("url", ""), item.get("provider", ""), observed_at,
                               details="Service data for a resolved IP; domain ownership of equipment unverified"))
        for item in domain.get("technologies", []):
            rows.append(_entry("domain", "website_technology", item.get("name", ""),
                               item.get("version", ""), item.get("url") or f"https://{name}/", item.get("source", "Web-Check"),
                               item.get("checked_at", observed_at), item.get("certainty", "candidate"),
                               details=f"Detection confidence {item.get('confidence', 'unknown')}"))
    summary = sections.get("spiderfoot") or {}
    if summary:
        rows.append(_entry("spiderfoot", "scan", summary.get("target_type", ""),
                           summary.get("event_count", ""), "", "SpiderFoot", observed_at,
                           summary.get("status", ""), details=summary.get("database", "")))
    for item in sections.get("findings") or []:
        rows.append(_entry("findings", item.get("event_type", item.get("kind", "")), item.get("module", item.get("title", "")),
                           item.get("value", item.get("snippet", "")), item.get("source_url") or item.get("url", ""), item.get("source") or "SpiderFoot",
                           item.get("observed_at", observed_at), item.get("verification", item.get("certainty", "observed")),
                           item.get("source_data", "")))
    for item in sections.get("businesses") or []:
        rows.append(_entry("businesses", "business", item.get("name", ""),
                           item.get("address", ""), item.get("url", ""), item.get("source") or "2GIS", observed_at,
                           details=json.dumps(item, ensure_ascii=False)))
    for item in sections.get("webcheck_modules") or []:
        rows.append(_entry("webcheck", "module", item.get("name", ""),
                           json.dumps(item.get("data"), ensure_ascii=False), item.get("url", ""),
                           "Web-Check", observed_at, item.get("status", ""), item.get("detail", "")))
    for error in errors:
        source = error.split(":", 1)[0]
        rows.append(_entry("source_errors", "source_error", source, "", "", source,
                           observed_at, "error", error=error))
    return rows


@diagnostics.traced_collection
def collect(query: str, kind: str, scope: str, output: Path, progress=None,
            finish_progress: bool = True, include_onion: bool = False,
            include_spiderfoot: bool = True, spiderfoot_timeout: int = 120,
            coverage: str = "quick", capture_pages: int = 0, city: str = "",
            business_query: str = "", two_gis_limit: int = 25, map_location: str = "",
            metadata_files=None, include_extra_tools: bool = True,
            include_careers: bool = True, include_domain_card: bool = True,
            wireless_files=None, include_archives: bool = True, archive_options=None,
            browser_files=None) -> dict:
    """Collect public evidence; failures stay visible and do not erase other sections."""
    query, kind = identify(query, kind)
    if scope not in SCOPES:
        raise ValueError(f"Scope must be one of: {', '.join(SCOPES)}")
    if coverage not in ("quick", "deep"):
        raise ValueError("Coverage must be quick or deep")
    if not -1 <= capture_pages <= 100 or not 1 <= two_gis_limit <= 500:
        raise ValueError("Capture pages must be -1–100; 2GIS limit must be 1–500")
    if browser_files is not None and (not isinstance(browser_files, (list, tuple)) or len(browser_files) > 10):
        raise ValueError("Choose at most 10 Chrome crawler exports")
    folder = _folder(output, query)
    artifacts = folder / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    if scope == "domain" and kind not in ("domain", "ip"):
        raise ValueError("Domain scope requires a domain, website URL, or IP address")
    if scope == "profiles" and kind not in ("person", "username"):
        raise ValueError("Profiles scope requires a person or username")
    observed_at = datetime.now(timezone.utc).isoformat()
    result = {"query": query, "kind": kind, "scope": scope, "observed_at": observed_at,
              "include_onion": include_onion and scope == "full",
              "sections": {"web": [], "profiles": [], "emails": [], "domain": None},
              "coverage": coverage, "source_checks": [], "artifacts": [],
              "settings": {"city": city, "business_query": business_query,
                           "two_gis_limit": two_gis_limit, "map_location": map_location,
                           "metadata_files": [str(p) for p in (metadata_files or [])],
                           "wireless_files": [str(p) for p in (wireless_files or [])],
                           "browser_files": [str(p) for p in (browser_files or [])],
                           "include_archives": include_archives, "archive_options": archive_options or {},
                           "capture_pages": capture_pages, "include_extra_tools": include_extra_tools,
                           "include_careers": include_careers, "include_domain_card": include_domain_card},
              "errors": [], "report_json": str(folder / "dossier.json"),
              "report_csv": str(folder / "dossier.csv")}
    diagnostics.attach(result)
    sections, errors = result["sections"], result["errors"]
    phases = []
    if scope == "full" or scope == "profiles" and kind == "person":
        phases.append("web")
    if kind == "domain" and scope in ("full", "domain"):
        phases.extend(("domain", "webcheck"))
        if include_domain_card:
            phases.extend(("domain_card", "dns_history"))
        if include_archives:
            phases.append("archive_search")
    if kind == "domain" and scope in ("full", "email") and include_careers:
        phases.append("careers")
    if kind == "domain" and scope == "full":
        if include_archives:
            phases.append("archive")
        phases.append("breaches")
    if ((kind == "username" or kind == "person" and " " not in query and
         _USERNAME.fullmatch(query)) and scope in ("full", "profiles")):
        phases.append("profiles")
    if kind in ("domain", "username") and scope in ("full", "email"):
        phases.append("emails")
    if kind == "username" and scope in ("full", "profiles"):
        phases.append("tiktok")
    if include_onion and scope == "full":
        phases.append("onion")
    if (scope == "full" or (scope == "email" and kind == "email")
            or (scope == "domain" and kind == "domain")
            or (scope == "profiles" and kind in ("username", "person"))):
        phases.append("public")
    if include_spiderfoot:
        phases.append("spiderfoot")
    if include_extra_tools:
        phases.append("additional")
    if city:
        phases.append("businesses")
    if map_location:
        phases.append("maps")
    if metadata_files:
        phases.append("metadata")
    if wireless_files:
        phases.append("wireless")
    if capture_pages >= 0:
        phases.append("capture")
    if browser_files:
        phases.append("browser_import")
    if not phases:
        errors.append(f"No verified source for {scope} research on a {kind} alone")
    if (kind == "person" and " " not in query and scope in ("full", "profiles")
            and not _USERNAME.fullmatch(query)):
        errors.append("Profile checks take a Latin username only. This query was searched as a name, "
                      "so Maigret, Sherlock, Social Analyzer, Blackbird and WhatsMyName did not run.")

    web_sources = [source for source in osint.SOURCES if source != "public"]
    phase_units = {phase: len(web_sources) if phase == "web" else 1 for phase in phases}
    total_units = sum(phase_units[phase] for phase in phases) + 1 + (0 if finish_progress else 1)
    completed_units = 0

    def emit(percent: int, stage: str, detail: str, **extra) -> None:
        if progress:
            progress({"percent": percent, "stage": stage, "detail": detail,
                      "completed": completed_units, "total": total_units, **extra})

    def advance(stage: str, source: str, state: str, detail: str, limit: int, count: int = 0) -> None:
        nonlocal completed_units
        completed_units = min(completed_units + 1, limit)
        record_status({"name": source, "state": state, "detail": detail, "count": count})
        emit(int(completed_units * 100 / max(1, total_units)), stage, detail,
             source=source, state=_status({"state": state, "detail": detail})["state"])

    def record_status(status):
        item = _record_check(result, status)
        emit(int(completed_units * 100 / max(1, total_units)), "source", item["detail"],
             source=item["source"], state=item["state"])

    def check_status(status):
        if status.get("state", status.get("status")) == "attempted":
            diagnostics.record_source(_status(status))
            emit(int(completed_units * 100 / max(1, total_units)), "source",
                 status.get("detail") or f"Checking {status.get('name', status.get('source', 'source'))}",
                 source=status.get("name", status.get("source", "")), state="attempted")
        else:
            record_status(status)

    emit(0, "starting", f"Researching public sources for {query}")
    # Source tools write their own reports; use a disposable folder so the dossier remains one JSON/CSV pair.
    with tempfile.TemporaryDirectory(prefix="jobfind-dossier-") as tmp:
        scratch = Path(tmp)
        for phase in phases:
            tool_state = ""
            phase_limit = completed_units + phase_units[phase]
            before_errors = len(errors)
            before_items = tuple(len(sections[name]) for name in ("web", "profiles", "emails")) + (len(sections.get("findings") or []),)
            emit(int(completed_units * 100 / max(1, total_units)), phase,
                 f"Checking {phase} sources")
            diagnostics.record_source({"source": "phase:" + phase, "state": "attempted"})
            try:
                if phase == "web":
                    found, source_errors, statuses = osint.search(query,
                        web_sources, limit=40 if coverage == "deep" else 10,
                        on_source=lambda source, count, error: advance("web", source,
                            "error" if error else "empty" if not count else "ok",
                            f"{source}: {error}" if error else f"{source}: {count} result(s)",
                            phase_limit, count))
                    sections["web"] = [{**row, "observed_at": observed_at,
                        "status": "candidate; identity unverified"} for row in found[:500]]
                    errors.extend(source_errors)
                    result["web_sources"] = statuses
                    for status in statuses:
                        record_status(status)
                elif phase == "domain":
                    data = domain_recon.investigate(query, scratch,
                        max_hosts=200 if coverage == "deep" else 30,
                        max_ips=20 if coverage == "deep" else 3, on_status=check_status)
                    sections["domain"] = {key: value for key, value in data.items()
                                          if key not in ("report", "csv")}
                    for status in data.get("statuses", []):
                        record_status(status)
                        if status.get("state") in ("error", "partial"):
                            errors.append(f"{status['name']}: {status.get('detail', '')}")
                    known_urls = {row.get("url") for row in sections["web"]}
                    for row in data.get("web_results", []):
                        if row.get("url") not in known_urls:
                            sections["web"].append({**row, "observed_at": observed_at,
                                "status": "candidate; identity unverified"})
                            known_urls.add(row.get("url"))
                elif phase == "profiles":
                    data = github_tools.maigret_search(query, artifacts, top_sites=500 if coverage == "deep" else 100)
                    sections["profiles"] = [{"site": item.get("site", ""), "url": item["url"],
                         "username": query, "source": "Maigret", "observed_at": observed_at,
                         "status": "candidate; same handle only, identity unverified"}
                         for item in data.get("rows", []) if item.get("url", "").startswith("https://")]
                    errors.extend(f"Maigret: {warning}" for warning in data.get("warnings", []))
                elif phase == "emails" and kind == "domain":
                    found = osint_contacts.find_public_emails(query, query)
                    sections["emails"] = [{"email": item["email"], "url": url,
                        "source": item.get("source", "Public company website"),
                        "observed_at": observed_at, "attribution": "Published on domain page; mailbox owner unverified"}
                        for item in found if item.get("verification") == "published"
                        for url in item.get("evidence", []) if url.startswith("https://")]
                elif phase == "emails" and kind == "username":
                    data = github_tools.github_email(query, artifacts,
                        max_repos=30 if coverage == "deep" else 5,
                        max_commit_pages=5 if coverage == "deep" else 1)
                    errors.extend(f"GitHub: {error}" for error in data.get("errors", []))
                    if data.get("email") and data.get("source_url", "").startswith("https://"):
                        sections["emails"] = [{"email": data["email"], "url": data["source_url"],
                            "source": "GitHub commit", "observed_at": observed_at,
                            "attribution": "Commit author email; ownership unverified"}]
                elif phase == "archive":
                    snapshot = osint.archived_homepage(query)
                    if snapshot:
                        sections["web"].append({**snapshot, "observed_at": observed_at,
                                                "status": "Public archive snapshot"})
                elif phase == "breaches":
                    sections["web"].extend({**row, "observed_at": observed_at,
                                             "status": "Public breach notice; no leaked records collected"}
                                            for row in osint.breach_catalogue(query))
                elif phase == "tiktok":
                    artifacts.mkdir(parents=True, exist_ok=True)
                    profile = github_tools.tiktok_profile(query, artifacts)
                    if profile.get("url", "").startswith("https://"):
                        merge_delta(result, {"profiles": [{"site": "TikTok", "url": profile["url"],
                            "username": query, "source": profile.get("source", "TikTok"),
                            "bio": profile.get("bio", ""), "observed_at": observed_at,
                            "status": "candidate; same handle only, identity unverified"}]})
                elif phase == "onion":
                    found = github_tools.onion_search(query, artifacts, on_status=check_status)
                    merge_delta(result, {"artifacts": found.get("artifacts", []), "statuses": found.get("statuses", [])})
                    sections["web"].extend({**row, "title": row.get("title") or row["url"],
                        "url": row["url"], "snippet": row.get("snippet", ""),
                        "source": "OnionSearch", "category": "Onion index",
                        "observed_at": observed_at, "status": "Unverified onion index match"}
                        for row in found.get("rows", []))
                    errors.extend(f"OnionSearch: {warning}" for warning in found.get("warnings", []))
                elif phase == "public":
                    extra = extra_osint.supplement(query, kind, coverage=coverage, on_status=check_status)
                    known = {row.get("url") for row in sections["profiles"]}
                    for row in extra.get("profiles") or []:
                        url = row.get("url") or ""
                        if url.startswith("https://") and url not in known:
                            sections["profiles"].append({**row, "observed_at": observed_at,
                                "username": row.get("username") or query,
                                "status": row.get("status") or "candidate; identity unverified"})
                            known.add(url)
                    known_web = {row.get("url") for row in sections["web"]}
                    for row in extra.get("web") or []:
                        url = row.get("url") or ""
                        if url.startswith(("https://", "http://")) and url not in known_web:
                            sections["web"].append({**row, "observed_at": observed_at,
                                "status": "candidate; identity unverified"})
                            known_web.add(url)
                    findings = sections.setdefault("findings", [])
                    for item in (extra.get("findings") or [])[:40]:
                        findings.append({**item, "observed_at": observed_at,
                                         "source": item.get("source") or item.get("module") or "public"})
                    hostnames = extra.get("hostnames") or []
                    domain_section = sections.get("domain")
                    if hostnames and isinstance(domain_section, dict):
                        known_hosts = {item.get("name"): item for item in domain_section.get("subdomains") or []}
                        domain_section.setdefault("subdomains", [])
                        for item in hostnames:
                            host, source = extra_osint.hostname_item(item)
                            if not host:
                                continue
                            existing = known_hosts.get(host)
                            if existing:
                                if source not in existing.setdefault("sources", []):
                                    existing["sources"].append(source)
                                continue
                            row = {"name": host, "ips": [], "sources": [source]}
                            domain_section["subdomains"].append(row)
                            known_hosts[host] = row
                    elif hostnames:
                        for item in hostnames[:40]:
                            host, source = extra_osint.hostname_item(item)
                            if not host:
                                continue
                            findings.append({"event_type": "INTERNET_NAME", "value": host,
                                             "module": source.lower(), "url": f"https://{host}/",
                                             "source_data": "Passive hostname", "source": source,
                                             "observed_at": observed_at})
                    errors.extend(extra.get("errors") or [])
                elif phase == "spiderfoot":
                    report = spiderfoot_scan.scan(
                        query, artifacts / "spiderfoot", kind=kind, use_case="passive",
                        modules=spiderfoot_scan.DOSSIER_MODULES,
                        timeout=spiderfoot_timeout,
                        on_status=lambda detail: emit(int(completed_units * 100 / max(1, total_units)),
                                                      "spiderfoot", detail))
                    spiderfoot_scan.merge_dossier(sections, report, observed_at)
                    if report.get("timed_out"):
                        errors.append(f"SpiderFoot: time limit reached; kept {report.get('event_count', 0)} events")
                    elif report.get("status") == "error" and report.get("error"):
                        errors.append(f"SpiderFoot: {report['error']}")
                    errors.extend(f"SpiderFoot: {note}" for note in report.get("errors") or [])
                    record_status({"name": "SpiderFoot", "state": "timeout" if report.get("timed_out") else report.get("status", "empty"),
                                   "count": report.get("event_count", 0), "detail": report.get("error", "")})
                elif phase in {"additional", "businesses", "maps", "metadata", "webcheck", "capture", "careers", "domain_card", "dns_history", "wireless", "archive_search", "browser_import"}:
                    tool = {"additional": "additional", "capture": "page_capture"}.get(phase, phase)
                    delta = run_tool(result, tool, {"target": query}, progress=check_status)
                    tool_state = delta.get("status", "")
                    merge_delta(result, delta)
            except Exception as exc:
                errors.append(f"{phase}: {exc}")
                record_status({"name": phase, "state": "timeout" if isinstance(exc, TimeoutError) else "error", "detail": str(exc)})
            completed_units = phase_limit
            after_items = tuple(len(sections[name]) for name in ("web", "profiles", "emails")) + (len(sections.get("findings") or []),)
            new_items = sum(max(0, after - before) for before, after in zip(before_items, after_items))
            phase_state = tool_state or ("partial" if len(errors) > before_errors and new_items else
                                       "error" if len(errors) > before_errors else "ok" if new_items else "empty")
            diagnostics.record_source({"source": "phase:" + phase, "state": phase_state, "count": new_items})
            if phase not in ("web", "domain", "additional", "webcheck", "capture", "businesses", "maps", "metadata", "onion", "public", "careers", "domain_card", "dns_history", "wireless", "archive_search", "browser_import"):
                record_status({"name": phase, "state": "partial" if len(errors) > before_errors and new_items else
                               "error" if len(errors) > before_errors else "ok" if new_items else "empty",
                               "count": new_items, "detail": "; ".join(errors[before_errors:])})
            emit(int(completed_units * 100 / max(1, total_units)), phase,
                 f"Finished {phase}; {len(errors)} source issue(s)",
                 **({"source": "page_capture" if phase == "capture" else phase, "state": phase_state}
                    if phase not in ("web", "domain") else {}))

    json_path = folder / "dossier.json"
    csv_path = folder / "dossier.csv"
    result["report_json"], result["report_csv"] = str(json_path), str(csv_path)
    emit(int(completed_units * 100 / total_units), "export", "Writing consolidated JSON and CSV")
    result["artifacts"].extend({"path": str(path), "source": "Collector", "kind": "file"}
                              for path in artifacts.rglob("*") if path.is_file()
                              and not any((entry.get("path") if isinstance(entry, dict) else entry) == str(path)
                                          for entry in result["artifacts"]))
    rows = _report_rows(result)
    result["counts"] = {"web": len(sections["web"]), "profiles": len(sections["profiles"]),
                        "emails": len(sections["emails"]),
                        "domain_assets": len((sections["domain"] or {}).get("assets", [])),
                        "spiderfoot_events": int((sections.get("spiderfoot") or {}).get("event_count") or 0),
                        "findings": len(sections.get("findings") or []),
                        "businesses": len(sections.get("businesses") or []),
                        "webcheck_modules": len(sections.get("webcheck_modules") or []),
                        "source_checks": len(result["source_checks"]),
                        "artifacts": len(result["artifacts"]),
                        "table_rows": len(rows)}
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    save_relationship_graph(result)
    completed_units += 1
    emit(int(completed_units * 100 / total_units), "complete" if finish_progress else "collected",
         f"Saved {len(rows)} evidence rows")
    return result


def append_ai_claims(csv_path: Path, analysis: dict, observed_at: str) -> None:
    """Append only cited model claims to the same evidence table."""
    claims = analysis.get("claims", [])
    if not claims:
        return
    with csv_path.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        for claim in claims:
            writer.writerow(_entry("ai_analysis", "cited_claim", claim.get("category", ""),
                                   claim.get("statement", ""), claim.get("source_url", ""),
                                   "AI analysis", observed_at, "model_summary",
                                   claim.get("quote", "")))


def save_relationship_graph(result: dict) -> dict:
    """Add the dossier to the common graph; extra formats require explicit export."""
    from . import evidence_graph, research_quality, dossier_history, markdown_export
    path = Path(result["report_json"]).resolve()
    if path.name != "dossier.json" or not isinstance(result.get("sections"), dict):
        raise ValueError("Expected a saved dossier with evidence sections")
    domain = result["sections"].get("domain")
    if isinstance(domain, dict):
        for row in result["sections"].get("web", []):
            observation = row.get("http_observation")
            if not isinstance(observation, dict):
                continue
            if observation not in domain.setdefault("http_observations", []):
                domain["http_observations"].append(observation)
            for name in observation.get("technologies", []):
                tech = {"name": name, "version": "", "url": row.get("url", ""), "source": "httpx signature",
                        "checked_at": observation.get("checked_at", ""), "certainty": "candidate"}
                if tech not in domain.setdefault("technologies", []):
                    domain["technologies"].append(tech)
    dossier_history.enrich(result)
    graph = evidence_graph.build_graph(result)
    output = path.parents[2]
    if output.name == "dossiers":
        output = output.parent
    shared = evidence_graph.accumulate(result, output)
    paths = {"graph_html": shared["graph_path"]}
    result["relationship_graph"] = graph
    result.setdefault("exported_paths", {}).update(paths)
    result["graph_path"] = paths["graph_html"]
    result["graph_json_path"] = paths.get("graph_json", "")
    result["bloodhound_graph_path"] = paths.get("bloodhound_graph", "")
    result.setdefault("counts", {}).update(graph_nodes=len(graph.get("nodes", [])),
                                           graph_edges=len(graph.get("edges", [])))
    result["quality_report"] = research_quality.evaluate(result)
    result.setdefault("counts", {}).update(jobs=len(result["sections"].get("jobs") or []),
                                            careers=len(result["sections"].get("careers") or []))
    csv_path = path.with_name("dossier.csv")
    if csv_path.is_file():
        rows = _report_rows(result)
        with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        append_ai_claims(csv_path, result.get("ai_analysis") or {}, result.get("observed_at", ""))
        result.setdefault("counts", {})["table_rows"] = len(rows) + len((result.get("ai_analysis") or {}).get("claims", []))
    result.setdefault("exported_paths", {}).update(markdown_export.save(result))
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def save_ai_analysis(result: dict, analysis: dict) -> dict:
    """Replace the AI section in one existing dossier without duplicating CSV rows."""
    json_path = Path(result["report_json"]).resolve()
    csv_path = Path(result["report_csv"]).resolve()
    if json_path.name != "dossier.json" or csv_path != json_path.with_name("dossier.csv"):
        raise ValueError("Expected a paired dossier.json and dossier.csv")
    if not isinstance(result.get("sections"), dict) or not isinstance(result.get("errors"), list):
        raise ValueError("Invalid dossier contents")
    rows = _report_rows(result)
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    append_ai_claims(csv_path, analysis, result["observed_at"])
    result["ai_analysis"] = analysis
    result.setdefault("counts", {}).update({"web": len(result["sections"].get("web") or []),
        "profiles": len(result["sections"].get("profiles") or []), "emails": len(result["sections"].get("emails") or []),
        "domain_assets": len((result["sections"].get("domain") or {}).get("assets") or []),
        "findings": len(result["sections"].get("findings") or []),
        "source_checks": len(result.get("source_checks") or []), "artifacts": len(result.get("artifacts") or [])})
    result.setdefault("counts", {})["table_rows"] = len(rows) + len(analysis.get("claims", []))
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return save_relationship_graph(result)
