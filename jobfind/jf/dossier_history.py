"""Bounded local snapshot comparison and dated, source-backed history."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_ITEMS = 2000
MAX_PREVIOUS = 300
DNS_TYPES = ("a", "aaaa", "mx", "ns", "soa", "txt")


def _hostname(value):
    try:
        return urlsplit(str(value or "")).hostname
    except ValueError:
        return ""


def _id(kind, value):
    return "FindAll_History_" + hashlib.sha256((kind + "|" + str(value)).encode()).hexdigest()[:32]


def _date(value):
    value = str(value or "").strip()
    if re.fullmatch(r"\d{8,14}", value):
        try:
            return datetime.strptime(value.ljust(14, "0"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return ""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ""


def _archived(row):
    return bool(row.get("archived") or "archive" in str(row.get("category", "")).lower()
                or "archive" in str(row.get("status", "")).lower()
                or str(row.get("source", "")).lower() in {"internet archive", "common crawl"}
                or _hostname(row.get("url")) == "web.archive.org")


def _domain_card(report):
    sections = report.get("sections") or {}
    card = sections.get("domain_card")
    if isinstance(card, dict):
        return card
    card = (sections.get("domain") or {}).get("domain_card")
    if isinstance(card, dict):
        return card
    dns = (sections.get("domain") or {}).get("dns") or {}
    return dns if isinstance(dns, dict) else {}


def _entities(report):
    """Stable values exclude collection timestamps and changing display prose."""
    found = {}
    sections = report.get("sections") or {}
    for section, keys in {"web": ("original_url", "url"), "profiles": ("url",),
                          "emails": ("email",), "jobs": ("url", "id"),
                          "vacancies": ("url", "id"), "businesses": ("url", "id")}.items():
        for row in (sections.get(section) or [])[:MAX_ITEMS]:
            if not isinstance(row, dict):
                continue
            value = next((str(row[key]) for key in keys if row.get(key)), "")
            if not value:
                continue
            historical = _archived(row)
            identity = value.casefold() if section == "emails" else value
            ident = _id(section + (":archived" if historical else ":current"), identity)
            found[ident] = {"id": ident, "section": section, "value": value[:2000],
                            "source": str(row.get("source") or row.get("provider") or ""),
                            "url": str(row.get("url") or row.get("source_url") or ""),
                            "archived": historical, "observed_at": row.get("observed_at", report.get("observed_at", "")),
                            "meaning": "Historical evidence; current validity unverified" if historical else "Collected observation; validity and ownership require evidence"}
    for row in ((sections.get("archives") or {}).get("records") or [])[:MAX_ITEMS]:
        if not isinstance(row, dict) or not row.get("original_url"):
            continue
        value=str(row["original_url"])
        ident=_id("archives:historical",value)
        found[ident]=dict(id=ident,section="archives",value=value,source=row.get("source", ""),
            url=row.get("source_url", ""),archived=True,observed_at=report.get("observed_at", ""),
            meaning="Historical URL candidate; current availability unverified")
    domain = sections.get("domain") or {}
    for row in domain.get("subdomains", domain.get("hostnames", [])) or []:
        value = row.get("hostname") or row.get("host") or row.get("name") if isinstance(row, dict) else row
        if value:
            ident = _id("domain", str(value).casefold())
            found[ident] = {"id": ident, "section": "domain", "value": str(value), "source": "",
                            "url": "", "archived": False, "observed_at": report.get("observed_at", "")}
    dns = domain.get("dns") or {}
    for name, rows in dns.items():
        if name.lower() not in {"a", "aaaa", "mx", "ns", "cname", "txt", "caa", "soa", "ptr", "srv"}:
            continue
        rows = rows if isinstance(rows, list) else [rows]
        for row in rows[:MAX_ITEMS]:
            value = json.dumps(row, sort_keys=True, ensure_ascii=False) if isinstance(row, dict) else str(row)
            ident = _id("dns:" + name.upper(), value.casefold())
            found[ident] = {"id": ident, "section": "dns", "record_type": name.upper(), "value": value,
                            "source": "DNS", "url": "", "archived": False, "observed_at": report.get("observed_at", "")}
    card = _domain_card(report)
    for name, item in (card.get("records") or {}).items():
        if not isinstance(item, dict) or item.get("state") != "success":
            continue
        for row in (item.get("records") or [])[:MAX_ITEMS]:
            value = str(row.get("value", "")) if isinstance(row, dict) else str(row)
            if not value:
                continue
            ident = _id("dns:" + name.upper(), value.casefold())
            found[ident] = {"id": ident, "section": "dns", "record_type": name.upper(), "value": value,
                            "source": item.get("source", "DNS"), "url": item.get("url", ""), "archived": False,
                            "observed_at": item.get("checked_at", report.get("observed_at", ""))}
    for module in sections.get("webcheck_modules") or []:
        if not isinstance(module, dict) or module.get("name") not in {"tech-stack", "technology", "technologies"}:
            continue
        data = module.get("data") or {}
        rows = data if isinstance(data, list) else data.get("technologies", []) if isinstance(data, dict) else []
        for row in rows[:MAX_ITEMS]:
            if not isinstance(row, dict):
                continue
            value = str(row.get("name", "")) + " " + str(row.get("version", ""))
            ident = _id("technology", value.casefold())
            found[ident] = {"id": ident, "section": "technologies", "value": value.strip(),
                            "source": "Web-Check/" + module["name"], "url": str(module.get("url", "")),
                            "archived": False, "observed_at": report.get("observed_at", "")}
    return dict(list(found.items())[:MAX_ITEMS])


def _covered(report, row):
    if row.get("section") == "dns":
        item = (_domain_card(report).get("records") or {}).get(row.get("record_type"), {})
        return isinstance(item, dict) and item.get("state") in {"success", "no_records", "nxdomain"} and not item.get("truncated")
    source = str(row.get("source", "")).casefold()
    if not source:
        return False
    matches = [item for item in report.get("source_checks", []) if isinstance(item, dict)
               and str(item.get("source") or item.get("name") or "").casefold() == source]
    if not matches or any(item.get("state", item.get("status")) not in {"ok", "empty", "success"} for item in matches):
        return False
    if any(item.get("truncated") or item.get("limit_reached") for item in matches):
        return False
    # Search engines and archive indexes are bounded samples, never exhaustive inventories.
    return row.get("section") not in {"web", "profiles"} and all(item.get("complete") is True for item in matches)


def timeline(report):
    events, seen = [], set()
    for section, rows in (report.get("sections") or {}).items():
        if not isinstance(rows, list):
            continue
        for row in rows[:MAX_ITEMS]:
            if not isinstance(row, dict):
                continue
            url = str((row.get("source_url") or row.get("url") or "") if section in {"jobs", "findings"}
                      else (row.get("url") or row.get("source_url") or ""))
            stamp = row.get("snapshot_at") or row.get("timestamp") or row.get("capture_timestamp")
            if not stamp and _hostname(url) == "web.archive.org":
                match = re.search(r"/web/(\d{8,14})", url)
                stamp = match.group(1) if match else ""
            for field, value in (("snapshot", stamp), ("first_seen", row.get("first_seen")),
                                 ("last_seen", row.get("last_seen")), ("observation", row.get("observed_at"))):
                date = _date(value)
                if not date:
                    continue
                ident = _id(field, section + "|" + url + "|" + str(row.get("value", "")) + "|" + date)
                if ident in seen:
                    continue
                seen.add(ident)
                events.append({"id": ident, "event": field, "date": date, "collected_at": report.get("observed_at", ""),
                               "section": section, "source": row.get("source", ""), "url": url,
                               "original_url": row.get("original_url", ""), "archived": _archived(row),
                               "certainty": row.get("certainty") if row.get("certainty") in {"candidate", "interpretation"} else "candidate" if row.get("verification") == "candidate" else "observed",
                               "label": str(row.get("title") or row.get("value") or row.get("email") or url)[:300]})
                if len(events) >= MAX_ITEMS:
                    return sorted(events, key=lambda event: event["date"])
    card = _domain_card(report)
    registration = card.get("registration") or {}
    for field in ("created", "updated", "expires"):
        date = _date(registration.get(field))
        if date:
            events.append({"id": _id("registration", field + "|" + str(card.get("domain", report.get("query"))) + "|" + date),
                "event": "domain_registration_" + field, "date": date, "collected_at": registration.get("checked_at", report.get("observed_at", "")),
                "section": "domain_card", "source": registration.get("source", "RDAP"), "url": registration.get("url", ""),
                "archived": False, "label": "Domain registration " + field + "; not a company founding date"})
    for row in _entities(report).values():
        if row.get("section") != "dns":
            continue
        date = _date(row.get("observed_at"))
        if date:
            events.append({"id": _id("dns_observation", row["id"] + "|" + date), "event": "dns_observation", "date": date,
                "collected_at": date, "section": "dns", "source": row.get("source", "DNS"), "url": row.get("url", ""),
                "archived": False, "label": str(row.get("record_type", "")) + " " + str(row.get("value", ""))})
    return sorted(events[:MAX_ITEMS], key=lambda event: event["date"])


def compare(current, previous):
    now, before = _entities(current), _entities(previous)
    added = [{**now[key], "change": "newly_observed"} for key in sorted(now.keys() - before.keys())]
    missing = [{**before[key], "change": "absent_from_complete_snapshot" if _covered(current, before[key])
                else "not_observed", "coverage_complete": _covered(current, before[key])}
               for key in sorted(before.keys() - now.keys())]
    return {"status": "partial" if any(not row["coverage_complete"] for row in missing) else "compared",
            "previous_observed_at": previous.get("observed_at", ""), "current_observed_at": current.get("observed_at", ""),
            "added": added, "missing": missing, "unchanged_count": len(now.keys() & before.keys()),
            "meaning": "Snapshot observations only. Missing from a bounded or failed collection does not establish deletion; archived contacts are not verified current contacts."}


def enrich(result, outputroot=None):
    current_path = Path(result["report_json"]).resolve()
    root = Path(outputroot).resolve() if outputroot else current_path.parent.parent.parent
    query, kind = str(result.get("query", "")).strip().casefold(), result.get("kind")
    previous = None
    # Normal exports have root/query/run/dossier.json. Search that query's runs
    # newest-first so a busy output tree cannot displace the latest same-target run.
    search_root = current_path.parent.parent if current_path.parent.parent.is_relative_to(root) else root
    paths = []
    if search_root.exists():
        for folder in sorted(search_root.iterdir(), key=lambda entry: entry.name, reverse=True):
            if folder.is_dir() and not folder.is_symlink():
                path = folder / "dossier.json"
                if path.is_file():
                    paths.append(path)
                if len(paths) >= MAX_PREVIOUS:
                    break
        for index, path in enumerate(paths):
            if index >= MAX_PREVIOUS:
                break
            if path.resolve() == current_path or path.is_symlink():
                continue
            try:
                if path.stat().st_size > 15_000_000:
                    continue
                data = json.loads(path.read_text(encoding="utf-8"))
                if (not isinstance(data, dict) or not isinstance(data.get("sections"), dict)
                        or any(not isinstance(value, (list, dict)) for value in data.get("sections", {}).values() if value is not None)
                        or str(data.get("query", "")).strip().casefold() != query or data.get("kind") != kind
                        or str(data.get("observed_at", "")) >= str(result.get("observed_at", ""))):
                    continue
                _entities(data)  # Reject malformed nested legacy snapshots before comparison.
                candidate = (str(data.get("observed_at", "")), str(path), data)
                if previous is None or candidate[:2] > previous[:2]:
                    previous = candidate
            except (OSError, ValueError, AttributeError, TypeError):
                continue
    comparison = compare(result, previous[2]) if previous else {"status": "no_previous_snapshot", "added": [], "missing": []}
    if previous:
        comparison["previous_report"] = previous[1]
    result["history"] = {"schema_version": 1, "timeline": timeline(result), "comparison": comparison,
                         "previous_search_limit": MAX_PREVIOUS, "entity_limit": MAX_ITEMS,
                         "previous_search_limited": len(paths) >= MAX_PREVIOUS,
                         "semantics": "Source snapshot dates differ from collection time; archived evidence does not imply present validity."}
    return result


def get_securitytrails_history(domain, record_types=DNS_TYPES, on_status=None):
    """Optional official history API; account authorization and quota remain provider dependent."""
    from . import domain_recon, net
    domain = domain.strip().lower().rstrip(".")
    if not domain_recon.DOMAIN_RE.fullmatch(domain) or domain.endswith((".local", ".internal", ".test", ".onion")):
        raise ValueError("Expected a public domain")
    if any(kind not in DNS_TYPES for kind in record_types):
        raise ValueError("Unsupported historical DNS type")
    key = domain_recon.configured_keys().get("SECURITY_TRAILS_API_KEY", "")
    found = {"findings": [], "statuses": [], "errors": []}
    def status(name, state, count=0, detail=""):
        item = {"name": name, "state": state, "count": count, "detail": detail}
        found["statuses"].append(item)
        if on_status:
            on_status(item)
    if not key:
        status("SecurityTrails history", "skipped", detail="Missing SECURITY_TRAILS_API_KEY; no request sent")
        return found
    for kind in dict.fromkeys(record_types):
        name = "SecurityTrails history/" + kind
        status(name, "running")
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/{kind}"
        response = net.get(url, params={"page": 1}, retries=0, extra_headers={"APIKEY": key, "Accept": "application/json"})
        data = response.json(log_errors=False)
        if response.status != 200 or not isinstance(data, dict) or not isinstance(data.get("records"), list):
            state = "blocked" if response.status in {401, 403, 429} else "timeout" if response.metadata.get("state") == "timeout" else "error"
            detail = f"HTTP {response.status}" if response.status != 200 else "Malformed history response"
            status(name, state, detail=detail)
            found["errors"].append(name + ": " + detail)
            continue
        records = data["records"][:100]
        for record in records:
            if not isinstance(record, dict):
                continue
            found["findings"].append({"kind": "historical_dns", "title": domain + " " + kind.upper(),
                "record_type": kind.upper(), "value": json.dumps(record.get("values", []), ensure_ascii=False, sort_keys=True)[:4000],
                "first_seen": record.get("first_seen", ""), "last_seen": record.get("last_seen", ""),
                "source": "SecurityTrails history", "url": url, "archived": True,
                "status": "historical provider observation; current validity unverified"})
        status(name, "partial" if records else "empty", len(records),
               "Bounded to the first history page and 100 records; tariff and quota dependent")
    return found
