"""Structured current DNS, registration and passive indexed infrastructure evidence."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

from . import net

DOH = "https://cloudflare-dns.com/dns-query"
DOH_PROVIDERS = [
    ("Cloudflare DoH", "https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
    ("Google DoH", "https://dns.google/resolve", {"Accept": "application/json"}),
]
RDAP = "https://rdap.org/domain/"
DNSDUMPSTER = "https://api.dnsdumpster.com/domain/"
TYPES = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "NS": 2, "CNAME": 5,
         "SOA": 6, "SRV": 33, "CAA": 257}
_dumpster_lock = threading.Lock()
_dumpster_next = 0.0


def _items(value, limit: int = 200) -> list:
    return value[:limit] if isinstance(value, list) else []


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _domain(value: str) -> str:
    value = value.strip().lower().rstrip(".").encode("idna").decode("ascii")
    if (len(value) > 253 or "." not in value or
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or
            any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                for label in value.split(".")) or
            value.endswith((".local", ".internal", ".test", ".onion"))):
        raise ValueError("Enter a public domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Use a domain, not an IP address")


def _transport_state(response) -> str:
    if response.status == 429:
        return "rate_limited"
    if response.status in (401, 403):
        return "blocked"
    if "timeout" in response.error.lower() or "timed out" in response.error.lower():
        return "timeout"
    return "error"


def dns_query(name: str, record_type: str) -> dict:
    """DoH preserves DNS RCODE and transport failures separately.
    Includes automatic fallback to Google DoH if primary provider is blocked or fails."""
    primary_source = DOH + "?" + urllib.parse.urlencode({"name": name, "type": record_type})
    row = {"type": record_type, "name": name, "records": [], "state": "error",
           "source": "Cloudflare DoH", "url": primary_source, "checked_at": now()}
    last_transport_state = None
    last_http_status = 0

    for provider_name, url, headers in DOH_PROVIDERS:
        source_url = url + "?" + urllib.parse.urlencode({"name": name, "type": record_type})
        row["source"] = provider_name
        row["url"] = source_url
        response = net.get(url, {"name": name, "type": record_type}, retries=0,
                           extra_headers=headers, timeout=8)
        if response.error or not 200 <= response.status < 300:
            last_transport_state = _transport_state(response)
            last_http_status = response.status
            continue
        data = response.json(log_errors=False)
        if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
            row["detail"] = "Invalid DNS JSON response"
            return row
        row["rcode"] = data["Status"]
        if data["Status"] == 3:
            row["state"] = "nxdomain"
            return row
        if data["Status"] != 0:
            row["detail"] = "DNS response code " + str(data["Status"])
            return row
        if "Answer" in data and not isinstance(data["Answer"], list):
            row["detail"] = "Invalid DNS answer section"
            return row
        number = 12 if record_type == "PTR" else TYPES.get(record_type, 16)
        seen = set()
        for answer in _items(data.get("Answer")):
            if not isinstance(answer, dict) or answer.get("type") != number:
                continue
            value = str(answer.get("data", ""))[:4000].strip()
            if not value or value in seen:
                continue
            seen.add(value)
            row["records"].append({"value": value, "ttl": answer.get("TTL"),
                                   "name": str(answer.get("name", name))[:253]})
        row["state"] = "success" if row["records"] else "no_records"
        return row

    if last_transport_state:
        row.update(state="timeout" if last_transport_state == "timeout" else "error",
                   detail="DNS transport " + last_transport_state, http_status=last_http_status)
    return row


def _web_data(webcheck: dict | None) -> dict:
    if not isinstance(webcheck, dict):
        return {}
    data = webcheck.get("data", webcheck)
    return data if isinstance(data, dict) else {}


def _web_dns(name: str, kind: str, payload: dict, stamp: str) -> dict | None:
    """Legacy Web-Check catches DNS failures as []; only reuse actual records."""
    values = payload.get(kind)
    if values is None or values == [] or values == {}:
        return None
    values = values if isinstance(values, list) else [values]
    records = []
    for value in values[:200]:
        if kind == "TXT" and isinstance(value, list):
            value = "".join(str(part) for part in value)
        elif isinstance(value, dict):
            if kind == "MX":
                value = f"{value.get('priority', '')} {value.get('exchange', '')}".strip()
            else:
                value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if value:
            records.append({"value": str(value)[:4000], "ttl": None, "name": name})
    if not records:
        return None
    return {"type": kind, "name": name, "records": records, "state": "success",
            "source": "Web-Check DNS", "url": "https://" + name + "/",
            "checked_at": stamp, "method": "reused collected records"}


def registration(domain: str, existing: dict | None = None, checked_at: str = "") -> dict:
    row = {"state": "error", "created": None, "updated": None, "expires": None,
           "age_years": None, "registrar": None, "redacted": False,
           "source": "RDAP", "url": RDAP + domain, "checked_at": checked_at or now(),
           "limits": "Registration date is not the founding date of a company; redacted contacts do not identify an owner."}
    if isinstance(existing, dict) and not existing.get("error") and not existing.get("skipped") and (
            existing.get("created") or existing.get("registrar") or existing.get("events")):
        data = existing
        row["source"] = "Web-Check WHOIS/RDAP"
        row["method"] = "reused collected registration"
    else:
        response = net.get(RDAP + domain, retries=0, extra_headers={"Accept": "application/rdap+json"})
        if response.status == 404:
            row["state"] = "no_records"
            return row
        if response.error or not 200 <= response.status < 300:
            row.update(state=_transport_state(response), detail="Registration transport " + _transport_state(response))
            return row
        row["url"] = response.url
        data = response.json(log_errors=False)
    if not isinstance(data, dict) or data.get("errorCode"):
        row["detail"] = "Invalid registration response"
        return row
    row.update(state="success", created=data.get("created"), updated=data.get("updated"),
               expires=data.get("expires"), registrar=data.get("registrar"))
    actions = {"registration": "created", "last changed": "updated", "expiration": "expires"}
    for event in _items(data.get("events"), 100):
        if isinstance(event, dict) and event.get("eventAction") in actions:
            row[actions[event["eventAction"]]] = event.get("eventDate")
    for entity in _items(data.get("entities"), 100):
        if not isinstance(entity, dict) or "registrar" not in entity.get("roles", []):
            continue
        card = entity.get("vcardArray", [])
        if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
            row["registrar"] = next((item[3] for item in card[1] if isinstance(item, list) and len(item) > 3 and item[0] == "fn"), None)
    # RFC 9537 redacted metadata or notices; no inference of private contact data.
    row["redacted"] = bool(data.get("redacted")) or "redact" in json.dumps(data.get("notices", []), ensure_ascii=False).lower()
    row["domain_status"] = [str(item)[:100] for item in _items(data.get("status"), 20)]
    try:
        created = dt.datetime.fromisoformat(str(row["created"]).replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=dt.timezone.utc)
        age = (dt.datetime.now(dt.timezone.utc) - created).days / 365.25
        row["age_years"] = round(age, 1) if age >= 0 else None
    except (ValueError, TypeError):
        pass
    return row


def domain_card(domain: str, webcheck: dict | None = None, existing_card: dict | None = None) -> dict:
    domain = _domain(domain)
    data = _web_data(webcheck)
    stamp = str((webcheck or {}).get("checked_at") or (webcheck or {}).get("generated_at") or now())
    dns = data.get("dns", {}) if isinstance(data.get("dns"), dict) else {}
    records = {}
    missing = []
    for kind in TYPES:
        existing = (existing_card or {}).get("records", {}).get(kind)
        reused = existing if isinstance(existing, dict) and existing.get("state") in ("success", "no_records", "nxdomain") and isinstance(existing.get("records"), list) else _web_dns(domain, kind, dns, stamp)
        if reused:
            records[kind] = reused
        else:
            missing.append(kind)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {kind: pool.submit(copy_context().run, dns_query, domain, kind) for kind in missing}
        for kind, future in futures.items():
            records[kind] = future.result()
    addresses = []
    for kind in ("A", "AAAA"):
        for item in records[kind]["records"]:
            try:
                address = str(ipaddress.ip_address(item["value"]))
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
    reverse = list((existing_card or {}).get("records", {}).get("PTR", {}).get("queries", []))
    for address in addresses[:4]:
        # Correct in-addr.arpa/ip6.arpa name; PTR of domain itself is not reverse DNS.
        if ipaddress.ip_address(address).is_global and not any(entry.get("address") == address for entry in reverse):
            entry = dns_query(ipaddress.ip_address(address).reverse_pointer, "PTR")
            entry["address"] = address
            reverse.append(entry)
    records["PTR"] = {"type": "PTR", "queries": reverse, "records": [item for query in reverse for item in query["records"]],
                      "state": "success" if any(query["records"] for query in reverse) else
                      "error" if any(query["state"] == "error" for query in reverse) else
                      "timeout" if any(query["state"] == "timeout" for query in reverse) else "no_records",
                      "detail": "Reverse lookups require resolved public addresses; up to four checked.", "checked_at": now()}
    mx_values = [item["value"] for item in records["MX"]["records"]]
    null_mx = any(re.fullmatch(r"0\s+\.", value) for value in mx_values)
    mx = [value.rstrip(".") for value in mx_values if not re.fullmatch(r"0\s+\.", value)]
    txt = [item["value"].strip('"') for item in records["TXT"]["records"]]
    dmarc = (existing_card or {}).get("records", {}).get("DMARC") or dns_query("_dmarc." + domain, "TXT")
    records["DMARC"] = dmarc
    old_registration = (existing_card or {}).get("registration")
    registered = old_registration if isinstance(old_registration, dict) and old_registration.get("state") in ("success", "no_records") else registration(domain, data.get("whois"), stamp)
    return {"domain": domain, "checked_at": now(), "records": records, "registration": registered,
            "addresses": addresses, "mx": mx, "null_mx": null_mx,
            "spf": [value for value in txt if value.lower().startswith("v=spf1")],
            "dmarc": [item["value"].strip('"') for item in dmarc["records"] if item["value"].strip('"').lower().startswith("v=dmarc1")],
            "age_years": registered["age_years"], "alive": any(records[kind]["state"] in ("success", "no_records") for kind in ("A", "AAAA")),
            "email_plausible": bool(mx) and not null_mx,
            "limits": "DNS and registration are observations, not proof of domain ownership or mail delivery. DoH uses the configured HTTP route; external Web-Check/system DNS has a separate resolver path."}


def _key() -> str:
    from .domain_recon import configured_keys
    return configured_keys().get("DNSDUMPSTER_API_KEY", "")


def dnsdumpster(domain: str, known_hosts=()) -> dict:
    domain = _domain(domain)
    stamp = now()
    url = DNSDUMPSTER + domain
    status = {"name": "DNSDumpster", "state": "missing_key", "count": 0,
              "url": url, "checked_at": stamp, "detail": "Set DNSDUMPSTER_API_KEY to use the official API."}
    result = {"subdomains": [], "findings": [], "technologies": [], "statuses": [status], "errors": []}
    key = _key()
    if not key:
        return result
    global _dumpster_next
    # One request, no automatic retries that might violate the provider's 2s limit.
    with _dumpster_lock:
        delay = max(0.0, _dumpster_next - time.monotonic())
        if delay:
            time.sleep(delay)
        _dumpster_next = time.monotonic() + 2.0
        response = net.get(url, retries=0, extra_headers={"X-API-Key": key})
    if response.error or not 200 <= response.status < 300:
        status.update(state=_transport_state(response), detail="DNSDumpster HTTP " + str(response.status), http_status=response.status)
        result["errors"].append(status["detail"])
        return result
    data = response.json(log_errors=False)
    if not isinstance(data, dict) or data.get("error") or not isinstance(data.get("a"), list):
        status.update(state="error", detail="Invalid DNSDumpster response")
        result["errors"].append(status["detail"])
        return result
    known = {str(item).lower().rstrip(".") for item in known_hosts}
    seen = set()
    for item in _items(data["a"]):
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).lower().rstrip(".").removeprefix("*.")
        if host in seen or not (host == domain or host.endswith("." + domain)):
            continue
        try:
            _domain(host)
        except ValueError:
            continue
        seen.add(host)
        ips = []
        for ip in _items(item.get("ips"), 20):
            if not isinstance(ip, dict):
                continue
            try:
                address = ipaddress.ip_address(str(ip.get("ip", "")))
            except ValueError:
                continue
            if not address.is_global:
                continue
            ips.append(str(address))
            evidence = {"title": host + " · indexed infrastructure", "snippet": "IP " + str(address) + "; ASN " + str(ip.get("asn", ""))[:30] + "; " + str(ip.get("asn_name", ""))[:250],
                        "url": url, "source": "DNSDumpster", "checked_at": stamp, "observed_at": None,
                        "category": "Indexed infrastructure", "host": host, "ip": str(address),
                        "asn": str(ip.get("asn", ""))[:30], "asn_name": str(ip.get("asn_name", ""))[:250],
                        "netblock": str(ip.get("asn_range", ""))[:100], "certainty": "candidate",
                        "limits": "Indexed observation; provider observation time unavailable. Shared hosting does not prove ownership."}
            if len(result["findings"]) < 1000:
                result["findings"].append(evidence)
            banners = ip.get("banners", {})
            if isinstance(banners, dict):
                for scheme in ("http", "https"):
                    banner = banners.get(scheme, {})
                    if not isinstance(banner, dict):
                        continue
                    for app in _items(banner.get("apps"), 20):
                        if len(result["technologies"]) < 200 and not any(row["name"] == str(app)[:150] and row["host"] == host for row in result["technologies"]):
                            result["technologies"].append({"name": str(app)[:150], "version": "", "host": host,
                                "source": "DNSDumpster indexed banner", "url": url, "checked_at": stamp, "observed_at": None, "certainty": "candidate"})
        result["subdomains"].append({"name": host, "ips": list(dict.fromkeys(ips)), "sources": ["DNSDumpster"],
                                       "url": url, "checked_at": stamp, "observed_at": None, "unique_to_source": host not in known})
    # MX/NS may legitimately point outside the requested domain. Keep these as
    # external DNS references, never as owned subdomains.
    for record_type in ("mx", "ns", "cname", "txt"):
        for row in _items(data.get(record_type), 100):
            value = row.get("host") if isinstance(row, dict) else row if isinstance(row, str) else None
            if not value or len(result["findings"]) >= 1000:
                continue
            result["findings"].append({"title": domain + " · indexed " + record_type.upper(),
                "snippet": str(value)[:4000], "record_type": record_type.upper(), "source": "DNSDumpster",
                "url": url, "checked_at": stamp, "observed_at": None, "category": "Indexed DNS reference",
                "certainty": "candidate", "limits": "Historical index observation; external mail/nameserver references are not owned assets."})
    try:
        total = int(data.get("total_a_recs") or 0)
    except (TypeError, ValueError):
        total = len(seen)
    status.update(state="success" if seen else "no_records", count=len(seen),
                  unique_count=sum(row["unique_to_source"] for row in result["subdomains"]),
                  detail="First API page only; account result limits apply. Provider observation time unavailable.",
                  truncated=total > len(seen))
    return result


def collect(domain: str, *, webcheck: dict | None = None, include_dnsdumpster: bool = True, known_hosts=(), existing_card: dict | None = None) -> dict:
    card = domain_card(domain, webcheck, existing_card)
    result = {"domain_card": card, "findings": [], "statuses": [], "errors": [], "technologies": [], "subdomains": []}
    for kind, entry in card["records"].items():
        result["statuses"].append({"name": "DNS " + kind, "state": entry["state"], "count": len(entry["records"]),
            "checked_at": entry["checked_at"], "url": entry.get("url", ""), "detail": entry.get("detail", "")})
        if entry["state"] in ("error", "timeout"):
            result["errors"].append("DNS " + kind + ": " + entry["state"])
        for item in entry["records"]:
            result["findings"].append({"title": card["domain"] + " · " + kind, "snippet": item["value"],
                "record_type": kind, "url": entry.get("url", DOH), "source": entry.get("source", "Cloudflare DoH"),
                "category": "DNS record", "checked_at": entry["checked_at"], "certainty": "observed"})
    registration_row = card["registration"]
    result["statuses"].append({"name": "Domain registration", "state": registration_row["state"],
        "count": int(registration_row["state"] == "success"), "checked_at": registration_row["checked_at"], "url": registration_row["url"]})
    if registration_row["state"] in ("error", "timeout", "blocked", "rate_limited"):
        result["errors"].append("Domain registration: " + registration_row["state"])
    if registration_row["state"] == "success":
        result["findings"].append({"title": card["domain"] + " · domain registration", "snippet": json.dumps({key: registration_row[key] for key in ("created", "updated", "expires", "registrar", "redacted")}, ensure_ascii=False),
            "source": registration_row["source"], "url": registration_row["url"], "category": "Domain registration", "checked_at": registration_row["checked_at"], "certainty": "observed"})
    tech = _web_data(webcheck).get("tech-stack", {})
    if isinstance(tech, dict):
        for row in _items(tech.get("technologies"), 100):
            if isinstance(row, dict) and row.get("name"):
                result["technologies"].append({"name": str(row["name"])[:150], "version": str(row.get("version") or "")[:100],
                    "source": "Wappalyzer / Web-Check", "url": "https://" + card["domain"] + "/", "checked_at": card["checked_at"],
                    "confidence": row.get("confidence"), "certainty": "candidate"})
    if include_dnsdumpster:
        extra = dnsdumpster(card["domain"], known_hosts)
        for key in ("findings", "statuses", "errors", "technologies", "subdomains"):
            result[key].extend(extra[key])
    return result
