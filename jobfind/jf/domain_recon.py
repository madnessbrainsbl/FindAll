"""Passive, source-backed domain research. No port scanning or guessed ownership."""

from __future__ import annotations

import base64
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import copy_context
from datetime import datetime, timezone
from pathlib import Path

from . import domains, github_tools, osint
from .osint_contacts import DOMAIN_RE


ROOT = Path(__file__).resolve().parents[1]
KEY_FILE = ROOT / "osint-keys.env"
KEY_NAMES = ("SHODAN_API_KEY", "CENSYS_API_TOKEN", "ZOOMEYE_API_KEY", "SECURITY_TRAILS_API_KEY", "GITHUB_TOKEN", "DNSDUMPSTER_API_KEY")
MAX_SUBDOMAINS = 1000


def configured_keys() -> dict[str, str]:
    keys = {}
    if KEY_FILE.exists():
        for line in KEY_FILE.read_text(encoding="utf-8-sig").splitlines():
            name, sep, value = line.partition("=")
            name = name.strip()
            if sep and name in KEY_NAMES:
                keys[name] = value.strip().strip("\"'")
    return {name: os.environ.get(name, keys.get(name, "")).strip() for name in KEY_NAMES}


def _api(url: str, *, headers: dict | None = None, payload: dict | None = None,
         timeout: int = 20) -> object:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=body,
                                     headers={"User-Agent": "FindAll/1.0", "Accept": "application/json",
                                              **({"Content-Type": "application/json"} if body else {}),
                                              **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(6_000_001)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"network: {getattr(exc, 'reason', exc)}") from None
    if len(raw) > 6_000_000:
        raise RuntimeError("response exceeds 6 MB")
    try:
        return json.loads(raw)
    except ValueError:
        raise RuntimeError("response is not JSON") from None


def _name(value: object, domain: str) -> str:
    name = str(value or "").strip().lower().removeprefix("*.").rstrip(".")
    return name if (name == domain or name.endswith("." + domain)) and DOMAIN_RE.fullmatch(name) else ""


def _public_ips(host: str) -> tuple[list[str], list[dict]]:
    from .domain_enrichment import dns_query
    queries = [dns_query(host, kind) for kind in ("A", "AAAA")]
    addresses = set()
    for query in queries:
        for record in query["records"]:
            try:
                address = ipaddress.ip_address(record["value"])
                if address.is_global:
                    addresses.add(str(address))
            except ValueError:
                continue
    return sorted(addresses), queries


def _status(name: str, state: str, count: int = 0, detail: str = "") -> dict:
    return {"name": name, "state": state, "count": count, "detail": detail[:240]}


class _StatusList(list):
    def __init__(self, on_status):
        super().__init__()
        self.on_status = on_status

    def append(self, status):
        super().append(status)
        if self.on_status:
            self.on_status(status)

    def extend(self, statuses):
        for status in statuses:
            self.append(status)


def investigate(domain: str, output: Path, max_hosts: int = 100, max_ips: int = 10,
                on_status=None) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain) or domain.endswith((".local", ".internal", ".test", ".onion")):
        raise ValueError("Enter a public domain, for example example.org")
    max_hosts = max(1, min(max_hosts, MAX_SUBDOMAINS))
    max_ips = max(1, min(max_ips, 50))
    keys = configured_keys()
    sources: list[dict] = _StatusList(on_status)
    names: dict[str, set[str]] = {}
    assets: list[dict] = []

    def collect(provider: str, getter) -> None:
        try:
            found = getter()
            count = 0
            for candidate in found:
                name = _name(candidate, domain)
                if name and name != domain:
                    names.setdefault(name, set()).add(provider)
                    count += 1
            sources.append(_status(provider, "ok", count))
        except Exception as exc:
            sources.append(_status(provider, "error", detail=str(exc)))

    def certspotter() -> list[str]:
        data = _api("https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode({
            "domain": domain, "include_subdomains": "true", "expand": "dns_names"}))
        if not isinstance(data, list):
            raise RuntimeError("unexpected response")
        return [name for row in data if isinstance(row, dict) for name in row.get("dns_names", [])]

    def crtsh() -> list[str]:
        data = _api("https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"}), timeout=30)
        if not isinstance(data, list):
            raise RuntimeError("unexpected response")
        return [name for row in data if isinstance(row, dict)
                for name in str(row.get("name_value", "")).splitlines()]

    collect("CertSpotter", certspotter)
    collect("crt.sh", crtsh)

    security_key = keys["SECURITY_TRAILS_API_KEY"]
    if security_key:
        def securitytrails() -> list[str]:
            data = _api(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                        headers={"APIKEY": security_key})
            if not isinstance(data, dict) or not isinstance(data.get("subdomains"), list):
                raise RuntimeError("unexpected response")
            return [f"{part}.{domain}" for part in data["subdomains"]]
        collect("SecurityTrails", securitytrails)
    else:
        sources.append(_status("SecurityTrails", "skipped", detail="missing SECURITY_TRAILS_API_KEY"))

    shodan_key = keys["SHODAN_API_KEY"]
    if shodan_key:
        def shodan_dns() -> list[str]:
            found = []
            for page in range(1, 11):
                data = _api(f"https://api.shodan.io/dns/domain/{domain}?" +
                            urllib.parse.urlencode({"key": shodan_key, "page": page}))
                if not isinstance(data, dict) or not isinstance(data.get("subdomains"), list):
                    raise RuntimeError("unexpected response")
                found.extend(f"{part}.{domain}" for part in data["subdomains"])
                if not data.get("more"):
                    break
            else:
                sources.append(_status("Shodan DNS pagination", "skipped", detail="limit: 10 pages"))
            return found
        collect("Shodan DNS", shodan_dns)
    else:
        sources.append(_status("Shodan DNS", "skipped", detail="missing SHODAN_API_KEY"))

    from .domain_enrichment import dnsdumpster
    dumpster_result = dnsdumpster(domain, names)
    for status in dumpster_result["statuses"]:
        sources.append(status)
    for row in dumpster_result["subdomains"]:
        name = _name(row["name"], domain)
        if name and name != domain:
            names.setdefault(name, set()).add("DNSDumpster")
    ordered = [domain, *sorted(names)]
    limited = ordered[:max_hosts]
    resolved, dns_lookups = {}, {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(copy_context().run, _public_ips, host): host for host in limited}
        for future in as_completed(futures):
            host = futures[future]
            try:
                resolved[host], dns_lookups[host] = future.result()
            except (OSError, ValueError, RuntimeError):
                resolved[host], dns_lookups[host] = [], [{"state":"error", "records":[]}]
    subdomains = [{"name": name, "ips": resolved.get(name, []),
                   "sources": sorted(names.get(name, {"entered domain"}))}
                  for name in ordered]
    dns_failed = any(query["state"] in {"error","timeout","blocked","rate_limited"}
                     for queries in dns_lookups.values() for query in queries)
    sources.append(_status("DNS A/AAAA", "partial" if dns_failed and any(resolved.values()) else "error" if dns_failed else "ok", sum(bool(ips) for ips in resolved.values()),
                           f"checked {len(limited)} of {len(ordered)} names"))
    ips = list(dict.fromkeys(ip for host in limited for ip in resolved.get(host, [])))[:max_ips]

    def add_asset(provider: str, ip: str, port: object, product: object, url: str,
                  hostnames: list[str] | None = None, observed_at: object = None) -> None:
        if not ip:
            return
        try:
            if not ipaddress.ip_address(ip).is_global:
                return
        except ValueError:
            return
        assets.append({"provider": provider, "ip": ip, "port": str(port or ""),
                       "product": str(product or "")[:140], "url": url,
                       "hostnames": [str(h) for h in (hostnames or [])][:20],
                       "checked_at": datetime.now(timezone.utc).isoformat(),
                       "observed_at": str(observed_at)[:100] if observed_at else None,
                       "certainty": "candidate", "limits": "Indexed IP services may be stale or shared; domain ownership is unverified."})

    count, missing, errors = 0, 0, []
    for ip in ips:
        try:
            data = _api(f"https://internetdb.shodan.io/{ip}")
            if not isinstance(data, dict) or not isinstance(data.get("ports"), list):
                raise RuntimeError("unexpected response")
            for port in data["ports"]:
                add_asset("Shodan InternetDB", ip, port, ", ".join((data.get("cpes") or [])[:3]),
                          f"https://internetdb.shodan.io/{ip}", data.get("hostnames", []))
                count += 1
        except RuntimeError as exc:
            if str(exc) == "HTTP 404":
                missing += 1
            else:
                errors.append(f"{ip}: {exc}")
    sources.append(_status("Shodan InternetDB", "skipped" if not ips else "partial" if errors and count else "error" if errors else "ok", count,
                           "no public IPs" if not ips else "; ".join(errors[:3]) if errors else
                           f"checked {len(ips)} IPs; no data for {missing}; snapshot updates weekly"))

    if shodan_key and ips:
        count, errors = 0, []
        for ip in ips:
            try:
                data = _api(f"https://api.shodan.io/shodan/host/{ip}?" +
                            urllib.parse.urlencode({"key": shodan_key, "minify": "true"}))
                if not isinstance(data, dict) or not isinstance(data.get("ports"), list):
                    raise RuntimeError("unexpected response")
                for port in data.get("ports", []):
                    add_asset("Shodan", ip, port, data.get("org") or data.get("isp"),
                              f"https://www.shodan.io/host/{ip}", data.get("hostnames"), data.get("last_update"))
                    count += 1
            except Exception as exc:
                errors.append(f"{ip}: {exc}")
        sources.append(_status("Shodan hosts", "partial" if errors and count else "error" if errors else "ok", count,
                               "; ".join(errors[:3]) if errors else f"checked {len(ips)} IPs"))
    else:
        sources.append(_status("Shodan hosts", "skipped", detail="no public IPs" if not ips else "missing SHODAN_API_KEY"))

    censys_key = keys["CENSYS_API_TOKEN"]
    if censys_key and ips:
        count, errors = 0, []
        for ip in ips:
            try:
                data = _api(f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                            headers={"Authorization": f"Bearer {censys_key}",
                                     "Accept": "application/vnd.censys.api.v3.host.v1+json"})
                resource = data.get("result", {}).get("resource") if isinstance(data, dict) else None
                if not isinstance(resource, dict):
                    raise RuntimeError("unexpected response")
                for service in resource.get("services", []):
                    if not isinstance(service, dict):
                        continue
                    add_asset("Censys", ip, service.get("port"), service.get("protocol"),
                              f"https://search.censys.io/hosts/{ip}", observed_at=service.get("observed_at") or resource.get("last_updated_at"))
                    count += 1
            except Exception as exc:
                errors.append(f"{ip}: {exc}")
        sources.append(_status("Censys", "partial" if errors and count else "error" if errors else "ok", count,
                               "; ".join(errors[:3]) if errors else f"checked {len(ips)} IPs"))
    else:
        sources.append(_status("Censys", "skipped", detail="no public IPs" if not ips else "missing CENSYS_API_TOKEN"))

    zoomeye_key = keys["ZOOMEYE_API_KEY"]
    if zoomeye_key:
        try:
            query = base64.b64encode(f'domain="{domain}"'.encode()).decode()
            data = _api("https://api.zoomeye.org/v2/search", headers={"API-KEY": zoomeye_key},
                        payload={"qbase64": query, "page": 1, "pagesize": 30,
                                 "fields": "ip,port,domain,hostname,service,product,url"})
            if not isinstance(data, dict) or data.get("code") != 60000 or not isinstance(data.get("data"), list):
                raise RuntimeError(str(data.get("message", "unexpected response"))[:120] if isinstance(data, dict) else "unexpected response")
            before = len(assets)
            for row in data["data"]:
                if isinstance(row, dict) and _name(row.get("domain"), domain):
                    add_asset("ZoomEye", str(row.get("ip", "")), row.get("port"),
                              row.get("product") or row.get("service"),
                              f"https://www.zoomeye.org/searchResult?q={urllib.parse.quote(domain)}",
                              [row.get("domain", "")])
            detail = f"page 1; total in response {data.get('total', '?')}"
            sources.append(_status("ZoomEye", "ok", len(assets) - before, detail))
        except Exception as exc:
            sources.append(_status("ZoomEye", "error", detail=str(exc)))
    else:
        sources.append(_status("ZoomEye", "skipped", detail="missing ZOOMEYE_API_KEY"))

    try:
        dns = domains.domain_report(domain)
        sources.append(_status("DNS/RDAP", "ok", detail="MX, SPF, DMARC, domain age"))
    except Exception as exc:
        dns = {}
        sources.append(_status("DNS/RDAP", "error", detail=str(exc)))

    try:
        web, _, web_status = osint.search(f"site:{domain}", list(osint.ENGINES))
        web = [row for row in web if (host := urllib.parse.urlsplit(row["url"]).hostname) and
               (host == domain or host.endswith("." + domain))]
        sources.extend(_status(f"Search {row['source']}", "error" if row["error"] else "ok",
                               row["count"], row["error"]) for row in web_status)
    except Exception as exc:
        web = []
        sources.append(_status("Web search", "error", detail=str(exc)))

    technologies: list[dict] = list(dumpster_result["technologies"])
    try:
        query = urllib.parse.urlencode({"url": f"https://{domain}"})
        with github_tools.web_check_api(output) as endpoint:
            data = _api(f"{endpoint}/tech-stack?{query}", timeout=45)
        if not isinstance(data, dict):
            raise RuntimeError("unexpected response")
        if data.get("error") or data.get("skipped"):
            raise RuntimeError(str(data.get("error") or data.get("skipped"))[:150])
        technologies.extend({"name": str(row.get("name") or ""), "version": str(row.get("version") or ""),
                         "confidence": int(row.get("confidence") or 0), "source": "Wappalyzer / Web-Check",
                         "url": f"https://{domain}/", "checked_at": datetime.now(timezone.utc).isoformat(),
                         "certainty": "candidate"}
                        for row in data.get("technologies", []) if isinstance(row, dict))
        sources.append(_status("Wappalyzer / Web-Check", "ok", len(technologies)))
    except Exception as exc:
        sources.append(_status("Wappalyzer / Web-Check", "error", detail=str(exc)))

    try:
        from .additional_tools import _run
        code, text = _run([sys.executable, '-c',
            'import json,sys; from jf.osint_contacts import parse_public_page; '
            'print(json.dumps(parse_public_page(sys.argv[1]),ensure_ascii=False))',
            f'https://{domain}/'], ROOT, 40)
        if code == 124:
            raise TimeoutError('Homepage parsing stopped after 40 seconds; earlier domain observations retained')
        if code:
            raise RuntimeError('Homepage could not be parsed; earlier domain observations retained')
        page = json.loads(text)
        script_sources = page["scripts"][:50]
        sources.append(_status("HTML / JS", "ok", len(script_sources), page["url"]))
    except Exception as exc:
        script_sources = []
        sources.append(_status("HTML / JS", "timeout" if isinstance(exc, TimeoutError) else "error", detail=str(exc)))

    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report = output / f"domain_{domain}_{stamp}.json"
    csv_file = output / f"domain_{domain}_{stamp}.csv"
    result = {"domain": domain, "generated_at": datetime.now(timezone.utc).isoformat(),
              "status": "partial" if any(row["state"] not in {"ok","empty"} for row in sources) else "ok",
              "dns": dns, "domain_card": dns, "dns_lookups": dns_lookups, "subdomains": subdomains, "assets": assets, "web_results": web,
              "indexed_findings": dumpster_result["findings"],
              "technologies": technologies, "script_sources": script_sources,
              "statuses": sources, "truncated": len(ordered) > max_hosts,
              "ip_lookup_limit": max_ips, "report": str(report), "csv": str(csv_file)}
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    with csv_file.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["name", "ips", "sources"])
        writer.writeheader()
        writer.writerows({"name": row["name"], "ips": ", ".join(row["ips"]),
                          "sources": ", ".join(row["sources"])} for row in subdomains)
    return result


if __name__ == "__main__":
    assert _name("*.api.example.com", "example.com") == "api.example.com"
    assert not _name("example.com.attacker.org", "example.com")
