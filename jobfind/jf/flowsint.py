"""Typed, bounded enrichment flows adapted from Flowsint's investigation model.

Reference: reconurge/flowsint, Apache-2.0, commit 4c05849bc6ca5055ad187d056ef26e61b3bc2fea.
FindAll implementation: no Neo4j/Celery, executable templates or arbitrary URLs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import re
import time
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl

from . import diagnostics, domain_enrichment, osint_contacts, net

UPSTREAM = "https://github.com/reconurge/flowsint"
COMMIT = "4c05849bc6ca5055ad187d056ef26e61b3bc2fea"
KINDS = ("Domain", "IP", "ASN", "CIDR", "Website", "Email", "WebTracker")


def entity(kind: str, value: str) -> dict:
    if kind not in KINDS or not isinstance(value, str) or len(value) > 1800:
        raise ValueError("Unsupported entity type or value")
    value = value.strip()
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("Control characters are not allowed")
    if kind == "Domain":
        value = value.lower().rstrip(".").encode("idna").decode("ascii")
        if (len(value) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value)
                or value.endswith((".localhost", ".local", ".internal"))):
            raise ValueError("Enter a public domain name")
    elif kind == "IP":
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("Only public IP addresses are supported")
        value = str(address)
    elif kind == "CIDR":
        network = ipaddress.ip_network(value, strict=False)
        if not network.network_address.is_global or not network.broadcast_address.is_global:
            raise ValueError("Only public CIDR ranges are supported")
        value = str(network)
    elif kind == "ASN":
        if not re.fullmatch(r"(?:AS)?[0-9]{1,10}", value, re.I):
            raise ValueError("Enter an ASN such as AS13335")
        number = int(value.upper().removeprefix("AS"))
        if not 1 <= number <= 4294967295:
            raise ValueError("ASN is outside the supported range")
        value = f"AS{number}"
    elif kind == "Email":
        if not re.fullmatch(r"[^\s@]{1,64}@[^\s@]+", value):
            raise ValueError("Enter an email address")
        local, host = value.rsplit("@", 1)
        value = local + "@" + entity("Domain", host)["value"]
    elif kind == "Website":
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or parsed.port not in (None, 443) or not parsed.hostname
                or parsed.username or parsed.password or "\\" in value):
            raise ValueError("Enter a public HTTPS website without credentials")
        host = entity("Domain", parsed.hostname)["value"]
        if any(re.search(r"key|token|secret|password|auth", key, re.I)
               for key, _ in parse_qsl(parsed.query)):
            raise ValueError("Sensitive URL parameters are not accepted")
        value = urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))
    elif not re.fullmatch(r"(?:GTM-[A-Z0-9]+|G-[A-Z0-9]+|UA-[0-9]+-[0-9]+|ym:[0-9]+)", value):
        raise ValueError("Unsupported tracker identifier")
    return {"kind": kind, "value": value}


@dataclass(frozen=True)
class Enricher:
    input_kind: str
    output_kind: str
    title: str
    network: bool = False


ENRICHERS = {
    "domain_root": Enricher("Domain", "Domain", "Registrable domain (PSL)"),
    "domain_website": Enricher("Domain", "Website", "HTTPS URL (syntax)"),
    "website_domain": Enricher("Website", "Domain", "URL hostname (syntax)"),
    "email_domain": Enricher("Email", "Domain", "Email domain (syntax)"),
    "domain_dns": Enricher("Domain", "IP", "DNS A / AAAA", True),
    "ip_asn": Enricher("IP", "ASN", "RIPE routing ASN", True),
    "asn_prefixes": Enricher("ASN", "CIDR", "RIPE announced prefixes", True),
    "cidr_addresses": Enricher("CIDR", "IP", "Bounded address sample (no scanning)"),
    "website_links": Enricher("Website", "Website", "Published page links", True),
    "website_trackers": Enricher("Website", "WebTracker", "Published tracking identifiers", True),
}


def _flow(name, kind, steps):
    return {"schema_version": 1, "name": name, "input_kind": kind,
            "steps": [{"id": ident, "enricher": enricher, "from": previous}
                      for ident, enricher, previous in steps]}


FLOWS = {
    "domain-network": _flow("Domain → DNS → ASN → prefixes", "Domain", [
        ("root", "domain_root", "seed"), ("dns", "domain_dns", "seed"),
        ("asn", "ip_asn", "dns"), ("prefixes", "asn_prefixes", "asn")]),
    "ip-network": _flow("IP → ASN → prefixes", "IP", [
        ("asn", "ip_asn", "seed"), ("prefixes", "asn_prefixes", "asn")]),
    "asn-network": _flow("ASN → announced prefixes", "ASN", [("prefixes", "asn_prefixes", "seed")]),
    "website-evidence": _flow("Website → links, trackers, root domain", "Website", [
        ("links", "website_links", "seed"), ("trackers", "website_trackers", "seed"),
        ("domain", "website_domain", "seed"), ("root", "domain_root", "domain")]),
    "email-domain": _flow("Email → domain → registrable domain", "Email", [
        ("domain", "email_domain", "seed"), ("root", "domain_root", "domain")]),
    "cidr-sample": _flow("CIDR → bounded address sample (offline)", "CIDR", [("addresses", "cidr_addresses", "seed")]),
}


def validate_flow(data: dict) -> dict:
    """Validate all branches before any request; templates cannot execute code."""
    if (not isinstance(data, dict) or set(data) - {"schema_version", "name", "input_kind", "steps"}
            or data.get("schema_version") != 1 or data.get("input_kind") not in KINDS
            or not isinstance(data.get("name"), str) or not 1 <= len(data["name"]) <= 120):
        raise ValueError("Invalid enrichment flow")
    steps = data.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
        raise ValueError("A flow requires 1–8 steps")
    pending, types = [], {"seed": data["input_kind"]}
    ids = {"seed"}
    for step in steps:
        if (not isinstance(step, dict) or set(step) != {"id", "enricher", "from"}
                or not isinstance(step["id"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", step["id"])
                or step["id"] in ids or not isinstance(step["enricher"], str)
                or step["enricher"] not in ENRICHERS or not isinstance(step["from"], str)):
            raise ValueError("Invalid, duplicate or unknown flow step")
        ids.add(step["id"])
        pending.append(dict(step))
    ordered = []
    while pending:
        ready = [step for step in pending if step["from"] in types]
        if not ready:
            raise ValueError("Flow has a cycle or a missing input step")
        for step in ready:
            spec = ENRICHERS[step["enricher"]]
            if types[step["from"]] != spec.input_kind:
                raise ValueError("Flow connects incompatible entity types")
            types[step["id"]] = spec.output_kind
            ordered.append(step)
            pending.remove(step)
    return {**data, "steps": ordered}


def load_flow(path: Path) -> dict:
    if path.stat().st_size > 64_000:
        raise ValueError("Flow file exceeds 64 KB")
    return validate_flow(json.loads(path.read_text(encoding="utf-8-sig")))


class SourceError(RuntimeError):
    def __init__(self, state: str, message: str):
        self.state = state
        super().__init__(message)


def _ripe(endpoint: str, resource: str) -> tuple[dict, str]:
    url = f"https://stat.ripe.net/data/{endpoint}/data.json?" + urlencode({"resource": resource})
    response = net.get(url, extra_headers={"Accept": "application/json"}, timeout=12, max_bytes=2_000_000)
    if response.status != 200:
        state = domain_enrichment._transport_state(response)
        if state == "rate_limited":
            state = "blocked"
        raise SourceError(state, f"RIPE Stat returned HTTP {response.status}")
    try:
        payload = json.loads(response.text)
        if not isinstance(payload, dict) or payload.get("status") != "ok" or not isinstance(payload.get("data"), dict):
            raise ValueError()
    except ValueError:
        raise SourceError("error", "RIPE Stat returned an invalid response") from None
    return payload["data"], url


def _relation(item, kind, value, relation, source, url="", **extra):
    return {"input": item, "output": entity(kind, value), "relation": relation,
            "source": source, "url": url, "certainty": "observed", **extra}


def enrich(name: str, item: dict, limit: int, cache: dict) -> tuple[list[dict], list[dict]]:
    value = item["value"]
    source = "Local syntax"
    if name == "domain_root":
        import tldextract
        root = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)(value).top_domain_under_public_suffix
        if not root:
            raise SourceError("empty", "No registrable domain in the bundled public suffix list")
        return [_relation(item, "Domain", root, "RegistrableDomain", "Bundled public suffix list")], []
    if name == "domain_website":
        return [_relation(item, "Website", f"https://{value}/", "DerivedHttpsUrl", source,
                          attribution="Constructed URL; site availability unverified")], []
    if name in {"website_domain", "email_domain"}:
        host = urlsplit(value).hostname if name == "website_domain" else value.rsplit("@", 1)[1]
        return [_relation(item, "Domain", host, "UrlHost" if name == "website_domain" else "MailboxDomain", source)], []
    if name == "cidr_addresses":
        network = ipaddress.ip_network(value)
        rows = [_relation(item, "IP", str(address), "AddressInRange", "Local CIDR arithmetic",
                          attribution="Mathematical address sample; activity and ownership unverified")
                for address in itertools.islice(network.hosts(), limit)]
        return rows, ([{"state": "partial", "detail": "Address range exceeds the bounded sample"}]
                      if network.num_addresses > len(rows) + (2 if network.version == 4 and network.prefixlen < 31 else 0) else [])
    if name == "domain_dns":
        rows, checks = [], []
        for record in ("A", "AAAA"):
            result = domain_enrichment.dns_query(value, record)
            state = result["state"]
            checks.append({"state": "ok" if state == "success" else "empty" if state in {"no_records", "nxdomain"} else state,
                           "source": f"DNS {record}", "detail": result.get("detail", ""), "count": len(result.get("records") or [])})
            for record_row in result.get("records") or []:
                address = record_row.get("value", "") if isinstance(record_row, dict) else str(record_row)
                try:
                    rows.append(_relation(item, "IP", address, "ResolvesTo", result.get("source", "DNS"), result.get("url", ""),
                                          attribution="DNS answer at collection time; equipment ownership unverified"))
                except ValueError:
                    continue
        if len(rows) > limit:
            checks.append({"state": "partial", "detail": "DNS answers exceed the result limit"})
        return rows[:limit], checks
    if name in {"ip_asn", "asn_prefixes"}:
        data, url = _ripe("network-info" if name == "ip_asn" else "announced-prefixes", value)
        values = data.get("asns") if name == "ip_asn" else data.get("prefixes")
        if not isinstance(values, list):
            raise SourceError("error", "RIPE Stat response is missing the expected list")
        rows = []
        for result in values:
            try:
                target = str(result) if name == "ip_asn" else result["prefix"]
                metadata = {key: str(data[key])[:80] for key in ("query_starttime", "query_endtime", "latest_time", "earliest_time")
                            if data.get(key) is not None}
                if name == "asn_prefixes":
                    periods = result.get("timelines") or []
                    metadata["visible_periods"] = [{key: str(period[key])[:80] for key in ("starttime", "endtime") if key in period}
                                                   for period in periods[:10] if isinstance(period, dict)]
                    metadata["visible_periods_omitted"] = max(0, len(periods) - 10)
                else:
                    metadata["matched_prefix"] = str(data.get("prefix") or "")[:80]
                rows.append(_relation(item, "ASN" if name == "ip_asn" else "CIDR", target,
                    "RoutingASN" if name == "ip_asn" else "AnnouncesPrefix", "RIPE Stat", url,
                    attribution=("RIS routing observation based on 8-hour dumps; equipment ownership and live connectivity unverified"
                                 if name == "ip_asn" else
                                 "Announced during the provider query window; current announcement and equipment ownership unverified"),
                    metadata=metadata,
                    provider_time=data.get("query_time") or data.get("latest_time") or ""))
            except (ValueError, TypeError, KeyError):
                continue
        rows = list({(row["output"]["kind"], row["output"]["value"]): row for row in rows}.values())
        return rows[:limit], ([{"state": "partial", "detail": "Published results exceed the result limit"}]
                              if len(rows) > limit else [])
    if name in {"website_links", "website_trackers"}:
        if value not in cache:
            page = osint_contacts.parse_public_page(value, capture_html=True)
            cache[value] = page
        page = cache[value]
        html, url = page["_snapshot_html"], page["url"]
        digest = page["html_sha256"]
        if name == "website_links":
            parser = osint_contacts._Links()
            parser.feed(html)
            targets = []
            for href in parser.hrefs:
                try:
                    target = entity("Website", urljoin(url, href))["value"]
                    if target != url and target not in targets:
                        targets.append(target)
                except ValueError:
                    continue
            rows = [_relation(item, "Website", target, "LinksTo", "Published HTML link", url,
                              html_sha256=digest, attribution="Link published on this page; association and ownership unverified")
                    for target in targets[:limit]]
            return rows, ([{"state": "partial", "detail": "Page links exceed the result limit"}] if len(targets) > limit else [])
        codes = set(re.findall(r"\b(?:GTM-[A-Z0-9]{4,20}|G-[A-Z0-9]{5,20}|UA-[0-9]{4,20}-[0-9]{1,5})\b", html))
        codes.update("ym:" + code for code in re.findall(r"\bym\(\s*([0-9]{4,12})\s*,\s*['\"]init['\"]", html))
        rows = [_relation(item, "WebTracker", code, "HasTracker", "Published HTML tracker identifier", url,
                          html_sha256=digest, certainty="candidate",
                          attribution="Identifier present in HTML; execution, ownership and shared operator unverified")
                for code in sorted(codes)[:limit]]
        return rows, ([{"state": "partial", "detail": "Tracker identifiers exceed the result limit"}] if len(codes) > limit else [])
    raise ValueError("Unknown enricher")


def run(value: str, flow: dict, output: Path, *, limit=20, max_tasks=12, progress=None) -> dict:
    """Execute a validated typed DAG; reuse duplicate requests within this run only."""
    from . import dossier
    flow = validate_flow(flow)
    if type(limit) is not int or not 1 <= limit <= 100 or type(max_tasks) is not int or not 1 <= max_tasks <= 24:
        raise ValueError("Results must be 1–100 and task budget 1–24")
    seed = entity(flow["input_kind"], value)
    folder = dossier._folder(Path(output) / "dossiers", seed["value"])
    observed = datetime.now(timezone.utc).isoformat()
    inputs = folder / "inputs.json"
    inputs.write_text(json.dumps({"seed": seed, "flow": flow}, ensure_ascii=False, indent=2), encoding="utf-8")
    digest = hashlib.sha256(inputs.read_bytes()).hexdigest()
    result = {"query": seed["value"], "kind": seed["kind"].lower(), "scope": "full", "coverage": "quick",
              "observed_at": observed, "report_json": str(folder / "dossier.json"), "report_csv": str(folder / "dossier.csv"),
              "sections": {"enrichments": [], "findings": [], "web": [], "profiles": [], "emails": [], "domain": None},
              "settings": {}, "errors": [], "source_checks": [], "counts": {},
              "artifacts": [{"path": str(inputs), "sha256": digest, "source": "User-selected enrichment input", "kind": "flow_input"}],
              "flow": {"definition": flow, "trace": [], "limits": {"tasks": max_tasks, "results_per_task": limit},
                       "reference": UPSTREAM, "reference_commit": COMMIT}}
    with diagnostics.trace_run() as trace:
        diagnostics.attach(result)
        outputs, page_cache, reused = {"seed": [seed]}, {}, {}
        tasks = 0
        for step in flow["steps"]:
            outputs[step["id"]] = []
            source = "Enrichment/" + step["id"]
            if not outputs[step["from"]]:
                dossier._record_check(result, {"source": source, "state": "skipped", "detail": "Previous step produced no compatible inputs"})
                result["flow"]["trace"].append({"step": step["id"], "state": "skipped", "count": 0,
                                                "detail": "Previous step produced no compatible inputs"})
            for item in outputs[step["from"]]:
                signature = (step["enricher"], item["kind"], item["value"])
                started = time.monotonic()
                cached = signature in reused
                state, detail, rows = "ok", "", []
                if not cached and tasks >= max_tasks:
                    state, detail = "skipped", "Flow task budget reached; inputs remain in the dossier"
                else:
                    if not cached:
                        tasks += 1
                    try:
                        if cached and isinstance(reused[signature], SourceError):
                            raise reused[signature]
                        rows, checks = reused[signature] if cached else enrich(step["enricher"], item, limit, page_cache)
                        reused[signature] = rows, checks
                        gaps = [check for check in checks if check["state"] not in {"ok", "empty"}]
                        state = "partial" if rows and gaps else gaps[0]["state"] if gaps else "ok" if rows else "empty"
                        detail = "; ".join(check.get("detail", "") or check["state"] for check in gaps)
                    except SourceError as exc:
                        state, detail = exc.state, str(exc)
                        reused[signature] = exc
                    except (OSError, ValueError, RuntimeError) as exc:
                        state = "blocked" if "robots.txt" in str(exc) else "error"
                        detail = "Page disallowed by robots.txt" if state == "blocked" else f"Enricher failed ({type(exc).__name__})"
                        reused[signature] = SourceError(state, detail)
                entry = {"step": step["id"], "enricher": step["enricher"], "input": item,
                         "state": state, "count": len(rows), "detail": detail, "reused": cached,
                         "elapsed_seconds": round(time.monotonic() - started, 3)}
                result["flow"]["trace"].append(entry)
                # The source ledger is per input, while diagnostics allowlist removes query values.
                dossier._record_check(result, {"source": source, "url": "entity:" + hashlib.sha256(
                    json.dumps(item, sort_keys=True).encode()).hexdigest(), **{key: entry[key] for key in ("state", "count", "detail", "elapsed_seconds")}})
                if progress:
                    progress({"stage": "enrichment", "percent": min(96, tasks * 96 // max_tasks), "detail": ENRICHERS[step["enricher"]].title,
                              "source": source, "state": state, "count": len(rows)})
                if state in {"error", "blocked", "timeout"}:
                    result["errors"].append(source + ": " + detail)
                for row in rows:
                    row = {**row, "observed_at": datetime.now(timezone.utc).isoformat(), "step": step["id"]}
                    if not row["url"]:
                        row.update(url="artifact:sha256:" + digest, sha256=digest)
                    if row not in result["sections"]["enrichments"]:
                        result["sections"]["enrichments"].append(row)
                        result["sections"]["findings"].append({"title": row["relation"], "value": row["output"]["value"],
                            "snippet": f"{row['input']['kind']} {row['input']['value']} → {row['relation']} → {row['output']['kind']} {row['output']['value']}",
                            "url": row["url"], "sha256": row.get("sha256", ""), "source": row["source"], "observed_at": row["observed_at"],
                            "metadata": row.get("metadata", {}),
                            "attribution": row.get("attribution", "Structural relationship; identity and ownership unverified"),
                            "certainty": row["certainty"], "graph_handled": True})
                    if row["output"] not in outputs[step["id"]]:
                        outputs[step["id"]].append(row["output"])
        for index, page in enumerate(page_cache.values()):
            snapshot = folder / f"page-{index + 1}.html.txt"
            snapshot.write_text(page["_snapshot_html"], encoding="utf-8", newline="")
            result["artifacts"].append({"path": str(snapshot), "sha256": page["html_sha256"], "source": page["url"], "kind": "html_snapshot"})
        entries = result["flow"]["trace"]
        gaps = [row for row in entries if row["state"] not in {"ok", "empty"}
                and row.get("detail") != "Previous step produced no compatible inputs"]
        result["flow"]["status"] = ("partial" if result["sections"]["enrichments"] else gaps[0]["state"]) if gaps else (
            "ok" if result["sections"]["enrichments"] else "empty")
        result["counts"].update(enrichments=len(result["sections"]["enrichments"]), flow_tasks=tasks)
        result["diagnostics"].update(trace.summary())
        Path(result["report_csv"]).touch()
        dossier.save_relationship_graph(result)
    return result
