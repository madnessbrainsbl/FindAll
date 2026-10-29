"""Observed dossier relationships and an offline graph, with BloodHound export.

This is an evidence graph. Search matches and matching handles are explicitly
candidate links; they never establish identity, equipment ownership or AD access.
OpenGraph format: https://bloodhound.specterops.io/opengraph/developer/graph-data
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

MAX_NODES = 600
MAX_EDGES = 1500
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)
_HASH = re.compile(r"^[a-f0-9]{64}$", re.I)


def _text(value, limit=600):
    return str(value or "")[:limit]


def _url(value):
    """Only HTTP(S) source links, never credentials or executable schemes."""
    try:
        value = _text(value, 4096).strip()
        parsed = urlsplit(value)
        if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or any(ord(ch) < 32 for ch in value) or "\\" in value):
            return ""
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        netloc = ("[" + host + "]" if ":" in host else host) + (f":{port}" if port else "")
        query = urlencode([(k, "[redacted]" if re.search(r"key|token|secret|password|auth", k, re.I) else v)
                           for k, v in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
    except (ValueError, UnicodeError):
        return ""


def _stable(kind, value):
    return "FindAll_" + kind + "_" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:32]


def build_graph(report: dict, max_nodes=MAX_NODES, max_edges=MAX_EDGES) -> dict:
    """Build deterministic IDs and typed links solely from explicit evidence.

    Nodes: id/kind/label/properties. Edges: id/source/target/kind/label,
    certainty (observed/candidate/interpretation), source_urls, evidence_hashes.
    Both bounds are applied during insertion and omitted counts are reported.
    """
    max_nodes = max(10, min(int(max_nodes), 3000))
    max_edges = max(10, min(int(max_edges), 10000))
    nodes, edges = {}, {}
    omitted = {"nodes": 0, "edges": 0}
    observed = _text(report.get("observed_at"), 80)
    query = _text(report.get("query"), 500)

    def node(kind, key, label=None, **props):
        if not key:
            return ""
        ident = _stable(kind, key)
        if ident not in nodes:
            if len(nodes) >= max_nodes:
                omitted["nodes"] += 1
                return ""
            nodes[ident] = {"id": ident, "kind": kind, "label": _text(label or key, 180),
                            "properties": {"value": _text(key, 1800), "observed_at": observed}}
        for k, v in props.items():
            if v is not None and v != "":
                nodes[ident]["properties"][k] = v if isinstance(v, (bool, int, float, list)) else _text(v, 1800)
        return ident

    def edge(start, end, kind, label, row=None, certainty="observed", urls=None, hashes=None):
        if not start or not end or start == end:
            return
        row = row if isinstance(row, dict) else {}
        sources = [u for value in [*(urls or []), row.get("url"), row.get("source_url"), row.get("index_url"), row.get("discovery_url")]
                   if (u := _url(value))]
        sha = [h.lower() for h in [*(hashes or []), row.get("sha256"), row.get("artifact_id"), row.get("html_sha256"), row.get("index_sha256")]
               if isinstance(h, str) and _HASH.fullmatch(h)]
        ident = _stable("Edge", f"{start}|{kind}|{end}")
        if ident not in edges:
            if len(edges) >= max_edges:
                omitted["edges"] += 1
                return
            edges[ident] = {"id": ident, "source": start, "target": end, "kind": kind,
                           "label": label, "certainty": certainty, "source_urls": [],
                           "evidence_hashes": [], "observed_at": _text(row.get("observed_at") or observed, 80),
                           "collector": _text(row.get("source") or row.get("provider") or row.get("module"), 100)}
        item = edges[ident]
        item["source_urls"] = sorted(set(item["source_urls"] + sources))[:12]
        item["evidence_hashes"] = sorted(set(item["evidence_hashes"] + sha))[:12]

    def domain(value):
        value = _text(value, 253).lower().rstrip(".")
        return node("Domain", value) if _DOMAIN.fullmatch(value) else ""

    def page(value, label="", **props):
        url = _url(value)
        if not url:
            return ""
        ident = node("Page", url, label or url, url=url, **props)
        host = urlsplit(url).hostname
        d = domain(host)
        if d:
            edge(ident, d, "UrlHost", "URL host", urls=[url])
        return ident

    def email(value):
        value = _text(value, 320).strip()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            return ""
        ident = node("Email", value)
        d = domain(value.rsplit("@", 1)[1])
        edge(ident, d, "MailboxDomain", "address domain (syntax)")
        return ident

    root = node("Query", str(report.get("kind", "auto")) + "|" + query, query,
                input_kind=report.get("kind", "auto"), meaning="Research query, not a verified identity")
    sections = report.get("sections") or {}
    if report.get("flow"):
        from .flowsint import entity as validate_entity

        def enriched_node(value):
            if not isinstance(value, dict):
                return ""
            try:
                value = validate_entity(value.get("kind"), value.get("value"))
            except (ValueError, TypeError, UnicodeError):
                return ""
            kind, key = value["kind"], value["value"]
            if kind == "Website":
                return page(key)
            if kind == "Domain":
                return domain(key)
            if kind == "Email":
                return email(key)
            return node(kind, key, attribution="Observed or derived entity; ownership unverified")

        definition = (report.get("flow") or {}).get("definition") or {}
        seed = enriched_node({"kind": definition.get("input_kind"), "value": query})
        edge(root, seed, "ResearchTarget", "selected enrichment input")
        for row in (sections.get("enrichments") or [])[:max_edges]:
            if not isinstance(row, dict):
                continue
            left, right = enriched_node(row.get("input")), enriched_node(row.get("output"))
            relation = _text(row.get("relation"), 80)
            if not re.fullmatch(r"[A-Za-z]{1,80}", relation):
                continue
            edge(left, right, relation, relation, row,
                 "candidate" if row.get("certainty") == "candidate" else "observed")
            if right in nodes:
                nodes[right]["properties"]["attribution"] = _text(row.get("attribution"), 600)
                nodes[right]["properties"]["observed_at"] = _text(row.get("observed_at") or observed, 80)
                metadata = row.get("metadata")
                if isinstance(metadata, dict):
                    for key in ("query_starttime", "query_endtime", "latest_time", "earliest_time", "matched_prefix", "visible_periods", "visible_periods_omitted"):
                        if key in metadata:
                            nodes[right]["properties"][key] = metadata[key]
    if report.get("kind") == "domain":
        edge(root, domain(query), "ResearchTarget", "input domain")
    elif report.get("kind") == "email":
        edge(root, email(query), "ResearchTarget", "input email address")
    elif report.get("kind") == "username":
        edge(root, node("Handle", query, attribution="Handle string, not a verified person"),
             "ResearchTarget", "input handle")
    elif report.get("kind") == "phone":
        edge(root, node("Phone", query), "ResearchTarget", "input phone number")
    elif report.get("kind") == "ip":
        try:
            address = str(ipaddress.ip_address(query))
            edge(root, node("IP", address, attribution="IP address; equipment ownership unverified"),
                 "ResearchTarget", "input IP address")
        except ValueError:
            pass
    for section in ("web", "profiles"):
        for row in (sections.get(section) or [])[:max_nodes * 2]:
            if not isinstance(row, dict):
                continue
            url = _url(row.get("url") or row.get("source_url"))
            item = page(url, row.get("title") or row.get("site") or row.get("name"),
                        snippet=_text(row.get("snippet") or row.get("excerpt"), 900),
                        collector=row.get("source", ""), published_at=row.get("published_at", ""),
                        observed_at=row.get("observed_at") or row.get("seen_at") or observed,
                        html_sha256=row.get("html_sha256", ""), index_url=row.get("index_url", ""),
                        index_sha256=row.get("index_sha256", ""), discovery_url=row.get("discovery_url", ""))
            if section == "profiles" and url:
                item = node("Profile", url, row.get("site") or row.get("title") or url,
                            url=url, username=_text(row.get("username"), 100),
                            attribution="Account ownership unverified")
                p = page(url)
                edge(item, p, "ProfilePage", "profile page", row)
                handle = _text(row.get("username"), 100)
                if handle:
                    h = node("Handle", handle, handle, attribution="Handle string, not a person")
                    edge(item, h, "ReportedHandle", "reported handle", row)
            edge(root, item, "SearchMatch", "search match; identity unverified", row, "candidate")
    for row in (sections.get("emails") or [])[:max_nodes]:
        if not isinstance(row, dict):
            continue
        e = email(row.get("email"))
        p = page(row.get("url") or row.get("source_url"))
        archived = bool(row.get("archived") or "archive" in _text(row.get("category")).lower()
                        or "archive" in _text(row.get("status")).lower()
                        or urlsplit(_url(row.get("url") or row.get("source_url"))).hostname == "web.archive.org")
        if row.get("verification") in {"hypothesis", "candidate", "unknown"}:
            edge(p or root, e, "CandidateEmail", "unverified address candidate", row, "candidate")
            continue
        edge(p or root, e, "HistoricalEmail" if archived else "PublishedEmail" if p else "CollectedEmail",
             "historically published email; current validity unverified" if archived else
             "published email" if p else "collected email; source unavailable", row,
             "observed" if p else "candidate")
    data = sections.get("domain") or {}
    d = domain(data.get("domain", ""))
    dns = data.get("dns") or {}
    for record_kind in ("a", "aaaa", "A", "AAAA"):
        values = dns.get(record_kind) or []
        if isinstance(values, str):
            values = [values]
        for value in values[:50]:
            try:
                address = str(ipaddress.ip_address(value))
            except (ValueError, TypeError):
                continue
            edge(d, node("IP", address), "ResolvesTo", "observed DNS resolution",
                 urls=[f"https://cloudflare-dns.com/dns-query?name={quote(data.get('domain', ''))}&type={record_kind.upper()}"])
    for value in (dns.get("mx") or [])[:50]:
        host = str(value).split()[-1].rstrip(".") if str(value).split() else ""
        edge(d, domain(host), "MailExchanger", "published MX record", urls=[
             f"https://cloudflare-dns.com/dns-query?name={quote(data.get('domain', ''))}&type=MX"])
    for row in (data.get("subdomains") or [])[:max_nodes]:
        if not isinstance(row, dict):
            continue
        name = _text(row.get("name"), 253).lower()
        sub = domain(name)
        sources = row.get("sources") or []
        urls = ([f"https://crt.sh/?q={quote(name)}"] if "crt.sh" in sources else
                [f"https://api.certspotter.com/v1/issuances?domain={quote(name)}"] if "CertSpotter" in sources else [])
        edge(d, sub, "ObservedHostname", "observed hostname; ownership unverified", row, urls=urls)
        for address in row.get("ips", [])[:50]:
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError:
                continue
            ip = node("IP", address, attribution="IP address; equipment ownership unverified")
            edge(sub, ip, "ResolvesTo", "observed DNS resolution", row,
                 urls=[f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type=A"])
    for row in (data.get("assets") or [])[:max_nodes]:
        if not isinstance(row, dict):
            continue
        try:
            address = str(ipaddress.ip_address(row.get("ip", "")))
        except ValueError:
            continue
        ip = node("IP", address, attribution="IP address; equipment ownership unverified")
        port = _text(row.get("port"), 12)
        service = node("Service", address + "|" + port, address + (":" + port if port else ""),
                       ip=address, port=port, product=_text(row.get("product"), 180))
        edge(ip, service, "IndexedService", "indexed service; snapshot", row)
        for hostname in (row.get("hostnames") or [])[:20]:
            edge(ip, domain(hostname), "ReportedHostname", "hostname reported by index", row)
    for row in (data.get("technologies") or [])[:100]:
        if isinstance(row, dict) and row.get("name"):
            tech = node("Technology", str(row["name"]) + "|" + str(row.get("version", "")),
                        row["name"], version=row.get("version", ""), confidence=row.get("confidence", 0))
            edge(d, tech, "DetectedTechnology", "technology detection", urls=[f"https://{data.get('domain')}/"])
    for row in (sections.get("businesses") or [])[:max_nodes]:
        if not isinstance(row, dict):
            continue
        url = _url(row.get("url"))
        b = node("Business", url or json.dumps(row, sort_keys=True, ensure_ascii=False), row.get("name"),
                 url=url, address=row.get("address", ""), attribution="Published business listing")
        edge(root, b, "SearchMatch", "business search match", row, "candidate")
        edge(b, page(url), "ListingPage", "listing page", row)
        for value in row.get("emails", [])[:20]:
            edge(b, email(value), "ListedEmail", "listed business email", row)
        for value in row.get("phones", [])[:20]:
            edge(b, node("Phone", value), "ListedPhone", "listed business phone", row)
        websites = row.get("websites", []) or ([row["website"]] if row.get("website") else [])
        for value in websites[:20]:
            edge(b, page(value), "ListedWebsite", "website listed by source", row)
    for row in ((sections.get("archives") or {}).get("records") or [])[:max_nodes]:
        if not isinstance(row, dict) or not _url(row.get("original_url")):
            continue
        original = _url(row["original_url"])
        endpoint = node("HistoricalURL", original, original, url=original,
                        categories=row.get("categories", []), parameters=row.get("parameters", []),
                        snapshot_at=row.get("snapshot_at", ""), attribution=row.get("certainty", ""))
        edge(root, endpoint, "HistoricalUrlCandidate", "historical path; current state unverified", row, "candidate")
        source = page(row.get("source_url"))
        edge(endpoint, source, "ArchiveReference" if row.get("discovered_in") else "ArchiveIndexEvidence",
             "referenced in archived content" if row.get("discovered_in") else "reported by archive index", row, "candidate")
        for parameter in (row.get("parameters") or [])[:40]:
            edge(endpoint, node("URLParameter", str(parameter)), "HistoricalParameter", "historical parameter name", row, "candidate")
    for row in (sections.get("findings") or [])[:max_nodes]:
        if not isinstance(row, dict) or row.get("graph_handled"):
            continue
        key = json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
        f = node("Finding", key, row.get("title") or row.get("event_type") or row.get("kind") or "Collected finding",
                 summary=_text(row.get("value") or row.get("snippet"), 1800), collector=row.get("source") or row.get("module"),
                 attribution="Collector observation; inspect the cited evidence")
        certainty = row.get("certainty") if row.get("certainty") in {"candidate", "interpretation"} else "candidate" if "candidate" in str(row.get("verification", "")).lower() else "observed"
        citation = {**row, "url": row.get("source_url") or row.get("url")}
        edge(root, f, "CollectedFinding", "collector observation", citation, certainty)
        edge(f, page(citation["url"]), "CitesSource", "cites source", citation, certainty)
        sha = row.get("sha256") or row.get("artifact_id")
        if isinstance(sha, str) and _HASH.fullmatch(sha):
            edge(f, node("Artifact", sha.lower(), "Evidence " + sha[:12], sha256=sha.lower()),
                 "CitesArtifact", "collector evidence artifact", row, hashes=[sha])
    for row in (sections.get("webcheck_modules") or [])[:100]:
        if not isinstance(row, dict) or row.get("status") not in ("ok", "partial", "success"):
            continue
        f = node("Finding", "WebCheck|" + query + "|" + str(row.get("name")), "Web-Check / " + str(row.get("name")),
                 summary=json.dumps(row.get("data"), ensure_ascii=False, default=str)[:1800], collector="Web-Check")
        edge(root, f, "CollectedFinding", "Web-Check observation", row)
        edge(f, page(row.get("url")), "CitesSource", "checked page", row)
    for row in (report.get("artifacts") or [])[:max_nodes]:
        if isinstance(row, str):
            row = {"path": row, "source": "Collected evidence"}
            linked = next((item for item in sections.get("web", []) if isinstance(item, dict)
                           and row["path"] in (item.get("artifact"), item.get("metadata"))), None)
            if linked:
                row["url"] = linked.get("url")
        if not isinstance(row, dict):
            continue
        sha = row.get("sha256") or row.get("artifact_id")
        sha = sha.lower() if isinstance(sha, str) and _HASH.fullmatch(sha) else ""
        key = sha or _text(row.get("path"), 1800)
        a = node("Artifact", key, row.get("name") or Path(str(row.get("path", "evidence"))).name,
                 sha256=sha, path=row.get("path", ""), collector=row.get("source", ""),
                 evidence_kind=row.get("kind", ""))
        edge(root, a, "CollectedArtifact", "collected artifact", row)
        edge(a, page(row.get("url") or row.get("source_url")), "ArchivedSource", "archived source", row)
    for row in (sections.get("careers") or [])[:100]:
        if not isinstance(row, dict):
            continue
        link = _url(row.get("url"))
        if not link:
            continue
        c = node("CareerPage", link, row.get("title") or row.get("provider") or "Career page",
                 url=link, collector=row.get("source"), status=row.get("status"),
                 company_source_url=_url(row.get("company_source_url")))
        citation = {**row, "url": row.get("company_source_url") or row.get("source_url") or row.get("url")}
        edge(root, c, "PublishesCareerLink", "company page links to careers", citation,
             "observed" if row.get("company_source_url") else "candidate",
             urls=[row.get("company_source_url")])
        edge(c, page(row.get("company_source_url")), "CitesSource", "association source", citation)
    for row in (sections.get("jobs") or [])[:200]:
        if not isinstance(row, dict) or not _url(row.get("url")):
            continue
        j = node("Job", _url(row["url"]), row.get("title") or "Published vacancy",
                 url=_url(row["url"]), company=row.get("company"), location=row.get("location"),
                 posted=row.get("posted"), collector=row.get("source"))
        citation = {**row, "url": row.get("source_url") or row.get("url")}
        edge(root, j, "PublishedVacancy", "vacancy from linked career platform", citation,
             "observed" if row.get("company_source_url") else "candidate")
        edge(j, page(row.get("company_source_url")), "CitesSource", "company association source", citation,
             urls=[row.get("company_source_url")])
        edge(j, page(citation["url"]), "CitesSource", "fetched vacancy publication", citation)
    for row in sections.get("analysis_observations", [])[:max_nodes]:
        if not isinstance(row, dict) or not row.get("relation_source") or not row.get("relation_target"):
            continue
        dataset = row.get("sha256", "")
        # Imported actor labels are local to their dataset, never global identities.
        a = node("ImportedEntity", dataset + ":" + row["relation_source"], row["relation_source"], attribution="imported label; identity unverified")
        b = node("ImportedEntity", dataset + ":" + row["relation_target"], row["relation_target"], attribution="imported label; identity unverified")
        edge(root, a, "ImportedObservation", "entity in selected dataset", row, "candidate")
        edge(a, b, "ImportedRelation", "relationship reported in selected dataset", row, "candidate")
    for row in sections.get("statistics", []):
        if isinstance(row, dict) and row.get("status") == "ok":
            calculation = node("StatisticalCalculation", row.get("sha256", "") + row.get("title", ""), row.get("title"),
                               attribution="exploratory statistical interpretation", sha256=row.get("sha256"))
            edge(root, calculation, "InterpretsEvidence", "sample calculation", row, "interpretation")
    for row in ((report.get("history") or {}).get("timeline") or [])[:max_nodes]:
        if not isinstance(row, dict) or not row.get("date") or not row.get("id"):
            continue
        if report.get("flow") and row.get("event") == "observation":
            # Enrichment edges already retain collection time; avoid one duplicate
            # timeline node per result in the interactive graph.
            continue
        history_node = node("HistoryEvent", str(row["id"]), row.get("label") or row.get("event"),
                            event_date=row.get("date"), collected_at=row.get("collected_at"),
                            event_type=row.get("event"), archived=bool(row.get("archived")),
                            collector=row.get("source"),
                            attribution="Dated source observation; historical evidence does not establish present validity or ownership")
        certainty = "candidate" if row.get("certainty") == "candidate" else "observed"
        edge(root, history_node, "SourceObservation", "dated source observation", row, certainty)
        edge(history_node, page(row.get("url")), "CitesSource", "history source", row, certainty)
        if row.get("original_url"):
            edge(history_node, page(row["original_url"]), "HistoricalPage", "historical page; present content unverified", row)
    analysis = report.get("ai_analysis") or {}
    for index, row in enumerate((analysis.get("claims") or [])[:80]):
        if not isinstance(row, dict):
            continue
        statement = row.get("claim") or row.get("statement") or row.get("text") or row.get("summary")
        if not statement:
            continue
        c = node("AIClaim", str(statement), _text(statement, 150), summary=_text(statement, 1800),
                 attribution="AI interpretation; verify cited source")
        edge(root, c, "InterpretsEvidence", "AI interpretation", row, "interpretation")
        urls = row.get("source_urls") or row.get("sources") or row.get("citations") or ([row["source_url"]] if row.get("source_url") else [])
        if isinstance(urls, str):
            urls = [urls]
        for value in urls[:12]:
            value = value.get("url", "") if isinstance(value, dict) else value
            if isinstance(value, str) and value.startswith("artifact:sha256:") and _HASH.fullmatch(value.rsplit(":", 1)[-1]):
                sha = value.rsplit(":", 1)[-1].lower()
                edge(c, node("Artifact", sha, "Evidence " + sha[:12], sha256=sha),
                     "CitesArtifact", "AI citation to collected artifact", certainty="interpretation", hashes=[sha])
            else:
                edge(c, page(value), "CitesSource", "AI citation", certainty="interpretation", urls=[value])
    return {"schema_version": 1, "query": query, "root_id": root, "observed_at": observed,
            "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
            "edges": sorted(edges.values(), key=lambda item: item["id"]),
            "limits": {"max_nodes": max_nodes, "max_edges": max_edges, "omitted": omitted},
            "semantics": "Relationships represent collected evidence. Search matches do not prove identity; DNS or indexed services do not prove ownership. Paths are evidence connections, not privilege escalation paths."}


def bloodhound_export(graph: dict) -> dict:
    """Generic OpenGraph payload: prefixed kinds, IDs without ':', flat properties."""
    def properties(data):
        clean = {}
        for key, value in data.items():
            key = re.sub(r"[^a-z0-9_]", "_", key.lower())
            if key in {"objectid", "lastseen", "reconcile"} or value is None:
                continue
            if isinstance(value, (str, bool, int, float)):
                clean[key] = value
            elif isinstance(value, list):
                clean[key] = [str(item) for item in value]
        return clean
    return {"graph": {"nodes": [{"id": row["id"], "kinds": ["FindAll_" + row["kind"]],
                "properties": properties({**row.get("properties", {}), "name": row["label"], "displayname": row["label"]})}
                for row in graph["nodes"]],
            "edges": [{"kind": "FindAll_" + row["kind"], "start": {"value": row["source"], "match_by": "id"},
                "end": {"value": row["target"], "match_by": "id"}, "properties": properties({
                    "label": row["label"], "certainty": row["certainty"], "source_urls": row["source_urls"],
                    "evidence_hashes": row["evidence_hashes"], "observed_at": row["observed_at"], "collector": row["collector"]})}
                for row in graph["edges"]]}}


def write_exports(graph: dict, folder: Path) -> dict:
    folder = Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    paths = {"graph_json": folder / "relationship_graph.json", "graph_html": folder / "relationship_graph.html",
             "bloodhound_graph": folder / "bloodhound_opengraph.json"}
    paths["graph_json"].write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
    paths["bloodhound_graph"].write_text(json.dumps(bloodhound_export(graph), ensure_ascii=False, indent=2), encoding="utf-8")
    payload = json.dumps(graph, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = Path(__file__).with_name("evidence_graph.html").read_text(encoding="utf-8")
    paths["graph_html"].write_text(template.replace("__GRAPH_PAYLOAD__", payload), encoding="utf-8")
    return {key: str(value) for key, value in paths.items()}


def accumulate(report: dict, output: Path) -> dict:
    """Merge evidence into one workspace graph; retain prior searches in SQLite."""
    output = Path(output).resolve()
    storage = output / ".research"
    storage.mkdir(parents=True, exist_ok=True)
    fragment = build_graph(report, max_nodes=3000, max_edges=10000)
    root = _stable("Query", "workspace")
    workspace = {"id": root, "kind": "Query", "label": "FindAll workspace",
                 "properties": {"meaning": "Accumulated research; query matches do not prove identity"}}
    link = {"id": _stable("Edge", root + "|ResearchQuery|" + fragment["root_id"]),
            "source": root, "target": fragment["root_id"], "kind": "ResearchQuery",
            "label": "research query", "certainty": "observed", "source_urls": [],
            "evidence_hashes": [], "observed_at": fragment["observed_at"], "collector": "FindAll"}
    with closing(sqlite3.connect(storage / "graph.sqlite3", timeout=30)) as conn, conn:
        conn.execute("CREATE TABLE IF NOT EXISTS graph_items (kind TEXT, id TEXT, payload TEXT, PRIMARY KEY(kind,id))")
        conn.execute("BEGIN IMMEDIATE")
        for kind, rows in (("node", [workspace, *fragment["nodes"]]), ("edge", [link, *fragment["edges"]])):
            for row in rows:
                previous = conn.execute("SELECT payload FROM graph_items WHERE kind=? AND id=?", (kind, row["id"])).fetchone()
                if previous:
                    old = json.loads(previous[0])
                    if kind == "node":
                        row = {**old, **row, "properties": {**old.get("properties", {}),
                               **{k: v for k, v in row.get("properties", {}).items() if v not in (None, "")}}}
                    else:
                        row = {**old, **row, **{key: sorted(set(old.get(key, []) + row.get(key, [])))
                                               for key in ("source_urls", "evidence_hashes")}}
                        if not row.get("observed_at"):
                            row["observed_at"] = old.get("observed_at", "")
                conn.execute("INSERT OR REPLACE INTO graph_items VALUES(?,?,?)",
                             (kind, row["id"], json.dumps(row, ensure_ascii=False)))
        graph = {**fragment, "query": "FindAll workspace", "root_id": root,
                 "nodes": [], "edges": [], "limits": fragment["limits"]}
        for kind, payload in conn.execute("SELECT kind,payload FROM graph_items ORDER BY id"):
            graph["nodes" if kind == "node" else "edges"].append(json.loads(payload))
        # Write under the transaction lock so concurrent collectors cannot publish an older graph.
        payload = json.dumps(graph, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        template = Path(__file__).with_name("evidence_graph.html").read_text(encoding="utf-8")
        path = output / "relationship_graph.html"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output, suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(template.replace("__GRAPH_PAYLOAD__", payload))
        try:
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return {"graph_path": str(path), "graph_nodes": len(graph["nodes"]), "graph_edges": len(graph["edges"])}


def from_search(result: dict) -> dict:
    """Use the same evidence semantics for discovery and dossier collectors."""
    sections = {"web": [*result.get("results", []), *result.get("web_results", []),
                        *result.get("pages", []), *result.get("projects", [])],
                "jobs": result.get("jobs", []), "emails": [*result.get("emails", []),
                         *[{**row, "url": row.get("url") or row.get("job_url", "")}
                           for row in result.get("contacts", [])]], "domain": result.get("domain")}
    return {"query": result.get("query", ""), "kind": "auto",
            "observed_at": result.get("observed_at", ""), "sections": sections}
