"""Bounded public company-site careers discovery and source-confirmed ATS boards.

JavaScript URLs are leads only. An ATS association requires an anchor, frame or
form on a fetched company HTML page; tenant names are never guessed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse as up
import urllib.request
import urllib.robotparser
import xml.etree.ElementTree as ET
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from . import contacts, diagnostics, net, osint_contacts, sources

RELEVANT = re.compile(r"career|jobs?|vacanc|hiring|contact|team|работ|вакан", re.I)
TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
ATS_HOSTS = {
    "boards.greenhouse.io": "greenhouse", "job-boards.greenhouse.io": "greenhouse",
    "boards.eu.greenhouse.io": "greenhouse", "jobs.lever.co": "lever",
    "jobs.eu.lever.co": "lever", "apply.workable.com": "workable",
    "jobs.ashbyhq.com": "ashby", "jobs.smartrecruiters.com": "smartrecruiters",
    "careers.smartrecruiters.com": "smartrecruiters",
}
API_HOSTS = {"boards-api.greenhouse.io", "api.lever.co", "api.eu.lever.co",
             "apply.workable.com", "api.ashbyhq.com", "api.smartrecruiters.com"}
JS_STRINGS = re.compile(r"[\"'`]((?:https?://|/|\./|\.\./)[^\"'`\s<>]{1,2048})[\"'`]")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _url(value: str, base: str = "") -> str:
    try:
        p = up.urlsplit(up.urljoin(base, value.strip()))
        if (p.scheme != "https" or not p.hostname or p.username or p.password
                or p.port not in (None, 443)):
            return ""
        return up.urlunsplit(("https", p.hostname.lower(), p.path or "/", p.query, ""))
    except (TypeError, ValueError):
        return ""


def ats_identity(url: str) -> tuple[str, str] | None:
    p = up.urlsplit(_url(url))
    provider = ATS_HOSTS.get(p.hostname or "")
    pieces = [up.unquote(x) for x in p.path.split("/") if x]
    tenant = ((up.parse_qs(p.query).get("for") or [""])[0]
              if provider == "greenhouse" and (not pieces or pieces[0] == "embed")
              else pieces[0] if pieces else "")
    if provider and TENANT.fullmatch(tenant) and ".." not in tenant:
        return provider, tenant
    return None


class _Page(osint_contacts._VisiblePage):
    def __init__(self):
        super().__init__()
        self.associations = []
        self.json_blocks = []
        self._json = None

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        attributes = dict(attrs)
        if tag in {"a", "iframe", "form"}:
            value = attributes.get({"a": "href", "iframe": "src", "form": "action"}[tag])
            if value:
                self.associations.append(value)
        if tag == "script" and attributes.get("type", "").lower() == "application/ld+json":
            self._json = []

    def handle_data(self, data):
        super().handle_data(data)
        if self._json is not None:
            self._json.append(data)

    def handle_endtag(self, tag):
        super().handle_endtag(tag)
        if tag == "script" and self._json is not None:
            self.json_blocks.append("".join(self._json))
            self._json = None


class _Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts, self.count = hosts, 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        url = _url(newurl, req.full_url)
        if (self.count > 5 or not url or up.urlsplit(url).hostname not in self.hosts
                or not osint_contacts._public_host(up.urlsplit(url).hostname)):
            raise urllib.error.URLError("Redirect outside public HTTPS scope")
        return super().redirect_request(req, fp, code, msg, headers, url)


class _Transport:
    def __init__(self, deadline, byte_limit, cancel):
        self.deadline, self.byte_limit, self.cancel = deadline, byte_limit, cancel
        self.bytes = 0
        self.requests = 0

    def stopped(self):
        return bool(self.cancel and self.cancel()) or time.monotonic() >= self.deadline or self.bytes >= self.byte_limit

    def fetch(self, url, hosts, per_resource=750_000):
        start = time.monotonic()
        safe = _url(url)
        status, body, error, mime = 0, b"", "", ""
        host = up.urlsplit(safe).hostname if safe else ""
        if self.stopped():
            error = "Collection cancelled or budget exhausted"
        elif not host or host not in hosts or not osint_contacts._public_host(host):
            error = "Outside public HTTPS scope"
        else:
            try:
                net._polite_wait(host, deadline=self.deadline)
                if self.stopped():
                    raise TimeoutError("Collection budget exhausted")
                proxy = os.environ.get("JOBFIND_ACTIVE_PROXY", "").strip()
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}), _Redirect(hosts))
                req = urllib.request.Request(safe, headers={"User-Agent": net.USER_AGENT, "Accept": "*/*"})
                self.requests += 1
                with opener.open(req, timeout=min(10.0, max(.1, self.deadline - time.monotonic()))) as response:
                    status = response.status
                    limit = min(per_resource, self.byte_limit - self.bytes)
                    chunks, size = [], 0
                    while size <= limit:
                        if self.stopped():
                            raise TimeoutError("Collection budget exhausted")
                        chunk = response.read(min(65536, limit + 1 - size))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                        self.bytes += len(chunk)
                    body = b"".join(chunks)
                    mime = response.headers.get_content_type()
                    safe = _url(response.geturl())
                    if len(body) > limit:
                        body, error = b"", "Resource exceeds byte limit"
            except urllib.error.HTTPError as exc:
                status, error = exc.code, f"HTTP {exc.code}"
                exc.close()
            except (urllib.error.URLError, OSError, ValueError) as exc:
                error = str(exc)[:180]
        state = ("ok" if status == 200 and not error else "empty" if status == 404 else "blocked" if status in (401, 403, 429)
                 or "scope" in error else "timeout" if "budget" in error or "timed out" in error
                 else "partial" if "byte limit" in error else "error")
        metadata = {"host": host, "method": "GET", "status": status, "state": state,
                    "attempts": 1 if status or body else 0, "retry_count": 0,
                    "elapsed_seconds": round(time.monotonic() - start, 3)}
        diagnostics.record_network(metadata)
        result = net.HttpResult(status, body, safe or url, error, metadata)
        result.content_type = mime
        return result


def _structured_jobs(blocks, page, domain):
    found = []
    for block in blocks:
        try:
            initial = json.loads(block)
        except (ValueError, TypeError):
            continue
        queue = [initial]
        visited = 0
        while queue and visited < 300:
            node = queue.pop()
            visited += 1
            if isinstance(node, list):
                queue.extend(node[:100])
            elif isinstance(node, dict):
                typ = node.get("@type")
                if typ == "JobPosting" or isinstance(typ, list) and "JobPosting" in typ:
                    location = node.get("jobLocation") or {}
                    if isinstance(location, list):
                        location = location[0] if location else {}
                    address = location.get("address") if isinstance(location, dict) else {}
                    address = address if isinstance(address, dict) else {}
                    organisation = node.get("hiringOrganization") or {}
                    organisation = organisation if isinstance(organisation, dict) else {}
                    target = _url(str(node.get("url") or page), page)
                    if target and up.urlsplit(target).hostname in {domain, "www." + domain.removeprefix("www.")}:
                        found.append(sources._job(str(node.get("title") or ""), organisation.get("name") or domain,
                                     target, "Company JobPosting", address.get("addressLocality") or "",
                                     node.get("jobLocationType") == "TELECOMMUTE", str(node.get("description") or ""),
                                     node.get("datePosted") or ""))
                queue.extend(value for value in node.values() if isinstance(value, (dict, list)))
    return [job for job in found if job["title"]]


def collect(domain: str, *, output=None, db_path=None, max_pages: int = 12,
            max_scripts: int = 4, max_sitemaps: int = 3, max_boards: int = 4,
            max_jobs: int = 100, time_limit: float = 60, byte_limit: int = 4_000_000,
            cancel=None, on_status=None, time_budget=None) -> dict:
    """Collect selected company pages, sitemap leads, JS candidates and ATS jobs.

    ``cancel`` is an optional zero-argument predicate. Only five known public
    ATS adapters may issue external requests after HTML association is observed.
    """
    root = _url(domain if "://" in domain else "https://" + domain)
    if not root:
        raise ValueError("Enter a public HTTPS company domain")
    host = up.urlsplit(root).hostname
    if not osint_contacts._public_host(host):
        raise ValueError("Company domain must resolve only to public addresses")
    max_pages, max_scripts = max(1, min(int(max_pages), 30)), max(0, min(int(max_scripts), 10))
    max_sitemaps, max_boards = max(0, min(int(max_sitemaps), 5)), max(0, min(int(max_boards), 6))
    max_jobs = max(1, min(int(max_jobs), 300))
    time_limit = max(1.0, min(float(time_limit if time_budget is None else time_budget), 180.0))
    byte_limit = max(1024, min(int(byte_limit), 12_000_000))
    origin = f"https://{host}"
    hosts = {host, host.removeprefix("www."), "www." + host.removeprefix("www.")}
    transport = _Transport(time.monotonic() + time_limit, byte_limit, cancel)
    result = {"domain": host, "observed_at": _now(), "jobs": [], "web": [], "emails": [],
              "findings": [], "statuses": [], "errors": [], "ats_links": [], "careers": [], "js_candidates": []}
    result["limits"] = {"max_pages": max_pages, "max_scripts": max_scripts, "max_sitemaps": max_sitemaps,
                        "max_boards": max_boards, "max_jobs": max_jobs, "time_limit_seconds": time_limit,
                        "byte_limit": byte_limit, "partial": True}
    started = time.monotonic()

    def status(url, state, detail, count=0, elapsed=0):
        row = {"source": "careers", "url": url, "state": state, "detail": detail,
               "count": count, "elapsed_seconds": elapsed, "observed_at": _now()}
        result["statuses"].append(row)
        if state in {"error", "blocked", "timeout", "partial"}:
            result["errors"].append(detail)
        if on_status:
            on_status(row)

    def fetch(url, allowed=hosts):
        r = transport.fetch(url, allowed)
        status(r.url, r.metadata["state"], r.error or "Public resource fetched", elapsed=r.metadata["elapsed_seconds"])
        return r

    robots = urllib.robotparser.RobotFileParser()
    robots_result = fetch(origin + "/robots.txt")
    if robots_result.status == 404:
        robots.parse([])
    elif robots_result.status == 200 and not robots_result.error:
        robots.parse(robots_result.text.splitlines())
    else:
        status(origin, "blocked", "Cannot establish robots policy; site crawl stopped")
        return result
    queue = deque([root, origin + "/careers", origin + "/jobs", origin + "/contact"])
    visited, scripts, associations, job_urls, email_keys, candidates = set(), [], {}, set(), set(), set()
    sitemap_queue = deque((robots.site_maps() or []) + [origin + "/sitemap.xml"])
    sitemap_seen = set()
    while sitemap_queue and len(sitemap_seen) < max_sitemaps and not transport.stopped():
        url = _url(sitemap_queue.popleft(), origin)
        if not url or up.urlsplit(url).hostname not in hosts or url in sitemap_seen:
            continue
        sitemap_seen.add(url)
        if not robots.can_fetch(net.USER_AGENT, url):
            status(url, "skipped", "Disallowed by robots.txt")
            continue
        r = fetch(url)
        if r.status != 200 or r.error:
            continue
        try:
            tree = ET.fromstring(r.body)
        except ET.ParseError:
            status(url, "error", "Sitemap XML could not be parsed")
            continue
        index = tree.tag.rsplit("}", 1)[-1] == "sitemapindex"
        for element in list(tree.iter())[:3000]:
            if element.tag.rsplit("}", 1)[-1] != "loc" or not element.text:
                continue
            target = _url(element.text, origin)
            if not target or up.urlsplit(target).hostname not in hosts:
                continue
            if index and len(sitemap_queue) < 20:
                sitemap_queue.append(target)
            elif RELEVANT.search(up.unquote(target)) and len(queue) < 100:
                queue.append(target)

    def jobs_add(jobs, evidence, association=None):
        for job in jobs:
            url = _url(job.get("url", ""), evidence)
            if not url or url in job_urls or len(result["jobs"]) >= max_jobs:
                continue
            job_urls.add(url)
            job.update(url=url, source_url=evidence, domain=host, observed_at=_now(), evidence=[evidence],
                       company_association="company_page_link" if association else "company_page_jobposting")
            if association:
                job["association_source_url"] = association
                job["evidence"].append(association)
            job["company_source_url"] = association or evidence
            result["jobs"].append(job)
            for email in contacts.extract_emails(job.get("description", "")):
                add_email(email, evidence, job.get("company") or host, job.get("source", "ATS"))

    def add_email(email, url, company=host, source="Public company website"):
        key = email, url
        if key in email_keys or len(email_keys) >= 100:
            return
        email_keys.add(key)
        result["emails"].append({"email": email, "url": url, "source": source, "company": company,
                                 "domain": host, "verification": "published", "evidence": [url],
                                 "observed_at": _now(), "confidence": 0})

    while queue and len(visited) < max_pages and not transport.stopped():
        url = _url(queue.popleft(), origin)
        if not url or url in visited or up.urlsplit(url).hostname not in hosts:
            continue
        visited.add(url)
        if not robots.can_fetch(net.USER_AGENT, url):
            status(url, "skipped", "Disallowed by robots.txt")
            continue
        r = fetch(url)
        if r.status != 200 or r.error:
            continue
        if r.content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
            status(url, "skipped", "Resource is not a public HTML page")
            continue
        parser = _Page()
        parser.feed(r.text)
        visible = " ".join(" ".join(parser.text).split())
        page = {"url": r.url, "title": " ".join(parser.title)[:200] or r.url,
                "snippet": visible[:1200], "source": "Company careers crawl", "category": "Company page",
                "observed_at": _now(), "html_sha256": hashlib.sha256(r.body).hexdigest()}
        result["web"].append(page)
        for email in contacts.extract_emails(visible + " " + " ".join(parser.mailto)):
            add_email(email, r.url)
        for value in parser.associations:
            target = _url(value, r.url)
            identity = ats_identity(target)
            if identity:
                associations.setdefault(identity, {"url": target, "source_url": r.url, "company_source_url": r.url,
                     "source": "Company ATS association", "title": f"{identity[0]} careers board",
                     "status": "verified_company_link",
                     "provider": identity[0], "tenant": identity[1], "verification": "company_page_link",
                     "observed_at": _now()})
        for value in parser.hrefs:
            target = _url(value, r.url)
            if (target and up.urlsplit(target).hostname in hosts and target not in visited
                    and RELEVANT.search(up.unquote(target)) and len(queue) < 100):
                queue.append(target)
        for value in parser.scripts:
            target = _url(value, r.url)
            if target and up.urlsplit(target).hostname in hosts and target not in scripts:
                scripts.append(target)
        jobs_add(_structured_jobs(parser.json_blocks, r.url, host), r.url)

    for script in scripts[:max_scripts]:
        if transport.stopped():
            break
        if not robots.can_fetch(net.USER_AGENT, script):
            status(script, "skipped", "Script disallowed by robots.txt")
            continue
        r = fetch(script)
        if r.status != 200 or r.error:
            continue
        for match in JS_STRINGS.finditer(r.text.replace("\\/", "/")):
            target = _url(match.group(1), r.url)
            if target and target not in candidates and (RELEVANT.search(target) or ats_identity(target)):
                candidates.add(target)
                result["js_candidates"].append({"url": target, "source_url": r.url, "observed_at": _now(),
                    "verification": "candidate", "note": "Static JavaScript lead; not invoked as an API or verified ATS"})
                if len(candidates) >= 100:
                    break

    result["ats_links"] = list(associations.values())
    result["careers"] = result["ats_links"]
    for candidate in result["js_candidates"]:
        result["findings"].append({"url": candidate["url"], "source_url": candidate["source_url"],
             "title": "Unverified JavaScript careers lead", "snippet": candidate["note"],
             "source": "Static JavaScript analysis", "category": "Candidate careers link",
             "observed_at": candidate["observed_at"], "evidence": [candidate["source_url"]],
             "verification": "candidate"})
    for association in list(associations.values())[:max_boards]:
        if transport.stopped():
            break
        provider, tenant = association["provider"], association["tenant"]
        fetched = []

        def ats_fetch(url, params=None, **kwargs):
            target = url + ("?" + up.urlencode(params) if params else "")
            r = fetch(target, {up.urlsplit(target).hostname} & API_HOSTS)
            fetched.append(r)
            return r

        try:
            jobs = sources.SOURCE_ATS[provider](tenant, fetch=ats_fetch)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            status(association["url"], "error", f"ATS data could not be parsed: {type(exc).__name__}")
            continue
        valid = False
        for response in fetched:
            data = response.json(log_errors=False)
            valid = valid or (response.status == 200 and not response.error and
                (isinstance(data, list) if provider == "lever" else isinstance(data, dict) and
                 isinstance(data.get("content" if provider == "smartrecruiters" else "jobs"), list)))
        if jobs:
            jobs_add(jobs, fetched[-1].url if fetched else association["url"], association["source_url"])
        state = "ok" if jobs else "empty" if valid else "error"
        if jobs and any(r.error for r in fetched):
            state = "partial"
        status(association["url"], state, f"{provider}: {len(jobs)} published job(s)" if valid or jobs
               else f"{provider}: ATS unavailable or malformed response", len(jobs))
    for association in associations.values():
        result["findings"].append({"url": association["url"], "title": f"{association['provider']} careers board",
             "source_url": association["source_url"],
             "snippet": f"Company page links to tenant {association['tenant']}", "source": "Company ATS association",
             "category": "ATS", "observed_at": association["observed_at"],
             "evidence": [association["source_url"]], "verification": "company_page_link"})
    limited = (transport.stopped() or bool(queue) or len(scripts) > max_scripts
               or len(associations) > max_boards or len(result["jobs"]) >= max_jobs or bool(result["errors"]))
    result["limits"].update({"requests": transport.requests, "bytes": transport.bytes,
                        "pages_attempted": len(visited), "elapsed_seconds": round(time.monotonic()-started, 3),
                        "partial": limited, "cancelled": bool(cancel and cancel())})
    status(origin, "partial" if limited else "ok" if result["web"] else "error",
           "Bounded careers discovery finished; uncovered leads remain" if limited else "Careers discovery finished",
           len(result["jobs"]), result["limits"]["elapsed_seconds"])
    if db_path:
        from . import db
        with closing(db.connect(db_path)) as connection:
            result["saved_jobs"] = db.save_jobs(connection, result["jobs"])
            db.save_people_contacts(connection, result["emails"])
            db.save_osint_results(connection, host, result["web"] + result["findings"])
    if output:
        path = Path(output)
        path.mkdir(parents=True, exist_ok=True)
        target = path / "careers.json"
        target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        result["report_json"] = str(target.resolve())
    return result
