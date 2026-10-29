import json
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from contextlib import closing
from unittest.mock import patch

from jf import careers, db, net


class CareersTests(unittest.TestCase):
    def fixture(self, pages, *, callbacks=None, **options):
        fetched = []

        def fetch(transport, url, hosts, per_resource=750_000):
            self.assertIn(careers.up.urlsplit(url).hostname, hosts)
            fetched.append(url)
            transport.requests += 1
            payload = pages.get(url)
            if payload is None:
                response = net.HttpResult(404, b"", url, "HTTP 404", {"state": "empty", "elapsed_seconds": .01})
            else:
                body, content_type = payload if isinstance(payload, tuple) else (payload, "text/html")
                response = net.HttpResult(200, body.encode(), url, metadata={"state": "ok", "elapsed_seconds": .01})
                response.content_type = content_type
                transport.bytes += len(response.body)
            return response

        with patch.object(careers.osint_contacts, "_public_host", return_value=True), patch.object(careers._Transport, "fetch", fetch):
            result = careers.collect("company.example", on_status=callbacks, **options)
        return result, fetched

    def test_company_link_reuses_ats_adapter_and_deduplicates_db(self):
        pages = {
            "https://company.example/robots.txt": "User-agent: *\nAllow: /",
            "https://company.example/": '<a href="/careers">Careers</a><a href="/contact">Contact</a>',
            "https://company.example/careers": '<a href="https://jobs.ashbyhq.com/example">Jobs</a>',
            "https://company.example/contact": '<a href="mailto:hr@fixture-company.dev">Write to HR</a>',
            "https://api.ashbyhq.com/posting-api/job-board/example": (json.dumps({"jobs": [{"title": "Engineer", "jobUrl": "https://jobs.ashbyhq.com/example/job-1"}]}), "application/json"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.sqlite"
            result, fetched = self.fixture(pages, db_path=path, output=Path(tmp) / "results")
            again, _ = self.fixture(pages, db_path=path)
            with closing(db.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(result["saved_jobs"][0], 1)
            self.assertEqual(again["saved_jobs"][0], 0)
            self.assertTrue(Path(result["report_json"]).is_file())
        self.assertEqual(len(result["jobs"]), 1)
        self.assertEqual(result["jobs"][0]["association_source_url"], "https://company.example/careers")
        self.assertEqual(result["emails"][0]["email"], "hr@fixture-company.dev")
        self.assertEqual(result["ats_links"][0]["verification"], "company_page_link")
        self.assertIn("https://api.ashbyhq.com/posting-api/job-board/example", fetched)

    def test_sitemap_and_javascript_leads_are_bounded_and_not_apis(self):
        pages = {
            "https://company.example/robots.txt": "User-agent: *\nAllow: /\nSitemap: https://company.example/index.xml",
            "https://company.example/index.xml": ('<sitemapindex><sitemap><loc>https://company.example/nested.xml</loc></sitemap></sitemapindex>', "application/xml"),
            "https://company.example/nested.xml": ('<urlset><url><loc>https://company.example/team/careers</loc></url><url><loc>https://private.example/jobs</loc></url></urlset>', "application/xml"),
            "https://company.example/": '<script src="/static/app.js"></script>',
            "https://company.example/team/careers": '<a href="mailto:jobs@fixture-company.dev">Jobs</a>',
            "https://company.example/static/app.js": ('const jobs="https://jobs.lever.co/guess"; const api="/api/jobs/delete";', "application/javascript"),
        }
        result, fetched = self.fixture(pages)
        self.assertEqual(len(result["js_candidates"]), 2)
        self.assertTrue(all(x["verification"] == "candidate" for x in result["js_candidates"]))
        self.assertFalse(result["ats_links"])
        self.assertFalse(any("api.lever.co" in x or "/api/jobs" in x or "private.example" in x for x in fetched))
        self.assertEqual(result["emails"][0]["email"], "jobs@fixture-company.dev")
        self.assertTrue(any(row["verification"] == "candidate" for row in result["findings"]))

    def test_jsonld_jobs_are_published_on_company_page(self):
        structured = {"@context": "https://schema.org", "@type": "JobPosting", "title": "Designer",
                      "url": "https://company.example/jobs/design", "description": "Email design@fixture-company.dev"}
        result, _ = self.fixture({"https://company.example/robots.txt": "User-agent: *\nAllow: /",
                                "https://company.example/": '<script type="application/ld+json">' + json.dumps(structured) + "</script>"})
        self.assertEqual(result["jobs"][0]["title"], "Designer")
        self.assertEqual(result["jobs"][0]["evidence"], ["https://company.example/"])
        self.assertEqual(result["emails"][0]["email"], "design@fixture-company.dev")

    def test_robots_disallow_and_unavailable_fail_closed(self):
        result, fetched = self.fixture({"https://company.example/robots.txt": "User-agent: *\nDisallow: /"})
        self.assertFalse(result["web"])
        self.assertEqual(fetched, ["https://company.example/robots.txt"])
        self.assertTrue(any(s["state"] == "skipped" for s in result["statuses"]))
        with patch.object(careers.osint_contacts, "_public_host", return_value=True), patch.object(careers._Transport, "fetch") as fetch:
            response = net.HttpResult(403, b"", "https://company.example/robots.txt", "HTTP 403", {"state": "blocked", "elapsed_seconds": .01})
            fetch.return_value = response
            result = careers.collect("company.example")
        self.assertEqual(fetch.call_count, 1)
        self.assertFalse(result["web"])

    def test_empty_ats_and_malformed_ats_are_different(self):
        base = {"https://company.example/robots.txt": "User-agent: *\nAllow: /",
                "https://company.example/": '<a href="https://jobs.ashbyhq.com/example">Careers</a>'}
        for payload, state in [('{"jobs":[]}', "empty"), ('{"unexpected":[]}', "error")]:
            result, _ = self.fixture({**base, "https://api.ashbyhq.com/posting-api/job-board/example": (payload, "application/json")})
            row = next(s for s in result["statuses"] if s["url"] == "https://jobs.ashbyhq.com/example")
            self.assertEqual(row["state"], state)

    def test_cancelled_collection_stops_after_policy(self):
        result, fetched = self.fixture({"https://company.example/robots.txt": "User-agent: *\nAllow: /"}, cancel=lambda: True)
        self.assertEqual(len(fetched), 1)
        self.assertTrue(result["limits"]["cancelled"])
        self.assertFalse(result["web"])

    def test_page_limits_and_callbacks(self):
        calls = []
        result, _ = self.fixture({"https://company.example/robots.txt": "User-agent: *\nAllow: /",
                                "https://company.example/": '<a href="/careers/one">Jobs</a>'},
                               max_pages=1, callbacks=calls.append)
        self.assertEqual(result["limits"]["pages_attempted"], 1)
        self.assertTrue(result["limits"]["partial"])
        self.assertEqual(calls, result["statuses"])

    def test_tenant_not_guessed_and_invalid_inputs(self):
        self.assertEqual(careers.ats_identity("https://boards.greenhouse.io/embed/job_board?for=fixture"), ("greenhouse", "fixture"))
        self.assertIsNone(careers.ats_identity("https://jobs.ashbyhq.com"))
        self.assertIsNone(careers.ats_identity("https://jobs.ashbyhq.com/a%2Fb"))
        self.assertIsNone(careers.ats_identity("https://jobs.ashbyhq.com/../x"))
        for value in ["http://company.example", "https://user:pass@company.example", "https://company.example:444"]:
            with self.assertRaises(ValueError):
                careers.collect(value)
        with patch.object(careers.osint_contacts, "_public_host", return_value=False):
            with self.assertRaises(ValueError):
                careers.collect("private.example")

    def test_redirect_private_crosshost_and_https_boundary(self):
        req = urllib.request.Request("https://company.example/")
        for target in ["https://private.example/jobs", "http://company.example/jobs", "https://company.example/jobs"]:
            with patch.object(careers.osint_contacts, "_public_host", return_value=False):
                with self.assertRaises(urllib.error.URLError):
                    careers._Redirect({"company.example"}).redirect_request(req, None, 302, "redirect", {}, target)

    def test_transport_resource_size_limit(self):
        class Response:
            status = 200
            def __init__(self):
                self.offset = 0
                self.headers = type("Headers", (), {"get_content_type": lambda _: "text/html"})()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return "https://company.example/"
            def read(self, size):
                body = b"X" * 100
                value = body[self.offset:self.offset+size]
                self.offset += len(value)
                return value
        transport = careers._Transport(time.monotonic()+5, 1000, None)
        with patch.object(careers.osint_contacts, "_public_host", return_value=True), patch.object(careers.net, "_polite_wait"), patch.object(careers.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = Response()
            response = transport.fetch("https://company.example/", {"company.example"}, per_resource=50)
        self.assertEqual(response.metadata["state"], "partial")
        self.assertFalse(response.body)
        self.assertEqual(transport.bytes, 51)
        handlers = opener.call_args.args
        self.assertIsInstance(handlers[0], urllib.request.ProxyHandler)

    def test_ats_contact_evidence_is_fetched_api_not_unread_job_page(self):
        api = "https://boards-api.greenhouse.io/v1/boards/fixture/jobs?content=true"
        pages = {"https://company.example/robots.txt": "User-agent: *\nAllow: /",
                 "https://company.example/": '<iframe src="https://boards.greenhouse.io/embed/job_board?for=fixture"></iframe>',
                 api: (json.dumps({"jobs": [{"title": "Analyst", "absolute_url": "https://boards.greenhouse.io/fixture/jobs/1",
                                            "content": "Contact recruiting@fixture-company.dev"}]}), "application/json")}
        result, fetched = self.fixture(pages)
        self.assertEqual(result["emails"][0]["url"], api)
        self.assertEqual(result["emails"][0]["evidence"], [api])
        self.assertNotIn("https://boards.greenhouse.io/fixture/jobs/1", fetched)


if __name__ == "__main__":
    unittest.main()
