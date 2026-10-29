"""Offline check that integrated sources reach one result and its history."""

import io
import json
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import jobfind
from jf import contacts


def test_unified_osint():
    with TemporaryDirectory() as temporary, ExitStack() as mocks:
        mocks.enter_context(patch.object(jobfind.osint, "search", return_value=([], [], [])))
        mocks.enter_context(patch.object(jobfind.github_tools, "github_email", return_value={
            "status": "found", "email": "author@example.org", "source_url": "https://github.com/target/demo/commit/abc.patch"}))
        mocks.enter_context(patch.object(jobfind.github_tools, "maigret_search", return_value={
            "rows": [{"site": "GitHub", "url": "https://github.com/target"}]}))
        mocks.enter_context(patch.object(jobfind.github_tools, "tiktok_profile", return_value={
            "name": "Target", "bio": "Public profile", "url": "https://www.tiktok.com/@target", "source": "TikTok Scraper"}))
        mocks.enter_context(patch.object(jobfind.spiderfoot_scan, "scan", return_value={
            "status": "ok", "error": "", "target": "target", "target_type": "USERNAME",
            "use_case": "passive", "modules": 1, "scan_id": "T", "database": "",
            "timed_out": False, "event_count": 0, "rows": [], "emails": [], "errors": []}))
        mocks.enter_context(patch.object(jobfind.extra_osint, "supplement", return_value={
            "profiles": [], "web": [], "findings": [], "hostnames": [], "errors": []}))
        args = SimpleNamespace(query="target", mode="full", sources="wikipedia", domain="", username="",
                               onion=False, db=str(Path(temporary) / "data.db"), out=temporary)
        output = io.StringIO()
        with redirect_stdout(output):
            assert jobfind.cmd_osint_search(args) == 0
        result = json.loads(output.getvalue())
        assert len(result["results"]) == 2 and len(result["emails"]) == 1
        assert set(result["integrations"]) == {"github_email", "maigret", "tiktok", "spiderfoot", "public"}
        output = io.StringIO()
        with redirect_stdout(output):
            jobfind.cmd_osint_history(SimpleNamespace(query="target", db=args.db))
        history = json.loads(output.getvalue())
        assert len(history["emails"]) == 1 and len(history["integrations"]) == 5


def test_company_without_domain():
    with ExitStack() as mocks:
        mocks.enter_context(patch.object(jobfind.osint, "search", return_value=([
            {"title": "Web3Tech", "url": "https://web3tech.org/", "source": "Bing"},
            {"title": "Web3Tech", "url": "https://web3tech.ru/", "source": "Bing"},
            {"title": "Web3Tech", "url": "https://www.linkedin.com/company/web3tech/", "source": "Bing"},
        ], [], [])))
        crawl = mocks.enter_context(patch.object(jobfind.osint_contacts, "find_public_emails"))
        output = io.StringIO()
        with redirect_stdout(output):
            assert jobfind.cmd_contact_search(SimpleNamespace(company="web3tech", domain="", name="", db="")) == 0
        result = json.loads(output.getvalue())
        assert result["needs_domain"] and {row["domain"] for row in result["candidates"]} == {"web3tech.org", "web3tech.ru"}
        crawl.assert_not_called()


def test_email_examples_are_ignored():
    assert contacts.extract_emails("-help@apache.org user@oldname.example jobs@apache.org") == ["jobs@apache.org"]


def test_job_query_requires_role_match():
    assert not jobfind._matches_job_query({"title": "Machine Learning Engineer",
                                           "description": "Software for photographers"}, "photographer")
    assert jobfind._matches_job_query({"title": "Studio Photographer",
                                       "description": "Product shoots"}, "photographer")
    assert jobfind._matches_job_query({"title": "Backend Engineer",
                                       "description": "Build services with Rust"}, "Rust backend")


def test_exact_github_name():
    with patch.object(jobfind.osint, "_json", return_value={"items": [
        {"full_name": "web3stack/web3techstack", "name": "web3techstack", "owner": {"login": "web3stack"},
         "html_url": "https://github.com/web3stack/web3techstack", "description": "unrelated"},
        {"full_name": "web3tech/project", "name": "project", "owner": {"login": "web3tech"},
         "html_url": "https://github.com/web3tech/project", "description": "account repository"},
    ]}):
        assert [row["url"] for row in jobfind.osint._github("web3tech")] == ["https://github.com/web3tech/project"]


def test_email_only_osint():
    with TemporaryDirectory() as temporary, ExitStack() as mocks:
        mocks.enter_context(patch.object(jobfind.osint, "search", side_effect=AssertionError("full search ran")))
        mocks.enter_context(patch.object(jobfind.spiderfoot_scan, "scan", return_value={
            "status": "ok", "error": "", "target": "example.org", "target_type": "INTERNET_NAME",
            "use_case": "passive", "modules": 1, "scan_id": "T", "database": "",
            "timed_out": False, "event_count": 0, "rows": [], "emails": [], "errors": []}))
        mocks.enter_context(patch.object(jobfind.osint_contacts, "find_public_emails", return_value=[
            {"email": "jobs@example.org", "company": "example.org", "domain": "example.org",
             "verification": "published", "evidence": ["https://example.org/careers"]},
            {"email": "guess@example.org", "company": "example.org", "domain": "example.org",
             "verification": "guess", "evidence": []},
        ]))
        args = SimpleNamespace(query="example.org", mode="email", sources="", domain="", username="",
                               onion=False, db=str(Path(temporary) / "data.db"), out=temporary)
        output = io.StringIO()
        with redirect_stdout(output):
            assert jobfind.cmd_osint_search(args) == 0
        result = json.loads(output.getvalue())
        assert result["mode"] == "email" and result["results"] == []
        assert result["emails"] == [{"email": "jobs@example.org", "url": "https://example.org/careers"}]
        conn = jobfind.db.connect(Path(args.db))
        saved = conn.execute("SELECT verification FROM people_contacts WHERE email=?", ("jobs@example.org",)).fetchone()
        conn.close()
        assert saved["verification"] == "published"
        mocks.enter_context(patch.object(jobfind.github_tools, "github_email", return_value={
            "email": "author@example.org", "source_url": "https://github.com/target/demo/commit/abc.patch",
            "errors": []}))
        args.query = "@target"
        output = io.StringIO()
        with redirect_stdout(output):
            assert jobfind.cmd_osint_search(args) == 0
        result = json.loads(output.getvalue())
        assert result["emails"] == [{"email": "author@example.org",
                                     "url": "https://github.com/target/demo/commit/abc.patch"}]
        assert set(result["integrations"]) == {"github_email", "spiderfoot"}


def test_google_modern_desktop_and_mobile_result_parser():
    document = '''<html><div><a href="https://example.org/search?q=alpha%20beta"><h3>Example.org official page</h3></a><div>A public example.org result with a detailed contextual snippet that belongs to this page.</div></div>
        <div><h3><a href="/url?q=https%3A%2F%2Fexample.org%2Fabout%3Ftopic%3Dtwo%26lang%3Den&sa=U">About example.org</a></h3><p>Public description</p></div>
        <a href="https://example.org/search?q=alpha%20beta"><h3>Duplicate example.org result</h3></a>
        <a href="/search?q=example.org"><h3>More example.org results</h3></a>
        <a href="javascript:alert(1)"><h3>example.org fake</h3></a></html>'''
    rows = jobfind.osint._google_rows(document, "example.org", 10)
    assert [row["url"] for row in rows] == ["https://example.org/search?q=alpha%20beta", "https://example.org/about?topic=two&lang=en"]
    assert all(row["source"] == "Google" for row in rows)
    assert "contextual snippet" in rows[0]["snippet"]


def test_google_captcha_detection_and_ordinary_empty_results():
    assert jobfind.osint._google_blocked('<form action="/sorry/index"><div class="g-recaptcha"></div></form>')
    assert jobfind.osint._google_blocked("Our systems have detected unusual traffic from your computer network")
    assert jobfind.osint._google_blocked("", "https://www.google.com/sorry/index")
    assert not jobfind.osint._google_blocked("<h3>CAPTCHA research article</h3><p>Public description.</p>")


def test_google_ddgs_failure_calls_same_google_browser():
    with patch("ddgs.DDGS") as client, patch.object(jobfind.osint, "_google_browser", return_value=[
        {"title": "example.org", "url": "https://example.org/", "snippet": "Public", "source": "Google", "category": "Web"}]) as browser:
        client.return_value.text.side_effect = RuntimeError("No results found.")
        rows = jobfind.osint._engine("example.org", "google", 10)
        browser.assert_called_once_with("example.org", 10)
        assert rows[0]["source"] == "Google"


def test_google_browser_failure_and_partial_warning_reach_ledger():
    with patch.object(jobfind.osint, "_engine", side_effect=RuntimeError("Google requires CAPTCHA/human verification")):
        rows, errors, statuses = jobfind.osint.search("example.org", ["google"])
        assert not rows and "CAPTCHA" in errors[0] and "CAPTCHA" in statuses[0]["error"]
    with patch.object(jobfind.osint, "_engine", return_value=[
        {"title": "example.org", "url": "https://example.org/", "snippet": "Public", "source": "Google", "category": "Web", "_source_warning": "Google page 2: HTTP 429"}]):
        rows, errors, statuses = jobfind.osint.search("example.org", ["google"])
        assert len(rows) == 1 and statuses[0]["count"] == 1 and "HTTP 429" in statuses[0]["error"]
        assert "_source_warning" not in rows[0]


if __name__ == "__main__":
    test_unified_osint()
    test_company_without_domain()
    test_email_examples_are_ignored()
    test_job_query_requires_role_match()
    test_exact_github_name()
    test_email_only_osint()
    test_google_modern_desktop_and_mobile_result_parser()
    test_google_captcha_detection_and_ordinary_empty_results()
    test_google_ddgs_failure_calls_same_google_browser()
    test_google_browser_failure_and_partial_warning_reach_ledger()
