"""Offline checks for exact query submission to the public Ahmia index."""
import html
import sys
import unittest
import urllib.parse
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from jf import github_tools


class AhmiaQueryChecks(unittest.TestCase):
    def test_response_must_confirm_original_query(self):
        query = "neutral query " + "x" * 180
        url = "https://ahmia.fi/search/?" + urllib.parse.urlencode({"q": query})
        github_tools._verify_ahmia_query(query, url, "")
        github_tools._verify_ahmia_query(query, "https://ahmia.fi/search/",
            '<input name="q" value="' + html.escape(query, quote=True) + '">')
        for wrong in ("other", query[:100]):
            with self.assertRaises(RuntimeError):
                github_tools._verify_ahmia_query(query,
                    "https://ahmia.fi/search/?" + urllib.parse.urlencode({"q": wrong}), "")
        with self.assertRaises(RuntimeError):
            github_tools._verify_ahmia_query(query, "https://ahmia.fi/", "<body>Directory</body>")

    def test_browser_submits_all_200_characters(self):
        query = "x" * 200
        field, locator, page, context, browser, driver = [MagicMock() for _ in range(6)]
        locator.first = field
        locator.count.return_value = 1
        page.locator.return_value = locator
        page.content.return_value = '<li class="result"><h4>Neutral result</h4></li>'
        page.url = "https://ahmia.fi/search/?" + urllib.parse.urlencode({"q": query})
        context.new_page.return_value = page
        browser.new_context.return_value = context
        driver.chromium.launch.return_value = browser
        entry = MagicMock()
        entry.__enter__.return_value = driver
        package = SimpleNamespace(sync_playwright=MagicMock(return_value=entry))
        with patch.dict(sys.modules, {"playwright.sync_api": package}):
            result = github_tools._ahmia_browser(query)
        field.fill.assert_called_once_with(query)
        self.assertEqual(result["url"], page.url)
        browser.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
