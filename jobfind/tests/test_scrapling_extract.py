import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jf import ai_agents, browser_research, evidence_capture, scrapling_extract


class ScraplingChecks(unittest.TestCase):
    def test_exact_then_relocated_and_domain_isolation(self):
        before = '<html><body><section><article id="job"><h2>Security analyst</h2><p>Company A</p></article></section></body></html>'
        after = before.replace('id="job"', 'class="job"')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, check = scrapling_extract.extract(before, 'https://example.org/jobs', '#job', root, 10)
            self.assertEqual(check['state'], 'ok')
            self.assertEqual(first[0]['value'], 'Security analyst Company A')
            candidate, check = scrapling_extract.extract(after, 'https://example.org/jobs', '#job', root, 10)
            self.assertEqual(check['state'], 'partial')
            self.assertEqual(candidate[0]['method'], 'adaptive relocation')
            self.assertIn('Candidate', candidate[0]['attribution'])
            self.assertEqual(len(candidate[0]['baseline_sha256']), 64)
            other, check = scrapling_extract.extract(after, 'https://other.org/jobs', '#job', root, 10)
            self.assertEqual(other, [])
            self.assertEqual(check['state'], 'empty')

    def test_source_evidence_and_invalid_selector(self):
        html = '<title>Jobs</title><div class="vacancy">Analyst Company A</div>'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            delta = {key: [] for key in ('web', 'findings', 'profiles', 'emails', 'artifacts', 'statuses', 'errors')}
            browser_research._save_page(delta, html, 'https://example.org/jobs', root, 10, None, '.vacancy', root / 'state')
            row = next(item for item in delta['findings'] if item['source'] == scrapling_extract.SOURCE)
            self.assertEqual(row['url'], 'https://example.org/jobs')
            self.assertEqual(len(row['sha256']), 64)
            evidence = ai_agents._evidence({'sections': {'findings': [row]}}, complete=True)
            self.assertTrue(any('Analyst Company A' in item['text'] for item in evidence))
            self.assertTrue(any(item['url'] == row['url'] for item in evidence))
            with patch('jf.evidence_capture.validated_url') as dns:
                with self.assertRaises(ValueError):
                    browser_research.collect('https://example.org', root, selector='a::text')
                dns.assert_not_called()

    def test_rendered_browser_runs_scrapling_on_changed_page(self):
        before = '<title>Jobs</title><section><article id="job"><h2>Security analyst</h2><p>Company A</p></article></section>'
        after = before.replace('id="job"', 'class="job"')
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(evidence_capture, 'validated_url', return_value=('https://example.org/jobs', 'example.org', ['93.184.216.34'])), \
                patch.object(evidence_capture, 'fetch_public') as fetch:
            root = Path(directory)
            for index, html in enumerate((before, after)):
                fetch.return_value = dict(url='https://example.org/jobs', http_status=200, content_type='text/html', body=html.encode())
                delta = browser_research._render('https://example.org/jobs', root / str(index), 1, 10, '#job', root / 'state')
                check = next(row for row in delta['statuses'] if row['source'] == scrapling_extract.SOURCE)
                self.assertEqual(check['state'], 'ok' if index == 0 else 'partial')
                self.assertTrue(any(row.get('source') == scrapling_extract.SOURCE for row in delta['findings']))
            self.assertEqual(fetch.call_count, 2)


if __name__ == '__main__':
    unittest.main()
