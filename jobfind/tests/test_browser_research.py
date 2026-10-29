import hashlib
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from jf import ai_agents, browser_research as browser, evidence_capture, library


class BrowserTests(unittest.TestCase):
    def test_structured_rows_links_and_limits(self):
        html = '''<script type="application/ld+json">{"@graph":[{"@type":"Organization","name":"Aster"}]}</script>
            <table><tr><th>Name</th><th>Year</th></tr><tr><td>Aster</td><td>2020</td></tr></table>
            <article><h2>Card</h2><a href="/item">Public record</a></article>
            <a rel="next" href="/page/2">Next</a><a rel="next" href="https://other.org/next">Next</a>
            <a rel="next" href="/next?token=private">Next</a>'''
        rows, following = browser.extract(html, 'https://example.org/', 100)
        self.assertEqual(following, ['https://example.org/page/2'])
        table = json.loads(next(r['value'] for r in rows if r['title'] == 'Table 1 · row 2'))
        self.assertEqual(table['cells'], ['Aster', '2020'])
        self.assertEqual(table['columns'], ['Name', 'Year'])
        self.assertEqual(len(browser.extract(html, 'https://example.org/', 1)[0]), 1)
        self.assertTrue(any(r['linked_url'] == 'https://example.org/item' for r in rows))

    def test_private_urls_and_mixed_dns_never_launch_worker(self):
        with tempfile.TemporaryDirectory() as directory, patch('jf.additional_tools._run') as worker:
            for url in ('http://127.0.0.1/', 'https://user:pass@example.org/', 'https://example.org:8443/'):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    browser.collect(url, Path(directory))
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in ('93.184.216.34', '127.0.0.1')]
            with patch.object(socket, 'getaddrinfo', return_value=answers), self.assertRaises(ValueError):
                browser.collect('https://example.org/', Path(directory))
            worker.assert_not_called()

    def test_challenge_is_not_evidence(self):
        delta = {key: [] for key in ('web', 'findings', 'emails', 'profiles', 'statuses', 'artifacts')}
        with tempfile.TemporaryDirectory() as directory:
            browser._save_page(delta, '<title>Verify you are human</title><p>Challenge</p>',
                               'https://example.org/', Path(directory), 50, None)
        self.assertEqual(delta['statuses'][0]['state'], 'blocked')
        self.assertFalse(delta['web'])
        self.assertFalse(delta['findings'])

    def test_worker_timeout_retains_completed_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / 'browser'
            folder.mkdir()
            (folder / 'browser-delta.json').write_text(json.dumps(dict(web=[{'title': 'Retained'}], statuses=[])))
            with patch.object(evidence_capture, 'validated_url', return_value=('https://example.org/', 'example.org', ['93.184.216.34'])), \
                    patch('jf.additional_tools._run', return_value=(124, 'not displayed')):
                delta = browser.collect('https://example.org/', Path(directory))
        self.assertEqual(delta['web'][0]['title'], 'Retained')
        self.assertEqual(delta['statuses'][-1]['state'], 'timeout')

    def test_protocol_redirect_is_blocked_before_connecting_again(self):
        from unittest.mock import Mock
        reply = Mock(status=302)
        reply.getheaders.return_value = [('Location', 'http://example.org/downgrade')]
        connection = Mock(sock=None)
        connection.getresponse.return_value = reply
        with patch.object(socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('93.184.216.34', 443))]), \
                patch.object(evidence_capture, '_PinnedConnection', return_value=connection) as connect:
            with self.assertRaisesRegex(ValueError, 'protocol'):
                evidence_capture.fetch_public('https://example.org/', allowed_hosts={'example.org'}, allowed_scheme='https')
        self.assertEqual(connect.call_count, 1)

    def test_every_browser_record_is_supplied_to_ai(self):
        data = dict(sections=dict(findings=[dict(source=browser.SOURCE, title=f'Record {i}', value=f'RECORD-{i}',
                        url=f'https://example.org/page/{i}') for i in range(100)]))
        evidence = ai_agents._evidence(data)
        self.assertEqual(len(evidence), 100)
        self.assertEqual(len({r['id'] for r in evidence}), 100)

    def test_real_chromium_dynamic_pagination_dossier_graph_ai_and_rag(self):
        calls = []
        script = '''fetch('/data.json').then(r=>r.json()).then(r=>{
            let a=document.createElement('article'); a.innerHTML='<h2>'+r.name+'</h2><a href="/item">Public card</a>'; document.body.append(a);
            let p=document.createElement('p'); p.textContent='padding '.repeat(800)+' LATE-MARKER-9381'; document.body.append(p);
            }); fetch('/write',{method:'POST',body:'denied'}).catch(()=>{});
            fetch('https://other.org/out').catch(()=>{});
            fetch('http://127.0.0.1/private').catch(()=>{});'''
        documents = {
            'https://example.org/catalog': ('text/html', '<title>Dynamic directory</title><script src="/app.js"></script><a rel="next" href="/page/2">Next</a>'),
            'https://example.org/app.js': ('application/javascript', script),
            'https://example.org/data.json': ('application/json', '{"name":"DYNAMIC-9381"}'),
            'https://example.org/page/2': ('text/html', '<title>Second page</title><table><tr><th>Record</th><th>Year</th></tr><tr><td>ASTER-2244</td><td>2020</td></tr></table>'),
        }

        def fetch(url, **kwargs):
            calls.append(url)
            self.assertEqual(kwargs['allowed_hosts'], {'example.org'})
            self.assertEqual(kwargs['allowed_scheme'], 'https')
            if url.endswith('/data.json') and calls.count(url) == 1:
                raise TimeoutError('Synthetic transient GET failure')
            mime, html = documents[url]
            return dict(url=url, http_status=200, content_type=mime, body=html.encode(), html=html)

        def validated(url, *_args):
            return url, 'example.org', ['93.184.216.34']

        def provider(_provider, _model, _key, messages, _tokens):
            data = json.loads(messages[1]['content'])
            row = next(r for r in data['evidence'] if 'DYNAMIC-9381' in r['text'])
            return json.dumps({'claims': [dict(evidence_id=row['id'], quote='DYNAMIC-9381',
                statement='The public directory lists DYNAMIC-9381.', category='other'),
                dict(evidence_id=row['id'], quote='Invented content', statement='Unsupported')]})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(evidence_capture, 'validated_url', side_effect=validated), \
                    patch.object(evidence_capture, 'fetch_public', side_effect=fetch):
                delta = browser._render('https://example.org/catalog', root / 'rendered', 2, 50)
            self.assertEqual(len(delta['web']), 2)
            self.assertTrue(any('DYNAMIC-9381' in r['value'] for r in delta['findings']))
            self.assertTrue(any('ASTER-2244' in r['value'] for r in delta['findings']))
            self.assertEqual(set(calls), set(documents))
            self.assertTrue(any(r['state'] == 'partial' for r in delta['statuses']))
            self.assertTrue(any(Path(a['path']).suffix == '.png' for a in delta['artifacts']))
            # Render into the dossier's own folder so the normal RAG containment guard remains active.
            def collect(url, folder, **_options):
                target = folder / 'browser'
                target.mkdir()
                for row in delta['web']:
                    meta = json.loads(Path(row['metadata']).read_text())
                    text = Path(next(p for p in meta['files'] if p.endswith('.txt'))).read_bytes()
                    dest = target / (hashlib.sha256(text).hexdigest() + '.txt')
                    dest.write_bytes(text)
                    metadata = dest.with_suffix('.json')
                    metadata.write_text(json.dumps({'files': [str(dest)]}))
                    row['metadata'] = str(metadata)
                return delta
            with patch.object(evidence_capture, 'validated_url', side_effect=validated), patch.object(browser, 'collect', side_effect=collect), \
                    patch.object(ai_agents, '_settings', return_value=('groq', 'fixture', 'fixture-secret')), \
                    patch.object(ai_agents, '_chat', side_effect=provider):
                result = browser.run('https://example.org/catalog', root, question='Dynamic directory', ai=True)
            saved = Path(result['report_json'])
            self.assertTrue(saved.is_file())
            self.assertTrue(Path(result['report_csv']).is_file())
            self.assertTrue(Path(result['graph_path']).is_file())
            self.assertTrue(result['relationship_graph']['nodes'])
            self.assertEqual(result['ai_analysis']['status'], 'partial')
            self.assertEqual(result['ai_analysis']['rejected_claims'], 1)
            self.assertEqual(result['ai_analysis']['claims'][0]['source_url'], 'https://example.org/catalog')
            self.assertNotIn('fixture-secret', saved.read_text(encoding='utf-8'))
            diagnostics = Path(result['diagnostics']['trace_path']).read_text(encoding='utf-8')
            self.assertNotIn('https://', diagnostics)
            self.assertNotIn('DYNAMIC-9381', diagnostics)
            self.assertEqual(result['diagnostics']['network_retries'], 1)
            with patch.object(library.analytics_models, 'embed_texts', side_effect=lambda texts: np.tile(np.array([1., 0., 0.], dtype=np.float32), (len(texts), 1))):
                found = library.search('LATE-MARKER-9381', root, roots=[root / 'dossiers'])
            self.assertTrue(any('LATE-MARKER-9381' in r['text'] and r['section'] == 'captured_text' for r in found['evidence']))

    def test_real_chromium_http_429_is_blocked_and_not_retried(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(evidence_capture, 'validated_url', return_value=('https://example.org/', 'example.org', ['93.184.216.34'])), \
                patch.object(evidence_capture, 'fetch_public', side_effect=RuntimeError('HTTP 429')) as fetch:
            delta = browser._render('https://example.org/', Path(directory), 1, 50)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(delta['statuses'][0]['state'], 'blocked')
        self.assertFalse(delta['web'])

    def test_real_chromium_script_failure_retains_partial_page(self):
        html = '<title>Partial directory</title><p>Published text</p><script>throw new Error("fixture")</script>'
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(evidence_capture, 'validated_url', return_value=('https://example.org/', 'example.org', ['93.184.216.34'])), \
                patch.object(evidence_capture, 'fetch_public', return_value=dict(url='https://example.org/', http_status=200,
                    content_type='text/html', body=html.encode())):
            delta = browser._render('https://example.org/', Path(directory), 1, 50)
        self.assertEqual(delta['statuses'][0]['state'], 'partial')
        self.assertIn('Published text', delta['web'][0]['snippet'])


if __name__ == '__main__':
    unittest.main()
