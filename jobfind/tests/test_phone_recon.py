import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jf import phone_recon, additional_tools, dossier, ai_agents, evidence_graph, dossier_history


class PhoneReconCheck(unittest.TestCase):
    def test_all_phone_results_survive_both_sampling_limits_and_merged_sources(self):
        digest = 'a' * 64
        ordinary = [dict(url=f'https://example.org/{index}', value=f'Ordinary result {index}', source='Fixture')
                    for index in range(250)]
        phone = [dict(url=f'https://www.google.com/search?q={index}', value=f'Phone query {index}',
                      module='PhoneInfoga', source='PhoneInfoga / googlesearch', sha256=digest,
                      attribution='Generated query; search not executed; no match established') for index in range(120)]
        merged = dict(url='https://example.org/phone-listing', title='Indexed phone candidate',
                      source='Bing', sources=['Bing', 'PhoneInfoga / googlecse'],
                      attribution='Indexed search candidate; identity unverified')
        baseline = ai_agents._evidence({'sections': {'findings': ordinary, 'web': ordinary}})
        report = {'sections': {'findings': [*ordinary, *phone, phone[0],
                              dict(module='PhoneInfoga', source='PhoneInfoga / numverify', status='error',
                                   url='https://example.org/error', value='Provider failure')],
                              'web': [*ordinary, merged]}}
        evidence = ai_agents._evidence(report)
        self.assertEqual(evidence[:80], baseline)
        self.assertEqual(len(evidence), 201)
        self.assertTrue({row['url'] for row in phone} <= {row['url'] for row in evidence})
        self.assertTrue(any(row['url'] == merged['url'] for row in evidence))
        self.assertFalse(any(row['url'] == 'https://example.org/error' for row in evidence))
        self.assertEqual([row['id'] for row in evidence], [f'E{i}' for i in range(1, 202)])

    def test_cli_routes_external_scans_and_keeps_local_mode_offline(self):
        import jobfind
        with patch.object(jobfind, 'cmd_phone', return_value=0) as command, patch.object(jobfind.apex_network, 'route') as route:
            self.assertEqual(jobfind.main(['phone', '--number', '+12025550123']), 0)
            route.assert_called_once()
            command.assert_called_once()
            route.reset_mock()
            self.assertEqual(jobfind.main(['phone', '--number', '+12025550123', '--local-only']), 0)
            route.assert_not_called()

    def test_all_scanners_preserve_evidence_queries_candidates_and_secrets(self):
        secret = 'test-provider-secret-never-persist'
        responses = {
            'local': {'state': 'ok', 'data': {'e164': '+12025550123', 'country': 'US'}},
            'googlesearch': {'state': 'ok', 'data': {'general': [
                {'dork': 'intext:12025550123', 'url': 'https://www.google.com/search?q=12025550123'}]}},
            'numverify': {'state': 'blocked', 'detail': 'HTTP 403 ' + secret},
            'ovh': {'state': 'ok', 'data': {'found': False}},
            'googlecse': {'state': 'ok', 'data': {'items': [
                {'title': 'Example public listing', 'url': 'https://example.org/contact'},
                {'title': 'Duplicate', 'url': 'https://example.org/contact'},
                {'title': 'Unsafe', 'url': 'javascript:alert(1)'}]}},
        }
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, 'is_file', return_value=True), patch.dict(
                'os.environ', {'NUMVERIFY_API_KEY': secret, 'GOOGLE_API_KEY': secret, 'GOOGLECSE_CX': 'fixture-cx'}), patch.object(
                additional_tools, '_run', side_effect=lambda cmd, *a, **kw: (0, json.dumps(responses[cmd[1]]))) as run:
            delta = phone_recon.collect('+12025550123', directory)
            self.assertEqual(run.call_count, 5)
            self.assertEqual([r['status'] for r in delta['statuses']], ['ok', 'ok', 'blocked', 'empty', 'ok', 'partial'])
            self.assertEqual(len(delta['web']), 1)
            self.assertNotIn(secret, json.dumps(delta))
            for artifact in delta['artifacts']:
                raw = Path(artifact['path']).read_bytes()
                self.assertNotIn(secret.encode(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact['sha256'])
            saved = dict(query='+12025550123', kind='phone', observed_at='2026-10-16T00:00:00Z',
                         sections={'domain': None}, source_checks=[], errors=[], artifacts=[])
            dossier.merge_delta(saved, delta)
            sampled = ai_agents._evidence(saved)
            self.assertTrue(any('Generated query' in r['attribution'] for r in sampled))
            self.assertTrue(any('identity unverified' in r['attribution'] for r in sampled))
            graph = evidence_graph.build_graph(saved)
            self.assertTrue(any(e.get('certainty') == 'interpretation' for e in graph['edges']))
            self.assertTrue(any(e.get('certainty') == 'interpretation' for e in dossier_history.timeline(saved)))
            self.assertTrue(any('PhoneInfoga' in row['source'] for row in dossier._report_rows(saved)))

    def test_invalid_missing_malformed_and_timeout_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            for number in ('2025550123', '+0123456789', '+123;echo x', '+1'):
                with self.assertRaises(ValueError):
                    phone_recon.collect(number, directory)
            with patch.object(Path, 'is_file', return_value=False):
                result = phone_recon.collect('+12025550123', directory)
                self.assertEqual(result['statuses'][0]['status'], 'skipped')
            for response, expected in (((0, 'garbage'), 'error'), ((124, 'private error'), 'timeout'),
                                       ((0, '{"state":"ok","data":[]}'), 'error')):
                with patch.object(Path, 'is_file', return_value=True), patch.object(additional_tools, '_run', return_value=response):
                    result = phone_recon.collect('+12025550123', directory)
                self.assertEqual(result['statuses'][0]['status'], expected)
                self.assertFalse(result['findings'])

    @unittest.skipUnless(phone_recon.ENGINE.is_file(), 'Run setup-phoneinfoga.bat for real upstream integration')
    def test_normal_search_runs_real_phoneinfoga_and_ai_cites_its_saved_artifact(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dossier.osint, 'search', return_value=([], [], [])), patch.object(
                dossier.extra_osint, 'supplement', return_value={}), patch.object(phone_recon, 'dotenv_values', return_value={}), patch.dict(
                'os.environ', {key: '' for key in phone_recon.KEYS}), patch.object(
                additional_tools, '_run', wraps=additional_tools._run) as run:
            result = dossier.collect('+12025550123', 'auto', 'full', Path(directory) / 'dossiers',
                                     include_spiderfoot=False, capture_pages=-1)
            self.assertEqual(result['kind'], 'phone')
            self.assertTrue(result['settings']['include_extra_tools'])
            self.assertEqual([call.args[0][1] for call in run.call_args_list], ['local', 'googlesearch', 'ovh'])
            saved = json.loads(Path(result['report_json']).read_text(encoding='utf-8'))
            phone_rows = [r for r in saved['sections']['findings'] if r.get('module') == 'PhoneInfoga']
            self.assertEqual(len(phone_rows), 46)
            statuses = {r['source']: r['state'] for r in saved['source_checks']}
            self.assertEqual(statuses['PhoneInfoga / local'], 'ok')
            self.assertEqual(statuses['PhoneInfoga / googlesearch'], 'ok')
            self.assertEqual(statuses['PhoneInfoga / googlecse'], 'skipped')
            graph = saved['relationship_graph']
            self.assertEqual(sum(n.get('kind') == 'Finding' and
                n['properties'].get('collector', '').startswith('PhoneInfoga') for n in graph['nodes']), 46)
            hashes = {row['sha256'] for row in phone_rows}
            self.assertTrue(hashes <= {h for e in graph['edges'] for h in e['evidence_hashes']})

            def provider(_provider, _model, _key, messages, _tokens):
                payload = json.loads(messages[1]['content'])
                evidence = payload['evidence']
                self.assertEqual(sum('module: PhoneInfoga' in row['text'] for row in evidence), len(phone_rows))
                local = next(e for e in evidence if e['section'] == 'findings' and 'Phone numbering plan' in e['text'])
                generated = next(e for e in evidence if 'Generated query' in e['attribution'])
                self.assertTrue(local['url'].startswith('artifact:sha256:'))
                self.assertIn(local['url'].rsplit(':', 1)[-1], hashes)
                self.assertIn('search not executed', generated['attribution'])
                return json.dumps({'claims': [dict(evidence_id=local['id'], quote=local['text'],
                    statement='PhoneInfoga reports numbering-plan metadata; subscriber identity is unverified. SHA-256: ' + local['url'].rsplit(':', 1)[-1], category='other')]})

            with patch.object(ai_agents, '_chat', side_effect=provider) as chat:
                analysis = ai_agents.analyze_dossier(saved, provider='groq', model='fixture-model', api_key='fixture-secret')
            chat.assert_called_once()
            self.assertEqual(analysis['status'], 'ok')
            self.assertEqual(len(analysis['claims']), 1)
            dossier.save_ai_analysis(saved, analysis)
            updated = json.loads(Path(saved['report_json']).read_text(encoding='utf-8'))
            self.assertEqual(updated['ai_analysis']['claims'][0]['source_url'], analysis['claims'][0]['source_url'])
            self.assertTrue(any(n['kind'] == 'AIClaim' for n in updated['relationship_graph']['nodes']))
            self.assertNotEqual(updated['quality_report']['status'], 'invariant_failures')

    def test_checksum_is_one_anchor_and_invented_hash_or_number_is_rejected(self):
        digest = '158d4d859857070cfd177e400025fb845d08fbebb5ea990e11b01f2dac214ab5'
        evidence = [dict(id='E1', text='Phone +12025550123; sha256: ' + digest,
                         url='artifact:sha256:' + digest, section='findings')]
        for label in ('sha256', 'SHA-256', 'SHA256'):
            statement = 'Phone +12025550123; ' + label + ': ' + digest
            content = json.dumps({'claims': [dict(evidence_id='E1', quote=evidence[0]['text'], statement=statement)]})
            claims, rejected = ai_agents._validated_claims(content, evidence)
            self.assertEqual((len(claims), rejected), (1, 0))
            for fabricated in (statement.replace(digest, '2' + digest[1:]), statement.replace('12025550123', '12025550124')):
                content = json.dumps({'claims': [dict(evidence_id='E1', quote=evidence[0]['text'], statement=fabricated)]})
                self.assertEqual(ai_agents._validated_claims(content, evidence), ([], 1))

    @unittest.skipUnless(phone_recon.ENGINE.is_file(), 'Run setup-phoneinfoga.bat for real upstream integration')
    def test_real_local_upstream_saved_dossier_without_external_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            result = phone_recon.investigate('+12025550123', directory, local_only=True)
            states = {r['source']: r['state'] for r in result['source_checks']}
            self.assertEqual(states['PhoneInfoga / local'], 'ok')
            self.assertEqual(states['PhoneInfoga / googlesearch'], 'ok')
            self.assertEqual(states['PhoneInfoga / ovh'], 'skipped')
            self.assertFalse(result['sections']['web'])
            self.assertTrue(result['sections']['findings'])
            self.assertTrue(Path(result['report_csv']).is_file())
            self.assertTrue(Path(result['report_json']).is_file())
            self.assertNotEqual(result['quality_report']['status'], 'invariant_failures')


if __name__ == '__main__':
    unittest.main()
