import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from jf import ai_agents, library, pdf_documents


def fake_vectors(texts):
    # Deterministic unit vectors isolate index/citation contracts from model quality.
    return np.tile(np.array([1., 0., 0.], dtype=np.float32), (len(texts), 1))


class LibraryTests(unittest.TestCase):
    def source(self, folder, name, text, source='https://example.org/source'):
        path = folder / 'dossiers' / name / 'dossier.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        data = dict(query=name, kind='person', observed_at='2026-10-19T00:00:00Z',
                    sections={'web': [dict(title=name, text=text, url=source, source='Fixture')], 'domain': None}, errors=[])
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    @patch.object(library.analytics_models, 'embed_texts', side_effect=fake_vectors)
    def test_all_dossiers_incremental_update_removed_source_and_snapshots(self, _embed):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = self.source(root, 'Aster', 'ASTER-9381 was registered in 2019.')
            b = self.source(root, 'Birch', 'BIRCH-2299 was registered in 2021.')
            result = library.refresh(root, [root / 'dossiers'])
            self.assertEqual(result['document_count'], 2)
            self.assertEqual(result['chunk_count'], 2)
            again = library.refresh(root, [root / 'dossiers'])
            self.assertEqual(again['chunk_count'], 2)
            self.assertTrue(all(row['status'] == 'cached' for row in again['sources']))
            found = library.search('ASTER-9381', root, roots=[root / 'dossiers'])
            original = next(r for r in found['evidence'] if r['title'] == 'Aster')
            self.assertEqual(hashlib.sha256(Path(original['snapshot_path']).read_bytes()).hexdigest(), original['document_sha256'])
            a.write_text(a.read_text().replace('2019', '2020'))
            library.refresh(root, [root / 'dossiers'])
            self.assertIn('2019', Path(original['snapshot_path']).read_text())
            b.unlink()
            updated = library.search('BIRCH-2299', root, roots=[root / 'dossiers'])
            self.assertFalse(any(row['title'] == 'Birch' for row in updated['evidence']))
            self.assertTrue(any(row['status'] == 'missing' for row in updated['inventory']['sources']))

    @patch.object(library.analytics_models, 'embed_texts', side_effect=fake_vectors)
    def test_index_is_not_the_ai_sample_and_reads_full_capture(self, _embed):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p = self.source(root, 'Many records', 'First publication')
            data = json.loads(p.read_text())
            data['sections']['findings'] = [dict(value=f'Unique finding CODE-{i}', source='Fixture', sha256='a'*64) for i in range(240)]
            artifacts = p.parent / 'artifacts'; artifacts.mkdir()
            textfile = artifacts / 'page.txt'; textfile.write_text(('long capture content ' * 500) + ' LASTCAPTURE-7788', encoding='utf-8')
            metadata = artifacts / 'page.json'; metadata.write_text(json.dumps({'files':[str(textfile)]}))
            data['sections']['web'].append(dict(kind='captured_page', url='https://example.org/capture', metadata=str(metadata)))
            p.write_text(json.dumps(data))
            result = library.refresh(root, [root / 'dossiers'])
            self.assertGreater(result['chunk_count'], 240)
            result = library.search('LASTCAPTURE-7788', root, roots=[root / 'dossiers'])
            self.assertTrue(any('LASTCAPTURE-7788' in row['text'] for row in result['evidence']))

    @patch.object(library.analytics_models, 'embed_texts', side_effect=OSError('Model unavailable'))
    def test_keyword_fallback_and_empty_corpus_do_not_invent_answers(self, _embed):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source(root, 'Aster', 'ASTER-7788 is a synthetic reference.')
            result = library.search('ASTER-7788', root, roots=[root / 'dossiers'])
            self.assertEqual(result['semantic_status'], 'unavailable')
            self.assertTrue(result['evidence'])
            with patch.object(ai_agents, '_chat') as chat:
                result = library.ask('NO_MATCH_383833', root, roots=[root / 'dossiers'], provider='groq', model='fixture')
            self.assertEqual(result['analysis']['status'], 'no_evidence')
            chat.assert_not_called()

    @patch.object(library.analytics_models, 'embed_texts', side_effect=fake_vectors)
    def test_ai_payload_quotes_and_navigation_metadata_are_preserved(self, _embed):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source(root, 'Aster', 'ASTER-9381 was registered in 2019.')
            def provider(_provider, _model, _key, messages, _limit):
                payload = json.loads(messages[1]['content'])
                self.assertNotIn(str(root), messages[1]['content'])
                row = payload['evidence'][0]
                return json.dumps({'claims': [dict(evidence_id=row['id'], quote=row['text'], statement='The source reports registration in 2019.', category='other'),
                    dict(evidence_id='E999', quote='not present', statement='Invented source')]})
            with patch.dict('os.environ', {'JOBFIND_AI_API_KEY':'fixture-secret'}), patch.object(ai_agents, '_chat', side_effect=provider):
                result = library.ask('ASTER-9381', root, roots=[root / 'dossiers'], provider='groq', model='fixture')
            self.assertEqual(result['analysis']['status'], 'partial')
            self.assertEqual(len(result['analysis']['claims']), 1)
            claim = result['analysis']['claims'][0]
            self.assertEqual(claim['source_url'], 'https://example.org/source')
            self.assertTrue(Path(claim['snapshot_path']).is_file())
            self.assertTrue(Path(result['report_json']).is_file())
            self.assertNotIn('fixture-secret', Path(result['report_json']).read_text())

    @patch.object(library.analytics_models, 'embed_texts', side_effect=fake_vectors)
    def test_tampered_snapshot_is_not_cited_and_refresh_repairs_it(self, _embed):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source(root, 'Aster', 'ASTER-7788 was registered in 2019.')
            found = library.search('ASTER-7788', root, roots=[root / 'dossiers'])
            snapshot = Path(found['evidence'][0]['snapshot_path'])
            snapshot.write_text('tampered')
            self.assertFalse(library.search('ASTER-7788', root, update=False)['evidence'])
            repaired = library.search('ASTER-7788', root, roots=[root / 'dossiers'])
            self.assertTrue(repaired['evidence'])
            self.assertIn('2019', snapshot.read_text())

    def test_complete_evidence_still_filters_errors_and_secret_metadata(self):
        data = {'sections':{'findings':[dict(value='Saved unlinked record', metadata={'token':{'value':'private-value'},'safe':'retained'},
                                          hostnames=[f'host-{i}.example.org' for i in range(15)]),
                                       dict(value='Failed response', status='error', url='https://example.org/error')]}}
        evidence = ai_agents._evidence(data, complete=True, fallback_link='artifact:sha256:'+'a'*64)
        self.assertTrue(any('Saved unlinked record' in row['text'] for row in evidence))
        self.assertNotIn('private-value', json.dumps(evidence))
        self.assertNotIn('Failed response', json.dumps(evidence))
        self.assertIn('host-14.example.org', json.dumps(evidence))


if __name__ == '__main__':
    unittest.main()
