import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from pypdf import PdfReader

from jf import ai_agents, library, pdf_documents, pdf_tables
from tests.pdf_table_fixtures import scanned_tables


def vectors(texts):
    return np.tile(np.array([1., 0.], dtype=np.float32), (len(texts), 1))


@unittest.skipUnless(
    pdf_documents.tesseract() and all((pdf_documents.TESSDATA / name).is_file()
        for name in ('eng.traineddata', 'rus.traineddata', 'pdf.ttf')),
    'Install Tesseract and run setup-library.bat for the OCR integration tests',
)
class ScannedTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / 'tables.pdf'
        cls.expected = scanned_tables(cls.source)
        cls.original = cls.source.read_bytes()
        cls.report = pdf_documents.import_pdf(cls.source, cls.root, source_url='https://aster.example/tables.pdf')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_ocr_retains_grid_blank_cells_and_merged_spans(self):
        report = self.report
        self.assertEqual(report['status'], 'ok', report)
        self.assertEqual(report['table_count'], 3)
        self.assertEqual(report['pages'][0]['tables'][0], self.expected[0])
        self.assertEqual(report['pages'][1]['tables'][0], self.expected[1])
        merged = report['pages'][1]['table_details'][0]
        self.assertTrue(any(c['colspan'] == 3 and c['text'] == 'Quarterly report' for c in merged['cells']))
        self.assertTrue(any(c['rowspan'] == 2 and c['text'] == 'North' for c in merged['cells']))
        blank = next(c for c in report['pages'][0]['table_details'][0]['cells'] if c['row'] == 3 and c['column'] == 3)
        self.assertEqual(blank['text'], '')
        for page in report['pages']:
            table = page['table_details'][0]
            self.assertEqual(table['columns'], 3)
            self.assertTrue(all(0 <= c['bbox'][0] < c['bbox'][2] <= table['image_width'] for c in table['cells']))
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), report['sha256'])
        searchable = PdfReader(report['searchable_pdf'])
        self.assertEqual(len(searchable.pages), 3)
        self.assertIn('3400', searchable.pages[0].extract_text())

    def test_borderless_table_keeps_column_associations_and_review_flags(self):
        table = self.report['pages'][2]['table_details'][0]
        self.assertEqual((table['rows'], table['columns']), (5, 3))
        self.assertEqual(table['matrix'][4], ['East', '36', '84000'])
        self.assertEqual(table['matrix'][1][2], '42000')
        self.assertTrue(all('needs_review' in c for c in table['cells']))
        words = [dict(text='Normal prose', confidence=90, x=50, y=40+i*50, width=300, height=20) for i in range(5)]
        self.assertFalse(pdf_tables._aligned_tables(words))

    def test_existing_ocr_text_layer_does_not_skip_table_geometry(self):
        report = pdf_documents.import_pdf(self.report['searchable_pdf'], self.root/'text-layer')
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['ocr_pages'], 3)
        self.assertEqual(report['table_count'], 3)
        self.assertEqual(report['pages'][0]['table_details'][0]['columns'], 3)

    def test_exports_preserve_shapes_and_html_spans(self):
        page = self.report['pages'][1]
        detail = json.loads(Path(page['table_json']).read_text(encoding='utf-8'))
        self.assertEqual(detail['page'], 2)
        self.assertEqual(detail['tables'][0]['rows'], 5)
        with Path(page['table_csv'][0]).open(encoding='utf-8-sig', newline='') as stream:
            self.assertEqual(list(csv.reader(stream)), page['tables'][0])
        html = Path(page['preview_path']).read_text(encoding='utf-8')
        self.assertIn('rowspan="2"', html)
        self.assertIn('colspan="3"', html)
        numeric_copy = copy.deepcopy(page['table_details'][0])
        numeric_copy['cells'][0]['confidence'] += 1e-12
        self.assertEqual(pdf_tables.table_hash({k:v for k,v in numeric_copy.items() if k != 'sha256'}), numeric_copy['sha256'])
        table = copy.deepcopy(page['table_details'][0])
        table['cells'][0]['text'] = '<script>alert(1)</script>'
        self.assertNotIn('<script>', pdf_tables.table_html(table, 1))

    @patch.object(library.analytics_models, 'embed_texts', side_effect=vectors)
    def test_rag_cites_exact_page_table_and_row(self, _embed):
        def provider(_provider, _model, _key, messages, _limit):
            data = json.loads(messages[1]['content'])
            row = next(r for r in data['evidence'] if 'C3 (2025): 3400' in r['text'])
            return json.dumps({'claims': [dict(evidence_id=row['id'], quote=row['text'],
                statement='Согласно распознанной таблице, Север: 3400 в 2025.', category='other')]})
        with patch.object(ai_agents, '_chat', side_effect=provider), patch.dict('os.environ', {'JOBFIND_AI_API_KEY':'fixture'}):
            result = library.ask('Север 3400 2025', self.root, roots=[self.root/'no-dossiers'], provider='groq', model='fixture')
        self.assertEqual(result['analysis']['status'], 'ok')
        claim = result['analysis']['claims'][0]
        self.assertEqual((claim['page'], claim['table'], claim['table_row']), (1, 1, 2))
        self.assertEqual(claim['source_url'], 'https://aster.example/tables.pdf#page=1')
        self.assertTrue(Path(claim['preview_path']).is_file())
        rows = list(library._pdf_rows(self.report))
        self.assertTrue(any(r.get('table_row') == 3 and r['page'] == 2 and 'Quarterly report / Revenue' in r['text'] and '42000' in r['text'] for r in rows))
        self.assertTrue(any(c['rowspan'] == 2 for r in rows if r.get('table_row') == 4 and r['page'] == 2 for c in r['cells']))
        bad = copy.deepcopy(self.report)
        bad['pages'][0]['tables'][0][1][2] = '99999'
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            list(library._pdf_rows(bad))

    @patch.object(library.analytics_models, 'embed_texts', side_effect=vectors)
    def test_existing_extraction_is_upgraded_without_changing_original(self, _embed):
        report = copy.deepcopy(self.report)
        report['table_extraction_version'] = 1
        manifest = Path(report['report_json'])
        original_manifest = manifest.read_bytes()
        manifest.write_text(json.dumps(report), encoding='utf-8')
        try:
            with patch.object(pdf_documents, 'import_pdf', wraps=pdf_documents.import_pdf) as importer:
                library.refresh(self.root, [self.root/'no-dossiers'])
            self.assertEqual(importer.call_count, 1)
            self.assertEqual(self.source.read_bytes(), self.original)
            self.assertTrue(manifest.exists())
        finally:
            manifest.write_bytes(original_manifest)


if __name__ == '__main__':
    unittest.main()
