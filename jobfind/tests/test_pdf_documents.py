import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle

from jf import pdf_documents, library


class PdfTests(unittest.TestCase):
    def document(self, folder):
        path = folder / 'fixture.pdf'
        pdf = canvas.Canvas(str(path))
        pdf.drawString(60, 760, 'Synthetic ASTER-7319 report. Contact research@aster.example.')
        pdf.linkURL('https://aster.example/report', (60, 750, 400, 775))
        pdf.showPage()
        table = Table([['Metric', 'Value'], ['Revenue', '42000'], ['Employees', '18']])
        table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 1, 'black')]))
        table.wrapOn(pdf, 400, 500)
        table.drawOn(pdf, 60, 650)
        pdf.save()
        return path

    def test_text_tables_links_encryption_and_immutable_source(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = self.document(root)
            before = path.read_bytes()
            report = pdf_documents.import_pdf(path, root, source_url='https://aster.example/report.pdf')
            self.assertEqual(report['status'], 'ok', report['errors'])
            self.assertEqual(report['page_count'], 2)
            self.assertEqual(report['table_count'], 1)
            self.assertIn('research@aster.example', report['pages'][0]['emails'])
            self.assertIn('https://aster.example/report', report['pages'][0]['links'])
            self.assertEqual(len(PdfReader(report['searchable_pdf']).pages), 2)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(report['sha256'], hashlib.sha256(before).hexdigest())
            rows = list(library._pdf_rows(report))
            self.assertTrue(any(r['page'] == 2 and '42000' in r['text'] and r['source_url'].endswith('#page=2') for r in rows))
            self.assertTrue(all(Path(r['preview_path']).is_file() for r in rows))
            with patch.object(library.analytics_models, 'embed_texts', side_effect=lambda texts: np.tile([1., 0.], (len(texts), 1))):
                library.refresh(root, [root / 'no-dossiers'])
                snapshot = Path(report['source_path'])
                snapshot.write_bytes(b'tampered')
                self.assertTrue(any(d['status'] == 'error' for d in library.refresh(root, [root / 'no-dossiers'])['documents']))
                self.assertFalse(library.search('ASTER-7319', root, update=False)['evidence'])
                snapshot.write_bytes(before)
                self.assertTrue(library.search('ASTER-7319', root, roots=[root / 'no-dossiers'])['evidence'])
            encrypted = root / 'locked.pdf'
            writer = PdfWriter(clone_from=str(path))
            writer.encrypt('fixture-password-5523')
            writer.write(encrypted)
            writer.close()
            locked = pdf_documents.import_pdf(encrypted, root)
            self.assertEqual(locked['status'], 'locked')
            unlocked = pdf_documents.import_pdf(encrypted, root, password='fixture-password-5523')
            self.assertEqual(unlocked['status'], 'ok')
            self.assertNotIn('fixture-password-5523', Path(unlocked['report_json']).read_text())

    @unittest.skipUnless(pdf_documents.tesseract() and (pdf_documents.TESSDATA / 'eng.traineddata').is_file(), 'Local OCR not installed')
    def test_real_scanned_page_has_searchable_text_and_page_preview(self):
        from PIL import Image, ImageDraw, ImageFont
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            image = Image.new('RGB', (1800, 1000), 'white')
            font = ImageFont.truetype('arial.ttf', 50)
            draw = ImageDraw.Draw(image)
            for i, line in enumerate(['SCANNED RESEARCH REPORT', 'Audit reference SCAN-8472',
                                      'Synthetic company Aster', 'Revenue 42000 dollars', 'Evidence retained per page']):
                draw.text((90, 100 + i * 130), line, font=font, fill='black')
            path = root / 'scan.pdf'
            image.save(path, 'PDF', resolution=150)
            image.close()
            report = pdf_documents.import_pdf(path, root, languages='eng')
            self.assertEqual(report['status'], 'ok', report)
            page = report['pages'][0]
            self.assertEqual(page['method'], 'ocr')
            self.assertIn('SCAN-8472', page['text'])
            self.assertTrue(page['ocr_words'])
            self.assertIn('SCAN-8472', PdfReader(report['searchable_pdf']).pages[0].extract_text())
            self.assertTrue(Path(page['preview_path']).is_file())

    def test_invalid_pdf_and_worker_timeout_are_not_empty_success(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'invalid.pdf'
            path.write_bytes(b'not a PDF')
            self.assertEqual(pdf_documents.import_pdf(path, root)['status'], 'error')
            path = self.document(root)
            with patch.object(pdf_documents.additional_tools, '_run', return_value=(124, '')):
                report = pdf_documents.import_pdf(path, root)
            self.assertEqual(report['status'], 'timeout')
            self.assertEqual(report['pages'], [])
            with self.assertRaises(ValueError):
                pdf_documents.import_pdf(path, root, source_url='https://example.org/?token=private')

    def test_preview_escapes_document_markup(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            page = dict(page=1, method='text', text_sha256='a'*64, image_path=str(root / 'page.png'),
                        text='<script>alert(1)</script>', tables=[[['<img src=x>']]])
            preview = Path(pdf_documents._page_preview(root, page, '<title>', root / 'original.pdf')).read_text()
            self.assertNotIn('<script>', preview)
            self.assertIn('&lt;script&gt;', preview)


if __name__ == '__main__':
    unittest.main()
