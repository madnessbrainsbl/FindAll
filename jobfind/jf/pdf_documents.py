"""Local, page-addressable PDF extraction and OCR in a bounded child process."""
from __future__ import annotations

import csv
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from .analytics_models import checksum
from . import additional_tools, contacts, ai_agents, pdf_tables

ROOT = Path(__file__).resolve().parents[1]
TESSDATA = ROOT / 'third_party' / 'tesseract-data'
OCR_REVISION = '87416418657359cb625c412a48b6e1d6d41c29bd'
OCR_FILES = {'eng.traineddata': '7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2',
             'rus.traineddata': 'e16e5e036cce1d9ec2b00063cf8b54472625b9e14d893a169e2b0dedeb4df225',
             'osd.traineddata': '9cf5d576fcc47564f11265841e5ca839001e7e6f38ff7f7aacf46d15a96b00ff',
             'LICENSE': 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'}


def now():
    return datetime.now(timezone.utc).isoformat()


def _json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def tesseract():
    candidates = [os.environ.get('FINDALL_TESSERACT', ''), shutil.which('tesseract') or '',
                  r'C:\Program Files\Tesseract-OCR\tesseract.exe']
    return next((str(Path(p)) for p in candidates if p and Path(p).is_file()), '')


def setup_ocr():
    import urllib.request
    if not tesseract():
        raise RuntimeError('Install Tesseract OCR, then run setup-library.bat. FINDALL_TESSERACT may specify its executable.')
    TESSDATA.mkdir(parents=True, exist_ok=True)
    for name, expected in OCR_FILES.items():
        path = TESSDATA / name
        if path.is_file() and checksum(path) == expected:
            continue
        url = f'https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/{OCR_REVISION}/{name}'
        with urllib.request.urlopen(url, timeout=40) as response:
            raw = response.read(30_000_001)
        if len(raw) > 30_000_000 or hashlib.sha256(raw).hexdigest() != expected:
            raise RuntimeError('OCR model checksum verification failed')
        temporary = path.with_suffix('.part')
        temporary.write_bytes(raw)
        os.replace(temporary, path)
    font = TESSDATA / 'pdf.ttf'
    if not font.is_file():
        origin = Path(tesseract()).parent / 'tessdata' / 'pdf.ttf'
        if not origin.is_file():
            raise RuntimeError('Tesseract PDF font missing; repair the Tesseract installation')
        shutil.copyfile(origin, font)
    _json(TESSDATA / 'manifest.json', dict(repository='https://github.com/tesseract-ocr/tessdata_fast',
          revision=OCR_REVISION, files={**OCR_FILES, 'pdf.ttf': checksum(font)}))
    return dict(status='ok', languages=['eng', 'rus'], engine=tesseract(), model_revision=OCR_REVISION)


def _ocr(image, destination, languages):
    executable = tesseract()
    if not executable:
        raise RuntimeError('Tesseract not found; run setup-library.bat')
    if not re.fullmatch(r'[a-zA-Z0-9_]+(?:\+[a-zA-Z0-9_]+)*', languages):
        raise ValueError('Invalid OCR languages')
    for lang in languages.split('+'):
        if not (TESSDATA / (lang + '.traineddata')).is_file():
            raise RuntimeError('OCR language data missing; run setup-library.bat')
    rotation = 0
    try:
        orientation = subprocess.run([executable, str(image), 'stdout', '--tessdata-dir', str(TESSDATA),
            '-l', 'osd', '--psm', '0'], capture_output=True, timeout=15,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        output = orientation.stdout.decode('utf-8', errors='replace')
        angle = re.search(r'Rotate:\s*(90|180|270)\b', output)
        certainty = re.search(r'Orientation confidence:\s*([\d.]+)', output)
        if angle and certainty and float(certainty.group(1)) >= 5:
            from PIL import Image
            rotation = int(angle.group(1))
            with Image.open(image) as incoming:
                corrected = incoming.rotate(-rotation, expand=True)
                corrected.save(image)
                corrected.close()
    except subprocess.TimeoutExpired:
        pass
    process = subprocess.run([executable, str(image), str(destination), '--tessdata-dir', str(TESSDATA),
        '-l', languages, '--psm', '11', '-c', 'tessedit_create_pdf=1', '-c', 'tessedit_create_txt=1',
        '-c', 'tessedit_create_tsv=1'], capture_output=True, timeout=45,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if process.returncode:
        raise RuntimeError('OCR engine failed')
    text = destination.with_suffix('.txt').read_text(encoding='utf-8').strip()
    words = []
    with destination.with_suffix('.tsv').open(encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream, delimiter='\t'):
            if row.get('text', '').strip():
                words.append(dict(text=row['text'], confidence=float(row['conf']),
                    x=int(row['left']), y=int(row['top']), width=int(row['width']), height=int(row['height']),
                    line='-'.join(row[k] for k in ('block_num', 'par_num', 'line_num'))))
    confidence = sum(r['confidence'] for r in words) / len(words) if words else None
    return text, words, confidence, rotation


def _page_preview(folder, page, title, original):
    source = html.escape(original.as_uri() + '#page=' + str(page['page']), quote=True)
    tables = ''.join('<table>' + ''.join('<tr>' + ''.join('<td>' + html.escape(str(c or '')) + '</td>'
        for c in row) + '</tr>' for row in table) + '</table>' for table in page['tables'])
    if page.get('table_details'):
        tables = ''.join(pdf_tables.table_html(table, i) for i, table in enumerate(page['table_details'], 1))
    links = ''.join('<li><a href="' + html.escape(url, quote=True) + '">' + html.escape(url) + '</a></li>'
                    for url in page.get('links', []) if ai_agents._url(url))
    body = ('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; img-src \'self\' data:; style-src \'unsafe-inline\'">'
        '<title>' + html.escape(title) + '</title><style>body{font:16px system-ui;max-width:1100px;margin:30px auto;padding:20px}'
        'img{max-width:100%}pre{white-space:pre-wrap;overflow-wrap:anywhere}td{border:1px solid #aaa;padding:5px}table{border-collapse:collapse}</style>'
        '</head><body><h1>' + html.escape(title) + ' · page ' + str(page['page']) + '</h1><p>'
        + html.escape(page['method']) + ' · SHA-256 ' + html.escape(page['text_sha256']) + '</p><a href="' + source
        + '">Open original PDF at this page</a><p><img src="' + Path(page['image_path']).name + '"></p><h2>Extracted text</h2><pre>'
        + html.escape(page['text']) + '</pre>' + tables + '<h2>Document links</h2><ul>' + links + '</ul></body></html>')
    path = folder / f'page-{page["page"]:04}.html'
    path.write_text(body, encoding='utf-8')
    return str(path)


def _extract(source, folder, title, languages, password):
    import pdfplumber
    import pypdfium2 as pdfium
    from pypdf import PdfReader, PdfWriter
    report = dict(kind='pdf', title=title, sha256=checksum(source), source_path=str(source),
                  created_at=now(), status='partial', pages=[], errors=[], metadata={}, source_url='', table_extraction_version=3)
    manifest = folder / 'document.json'
    writer = PdfWriter()
    try:
        reader = PdfReader(source)
        if reader.is_encrypted and not reader.decrypt(password):
            return {**report, 'status': 'locked', 'errors': ['PDF password required or incorrect']}
        report['page_count'] = len(reader.pages)
        report['metadata'] = {str(k): str(v)[:4000] for k, v in (reader.metadata or {}).items()}
        if len(reader.pages) > 500:
            raise ValueError('PDF exceeds 500 pages; split the document before import')
        with pdfplumber.open(source, password=password or None) as pdf, pdfium.PdfDocument(source, password=password or None) as render:
            for index, page in enumerate(pdf.pages):
                item = dict(page=index + 1, text='', tables=[], links=[], emails=[], method='text', status='ok', errors=[])
                output_page = reader.pages[index]
                try:
                    item['text'] = page.extract_text() or ''
                    item['tables'] = page.extract_tables()
                    item['links'] = [safe for link in page.hyperlinks if (safe := ai_agents._url(link.get('uri')))]
                    raster_area = sum(max(0, min(im['x1'], page.width) - max(im['x0'], 0)) *
                                      max(0, min(im['bottom'], page.height) - max(im['top'], 0)) for im in page.images)
                    scanned = sum(ch.isalnum() for ch in item['text']) < 30 or raster_area >= page.width * page.height * .5
                    width, height = render[index].get_size()
                    if not math.isfinite(width * height) or width <= 0 or height <= 0:
                        raise ValueError('Invalid page dimensions')
                    scale = min(3.0 if scanned else 1.3, math.sqrt(16_000_000 / (width * height)))
                    bitmap = render[index].render(scale=scale)
                    image = bitmap.to_pil()
                    image_path = folder / f'page-{index+1:04}.png'
                    image.save(image_path)
                    image.close()
                    bitmap.close()
                    item['image_path'] = str(image_path)
                    ocr_pdf = None
                    if scanned:
                        try:
                            text, words, confidence, rotation = _ocr(image_path, folder / f'ocr-{index+1:04}', languages)
                            item.update(text=text or item['text'], method='ocr', ocr_words=words, ocr_confidence=confidence,
                                        ocr_rotation_degrees=rotation)
                            ocr_pdf = folder / f'ocr-{index+1:04}.pdf'
                            try:
                                item['table_details'] = pdf_tables.scan_tables(image_path, words)
                                item['tables'] = [table['matrix'] for table in item['table_details']]
                                item['table_status'] = 'ok' if item['tables'] else 'empty'
                            except Exception:
                                item.update(status='partial', table_status='error')
                                item['errors'].append('Scanned table reconstruction failed; page OCR retained. Check setup-library.bat.')
                        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                            item.update(status='partial', errors=[str(exc) if isinstance(exc, (RuntimeError, ValueError)) else 'OCR timed out or could not start'])
                    if ocr_pdf and ocr_pdf.is_file():
                        output_page = PdfReader(ocr_pdf).pages[0]
                    item['text_sha256'] = hashlib.sha256(item['text'].encode('utf-8')).hexdigest()
                    item['emails'] = list(dict.fromkeys(contacts.EMAIL_RE.findall(item['text'])))
                    (folder / f'page-{index+1:04}.txt').write_text(item['text'], encoding='utf-8')
                    if not item['text'].strip() and item['status'] == 'ok':
                        item['status'] = 'empty'
                    item['preview_path'] = _page_preview(folder, item, title, source)
                    for t, table in enumerate(item['tables'], 1):
                        csv_path = folder / f'page-{index+1:04}-table-{t}.csv'
                        with csv_path.open('w', encoding='utf-8-sig', newline='') as stream:
                            csv.writer(stream).writerows([['\'' + cell if isinstance(cell, str) and cell.lstrip().startswith(('=', '+', '-', '@')) else cell
                                                         for cell in row] for row in table])
                        item.setdefault('table_csv', []).append(str(csv_path))
                    if item.get('table_details'):
                        item['table_json'] = str(folder / f'page-{index+1:04}-tables.json')
                        _json(Path(item['table_json']), dict(page=index+1, document_sha256=report['sha256'],
                              image_path=item['image_path'], tables=item['table_details']))
                    page.close()
                except Exception:
                    item.update(status='error', errors=['Page extraction or rendering failed'])
                writer.add_page(output_page)
                report['pages'].append(item)
                _json(manifest, report)
        searchable = folder / 'searchable.pdf'
        with searchable.open('wb') as stream:
            writer.write(stream)
        report['searchable_pdf'] = str(searchable)
        report['searchable_sha256'] = checksum(searchable)
        report['status'] = 'partial' if any(p['status'] in ('error', 'partial') for p in report['pages']) else 'ok'
        report['text_pages'] = sum(bool(p['text'].strip()) for p in report['pages'])
        report['ocr_pages'] = sum(p['method'] == 'ocr' for p in report['pages'])
        report['table_count'] = sum(len(p['tables']) for p in report['pages'])
    except Exception as exc:
        report.update(status='error', errors=[str(exc) if isinstance(exc, ValueError) else 'PDF parsing failed or password is incorrect'])
    finally:
        writer.close()
    return report


def import_pdf(path, output, *, password='', languages='eng+rus', source_url='', title=None):
    source = Path(path).resolve()
    if not source.is_file() or source.suffix.lower() != '.pdf' or not 0 < source.stat().st_size <= 100_000_000:
        raise ValueError('Choose a local PDF up to 100 MB')
    if source_url and not ai_agents._url(source_url):
        raise ValueError('PDF origin must be a public HTTP(S) URL without credentials')
    digest = checksum(source)
    base = Path(output).resolve() / 'library' / 'pdf' / digest
    base.mkdir(parents=True, exist_ok=True)
    snapshot = base / 'original.pdf'
    if not snapshot.exists() or checksum(snapshot) != digest:
        with tempfile.NamedTemporaryFile(dir=base, delete=False) as stream:
            temporary = Path(stream.name)
            with source.open('rb') as incoming:
                shutil.copyfileobj(incoming, stream)
        if checksum(temporary) != digest:
            temporary.unlink()
            raise ValueError('PDF changed during import; retry with a stable file')
        os.replace(temporary, snapshot)
    folder = Path(tempfile.mkdtemp(prefix='extraction-', dir=base))
    code, _text = additional_tools._run([sys.executable, '-m', 'jf.pdf_documents', str(snapshot), str(folder),
        title or source.name, languages], ROOT, 600, environment={'FINDALL_PDF_PASSWORD': password})
    manifest = folder / 'document.json'
    report = json.loads(manifest.read_text(encoding='utf-8')) if manifest.is_file() else dict(
        kind='pdf', title=source.name, source_path=str(snapshot), sha256=digest, pages=[], created_at=now(),
        status='timeout' if code == 124 else 'error', errors=['PDF extraction timed out' if code == 124 else 'PDF worker failed'])
    if code == 124:
        report.update(status='partial' if report.get('pages') else 'timeout', errors=['PDF extraction exceeded 600 seconds; completed pages retained'])
    report.update(original_path=str(source), source_url=source_url, report_json=str(manifest), languages=languages)
    _json(manifest, report)
    _json(base / 'latest.json', {'report_json': str(manifest)})
    return report


if __name__ == '__main__':
    try:
        result = _extract(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4], os.environ.get('FINDALL_PDF_PASSWORD', ''))
        _json(Path(sys.argv[2]) / 'document.json', result)
    except Exception:
        sys.exit(1)
