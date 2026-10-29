"""Persistent local retrieval across saved dossiers and page-addressable PDFs."""
from __future__ import annotations

from collections import defaultdict
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import heapq
import json
from pathlib import Path
import re
import sqlite3
import uuid

from . import ai_agents, analytics_models, markdown_export, pdf_documents, pdf_tables

ROOT = Path(__file__).resolve().parents[1]


def setup():
    ocr = pdf_documents.setup_ocr()
    if not (analytics_models.BERT_DIR / 'findall-model.json').is_file():
        analytics_models.install_bert()
    analytics_models._bert_components.cache_clear()
    analytics_models.embed_texts(['Library setup verification'])
    return dict(action='setup', status='ok', ocr=ocr, model=analytics_models.BERT_REPO)


def _hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _connect(output):
    folder = Path(output).resolve() / 'library'
    folder.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(folder / 'index.sqlite3', timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, path TEXT, digest TEXT, kind TEXT,
            title TEXT, status TEXT, detail TEXT, updated TEXT);
        CREATE TABLE IF NOT EXISTS chunks(rowid INTEGER PRIMARY KEY, id TEXT UNIQUE, doc_id TEXT REFERENCES documents(id)
            ON DELETE CASCADE, text TEXT, metadata TEXT, vector BLOB, revision TEXT);
        CREATE INDEX IF NOT EXISTS chunks_document ON chunks(doc_id);
        CREATE VIRTUAL TABLE IF NOT EXISTS chunk_fts USING fts5(text,content='chunks',content_rowid='rowid',tokenize='unicode61');
        CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
          INSERT INTO chunk_fts(rowid,text) VALUES(new.rowid,new.text); END;
        CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
          INSERT INTO chunk_fts(chunk_fts,rowid,text) VALUES('delete',old.rowid,old.text); END;
    ''')
    return conn


def _chunks(text, metadata):
    words = list(re.finditer(r'\S+', str(text)))
    for start in range(0, len(words), 65):
        end = min(start + 90, len(words))
        value = str(text)[words[start].start():words[end - 1].end()]
        if value.strip():
            yield {**metadata, 'text': value, 'offset': words[start].start(), 'end': words[end - 1].end()}
        if end == len(words):
            break


def _dossier_rows(path, data, digest, snapshot):
    base = dict(title=str(data.get('query', path.parent.name)), dossier_path=str(path), snapshot_path=str(snapshot),
                document_sha256=digest, page=None, preview_path='', source_path=str(snapshot), kind='dossier')
    for item in ai_agents._evidence(data, complete=True, fallback_link='artifact:sha256:' + digest):
        yield from _chunks(item['text'], {**base, 'source_url': item['url'], 'section': item['section'],
            'provenance': item['provenance'], 'attribution': item['attribution'], 'observed_at': item['observed_at'] or data.get('observed_at', '')})
    # Saved captures retain the full page text outside the dossier's shortened snippet.
    for row in (data.get('sections') or {}).get('web') or []:
        if not isinstance(row, dict) or row.get('kind') != 'captured_page' or not isinstance(row.get('metadata'), str):
            continue
        try:
            metadata = Path(row['metadata']).resolve()
            if not metadata.is_relative_to(path.parent) or metadata.stat().st_size > 1_000_000:
                continue
            capture = json.loads(metadata.read_text(encoding='utf-8'))
            for name in capture.get('files', []):
                textfile = Path(name).resolve()
                if textfile.suffix == '.txt' and textfile.is_relative_to(path.parent) and textfile.stat().st_size <= 10_000_000:
                    raw = textfile.read_bytes()
                    capture_hash = hashlib.sha256(raw).hexdigest()
                    retained = snapshot.parent / (capture_hash + '.txt')
                    if not retained.is_file() or analytics_models.checksum(retained) != capture_hash:
                        temporary = retained.with_suffix('.' + uuid.uuid4().hex + '.tmp')
                        temporary.write_bytes(raw)
                        temporary.replace(retained)
                    yield from _chunks(raw.decode('utf-8'), {**base,
                        'snapshot_path': str(retained), 'source_path': str(retained), 'document_sha256': capture_hash,
                        'source_url': ai_agents._url(row.get('url')) or 'artifact:sha256:' + digest,
                        'section': 'captured_text', 'provenance': 'captured_page', 'attribution': 'Captured publication; verify target association',
                        'observed_at': row.get('observed_at', '') or data.get('observed_at', ''), 'capture_sha256': capture_hash})
        except (OSError, ValueError, TypeError):
            continue


def _pdf_rows(report):
    for page in report.get('pages', []):
        if not page.get('text', '').strip() or page.get('status') == 'error':
            continue
        if _hash(page['text']) != page.get('text_sha256'):
            raise ValueError('PDF page text checksum mismatch')
        metadata = dict(title=report['title'], dossier_path='', snapshot_path=report['source_path'],
            document_sha256=report['sha256'], text_sha256=page.get('text_sha256', ''),
            source_path=report['source_path'], kind='pdf', page=page['page'], preview_path=page.get('preview_path', ''),
            source_url=(report.get('source_url', '').split('#')[0] + '#page=' + str(page['page'])) if report.get('source_url')
                       else 'artifact:sha256:' + report['sha256'], section='pdf',
            observed_at=report.get('created_at', ''), provenance='pdf_ocr' if page['method'] == 'ocr' else 'pdf_text',
            attribution='OCR transcription; verify page image' if page['method'] == 'ocr' else 'Document text; authorship and assertions unverified')
        yield from _chunks(page['text'], metadata)
        for index, table in enumerate(page.get('tables') or []):
            details = page.get('table_details') or []
            if index < len(details):
                structure = details[index]
                if structure.get('matrix') != table or pdf_tables.table_hash({k: v for k, v in structure.items() if k != 'sha256'}) != structure.get('sha256'):
                    raise ValueError('PDF table structure checksum mismatch')
                first = [cell for cell in structure['cells'] if cell['row'] == 1]
                header_rows = min(len(table), max((c['rowspan'] for c in first), default=1) + int(any(c['colspan'] > 1 for c in first)))
                headers = [' / '.join(dict.fromkeys(str(row[c] or '') for row in table[:header_rows] if c < len(row)))
                           for c in range(structure['columns'])]
                for r, row in enumerate(table, 1):
                    columns = ' | '.join(f'C{c+1} ({headers[c] or "unlabelled"}): {value or "[empty]"}'
                        if c < len(headers) else f'C{c+1}: {value or "[empty]"}' for c, value in enumerate(row))
                    text = f'Table {index+1}, row {r}.\n' + columns
                    cells = [cell for cell in structure['cells'] if cell['row'] <= r < cell['row'] + cell['rowspan']]
                    yield from _chunks(text, {**metadata, 'section': 'pdf_table', 'table': index+1, 'table_row': r,
                        'table_sha256': structure['sha256'], 'cells': cells,
                        'attribution': structure['attribution'] + ('; low-confidence cell OCR in this row' if any(c.get('needs_review') for c in cells) else '')})
                continue
            text = '\n'.join(' | '.join(str(cell or '') for cell in row) for row in table)
            yield from _chunks(text, {**metadata, 'section': 'pdf_table', 'table': index + 1})


def _store(conn, doc_id, path, digest, kind, title, rows, status='ok', detail=''):
    rows = list(rows)
    vectors = None
    semantic = 'ok'
    try:
        if rows:
            vectors = analytics_models.embed_texts([row['title'] + '\n' + row['text'] for row in rows])
    except (OSError, RuntimeError, ValueError, ImportError):
        semantic = 'unavailable'
    with conn:
        conn.execute('DELETE FROM documents WHERE id=?', (doc_id,))
        conn.execute('INSERT INTO documents VALUES(?,?,?,?,?,?,?,?)', (doc_id, str(path), digest, kind, title, status,
            json.dumps(dict(message=detail, semantic=semantic, schema=2)), datetime.now(timezone.utc).isoformat()))
        for index, row in enumerate(rows):
            text = row.pop('text')
            ident = _hash(doc_id + '|' + str(index) + '|' + text)
            conn.execute('INSERT INTO chunks(id,doc_id,text,metadata,vector,revision) VALUES(?,?,?,?,?,?)',
                (ident, doc_id, text, json.dumps(row, ensure_ascii=False), vectors[index].astype('float32').tobytes() if vectors is not None else None,
                 analytics_models.BERT_REVISION if vectors is not None else ''))
    return len(rows), semantic


def refresh(output, roots=None):
    output = Path(output).resolve()
    roots = [Path(p).resolve() for p in roots] if roots else list(dict.fromkeys([output, ROOT / 'jobfind_out']))
    sources, paths = [], set()
    with closing(_connect(output)) as conn:
        for root in roots:
            if not root.is_dir():
                sources.append(dict(path=str(root), status='skipped', detail='Dossier folder does not exist'))
                continue
            for candidate in root.rglob('dossier.json'):
                path = candidate.resolve()
                if path in paths or not path.is_relative_to(root) or 'library' in path.relative_to(root).parts:
                    continue
                paths.add(path)
                doc_id = 'dossier:' + _hash(str(path))
                try:
                    if path.stat().st_size > 64_000_000:
                        raise ValueError('Dossier exceeds 64 MB')
                    raw = path.read_bytes()
                    data = json.loads(raw)
                    if not isinstance(data, dict) or not isinstance(data.get('sections'), dict):
                        raise ValueError('Invalid dossier structure')
                    digest = hashlib.sha256(raw).hexdigest()
                    folder = output / 'library' / 'snapshots'
                    folder.mkdir(parents=True, exist_ok=True)
                    snapshot = folder / (digest + '.json')
                    if not snapshot.exists() or analytics_models.checksum(snapshot) != digest:
                        temporary = snapshot.with_suffix('.' + uuid.uuid4().hex + '.tmp')
                        temporary.write_bytes(raw)
                        temporary.replace(snapshot)
                    rows = list(_dossier_rows(path, data, digest, snapshot))
                    fingerprint = _hash(digest + ''.join(row.get('capture_sha256', '') for row in rows))
                    cached = conn.execute('SELECT digest,status,detail FROM documents WHERE id=?', (doc_id,)).fetchone()
                    if cached and cached['digest'] == fingerprint and cached['status'] == 'ok' and json.loads(cached['detail']).get('semantic') == 'ok' and json.loads(cached['detail']).get('schema') == 2:
                        sources.append(dict(path=str(path), status='cached'))
                        continue
                    count, semantic = _store(conn, doc_id, path, fingerprint, 'dossier', str(data.get('query', path.parent.name)), rows)
                    sources.append(dict(path=str(path), status='ok', chunks=count, semantic=semantic))
                except (OSError, ValueError, TypeError, RecursionError) as exc:
                    with conn:
                        conn.execute('UPDATE documents SET status=? WHERE id=?', ('error', doc_id))
                    sources.append(dict(path=str(path), status='error', detail=str(exc) if isinstance(exc, ValueError) else 'Dossier could not be indexed'))
        for row in conn.execute("SELECT id,path FROM documents WHERE kind='dossier'").fetchall():
            if any(Path(row['path']).is_relative_to(root) for root in roots) and not Path(row['path']).is_file():
                with conn:
                    conn.execute("UPDATE documents SET status='missing' WHERE id=?", (row['id'],))
                sources.append(dict(path=row['path'], status='missing', detail='Source file no longer exists'))
        pdf_root = output / 'library' / 'pdf'
        for latest in pdf_root.glob('*/latest.json') if pdf_root.exists() else []:
            try:
                manifest = Path(json.loads(latest.read_text(encoding='utf-8'))['report_json']).resolve()
                if not manifest.is_relative_to(pdf_root):
                    raise ValueError('Invalid PDF manifest location')
                report = json.loads(manifest.read_text(encoding='utf-8'))
                snapshot = Path(report['source_path']).resolve()
                if not snapshot.is_relative_to(pdf_root) or analytics_models.checksum(snapshot) != report['sha256']:
                    raise ValueError('PDF snapshot checksum mismatch')
                if (report.get('table_extraction_version', 0) < 3 or any(p.get('table_status') == 'error' for p in report.get('pages', []))) and any(p.get('method') == 'ocr' for p in report.get('pages', [])):
                    from pypdf import PdfReader
                    if PdfReader(snapshot).is_encrypted:
                        sources.append(dict(path=str(manifest), status='partial', detail='Re-import this encrypted PDF with its password to reconstruct scanned tables'))
                    else:
                        report = pdf_documents.import_pdf(snapshot, output, title=report['title'],
                            languages=report.get('languages', 'eng+rus'), source_url=report.get('source_url', ''))
                        manifest = Path(report['report_json'])
                doc_id = 'pdf:' + report['sha256']
                digest = analytics_models.checksum(manifest)
                cached = conn.execute('SELECT digest,status,detail FROM documents WHERE id=?', (doc_id,)).fetchone()
                if cached and cached['status'] in ('ok', 'partial') and cached['digest'] == digest and json.loads(cached['detail']).get('semantic') == 'ok' and json.loads(cached['detail']).get('schema') == 2:
                    continue
                if cached and report['status'] not in ('ok', 'partial'):
                    sources.append(dict(path=str(manifest), status=report['status'], detail='Earlier completed extraction retained'))
                    continue
                count, semantic = _store(conn, doc_id, manifest, digest, 'pdf', report['title'], _pdf_rows(report),
                    status=report['status'], detail='; '.join(report.get('errors') or []))
                sources.append(dict(path=str(manifest), status=report['status'], chunks=count, semantic=semantic))
            except (OSError, ValueError, KeyError, TypeError):
                with conn:
                    conn.execute("UPDATE documents SET status='error' WHERE id=?", ('pdf:' + latest.parent.name,))
                sources.append(dict(path=str(latest), status='error', detail='PDF manifest could not be indexed'))
    return {**status(output), 'action': 'index', 'sources': sources}


def status(output):
    with closing(_connect(output)) as conn:
        docs = [dict(row) for row in conn.execute('SELECT id,path,kind,title,status,detail,updated FROM documents ORDER BY updated DESC')]
        count, vectors = conn.execute('SELECT count(*),count(vector) FROM chunks').fetchone()
    return dict(status='ok', documents=docs, document_count=len(docs), chunk_count=count, semantic_chunks=vectors,
                index_path=str(Path(output).resolve() / 'library' / 'index.sqlite3'), ocr_available=bool(pdf_documents.tesseract()))


def search(question, output, *, limit=12, update=True, roots=None):
    question = question.strip()
    if not 2 <= len(question) <= 2000 or not 1 <= limit <= 40:
        raise ValueError('Question must contain 2–2000 characters; result limit 1–40')
    inventory = refresh(output, roots) if update else status(output)
    tokens = list(dict.fromkeys(re.findall(r'\w+', question.casefold())))[:24]
    ranks = defaultdict(float)
    semantic = 'ok'
    with closing(_connect(output)) as conn:
        if tokens:
            match = ' OR '.join('"' + token + '"*' for token in tokens)
            lexical = conn.execute("SELECT c.rowid FROM chunk_fts JOIN chunks c ON c.rowid=chunk_fts.rowid "
                "JOIN documents d ON d.id=c.doc_id WHERE chunk_fts MATCH ? AND d.status IN ('ok','partial') ORDER BY bm25(chunk_fts) LIMIT 80", (match,)).fetchall()
            for rank, row in enumerate(lexical, 1):
                ranks[row['rowid']] += 1 / (60 + rank)
        try:
            import numpy as np
            query = analytics_models.embed_texts([question])[0]
            best = []
            cursor = conn.execute("SELECT c.rowid,c.vector FROM chunks c JOIN documents d ON d.id=c.doc_id "
                "WHERE c.revision=? AND c.vector IS NOT NULL AND d.status IN ('ok','partial')", (analytics_models.BERT_REVISION,))
            while batch := cursor.fetchmany(256):
                for row in batch:
                    vector = np.frombuffer(row['vector'], dtype=np.float32)
                    if vector.shape != query.shape or not np.isfinite(vector).all():
                        continue
                    cosine = float(vector @ query)
                    if cosine >= .3:
                        heapq.heappush(best, (cosine, row['rowid']))
                        if len(best) > 80:
                            heapq.heappop(best)
            for rank, (_score, ident) in enumerate(sorted(best, reverse=True), 1):
                ranks[ident] += 1 / (60 + rank)
        except (ImportError, OSError, ValueError, RuntimeError):
            semantic = 'unavailable'
        candidates, checked = [], {}
        for ident, score in sorted(ranks.items(), key=lambda row: -row[1]):
            row = conn.execute('SELECT id,doc_id,text,metadata FROM chunks WHERE rowid=?', (ident,)).fetchone()
            if row:
                metadata = json.loads(row['metadata'])
                proof = metadata['snapshot_path']
                if proof not in checked:
                    try:
                        checked[proof] = analytics_models.checksum(Path(proof))
                    except OSError:
                        checked[proof] = ''
                if checked[proof] != metadata['document_sha256']:
                    continue
                candidates.append({**metadata, 'chunk_id': row['id'], 'doc_id': row['doc_id'],
                                   'text': row['text'], 'score': score})
    # Diversify the first pass across documents, then fill with further relevant chunks.
    chosen, documents, seen = [], set(), set()
    for row in candidates:
        if row['doc_id'] not in documents:
            chosen.append(row)
            documents.add(row['doc_id'])
            seen.add(row['chunk_id'])
    chosen = (chosen + [row for row in candidates if row['chunk_id'] not in seen])[:limit]
    for i, row in enumerate(chosen, 1):
        row['id'] = f'E{i}'
        row['url'] = row['source_url']
    return dict(action='search', status='ok' if chosen else 'empty', question=question, evidence=chosen,
                semantic_status=semantic, inventory=inventory, retrieval='SQLite FTS5 + local multilingual BERT + reciprocal rank fusion')


def ask(question, output, *, roots=None, provider=None, model=None):
    result = search(question, output, roots=roots)
    evidence = result['evidence']
    provider, model, key = ai_agents._settings(provider, model, None)
    analysis = dict(status='no_evidence', claims=[], rejected_claims=0, answer='', provider=provider, model=model)
    if evidence:
        if error := ai_agents._configuration_error(provider, model, key):
            analysis.update(status='unconfigured', error=error)
        else:
            # Local filesystem paths are UI navigation metadata, never model input.
            payload = {'question': question, 'answer_language': ai_agents._LANGUAGES[ai_agents._answer_language(question)],
                'evidence': [{k: row[k] for k in ('id', 'text', 'url', 'section', 'provenance', 'attribution', 'observed_at')}
                             for row in evidence]}
            try:
                reply = ai_agents._chat(provider, model, key, [dict(role='system', content=ai_agents._SYSTEM +
                    ' Compare the supplied sources for the question. Preserve conflicting accounts as separately cited claims; never choose a winner without evidence.'
                    ' For table values prefer pdf_table evidence with its row and column context. Reconstructed cells and low-confidence OCR are unverified readings, not confirmed facts.'
                    ' Describe provenance in natural language; do not expose internal section or provenance identifiers in statements.'),
                    dict(role='user', content=json.dumps(payload, ensure_ascii=False))], 1800)
                claims, rejected = ai_agents._validated_claims(reply, evidence)
                by_id = {row['id']: row for row in evidence}
                for claim in claims:
                    source = by_id[claim['evidence_id']]
                    claim.update({k: source.get(k) for k in ('chunk_id', 'title', 'page', 'preview_path', 'dossier_path',
                                  'source_path', 'document_sha256', 'snapshot_path', 'table', 'table_row', 'table_sha256')})
                analysis.update(status='partial' if rejected else 'ok' if claims else 'no_conclusions', claims=claims,
                    rejected_claims=rejected, answer='\n\n'.join(row['statement'] + ' [' + row['evidence_id'] + ']' for row in claims))
            except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
                analysis.update(status='error', error=ai_agents._error(exc))
    result.update(action='ask', analysis=analysis)
    folder = Path(output).resolve() / 'library' / 'answers' / uuid.uuid4().hex
    folder.mkdir(parents=True, exist_ok=True)
    result['report_json'] = str(folder / 'answer.json')
    result['report_markdown'] = str(folder / 'answer.md')
    (folder / 'answer.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# ' + markdown_export._text(question), '', markdown_export._text(analysis['answer']), '']
    for row in evidence:
        lines += ['## ' + row['id'] + ' · ' + markdown_export._text(row['title']) + (' · page ' + str(row['page']) if row.get('page') else ''),
                  '', '> ' + markdown_export._text(row['text']), '', 'SHA-256: ' + row['document_sha256'], '',
                  '[Saved source](<' + Path(row['preview_path'] or row['source_path']).as_uri() + '>)', '']
        if row.get('table'):
            lines += [f'Table {row["table"]} · row {row.get("table_row", "all")} · structure SHA-256 {row.get("table_sha256", "")}', '']
        if row['source_url'].startswith(('http://', 'https://')):
            lines += [markdown_export._link(row['source_url']), '']
    (folder / 'answer.md').write_text('\n'.join(lines), encoding='utf-8')
    return result
