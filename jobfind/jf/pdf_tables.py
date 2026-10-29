"""Local image geometry plus the existing page OCR; no second OCR engine."""
from collections import defaultdict
import hashlib
import json
from statistics import median


def _aligned_tables(words):
    """Recover repeated whitespace columns when image geometry finds no borders."""
    from collections import OrderedDict
    from img2table.tables.extraction import BBox, ExtractedTable, TableCell
    if not words:
        return []
    height = median(w['height'] for w in words)
    lines = []
    for word in sorted(words, key=lambda w: w['y'] + w['height']/2):
        center = word['y'] + word['height']/2
        if not lines or abs(center - median(w['y'] + w['height']/2 for w in lines[-1])) > height*.6:
            lines.append([])
        lines[-1].append(word)
    groups, current, tables = [], [], []
    for line in lines:
        segments = []
        for word in sorted(line, key=lambda w: w['x']):
            if not segments or word['x'] - max(w['x'] + w['width'] for w in segments[-1]) > height*2:
                segments.append([])
            segments[-1].append(word)
        starts = [min(w['x'] for w in segment) for segment in segments]
        y = min(w['y'] for w in line)
        matches = current and len(segments) == len(current[0][1]) and all(abs(a-b) <= height*2
            for a, b in zip(starts, current[0][2])) and y - current[-1][0] <= height*6
        if not matches:
            if len(current) >= 3:
                groups.append(current)
            current = []
        if len(segments) >= 2:
            current.append((y, segments, starts))
    if len(current) >= 3:
        groups.append(current)
    for group in groups:
        columns = len(group[0][1])
        left = min(row[2][0] for row in group)
        right = max(w['x'] + w['width'] for _, segments, _ in group for w in segments[-1])
        xs = [left] + [int((max(w['x'] + w['width'] for _, s, _ in group for w in s[c-1]) +
                           min(row[2][c] for row in group))/2) for c in range(1, columns)] + [right]
        ys = [group[0][0]] + [int((max(w['y'] + w['height'] for s in group[r-1][1] for w in s) + group[r][0])/2)
                                for r in range(1, len(group))] + [max(w['y'] + w['height'] for s in group[-1][1] for w in s)]
        if any(a >= b for edges in (xs, ys) for a, b in zip(edges, edges[1:])):
            continue
        content = OrderedDict((r, [TableCell(BBox(xs[c], ys[r], xs[c+1], ys[r+1]),
            ' '.join(w['text'] for w in segment)) for c, segment in enumerate(segments)])
            for r, (_, segments, _) in enumerate(group))
        tables.append(ExtractedTable(BBox(xs[0], ys[0], xs[-1], ys[-1]), None, content))
    return tables


def table_hash(table):
    # JSON consumers can round floating OCR scores differently; geometry/text stay exact.
    def canonical(value):
        if isinstance(value, float):
            return round(value, 3)
        if isinstance(value, dict):
            return {k: canonical(v) for k, v in value.items()}
        if isinstance(value, list):
            return [canonical(v) for v in value]
        return value
    return hashlib.sha256(json.dumps(canonical(table), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def scan_tables(image_path, words):
    import cv2
    from img2table.document import Image
    from img2table.ocr._types import OCRData, OCRInstance
    cv2.setNumThreads(1)

    class PageOCR(OCRInstance):
        def of(self, document):
            records = [dict(id=str(i), parent=w.get('line', str(i)), value=w['text'],
                confidence=w['confidence'], x1=w['x'], y1=w['y'], x2=w['x'] + w['width'], y2=w['y'] + w['height'])
                for i, w in enumerate(words) if w['width'] > 0 and w['height'] > 0 and w['confidence'] >= 0]
            return OCRData(records={0: records}) if records else None

    image = Image(src=str(image_path), detect_rotation=False)
    found = image.extract_tables(ocr=PageOCR(), implicit_rows=True, implicit_columns=True,
                                 borderless_tables=True, min_confidence=1, max_workers=1)
    height, width = image.images[0].shape[:2]
    fallback = _aligned_tables(words)
    fallback = [table for table in fallback if not any(table.bbox.x1 < t.bbox.x2 and table.bbox.x2 > t.bbox.x1
                and table.bbox.y1 < t.bbox.y2 and table.bbox.y2 > t.bbox.y1 for t in found)]
    found.extend(fallback)
    results = []
    for table in sorted(found, key=lambda t: (t.bbox.y1, t.bbox.x1)):
        matrix = [[cell.value or '' for cell in row] for row in table.content.values()]
        positions = defaultdict(list)
        for r, row in enumerate(table.content.values()):
            for c, cell in enumerate(row):
                box = (cell.bbox.x1, cell.bbox.y1, cell.bbox.x2, cell.bbox.y2)
                positions[box].append((r, c, cell.value or ''))
        cells = []
        for box, slots in positions.items():
            top, left = min(s[0] for s in slots), min(s[1] for s in slots)
            bottom, right = max(s[0] for s in slots), max(s[1] for s in slots)
            contained = [w for w in words if box[0] <= w['x'] + w['width']/2 <= box[2]
                         and box[1] <= w['y'] + w['height']/2 <= box[3]]
            cells.append(dict(row=top + 1, column=left + 1, rowspan=bottom-top+1, colspan=right-left+1,
                text=slots[0][2], bbox=list(box), confidence=round(sum(w['confidence'] for w in contained)/len(contained), 3) if contained else None))
            cells[-1]['needs_review'] = any(w['confidence'] < 70 for w in contained)
        value = dict(method='aligned OCR columns' if table in fallback else 'img2table 2.0.0 + Tesseract', coordinate_system='oriented_page_image_pixels',
            image_width=width, image_height=height, bbox=[table.bbox.x1, table.bbox.y1, table.bbox.x2, table.bbox.y2],
            rows=len(matrix), columns=max(map(len, matrix), default=0), cells=sorted(cells, key=lambda c: (c['row'], c['column'])),
            matrix=matrix, status='candidate', attribution='Reconstructed table geometry and OCR text; verify page image')
        value['sha256'] = table_hash(value)
        results.append(value)
    return results


def table_html(table, number):
    import html
    cells = {(c['row'], c['column']): c for c in table['cells']}
    rows = []
    for r in range(1, table['rows'] + 1):
        values = []
        for c in range(1, table['columns'] + 1):
            cell = cells.get((r, c))
            if cell:
                values.append(f'<td rowspan="{cell["rowspan"]}" colspan="{cell["colspan"]}" '
                    f'title="row {r}, column {c}">' + html.escape(cell['text']) + '</td>')
        rows.append('<tr>' + ''.join(values) + '</tr>')
    return f'<h2 id="table-{number}">Table {number} · {table["rows"]} rows × {table["columns"]} columns</h2><table>' + ''.join(rows) + '</table>'
