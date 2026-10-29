# Evidence library: saved dossiers and PDFs

Open **Research → Evidence library** in the native FindAll window. Enter a question
and choose **Search library** for local retrieval, or **Ask AI with citations** for
an answer through the provider/model configured in **Dossier**. AI configuration
is shared; no second API key store is created. The dossier AI checkbox does not
disable an explicit library question.

**Update index** discovers every `dossier.json` below the normal results folder and
the project's `jobfind_out` folder. Optional **Dossier folders** replace those roots.
New and changed documents are indexed automatically before each question. Source
folders, original dossiers and prior answers remain intact. Missing or invalid
sources are excluded from retrieval and reported in source diagnostics.

## PDF import

Use **Choose PDFs… → Import and index PDFs**. Processing retains an immutable
SHA-256 copy, metadata, per-page text, page images, digital and scanned tables (also CSV),
embedded public HTTP(S) links and email strings. Scanned pages use local Tesseract
with English/Russian models and orientation detection. A searchable PDF copy
combines the original digital pages with OCR text layers for scanned pages.
**Open PDF page** shows the exact page image, extracted text, tables and links.

Scanned table reconstruction runs locally using pinned `img2table` 2.0.0/OpenCV
and Tesseract word boxes. Repeated OCR column alignment handles borderless layouts
that image geometry misses. Each table retains its rectangular matrix and unique
cells with row/column, `rowspan`/`colspan`, bounding box, OCR confidence and structure
hash. Empty cells keep their positions. JSON and the page HTML retain merged-cell
geometry; CSV repeats merged values over their occupied slots. **Pages and extraction
details** provides CSV and **Cells and spans JSON** links. Low-confidence text is
marked for review and is never silently corrected to an assumed value.

Existing unencrypted OCR imports are reprocessed automatically on the next index
update/search, retaining previous extractions and originals. Re-import encrypted
PDFs with their password to upgrade their scanned tables; passwords remain unstored.

An optional published origin URL becomes a source link with `#page=N`; without it,
the source remains a local artifact identified by its hash. Origin and authorship
are supplied/unverified, rather than inferred. Password-protected PDFs accept a
password through stdin, then a worker environment variable; it is not stored in
reports or command arguments. The retained original remains encrypted, but derived
text, images and the searchable copy are readable local files.

Install optional dependencies/models using `setup-library.bat`, or the in-app
**Set up local search and OCR** after normal `setup.bat`. Tesseract must be installed
separately; `FINDALL_TESSERACT` can specify its executable. On this Windows setup
the standard `C:\Program Files\Tesseract-OCR\tesseract.exe` is detected automatically.
The setup verifies pinned English/Russian/orientation data from
`tesseract-ocr/tessdata_fast` revision
`87416418657359cb625c412a48b6e1d6d41c29bd`, retaining provenance and licence in
`third_party/tesseract-data`. BERT reuses the verified, offline multilingual model
already used by Statistics. Setup downloads models; indexing/search do not.

## Retrieval and citations

All eligible saved evidence is indexed, including PhoneInfoga records beyond the
ordinary dossier AI sample and full retained web capture text. Local SQLite FTS5
keyword retrieval is combined with normalized multilingual BERT vectors and
reciprocal rank fusion. Index updates are incremental; captures and dossier
snapshots are retained separately. A missing semantic model leaves an explicit
keyword-only result rather than silently installing or contacting a model host.

RAG selects up to 12 relevant fragments across the index for each AI question;
indexing all dossiers does not mean sending the whole collection in every prompt.
Only those excerpts, source URLs, attribution and timestamps are sent to the
selected provider. Navigation paths and unrelated dossiers stay local. Indexed
document text can contain sensitive user content; review selected excerpts with
**Search library** before sending an AI question when needed.

The model returns statements with an evidence ID and verbatim quote. Local checks
reject missing IDs, unmatched quotations and invented numeric/domain/email/hash
anchors. Citation metadata comes from the index, never from model-generated links.
Every retained source snapshot is hash-checked before retrieval. Exact quote
matching is not proof that a paraphrase, identity association or source assertion
is true. Contradictory accounts remain separately attributed claims.

Table rows are separate RAG fragments, with column context repeated from the
header region, including merged heading rows. Evidence retains page, table, row,
cell geometry and the table structure hash. AI claims and JSON/Markdown exports
retain the page/table/row reference. A changed matrix that no longer matches the
saved structural hash is excluded instead of being cited.

Click the source under a claim to open its publication, saved original, PDF page,
or original dossier in FindAll. Each answer is versioned under
`<output>/library/answers/` as JSON and Markdown with excerpts, page numbers, hashes,
public URLs and links to retained local evidence. The local index lives at
`<output>/library/index.sqlite3`; managed PDF extractions are in `library/pdf/`.
Answers are not re-indexed as independent source evidence.

## Limits and failure states

- Each PDF: 100 MB, 500 pages, ten-minute worker deadline; each scanned page has
  an OCR deadline. Completed pages survive a timeout. Locked, error, timeout,
  partial and empty-page outcomes remain distinct. A failed PDF does not discard
  other files in the same import batch.
- Table geometry and cell text are candidates requiring image verification.
  Borderless fallback requires at least three aligned rows; irregular spacing,
  multiline borderless cells and complex nested headers may be missed or split.
- OCR can misread names, identifiers, handwriting, rotated/sparse text and complex
  layouts. Use the retained page image to verify the quotation. Word confidence
  and bounding boxes are retained in the extraction report.
- No PDF scripts, attachments or embedded actions are executed. No URL from an
  imported PDF is requested during extraction. Rendering/parsing happen in a
  separate bounded process, not an OS security sandbox.
- Dossiers above 64 MB and external capture files above 10 MB are excluded with
  the dossier limit recorded as an error. Only captures inside the dossier folder
  are eligible. Existing dossier secret-metadata filtering remains active; this
  feature is not a universal document secret scrubber.
- BERT uses 128 tokens per embedding, overlapping 90-word chunks and batches.
  Retrieval is a relevance estimate; no claim of exhaustive answer coverage or
  measured factual accuracy is made.

```powershell
.venv\Scripts\python.exe jobfind.py library --action index --out ..\jobfind_out
.venv\Scripts\python.exe jobfind.py library --action pdf --file C:\Documents\report.pdf --out ..\jobfind_out
.venv\Scripts\python.exe jobfind.py library --action search --question "Компания Астра" --out ..\jobfind_out
.venv\Scripts\python.exe jobfind.py library --action ask --question "Какие даты указаны в источниках?" --ai-provider codex --ai-model gpt-6.1-sol --out ..\jobfind_out
```

Regression checks: `tests/test_library.py`, `tests/test_pdf_documents.py`, `tests/test_pdf_tables.py`, existing
PhoneInfoga/analytics tests and Rust argument/native UI checks. Verification
artifacts for this implementation: `jobfind_out/library-check-20261019/`.
Scanned table verification: `jobfind_out/scanned-tables-check-20261019/`.
