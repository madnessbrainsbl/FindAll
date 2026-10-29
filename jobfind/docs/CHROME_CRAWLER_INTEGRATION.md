# Chrome crawler in FindAll

## Integrated browser research

Browser research also supports [Scrapling 0.5](https://github.com/D4Vinci/Scrapling)
CSS selectors. Enter an element selector such as `.vacancy-card` in the optional
field or pass `--selector .vacancy-card` to `browser-research`. Exact matches are
saved in the dossier with the source URL and DOM hash. When the same page later
changes and the selector no longer matches, Scrapling attempts heuristic relocation
using the first element from the most recent exact match. Recovered matches are
marked candidate and partial; verify them against the current source. No match is
not evidence of absence. Saved baseline HTML is stored under the selected output
directory's `.research/scrapling` and may contain source-page data.

Only the Scrapling parser is used. Existing bounded, pinned public transport and
browser request controls still apply. `setup.bat` installs the pinned Python
dependency; its BSD-3-Clause license is included in its installed distribution.

Open **Research → Browser research**, enter a public page URL and optionally a
research question, then choose **Collect pages**. Web search results also have a
**Browser research** action. The background collector renders JavaScript, scrolls
three times for lazy content, follows linked next pages on the same origin and
extracts JSON-LD, cards/microdata containers and table rows with column context.
Repeated structured records are deduplicated, retaining additional source pages.

Every run creates a normal versioned dossier, source ledger, JSON/CSV/Markdown
exports and shared relationship graph. Rendered DOM, sanitized offline preview,
text, metadata and viewport screenshot are retained with source URL, observation
time and SHA-256. The graph retains observations and candidate relationships,
without treating a listing as identity or ownership proof.

**Analyze with AI and source citations** uses the provider/model configured in
Dossier. Every retained browser record is included in AI evidence selection,
including those beyond the ordinary 80-record balanced sample. Normal bounded
AI excerpts still apply; unsupported quotes are rejected locally. The evidence
library indexes all saved structured records and the full retained page text,
including content beyond the dossier snippet. Choose **Search in evidence
library** and run a search or cited question to refresh the normal local index.

```powershell
.\.venv\Scripts\python.exe jobfind.py --out jobfind_out browser-research --url https://example.org/ --pages 3 --items 50
.\.venv\Scripts\python.exe jobfind.py --out jobfind_out browser-research --url https://example.org/ --question "What does the page publish?" --ai
```

This is FindAll's independent implementation using its existing Playwright and
pinned public fetcher, rather than copied extension code. Existing Chrome/Edge
is used, with Playwright Chromium as fallback. Run `setup.bat` if the browser
dependency is missing. No new dependency or background service is introduced.

Boundaries: a fresh isolated browser, same-origin public GET requests only;
1–8 attempted pages, 1–100 structured records, 40 resource fetch attempts and
90 seconds inside a 110-second worker timeout. Each fetch has an 8-second
deadline and at most four redirect hops, with public DNS pinning, host and
protocol checks at every hop. Transient network errors receive at most one
bounded retry; HTTP blocks and certificate errors are not retried. The worker
retains each completed page before continuing. Partial, blocked, timeout,
error and empty outcomes remain distinct. The source ledger reports exclusions.
Text is limited to 100,000 characters per page; structured text to 6,000 per
record; table extraction to 30 tables, 101 rows and 50 cells per row per page.

Only first-party HTML/JavaScript/CSS/text/JSON resources are loaded. Media,
images, fonts, frames, sockets, popups, login/form submission, authenticated
profiles, generated scripts and arbitrary agent actions are excluded. Third-party
JavaScript/CDN dependencies may therefore produce a partial result. Screenshots
show the resulting text/CSS page, without excluded images. Pagination requires
an actual next-page link; button-only navigation and arbitrary deep-site crawling
are outside this collector. Captured raw HTML is untrusted evidence; open the
sanitized preview from the UI.

Diagnostics reuse FindAll's allowlisted trace fields and contain no page bodies,
questions, full query URLs or credentials. Selected AI analysis sends retained
evidence to the configured provider; normal collection and indexing need no AI.

Validation: see [browser integration check](../jobfind_out/browser-check-20261022/CHECK.md).

## Existing extension import

The pinned [ir00nman/chrome-crawler](https://github.com/ir00nman/chrome-crawler)
extension is in `third_party/chrome-crawler`. Its working listing extractor and
rendered-tab text feed FindAll through an explicit local JSON export/import.
Installation, attribution, limits and license: [FINDALL.md](../third_party/chrome-crawler/FINDALL.md).

The native Research tools → Network & Web card opens the extension folder and
imports the downloaded page JSON into the standard Dossier screen. Imports use
the shared graph, source ledger, quality checks, library, AI citation selection
and JSON/CSV/Markdown export. AI evidence identifies these as `browser_import`
and retains their imported, unverified attribution. No new service or Python
dependency is needed.

```powershell
.\.venv\Scripts\python.exe jobfind.py --out jobfind_out browser-import --file "C:\path\findall-chrome-export.json"
.\.venv\Scripts\python.exe jobfind.py --out jobfind_out browser-import --file "C:\path\findall-chrome-export.json" --query "Compare the listings on this page"
```

To include exported pages in a normal research run, open **Dossier → Search
settings → Selected local files → Add Chrome crawler page exports…**. Select up
to ten JSON files, then use **Create dossier**. Browser observations join the
other sources in that dossier, AI citations, graph and standard exports. Each
file is handled independently; invalid files retain an error, truncated files
retain a partial status, and other results survive. Duplicate selected paths
are read once. Import runs after ordinary page capture and makes no requests.

```powershell
.\.venv\Scripts\python.exe jobfind.py --out jobfind_out dossier --query "Research question" --browser-file "C:\path\page-one.json" --browser-file "C:\path\page-two.json"
```

The standalone `browser-import` command creates a new dossier; existing dossiers,
databases and browser state are preserved. **Create dossier** uses its normal
database-saving workflow and labels imported pages as browser observations.
The imported JSON is a user-selected observation, not an
independently fetched public page. The upstream extension's own agent remains
available separately after manual installation; its full feature set is not
claimed as a FindAll collector. Its CC BY-NC 4.0 license applies to that bundled
extension; the independent browser collector above does not copy its code.

Validation on 22 October 2026: 330 Python tests, 26 Rust tests and 22 Node test
files passed. An isolated Chromium run exercised the actual extension export and
importer with a synthetic HTTPS page and checked exclusion of form and hidden
text. See [check report](../jobfind_out/chrome-crawler-check-20261022/CHECK.md).
Live third-party sites and external AI providers were not tested.

Follow-up dossier-selection verification is recorded in
[the dossier import check](../jobfind_out/chrome-crawler-dossier-check-20261022/CHECK.md).
