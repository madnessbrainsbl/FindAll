# FindAll — поиск работы и открытых источников

## Workspace and interface

**RAG and PDF:** open **Research → Evidence library** to search every saved dossier
and imported PDF, then ask the configured AI for source-linked, quoted answers.
PDF import includes digital text/tables, Russian/English OCR, structured scanned
tables with merged cells, row-aware citations and exact page previews.
See [setup, citations and processing limits](docs/EVIDENCE_LIBRARY.md).

**Statistics:** open **Workspace → Statistics**, or choose **Statistical analysis**
in a saved dossier. Import CSV/TSV/JSON/JSONL for local descriptive statistics,
correlations, time-series signals, graph communities, text/geo clusters and a
source-linked HTML report. [Methods, input fields and limits](docs/STATISTICAL_ANALYSIS.md).
The same screen runs local multilingual BERT, an LSTM autoencoder, UMAP, ordinary
kriging and calibrated bearing/range triangulation. **Models and input guide**
provides model installation and working example datasets.

**Open diagram** opens the accumulated evidence in the application's **Diagram**
tab. Choose a research query to keep unrelated searches out of the view. **Full screen (F11)** expands the diagram inside FindAll; **Esc** returns. Labels, node types and neighborhoods can be filtered; the native canvas supports
zoom, dragging, node selection and connection paths. The inspector retains source
URLs, quotations, timestamps and hashes. HTML remains an explicit portable export.
Source availability distinguishes blocked access from empty results; technical
provider errors remain available under **Technical details**.

Run `start.bat` here or in the parent workspace. The native UI has grouped navigation,
a compact navigation menu at smaller widths, and a shared light/dark theme.
The Windows launcher selects the newer built executable from `findall-ui.exe`
and `rust-ui/target/release/findall-ui.exe`. Archives, Wireless and `wireless-ui`
use the same selection. Source edits require
`cargo build --release --locked --manifest-path rust-ui/Cargo.toml`;
test builds do not update the release UI.
Regression checks live in `tests/`; use `test.bat` for the Python suite,
standalone integration checks and Rust tests. To run only the Python unittest
suite, use `.venv\Scripts\python.exe -m unittest discover -s tests -v`.
The integration audit is in [docs/OSINT_INTEGRATION_AUDIT.md](docs/OSINT_INTEGRATION_AUDIT.md).
The parent [workspace guide](../README.md) describes research documents, examples,
archives and the preserved data locations.

## Historical web research (Wayback / waymore)

Open **Archives** in the native FindAll window (or `archives.bat`). Enter a domain,
choose Wayback/Common Crawl and the integrated waymore sources, then search.
Filter by snapshot date, path category, historical status or MIME; collapse URL
parameter values while retaining parameter names. Waymore 8.9 is vendored with
its MIT license and verified wheel provenance in `third_party/waymore`.

The collector queries archive indices and saved copies. It never requests the
discovered URL on the current target website. Captures only follow redirects on
`web.archive.org`, and save at most 20 text responses, 2 MB each. Select a dated
Wayback row and click **Save selected response**, or set the response count before
collection. Static HTML/JavaScript paths and indicator names are extracted without
executing scripts. Recognized credential assignments and sensitive query parameters are redacted from text, dossier and AI input;
the original response bytes remain local, with SHA-256 provenance.

**View dossier / AI / graph** loads the saved evidence into Research. Historical
paths and parameter names have candidate edges in the relationship graph, dates
appear in the timeline, and bounded archive observations participate in local
snapshot comparisons. Ordinary domain Research includes archive URL collection;
its checkbox disables it. AI can request another bounded archive search for the
same domain and settings, and cannot infer current vulnerabilities from snapshots.

URL export files from waymore, gau or waybackurls can be imported as plain URL
lines, JSON/JSONL records, or CDX tables. Disable online providers for an offline
import. JSON, CSV, a deduplicated URL list, dossier Markdown and graph exports are
saved under the chosen output folder. Failed, blocked, timed-out, empty, skipped
and partial sources remain distinct. Results are bounded samples: Wayback stores
one returned snapshot per URL; Common Crawl examines at most two collections.
Undated provider URLs remain candidates when a date range cannot be verified;
strict status/MIME filters exclude URLs without that metadata.

```powershell
.venv\Scripts\python.exe jobfind.py archive-search --domain example.org --from 2020 --to 2024 --category api --limit 500
.venv\Scripts\python.exe jobfind.py archive-search --domain example.org --providers wayback --captures 3
.venv\Scripts\python.exe jobfind.py archive-search --domain example.org --providers "" --import urls.txt
```

`setup.bat` installs the dependencies; `setup-archives.bat` installs just the
archive dependencies. URLScan optionally uses `URLSCAN_API_KEY`; VirusTotal and
Intelligence X require `VIRUSTOTAL_API_KEY` and `INTELX_API_KEY` in
`osint-keys.env`. These providers retain their upstream API/access requirements.
Waymore runs in isolated child processes with source-only hosts, at most six
HTTP requests per provider and a 40-second deadline. User waymore configuration
and notification settings are not used. Browser buttons open snapshots only on
explicit clicks; browser network routing uses its own settings.


## WireTapper integration (2026-10-03)

**Wireless** in the main Rust/egui interface uses the same Python collector as the `wireless` CLI. It includes a native multi-file chooser, drag-and-drop telemetry, survey name, optional column mappings, source controls, an in-window coordinate plot, filtering, exports and **View dossier / AI / graph**. Research also accepts selected telemetry files. Run `start.bat` for the main app or `wireless.bat` to open its Wireless tab directly. The separate Tkinter window has been removed. `setup-wireless.bat` installs optional telemetry/BLE dependencies into the existing virtual environment.

The adapter executes WireTapper's real column matching, telemetry normalization, camera-coordinate parsing, device classification and RSSI distance helpers. It imports CSV/TSV, JSON, GeoJSON Point features, KML Points, SQLite tables and XLSX. Optional JSON column mappings support unfamiliar schemas. Files are read-only, individually limited to 20 MB / 1,500 records; ten selected files and 5,000 retained observations per run are the maximum. Invalid rows and truncation remain visible as partial coverage. Categories and distances are candidates; absent RSSI, observation time and coordinates remain unknown.

Explicit sources include WiGLE, OpenCelliD and Shodan geographic indexes, Censys v3 enrichment of public IPs supplied in telemetry, Windows Wi-Fi enumeration, bounded BLE discovery and SDR USB presence. API credentials are read from the existing `osint-keys.env` or environment using `WIGLE_API_NAME`, `WIGLE_API_TOKEN`, `OPENCELLID_API_KEY`, `SHODAN_API_KEY` and `CENSYS_API_TOKEN`. Geographic requests require latitude/longitude and a 0.1–10 km search radius. WiGLE/OpenCelliD use a bounding box with that half-width; Shodan uses its geo radius. Only the first response page is collected, and indexes may be historical or inaccurate. OpenCelliD records identify logical cells rather than confirmed physical towers and retain their CC BY-SA attribution. Censys requires explicit imported IPs and retains at most ten IPs / thirty services each.

Wi-Fi signal percentage is kept separate from RSSI in dBm. Local Wi-Fi/BLE/USB observations have no measured coordinates. BLE distance uses the upstream path-loss estimate and does not establish identity. USB presence is hardware enumeration, not RF decoding. Upstream generated RF map points are excluded from evidence. All local discovery controls start disabled.

Each run saves JSON, CSV, GeoJSON and an offline, selectable WGS84 coordinate plot with source details. It also produces a FindAll dossier, relationship graph, Markdown and quality checks. Source files and reports retain SHA-256 evidence anchors; AI receives candidate attribution and exact evidence excerpts. Research's `--wireless-file` imports explicitly selected telemetry through the same collector; no local file search or automatic hardware discovery is performed. The generated `wireless.json` can itself be imported into a later dossier.

```powershell
# Import a field survey and produce the integrated dossier.
.venv\Scripts\python.exe jobfind.py --network direct wireless --file "D:\Surveys\survey.csv" --query "Field survey"
# Configure provider keys first; each missing key produces a skipped source check.
.venv\Scripts\python.exe jobfind.py wireless --providers wigle,opencellid,shodan --latitude 55.75 --longitude 37.61 --radius 1
# Discover local advertisements only when explicitly selected.
.venv\Scripts\python.exe jobfind.py wireless --wifi --bluetooth --seconds 8
.venv\Scripts\python.exe jobfind.py dossier --query example.org --wireless-file "D:\Surveys\survey.json"
.venv\Scripts\python.exe jobfind.py wireless-ui
```

Upstream revision and local adaptations are recorded in `third_party/wiretapper/FINDALL_INTEGRATION.md`. Preserve `LICENSE-NONCOMMERCIAL.md`: WireTapper's license file allows non-commercial use and requires the author's permission for commercial use. Its README's license label differs from the actual license text; no relicensing is implied.

## Company evidence, history and notes (2026-10-03)

A full or email-focused domain dossier now discovers company career/contact pages, sitemap entries and static JavaScript leads. A careers board must be linked by a fetched company page before its Greenhouse, Lever, Ashby, Workable or SmartRecruiters adapter runs. Jobs retain that association page and the fetched publication/API URL. JavaScript-only links remain candidates. Published contacts, vacancies and pages are persisted in the existing SQLite database; subsequent runs deduplicate them.

The collector checks public addresses on requests/redirects and applies robots rules, page/script/board/byte/time limits and a cancellation callback. Quick runs use 12 pages/45 seconds; deep runs use 30 pages/120 seconds. Limits and partial outcomes remain in `career_discovery` and AI coverage. This is bounded static collection; dynamic browser rendering and exhaustive website coverage are not included.

Domain dossiers include a structured DNS/registration card (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, PTR and CAA), separate `success`, `no_records`, `nxdomain`, `timeout`, and `error` outcomes, null MX handling and registration dates independent of IPv4 availability. Normalized httpx observations preserve selected HTTP/TLS/header/technology fields and timestamps. Technology signatures are candidates, not equipment ownership. DNSDumpster uses `DNSDUMPSTER_API_KEY`; SecurityTrails historical DNS uses `SECURITY_TRAILS_API_KEY` from `osint-keys.env`. Missing credentials and account/rate limits are reported. Historical DNS is bounded to the first page for each supported record type.

Each dossier includes `history.timeline`, a same-target prior-run comparison, `dossier.md`, CSV history rows and dated graph nodes. Failed or incomplete checks produce **not observed**, not deletion. Archived content stays separate from current pages. **History and notes** opens Markdown, compares prior snapshots or exports a new versioned Obsidian folder. Existing vault notes are preserved.

```powershell
.venv\Scripts\python.exe jobfind.py dossier --query example.org --kind domain --scope full
.venv\Scripts\python.exe jobfind.py dossier-export --path "jobfind_out\dossiers\example.org\<run>\dossier.json" --vault "D:\Notes"
.venv\Scripts\python.exe jobfind.py dossier --query example.org --no-careers --no-domain-card
```

### Explicit local source audit

**Research tools → Local source audit** scans a directory you select with Gitleaks, independently of web research. It runs no remote credential validation. The official Windows archive is checksum verified; reports retain rule/file/line/commit/date metadata, excluding secret values, matches and author contact data. A timeout is partial; no findings is not a security certification. Installed release provenance: `third_party/gitleaks/INTEGRATION.json`.

```powershell
.venv\Scripts\python.exe jobfind.py local-audit --install
.venv\Scripts\python.exe jobfind.py local-audit --path "D:\MySource" --timeout 120
.venv\Scripts\python.exe jobfind.py local-audit --path "D:\MySource" --history
```

These additions implement the company/domain priorities in the supplied analysis. Katana/headless crawling, external scanner-result imports, dependency advisories and the AppSec/C2 inventory are not installed by this change. Ordinary dossier creation never starts local secret scanning.

Инструмент с оболочкой Windows на **Rust/egui** и сборщиком на Python: получает вакансии из **публичных API** (без ключей и регистрации),
извлекает **компании** и **контакты** (email, опубликованные самими компаниями), ищет
публичные GitHub-проекты по интересам, строит
**готовые поисковые ссылки** на рекрутеров и нанимающих менеджеров, и складывает всё в
отчёты (HTML/CSV/XLS/Markdown) + SQLite-базу.

Backend использует Python 3.10+ и [DDGS](https://github.com/deedy5/ddgs) для поисковиков. На Windows один раз запустите `setup.bat`: он создаёт локальную `.venv` и устанавливает `requirements.txt`.

## Collection reliability

### Integrated development skills and quality diagnostics

The installed `python-resilience`, `python-observability`, `async-python-patterns`, `python-testing-patterns`, `llm-evaluation` and `security-best-practices` guides have been applied to the application workflow. The project-specific `findall-research-quality` skill is installed in the local Codex skills folder; `AGENTS.md` describes when these guides apply to future changes.

- The shared HTTP client retries transient GET failures with bounded attempts and server-directed Retry-After delays. Permanent errors and TLS failures are not retried; POST is sent once. HTTP status survives exhausted retries. Requests share a two-request host limit and spaced starts.
- Web sources run through an async dispatcher with at most four concurrent adapters. Each source produces its own completion result. Cancellation stops queued adapters; adapters already executing retain their transport timeouts.
- Each new dossier contains a `quality_report` covering source outcomes, pending checks, evidence attribution and AI citation invariants. It is refreshed when AI analysis or graphs are saved. **Evidence checks** in the UI shows the results and review notes. Matching citations do not prove identity or factual truth.
- Each collection writes a bounded `diagnostics.jsonl` beside `dossier.json`, with a run ID, host/method/status, retries, source states and timings. **Collection diagnostics** opens that trace. The trace excludes request bodies, authorization headers, query strings and user queries. External tool transports and subsequent AI follow-up retain separate reporting.

Inspect an existing dossier without modifying it, or run the synthetic benchmark:

```powershell
.venv\Scripts\python.exe jobfind.py dossier-quality --benchmark
.venv\Scripts\python.exe jobfind.py --out jobfind_out dossier-quality --path "jobfind_out\dossiers\example.org\<run>\dossier.json"
```

Exit 1 indicates failed invariants; exit 2 indicates invalid input. The benchmark tests eight fictional cases and makes no network or model calls. Neither it nor a passing quality report measures factual accuracy. The HTTP budget limits retry scheduling and socket timeouts; slowly streaming responses do not have hard cancellation.

### Source coverage

Quick research requests up to 10 results per web source; deep research requests up to 40. Wikipedia is additionally capped at 20. Page capture selects unique URLs across different hosts, preserves successful HTML/text evidence, and records one coverage notice for pages outside the selected limit. Source checks show the latest outcome; `source_events` retains the transition history.

Search engine outcomes distinguish access blocks, timeouts, filtered unrelated matches, and confirmed empty responses. A disabled DDGS backend cannot silently substitute another engine under the requested engine's name. External CAPTCHA and rate limits remain visible. AI receives provenance and match uncertainty, rejects unsupported numeric/contact anchors, and reports `no_conclusions` when no supported claims are accepted. These checks reduce errors; they do not establish that matching accounts belong to the same person.

## Interactive relationship graph

All research accumulates in **one workspace diagram**, `jobfind_out/relationship_graph.html`. Click **Open diagram** in the sidebar to include saved results and explore it inside FindAll. New web searches, jobs/projects, parsed pages, research tools, dossiers, archives and wireless evidence update the same diagram. Search matches and shared handles remain unverified links; they do not establish identity or ownership. Existing outputs are preserved.

**Enrichment flows** in Research tools and the selected-node inspector add typed,
bounded investigation chains adapted from [Flowsint](https://github.com/reconurge/flowsint).
Ten enrichers and six reusable flows expand DNS → ASN → prefixes, website links and
tracking IDs, registrable domains and offline CIDR samples into the same diagram.
Custom JSON flows are validated before execution. See [integration and verified scope](docs/FLOWSINT_INTEGRATION.md).

**Chrome crawler** in Research tools → Network & Web imports rendered tab text and
structured listing cards from the bundled extension's **Export page to FindAll**
button. Each local JSON import creates a dossier for the same diagram, library,
AI analysis and exports. No model key is needed for export/import. Install the
extension manually; imported browser observations remain unverified.
To combine exported pages with other sources, add up to ten files under Dossier →
Search settings → Selected local files, then choose Create dossier. CLI supports
repeatable `dossier --browser-file PATH`; malformed files leave other results intact.
See [setup, CLI and scope](docs/CHROME_CRAWLER_INTEGRATION.md).
Upstream by ir00nman uses CC BY-NC 4.0; commercial use requires separate permission.

The graph runs offline with embedded data. Pan/zoom, filter node types, inspect a selected node and its evidence, and find paths between nodes. **Export evidence** explicitly writes the accumulated `exports/research.json` and `exports/research.csv`; repeated exports replace these two files. The browser also offers Export JSON. Internal graph state and deduplicated HTML page captures live under `.research/`; dossier history and collector artifacts remain in their own folders. Routine web/jobs searches do not create timestamped JSON/CSV files. The Python `evidence_graph.write_exports` helper remains available for specialized BloodHound OpenGraph exports. Paths show recorded evidence connections, not inferred identity, ownership or privilege escalation.

Existing dossiers can use **Build relationship graph** without collecting again, or:

```powershell
.venv\Scripts\python.exe jobfind.py --out jobfind_out dossier-graph --path "jobfind_out\dossiers\example.org\<run>\dossier.json"
```

## Apex: сеть для поиска

[apex-parser](https://github.com/Diversan313/apex-parser) встроен в сетевой процесс FindAll:
его код разбирает plain/Base64/JSON-подписки и преобразует VLESS, VMess, Trojan,
Shadowsocks и Hysteria2 в конфигурации Xray. FindAll обновляет публичные подписки,
проверяет адреса и срок действия, удаляет одинаковые соединения и проверяет узлы
двумя HTTPS-запросами. Доступны группы `full`, `wl`, `bl`, `ai`, `torrent`, страны
по двухбуквенному коду и собственные HTTPS-подписки. Закрытый apex-sources не нужен.

**Запустите `network.bat`**: окно настроек работает с текущим EXE через обновлённый
Python backend. Установите Xray, обновите подписки, проверьте узлы, выберите строку
со статусом `ok` и нажмите **Enable selected**. **Disable Apex** возвращает прежний
сетевой режим. В исходниках Rust добавлена вкладка **Network**; она появится в
основном окне после следующей пересборки EXE. Эта интеграция не пересобирает EXE.

Выбранный маршрут применяется к вакансиям, GitHub, поисковикам DDGS, публичным
страницам, доменным HTTP API, AI HTTP API, Maigret, TikTok и Chrome-сборщику 2GIS.
Tor, сервер Web-Check, внешние AI CLI и ссылки, открываемые во внешнем браузере,
используют собственные транспорты. Настройки Windows не меняются. Xray запускается
только на время команды и закрывается вместе с ней. Если выбранный узел недоступен,
FindAll пробует до двух других проверенных узлов; если все три не работают,
команда возвращает ошибку без автоматического прямого подключения.

CLI из папки `jobfind` (тот же файл настроек, что у основного окна):

```powershell
.venv\Scripts\python.exe jobfind.py --db ..\jobfind.db network install
.venv\Scripts\python.exe jobfind.py --db ..\jobfind.db network refresh --group bl --limit 300
.venv\Scripts\python.exe jobfind.py --db ..\jobfind.db network check --limit 12
.venv\Scripts\python.exe jobfind.py --db ..\jobfind.db network enable
.venv\Scripts\python.exe jobfind.py --db ..\jobfind.db projects --kw python --limit 10
.venv\Scripts\python.exe jobfind.py --db ..\jobfind.db network disable
```

`--network direct` перед командой принудительно задаёт прямое подключение;
`--network apex` требует проверенный Apex-узел независимо от сохранённого переключателя.
`network refresh --country NL` выбирает страну, `--subscription https://…` задаёт
свою подписку (можно повторить), `network check --node <id> --test-url https://…`
проверяет доступ к нужному HTTPS-источнику. `network status` возвращает состояние
без конфигурационных секретов. Локальный `network/apex-state.json` рядом с `--db`
содержит конфигурации подключения; его не следует включать в публичные отчёты.
Запуск `network.bat` использует `..\jobfind.db`; обычный CLI без `--db` использует
`jobfind.db` текущей папки. `--network-state` позволяет явно указать файл настроек.

Xray устанавливается из официального релиза XTLS/Xray-core с проверкой SHA256
по его `.dgst`; существующий Xray можно задать через `JOBFIND_XRAY`. Исходники MIT,
зафиксированный коммит и локальные изменения перечислены в
`third_party/apex-parser/INTEGRATION.md`. Проверки: `.venv\Scripts\python.exe -m unittest tests.test_apex_network -v`.

## One-screen research dossier

### Integrated collection and AI follow-up

**Create dossier** now combines applicable collectors, page evidence, and optional AI follow-up in one run. Choose **Quick** or **Deep** in Search settings. Progress counts completed scheduled tasks; the individual source ledger records successes, partial results, timeouts, blocked sources, and missing credentials.

- Domains: DNS/registration, certificate discovery, passive discovery engines, full Web-Check modules, theHarvester, and indexed service APIs.
- Usernames: Maigret, WhatsMyName, Sherlock, Social Analyzer, Blackbird, public GitHub commits, TikTok, and public Instagram profile/posts through Instaloader.
- Emails: existing public-source checks plus GHunt when an authenticated Google session is configured using `ghunt-login.bat`.
- Phones: public searches and integrated PhoneInfoga v2.11.0 scanners: structured number-plan information, generated search queries, optional Google CSE/Numverify responses and supported OVH number ranges. See [PhoneInfoga integration](docs/PHONEINFOGA_INTEGRATION.md). Public IPs use InternetDB and configured Shodan/Censys/ZoomEye APIs.
- Business/map settings add the vendored 2GIS parser and OpenStreetMap Overpass results to the same dossier. Set a 2GIS city and/or an OSM administrative area.
- Selected files contribute SHA-256 and embedded EXIF/PDF/Office metadata. Source pages and public Telegram posts contribute captured text, contextual published emails, original HTML hashes, and safe offline previews rendered by SingleFile.
- OnionSearch queries selected engines individually. Ahmia uses its normal browser form; Tor engines use the local Tor route. Each index has its own status. Source capture can follow selected v3 onion results when onion collection is enabled.
- **Let AI request additional source checks** enables a bounded tool workflow for the original target: Quick permits up to 3 requests in 2 rounds; Deep permits 6 requests in 3 rounds. The dossier saves each request and result. The final answer cites web sources or hashed local evidence and uses the query language.

Each run saves `dossier.json`, `dossier.csv`, and an `artifacts` directory inside its timestamped folder. The UI exposes the artifacts, source ledger, and AI activity. A completed run with blocked sources does not establish that no information exists.

`setup.bat` installs the base environment and then invokes `setup-research-tools.bat`. New research engines use isolated Python 3.12/3.14 environments; the existing backend remains on its existing Python version. Source revisions and binary hashes are pinned in `setup-research-tools.ps1`. Chrome is needed by browser-based collectors. GHunt login and commercial/API credentials are configured separately; unavailable credentials are reported as skipped.

```powershell
.venv\Scripts\python.exe jobfind.py dossier --query example.org --kind domain --coverage deep --ai --ai-investigate
.venv\Scripts\python.exe jobfind.py dossier --query "Example Studio" --city moscow --map-location Berlin
.venv\Scripts\python.exe jobfind.py dossier --query example.org --metadata-file "C:\Evidence\photo.jpg"
```

Search settings expose the same options as CLI `--coverage`, `--capture-pages`, `--city`, `--business-query`, `--2gis-limit`, `--map-location`, repeatable `--metadata-file`, `--no-extra-tools`, and `--ai-investigate`.

Run `start.bat`, enter a person's name, `@username`, an email, an IP address, or a public website/domain on the **Research** screen, then press **Create dossier** or Enter. **Search settings** can limit the input type and focus to full research, published email, domain/equipment, or public profiles. The progress percentage counts completed scheduled tasks; the current stage and source warning count are shown beside it. The screen displays sourced results and buttons to open the consolidated `dossier.json` and `dossier.csv`. Each run saves these two files under `jobfind_out/dossiers/<query>/<timestamp>/`. The grouped navigation provides Web search, Jobs and projects, Research tools (2GIS, domain and profile tools), and Contacts and email. At smaller widths these sections are available through **FindAll / Navigate**.

The **Research answer** explains collected public evidence in the query's language (Russian for Cyrillic queries, English for Latin queries). Search settings offer 12 text providers: Groq, OpenRouter, Cerebras, Google Gemini, Cloudflare Workers AI, NVIDIA NIM, Token Harbor, B.AI, local Antigravity, Codex CLI, Claude Code CLI, and Grok CLI. Enter the provider key when required, click **Test connection · load models**, choose a model from the live catalog, then click **Verify selected model**. Model lists show what the provider reports; verification makes a short generation request to check actual access. Claude CLI does not expose a reliable model catalog, so its ID can be entered manually. Cloudflare also needs an Account ID. The local Antigravity gateway can use an optional key. CLI providers use their existing login and need the corresponding executable on PATH. The key is kept in the running window's memory and passed only to the backend child process; it is not written to the report or imported from Talkaside. The answer and matched quotes are saved in `dossier.json`. Without a working provider, the dossier still saves and shows a setup message. Once configured, **Analyze saved dossier** generates the answer without repeating the search. AI claims include exact matched source quotes and still require checking the source. The app does not assert that a matching profile belongs to a named person or that an observed IP service is equipment owned by the domain holder.

CLI: `.venv\Scripts\python.exe jobfind.py dossier --query "example.org" --scope domain --progress-json` (`--kind` accepts `auto`, `person`, `username`, `domain`, `email`, `ip`, `phone`; `--scope` accepts `full`, `email`, `domain`, `profiles`). `--no-spiderfoot` skips the passive SpiderFoot pass. `--spiderfoot-timeout` is the cap in seconds (default 120; `0` waits until the scan finishes). A direct scan is `.venv\Scripts\python.exe jobfind.py spiderfoot-scan --target example.org --use-case passive --timeout 180` (`--kind` also accepts `asn` and `bitcoin`; `--use-case` accepts `passive`, `footprint`, `investigate`, `all`; `--modules` is a comma-separated list). List current model IDs with `.venv\Scripts\python.exe jobfind.py ai-models --provider codex` (or another provider). `--ai` enables provider analysis after setting `JOBFIND_AI_PROVIDER` and `JOBFIND_AI_MODEL` in the process environment. API providers additionally need `JOBFIND_AI_API_KEY`; Cloudflare needs `JOBFIND_AI_ACCOUNT_ID`, and Antigravity may use `JOBFIND_AI_GATEWAY_URL`. To analyze an existing report, run `.venv\Scripts\python.exe jobfind.py dossier-analyze --path "<path-to-dossier.json>"` with the same provider environment. Progress events are written as JSON lines to stderr; the final report metadata is one JSON object on stdout.

The default full dossier queries Google, Yandex, Bing, DuckDuckGo, Brave, Mojeek, Bing RSS, Wikipedia, news, and GitHub in parallel. It also runs Maigret and TikTok profile checks plus GitHub commit-email lookup for an explicit username. A domain adds DNS, certificates, observed public IP services, full Web-Check results, published site emails, archive snapshots, and public breach notices. The same dossier then runs a short SpiderFoot passive set in-process for up to 2 minutes, so the scan can finish instead of starting every passive module. Events that include a page URL join the web, profile, and published-email sections; other events are listed as findings on the same screen. The event database is `jobfind_out/spiderfoot/spiderfoot.db`. After each scan, `PASSWORD_COMPROMISED`, `HASH_COMPROMISED`, and `CREDIT_CARD_NUMBER` rows are deleted and are not shown. The engine is MIT-licensed [SpiderFoot](https://github.com/smicallef/spiderfoot) at commit `0f815a203afebf05c98b605dba5cf0475a0ee5fd`, vendored in `third_party/spiderfoot`. FindAll does not start SpiderFoot's own web interface. Search settings include **Run SpiderFoot with this search**, on by default. A username also checks a sample of WhatsMyName sites and the fields published on the GitHub profile. An email checks Gravatar, whether Holehe reports the address as registered, and whether keys.openpgp.org has a published key; recovery addresses, phone fragments, and the key block are discarded. A domain adds existing urlscan.io results, passive Subfinder hostnames (`third_party/subfinder/subfinder.exe`, no active probing), and Internet Archive captures. A public IP adds its RDAP registration; private addresses are not sent out. A name, handle, email, or phone also keeps public https pages from VK, OK, Telegram, YouTube, Reddit, Pikabu, Habr, and Dzen. A name also keeps Wikidata entries, a DuckDuckGo instant answer, and a GLEIF legal-entity match when one is published. A public IP also keeps reverse DNS from HackerTarget and the RIPE Stat prefix. Passive DNS from AlienVault is included only when `OTX_API_KEY` is set. Phone targets also run the integrated PhoneInfoga scanners: numbering-plan facts, generated search queries, optional Google CSE/Numverify and supported OVH ranges; each source keeps its own coverage status. A username also runs Sherlock, Social Analyzer, and Blackbird; an email runs Blackbird. Those checks keep https profile links. Blackbird's AI upload, Instagram session, and saved page metadata are not used. A domain also runs passive Amass (`third_party/amass/amass.exe`, no `-active` and no brute force), one httpx request to that exact https site (`third_party/httpx/httpx.exe`), and passive hostname lists from Anubis, RapidDNS, HackerTarget, and Common Crawl. A public IP also gets the network location published for that address. Brute force, port scans, takeover checks, leak contents, and phone-location lookups are not run. OnionSearch can be enabled in Search settings or with `dossier --onion`; it needs local Tor. If direct Tor connections are blocked, turn on the Apex route: Tor then uses that local HTTP proxy. The onion checkbox is on by default and can be disabled in Search settings. Source checks update progress as each finishes. An empty search-engine response is shown as empty, while transport errors and partial Maigret coverage remain visible. AI can request bounded follow-up collectors when AI investigation is enabled, then summarizes a balanced sample from all dossier sections and cited artifacts. A bare Latin word is treated as a name, so prefix a handle with `@` or choose Username in settings.

## 2GIS business search

The **Tools → 2GIS** panel runs the bundled [Parser2GIS](https://github.com/interlark/parser-2gis) Chrome/CDP engine. Enter a business name or category, a supported city name/code (for example `moscow`), and a result limit. The parser reads actual 2GIS listing records. FindAll deduplicates businesses by their 2GIS URL, keeps addresses, phones, sites and published emails in SQLite, and shows a direct source link for every listing. Select **Use in Contacts** beside a listing email to review its source and compose a single message. **Find site emails** opens FindAll's existing public website crawler for a listed company site; emails found there retain their page URLs.

```bash
.venv\Scripts\python.exe jobfind.py 2gis-search --query "photo studio" --city moscow --limit 25
```

Requires Google Chrome and dependencies installed by `setup.bat`. Results are saved to `directory_businesses` and `people_contacts` in SQLite, plus raw 2GIS JSON and normalized JSON, CSV and XLSX in `jobfind_out/2gis/`. An email in a directory listing is evidence that it was published there; it does not identify a particular employee or guarantee delivery. 2GIS businesses are directory entries, not job openings. The upstream source and LGPL-3.0 license are retained in `third_party/parser-2gis/` (upstream commit `e12cc050ea811ed76e65a1be938214b6583f9072`). The headless Chrome viewport fix was adapted from the [Eroloft fork](https://github.com/Eroloft/parser-2gis-new).

## OSINT-поиск

Во вкладке **«Общий поиск»** введите запрос и нажмите **«Найти»**. DDGS параллельно опрашивает Google, Яндекс, Bing, DuckDuckGo, Brave и Mojeek; прямые источники дают MediaWiki/Wikipedia, новости и GitHub. Если указан домен, тот же запуск выполняет доменный анализ (включая Shodan InternetDB и Web-Check) и полный Web-Check. Если указан ник, он запускает GitHub Email Hunter, Maigret и TikTok Scraper; найденные профили и email попадают в общую выдачу с источниками. Тот же запуск, после остальных источников, выполняет пассивный SpiderFoot до 2 минут: события с URL страницы попадают в общую выдачу и в `osint_results`, остальные остаются в `jobfind_out/spiderfoot/spiderfoot.db`. Типы `PASSWORD_COMPROMISED`, `HASH_COMPROMISED` и `CREDIT_CARD_NUMBER` удаляются и не показываются. Отдельного окна и веб-интерфейса SpiderFoot нет. Движок — MIT SpiderFoot, коммит `0f815a203afebf05c98b605dba5cf0475a0ee5fd`, каталог `third_party/spiderfoot`. Ключи `SHODAN_API_KEY` и `SECURITY_TRAILS_API_KEY` из `osint-keys.env` подставляются в соответствующие модули. Ник дополнительно проверяется по выборке WhatsMyName и по полям, которые владелец сам указал в публичном профиле GitHub. Email проверяется по Gravatar, флагу регистрации Holehe и наличию опубликованного ключа на keys.openpgp.org; адреса восстановления, фрагменты телефонов и сам ключ не сохраняются. Домен дополняется уже опубликованными сканами urlscan.io, пассивными именами Subfinder и снимками Internet Archive. Для публичного IP запрашивается регистрация RDAP; частные адреса наружу не отправляются. Телефон описывается только по плану нумерации. Ник дополнительно прогоняется через Sherlock, Social Analyzer и Blackbird, email — через Blackbird; сохраняются только https-ссылки профилей. ИИ Blackbird, сессия Instagram и вытащенные со страниц метаданные не используются. Для домена дополнительно запускаются пассивный Amass (`third_party/amass/amass.exe`, без `-active` и без перебора), один запрос httpx к этому же https-сайту и пассивные списки имён Anubis, RapidDNS, HackerTarget и Common Crawl. Для публичного IP добавляется опубликованное сетевое местоположение этого адреса. Перебор имён, сканирование портов, проверка захвата поддоменов, содержимое утечек и геолокация телефона не запускаются. Tor/OnionSearch включается отдельной галочкой. Если прямой Tor не поднимается, включите маршрут Apex: Tor пойдёт через его локальный HTTP-прокси. Рядом с каждым источником видны число ответов или ошибка. CAPTCHA, таймаут и блокировка источника не считаются отсутствием сведений. У каждой записи есть
заголовок, краткий фрагмент, категория, время сбора и прямая ссылка. Ошибки
источников показываются отдельно; ссылки на поисковики, публичные посты
Telegram (Google CSE), Ahmia и OpenStreetMap являются ручным продолжением поиска,
не считаются собранными результатами. Домен организации можно ввести отдельно
для DNS/MX/SPF/DMARC, RDAP и ближайшего доступного снимка главной страницы
в Internet Archive. Для домена показываются публичные уведомления Have I Been Pwned об инцидентах: это не поиск записей из утечек. Наличие MX не доказывает существование email.

Кнопка **«Парсить страницу»** читает одну выбранную публичную HTTPS-страницу с учётом `robots.txt`, извлекает видимые email и сохраняет адрес вместе с URL. Дополнительно сохраняются время наблюдения, копия полученного HTML как текст (`.html.txt`) и её SHA-256; запись доступна из истории точного запроса. Хэш подтверждает целостность локальной копии, а не правдивость содержания страницы. Парсер не устанавливает личность владельца адреса.

Выдача сохраняется в `jobfind.db` (`osint_results`) и добавляется в общую диаграмму
`jobfind_out/relationship_graph.html`. Поиск больше не создаёт отдельные JSON/CSV на каждый запуск;
кнопка **Export evidence** выгружает общую диаграмму по запросу.
Результаты встроенных инструментов сохраняются в `osint_integrations` и открываются из истории точного запроса.
**«Открыть сохранённое»** повторно показывает результаты точного запроса без сети.

```bash
python jobfind.py osint-search --query "OpenAI" --sources web,wikipedia,news,github
python jobfind.py osint-search --query "OpenAI" --domain openai.com
python jobfind.py osint-search --query "torvalds" --username torvalds --sources github,wikipedia
python jobfind.py osint-search --query "example.org" --mode email
python jobfind.py spiderfoot-scan --target example.org --use-case passive --timeout 180
python jobfind.py osint-search --query "@torvalds" --mode email
python jobfind.py osint-search --query "photography jobs" --onion
python jobfind.py osint-history --query "OpenAI"
python jobfind.py osint-page --query "Apache" --url "https://www.apache.org/foundation/contact.html"
```

На вкладке OSINT выберите **«Полное исследование»** или **«Только опубликованные email»**.
Домен в основном поле автоматически включает доменные проверки; `@ник` или одиночный
ник без `@` включает поиск публичных профилей и GitHub Email Hunter.
Доменный поиск email читает до 15 открытых HTTPS-страниц сайта; поиск по нику проверяет
публичные коммиты GitHub. Адрес появляется только с URL-источником. Полный режим и режим «Только опубликованные email» после остальных проверок запускают тот же пассивный SpiderFoot; в почтовые записи попадает только адрес со ссылкой `https`. Полный режим для
домена также собирает опубликованные email сайта. Если источник ограничил доступ,
это показывается в состоянии источников; отсутствие результата не доказывает
отсутствие адреса в интернете.

Это поиск и журнал публичных публикаций. Он не делает поиск по содержимому утечек,
личным телефонам, истории аккаунтов в Telegram и закрытым чатам. Боты и
справочники из присланного списка не запускаются автоматически: многие
из них ориентированы на идентификацию частных лиц; открытый API для их
подключения здесь не проверен. Картографические ссылки OpenStreetMap доступны отдельно от встроенного поиска компаний 2GIS: публичный сервер Nominatim запрещает встраивать его как
универсальную геопоисковую службу в приложения такого типа.

## Доступ к поисковым источникам

Общий поиск включает источник **Telegram and public sites**: VK, OK, Telegram,
YouTube, Reddit, Pikabu, Habr и Dzen.
Для YouTube используется собственная публичная выдача, для Reddit и Хабра —
публичные поисковые RSS. Telegram находит до трёх каналов через публичный каталог
TgramSearch и читает их сообщения напрямую на `t.me`; запись каталога остаётся
кандидатом, а не подтверждением принадлежности канала человеку. Эти способы
работают независимо от доступа к общей выдаче поисковиков. Для остальных
площадок и при сбое прямого источника используются DuckDuckGo и Bing, затем
Brave/Яндекс API при наличии ключей. Поиск проверяет домен
каждой ссылки и совпадение с исходным запросом. Запросы к индексу выполняются
последовательно с интервалом; после блокировки тот же индекс не повторяется до
конца текущего поиска. Для Telegram дополнительно читаются публичные сообщения до трёх
найденных каналов: совпадение проверяется по тексту сообщения, сохраняются URL,
время публикации и хеш страницы. Для площадки сохраняется до восьми ссылок,
для Telegram — до трёх кандидатов и до сорока сообщений каждого канала.
Это ограниченная публичная выборка, а не полный поиск всех каналов и закрытых чатов.
В onion-индексах также проверяется совпадение запроса с заголовком, цитатой или URL;
ответы, состоящие только из посторонних ссылок, отмечаются как ошибка источника.

Brave и Яндекс автоматически используют официальный API, если в существующем
`osint-keys.env` или окружении заполнены `BRAVE_SEARCH_API_KEY` либо пара
`YANDEX_SEARCH_API_KEY` / `YANDEX_SEARCH_FOLDER_ID`. Шаблон —
`osint-keys.env.example`; ключи передаются в заголовках и не попадают в отчёты.
Запросы расходуют квоту соответствующего аккаунта. Без ключей остаются обычные
публичные адаптеры; CAPTCHA и HTTP 403/429 показываются как ограничения доступа.
API также имеет лимиты и не гарантирует отсутствие блокировок. Google и Mojeek
могут оставаться недоступны в текущей сети.

## Запуск с кнопкой «Старт» (Windows)

Оболочка написана на Rust; она вызывает локальный `jobfind.py` как backend. Для работы backend нужен Python 3.10+.
Запустите `setup.bat` один раз для установки зависимостей, затем `start.bat`: он открывает собранный `findall-ui.exe` из этой папки. Оболочку можно пересобрать командой `cargo build --release --manifest-path rust-ui\Cargo.toml`, после чего скопировать `rust-ui\target\release\findall-ui.exe` в корень проекта. CLI доступен через `.venv\Scripts\python.exe jobfind.py ...`.

В едином поиске введите профессию, специализацию или навыки, выберите источники вакансий
и нажмите **«Искать вакансии, проекты и контакты»**. Один запрос одновременно запускает
поиск вакансий, GitHub-проектов, совпавших веб-страниц Bing/Яндекс/Brave и email,
опубликованных в текстах вакансий. Результаты показываются в окне и сохраняются в CSV;
вакансии, контакты и проекты также сохраняются в SQLite. Дополнительные ссылки открывают
тот же запрос в Google, пользовательском Google CSE для публичных Telegram-постов,
HeadHunter и индексе onion-сайтов Ahmia. CSE запускается в браузере; автоматический Google
JSON API требует ключа и закрыт для новых клиентов. Для ручного поиска
контактов на сайте компании остаётся вкладка **«Контакты и письмо»**. Нужны Python 3.10+ и интернет.

На вкладке **«Контакты и письмо»** введите компанию или её домен. Если домен неизвестен,
поиск покажет сайты-кандидаты с исходными ссылками: выберите нужный сайт для поиска email.
Программа читает до 15 открытых HTTPS-страниц выбранного сайта, соблюдает
`robots.txt` и собирает опубликованные адреса с URL-источниками. Можно указать имя сотрудника:
тогда также будут показаны гипотезы адреса по распространённым шаблонам. Они не проверяются
SMTP и помечены как гипотезы; отправлять из программы можно только опубликованный адрес
после ручной проверки и отдельного подтверждения.

## Быстрый старт

```bash
python jobfind.py scan                     # борды по умолчанию: simplify, jobicy, remoteok, HN
python jobfind.py scan --kw python         # фильтр по ключевому слову
python jobfind.py scan --ats greenhouse:stripe ashby:ramp workable:epignosis   # ATS конкретных компаний
python jobfind.py companies                # кто уже попал в базу
python jobfind.py contacts                 # найденные email
python jobfind.py contacts --hypotheses    # + гипотезы careers@/hr@ (ручная проверка)
python jobfind.py report --limit 200       # HTML-отчёт из базы
python jobfind.py score --min 60           # скоринг вакансий под ваш профиль
python jobfind.py track add --company ACME --role "Python Dev" --contact hr@example.invalid --next-date 2026-10-01
python jobfind.py track list               # воронка откликов
python jobfind.py track due                # по кому пора дожать
python jobfind.py draft --id 31 --name "Иван" --lang en   # черновик письма по вакансии #31
python jobfind.py projects --kw "python security"       # поиск проектов на GitHub
```

Результаты: `jobfind_out/jobs_*.csv|xls|md`, `jobfind_out/report_*.html`, база `jobfind.db`.

## Источники (проверены живыми запросами 2026-09-28)

| Источник | Статус | Что даёт |
|---|---|---|
| HeadHunter API | ⚠️ HTTP 403 в текущей сети | публичный поиск по произвольной профессии; доступность зависит от сети |
| Jobicy | ✅ живой | remote-вакансии, полный текст описания, поиск по тегу |
| RemoteOK | ✅ живой | remote-вакансии (1-й элемент фида — служебный, пропускается) |
| HN «Who is hiring» | ✅ живой | компании ищут людей **сами** — самые тёплые контакты |
| Simplify (New-Grad-Positions) | ✅ живой | **~20k вакансий для джуниоров одним JSON**: активные фильтруются, свежесть по дате |
| Greenhouse | ✅ живой | вакансии компании с полным описанием (`content=true`) |
| Ashby | ✅ живой | вакансии компании (пример: `ashby:ramp`, `ashby:elevenlabs`) |
| Lever | ✅ живой | US + EU-эндпоинт с фолбэком (пример: `lever:blackshark`) |
| Workable | ⚠️ частично | GET `?details=true`; часть аккаунтов отвечает, часть нет |
| Remotive / Arbeitnow | ⚠️ HTTP 403 в текущей сети | API существуют, но доступность зависит от сети и ограничений источника |
| SmartRecruiters | ❌ IP-блок | 403 с серверных IP; код оставлен на будущее |

По условиям API RemoteOK и Jobicy требуют указание источника — кредиты встроены в HTML-отчёт.

## Проверка доменов (команда `domains`)

Встроенные проверки FindAll читают MX, SPF, DMARC через **DoH Cloudflare** и возраст домена через **RDAP**. Дополнительно локально установлен исходный [Web-Check](https://github.com/lissy93/web-check): вкладка **«Инструменты OSINT»** запускает его Node-сервер на `127.0.0.1:3031`, вызывает полный `/api` и сохраняет JSON каждого модуля. Перед первым запуском выполните `setup-webcheck.bat` (Node.js 22.12+). Часть внешних модулей может отвечать ошибкой или требовать ключ; это видно по каждому модулю. Web-Check не подтверждает существование конкретного почтового ящика.

```
python jobfind.py domains --limit 40      # быстрая проверка первых 40 компаний
```

## Исследование домена: Shodan и другие источники

Во вкладке **«Инструменты OSINT»** введите домен и нажмите **«Исследовать домен»**. Команда собирает поддомены из CertSpotter и crt.sh, разрешает публичные IP, читает сервисы из бесплатного Shodan InternetDB, проверяет DNS/RDAP, ищет страницы в шести веб-индексах, определяет технологии через локальный Web-Check/Wappalyzer и сохраняет ссылки на JS главной страницы. У каждого источника видны число записей и ошибка. InternetDB — периодический снимок IP, а не полный поиск Shodan; принадлежность всех сервисов организации по одному IP не утверждается.

Полные API Shodan (DNS и host), Censys v3 (host), ZoomEye v2 (domain) и SecurityTrails (subdomains) включаются доступными ключами. Скопируйте `osint-keys.env.example` в `osint-keys.env`, заполните имеющиеся значения и снова запустите команду. Этот файл исключён из Git; ключи не попадают в отчёт. Для полного отчёта Web-Check ключ Shodan передаётся его локальному серверу при запуске; после смены ключа перезапустите локальный сервер Web-Check. Доменный запрос Shodan может выполнить до 10 запросов страниц и расходует кредиты по тарифу аккаунта. Бесплатный InternetDB разрешён Shodan для некоммерческого использования. Пропущенный источник в интерфейсе не считается пустой выдачей.

```powershell
.\setup-webcheck.bat
.\.venv\Scripts\python.exe jobfind.py domain-recon --domain example.com --max-hosts 100 --max-ips 10
```

Результат сохраняется в `jobfind_out/domain_<домен>_<дата>.json` и `.csv`. Пассивный сбор не сканирует порты, не получает закрытые Telegram-данные и не ищет содержимое утечек.

## Про LinkedIn и ботов

[LinkedIn API](https://github.com/tomquirk/linkedin-api) и его клоны (включая
скиллы ClawHub вида linkedin-api) не встроены сознательно: неофициальный доступ к LinkedIn
нарушает их User Agreement, ведёт к блокировке аккаунта, и все публичные скрейперы живут
«до следующей смены верстки». Инструмент вместо этого даёт **готовые поисковые ссылки**
LinkedIn/Google/X по каждой компании — заходите своим аккаунтом и пишете живым людям.

Для автоматизации откликов есть open-source движки вроде
[CopilotKit/openbot](https://github.com/CopilotKit/openbot) (self-hosted агент с собственным
браузером, alpha) — это отдельный стек (Docker, Postgres), здесь он не нужен; FindAll
работает локально и не требует Docker.

## Бесплатный OSINT контактов и отправка

На вкладке **«Инструменты OSINT»** [OnionSearch](https://github.com/megadose/OnionSearch) запрашивает публичные onion-индексы через локальный Tor SOCKS и сохраняет CSV со ссылками. `setup-tor.ps1` скачивает официальный Tor Expert Bundle с фиксированным SHA-256; затем Tor запускается локально по мере надобности. Каталог данных фиксированный: `jobfind_out/tor-data`, журнал `jobfind_out/tor.log`. Если сеть не даёт соединиться с Tor или индексом, показывается ошибка, а пустой ответ нельзя считать отсутствием информации. При включённом маршруте Apex Tor получает его локальный HTTP-прокси как `--HTTPSProxy`. Содержимое скрытых сайтов FindAll не загружает.

Hunter.io удалён. Поиск контактов теперь не требует API-ключа или платных кредитов:
`jf/osint_contacts.py` проверяет общедоступный сайт компании и ищет опубликованные
адреса на главной странице, страницах контактов, вакансий, о компании и связанных
страницах того же домена (до 15 страниц, только HTTPS, с учётом `robots.txt`). Сохраняется URL
страницы, где найден email. Паттерны, построенные из имени сотрудника, имеют статус
`guess`: это только догадки, а MX-запись домена не подтверждает существование ящика.
SMTP-проверок и массовой рассылки нет.

Для сравнения: [EmailFinder](https://github.com/Zahidulislam2222/email-finder) — MIT,
без платных API, сочетает публичные страницы и генерацию паттернов. В FindAll сделан
похожий сценарий на стандартной библиотеке; код EmailFinder не включён как зависимость.
[theHarvester](https://github.com/laramies/theHarvester) — более крупный доменный OSINT-проект с
пассивными источниками, но текущая версия требует Python 3.14 и отдельную установку,
тогда как FindAll запускается на Python 3.10+.

Опубликованный адрес показывается с источником. Отправка разрешена только для адреса,
найденного на открытой странице, и только после ручной проверки, редактирования письма
и отдельного подтверждения. SMTP STARTTLS/SSL использует ваши настройки почты; пароль
держится в памяти окна. Журнал фиксирует получателя, тему и результат, но не тело письма.

### Подключение отправки

В окне письма SMTP-логин и адрес отправителя должны совпадать. Для Gmail укажите
`smtp.gmail.com`, порт `587`, защиту `STARTTLS`, полный адрес Gmail и пароль приложения
(для него Google требует включённую двухэтапную проверку). Google рекомендует OAuth для
сторонних приложений; FindAll пока использует SMTP с паролем приложения.
Для Яндекс Почты: `smtp.yandex.com`, порт `465`, защита `SSL`, полный адрес и пароль
приложения; SMTP-доступ и пароли приложений должны быть разрешены в настройках почты.
Outlook.com указывает `smtp-mail.outlook.com:587` и `STARTTLS`, но требует OAuth2 /
Modern Auth — текущий SMTP-клиент FindAll не поддерживает OAuth2, поэтому отправка для
этой учётной записи сейчас не подключается.

## Найденные GitHub-инструменты и выбор

- [theHarvester](https://github.com/laramies/theHarvester) собирает доменные OSINT-адреса,
  но не ориентирован на поиск нанимающих; актуальная ветка требует Python 3.14 и `uv`.
- [work-email-finder](https://github.com/logiover/work-email-finder) работает как Apify
  Actor: нужен аккаунт/токен Apify, а результат может строиться по шаблону адресов.
  MX-проверка подтверждает почтовый домен, но не конкретный ящик.
- [Prospector](https://github.com/anusbutt/Prospector) ближе всего к отправке: требует
  явного одобрения каждой записки, но ориентирован на локальные сервисные компании и
  требует отдельного Python/WSL-стека. В FindAll перенесён принцип ручного подтверждения,
  без копирования его зависимостей.
- Платный Hunter.io не используется. Контактный поиск бесплатный и читает только
  открытые страницы указанного сайта; гипотезы по имени не считаются подтверждением.
- [rawfilejson/awesome-osint-arsenal](https://github.com/rawfilejson/awesome-osint-arsenal)
  используется как реестр инструментов во вкладке **«Инструменты OSINT»**: записи Maigret, OnionSearch, Web-Check, Shodan и TikTok Scraper имеют кнопку запуска соответствующего адаптера FindAll. Остальные 747 записей описывают внешние программы; их Linux-установщики на Windows не выполняются и результаты не смешиваются с поисковой выдачей.
- [soxoj/maigret](https://github.com/soxoj/maigret) подключён как отдельный поиск публичных профилей по нику с JSON-отчётом и показом ошибок источников. Установлен в `.venv` через `setup.bat`.
- [vahid56/github-email-hunter](https://github.com/vahid56/github-email-hunter) включён в `third_party` и запускается прямо из вкладки **«Инструменты OSINT»**. Он проверяет публичные репозитории и коммиты GitHub-аккаунта, извлекает email из заголовка `.patch`, показывает ссылку на коммит и сохраняет результат в SQLite (`osint_emails`, запрос `github:<username>`) и JSON. Встроенная проверка принимает только коммиты, у которых `author.login` совпадает с искомым аккаунтом; скрытые/непривязанные к аккаунту email она не выявляет. Бесплатный режим работает без токена в пределах лимита GitHub API; необязательный `GITHUB_TOKEN` задаётся в `osint-keys.env` или окружении. Найденный адрес — опубликованный email автора коммита, он не помечается как контакт работодателя и не отправляется автоматически.
- [drawrowfly/tiktok-scraper](https://github.com/drawrowfly/tiktok-scraper) включён для публичных метаданных профиля. Его старый HTML-парсер обновлён под `__UNIVERSAL_DATA_FOR_REHYDRATION__`; если сайт не отдаёт HTML, используется TikTok oEmbed с меньшим набором полей. Лента и скачивание видео у этой версии на текущем Node.js не работают и в FindAll не предлагаются. Установка: `setup-tiktok.bat`. Блокировка или лимит TikTok показывается ошибкой источника.
- [megadose/OnionSearch](https://github.com/megadose/OnionSearch) подключён через Tor SOCKS; запрос ограничен одной страницей на индекс и имеет CSV-отчёт. Нужен работающий Tor, который можно установить через `setup-tor.ps1`. Если прямой выход блокируется, включённый маршрут Apex передаётся Tor как `--HTTPSProxy`.
- [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) (MIT, коммит `0f815a203afebf05c98b605dba5cf0475a0ee5fd`) лежит в `third_party/spiderfoot` и вызывается внутри досье и OSINT-поиска, без `sf.py` и без своего веб-интерфейса. По умолчанию набор Passive, остановка через 120 секунд, события в `jobfind_out/spiderfoot/spiderfoot.db` и в тех же разделах отчёта. `spiderfoot-scan` может выбрать `footprint`, `investigate` или `all`. Строки `PASSWORD_COMPROMISED`, `HASH_COMPROMISED` и `CREDIT_CARD_NUMBER` из базы удаляются.

```powershell
.\setup.bat
.\setup-webcheck.bat
.\setup-tor.ps1
.\setup-tiktok.bat
.\.venv\Scripts\python.exe jobfind.py tools-catalog --query email --limit 100
.\.venv\Scripts\python.exe jobfind.py web-check --domain example.com
.\.venv\Scripts\python.exe jobfind.py maigret --username example --top-sites 20
.\.venv\Scripts\python.exe jobfind.py github-email --username torvalds
.\.venv\Scripts\python.exe jobfind.py tiktok-profile --username tiktok
.\.venv\Scripts\python.exe jobfind.py onion-search --query "photography jobs"
```

### Доступ к поисковым источникам и Tor

Yahoo доступен в общем поиске и полном досье. Если основные индексы не отдают публичные страницы платформы, FindAll пробует Yahoo и указывает реальный индекс в источнике результата. Блокировки Google, Яндекса и других сервисов остаются отдельными статусами; найденные через другой индекс ссылки не выдаются за их результаты.

Команда `onion-search` применяет выбранный `--network` так же, как общий поиск. Через проверенный маршрут Apex Tor сначала подключается к обычным узлам на порту 443 с предпочтением IPv6; состояние этого подключения хранится в `jobfind_out/tor-upstream`. Затем используются совместимые мосты. Snowflake не запускается через неподдерживаемый им HTTP-прокси. Загрузка описаний узлов на стадии 50% не считается ранним зависанием; общий запуск ограничен шестью минутами. Работа onion-индекса проверяется отдельно от успешного подключения Tor.

## Скоринг и трекер (v1.1)

**score** оценивает вакансии в базе по вашему профилю (`profile.json`, создаётся шаблон
при первом запуске): совпадение позиции (до 40), навыки (до 25), remote/локация (до 10),
свежесть (до 15), прямой email в описании (+10). Каждая оценка сопровождается объяснением
«почему» — никаких чёрных ящиков. Профиль:

```json
{
  "titles": ["python", "developer", "engineer"],
  "skills": ["python", "sql", "docker"],
  "exclude": ["senior", "principal"],
  "remote_only": false,
  "locations": [],
  "role": "Python Developer",
  "highlight": "5 лет Python: API на FastAPI, Postgres в Docker",
  "team": "Notifications",
  "project": "notification delivery pipeline",
  "metric": "сократил(а) время доставки на 40%"
}
```

**track** — воронка откликов в той же SQLite: new → contacted → interview → offer / rejected.
`track due` показывает, по кому пора написать повторно (next_date).

**draft** генерирует черновик письма (EN/RU; `apply` — на вакансию, `recruiter` — без вакансии,
`follow` — фоллоу-ап) по шаблонам, собранным из отдельного исследования холодного аутрича:

| Правило | Значение |
|---|---|
| Длина тела | ~100 слов (рабочий диапазон 50–150) |
| Тема | 6–10 слов, формула «{role} — {highlight}» |
| CTA | ровно один мягкий вопрос («отправить резюме?», «15 минут?») |
| Первое письмо | без вложения резюме, без слова «job/position» |
| Фоллоу-ап | через 3–7 дней, 1–2 раза, тема `Re:` |
| Лучшее время | Вт–Чт, утро по локальному времени получателя |

Полное исследование с источниками — `.cluster/osint-job-finder/subagent_04.md`.

## Как искать людей, которым написать

1. `scan` собирает вакансии и вытаскивает **реальные email** из описаний (компании иногда
   пишут «questions? jobs@example.invalid» — это самый короткий путь).
2. `contacts` показывает их; для каждого — ссылка на вакансию, чтобы понять контекст.
3. `domains` проверяет домены компаний: MX (почта принимается?), возраст домена (RDAP).
4. `contacts --hypotheses` строит правдоподобные адреса (`careers@`, `jobs@`, `hr@`,
   `talent@`, `people@`...) по домену компании и отмечает те, где домен точно принимает почту.
   ⚠️ Это **гипотезы**, не проверенные ящики — только для ручной сверки.
5. HTML-отчёт содержит раздел **«Ссылки для поиска людей»**: готовые запросы LinkedIn
   («recruiter + компания»), Google (email/контакты компании), X/Twitter.
   Открыл → увидел живого человека → написал персонализированно.

## Этика и границы

- Только публичные API и открытые данные. Никакого скрейпинга
  LinkedIn/Indeed, никаких обходов защит, никакой массовой рассылки.
- Для прямых HTTP-запросов встроена пауза на хост; DDGS работает по ограничениям поисковиков. Ошибка одного источника не прерывает прогон.
- Инструмент помогает **найти, кому писать**. Писать — вы, своими словами.

## Структура

```
jobfind.py          CLI: scan / score / draft / track / report / companies / domains / contacts
jf/net.py           HTTP (GET/POST JSON), таймауты, retries, rate-limit, лимит тела 25 МБ
jf/sources.py       источники вакансий (борды + ATS), унификация записей
jf/score.py         скоринг вакансий под профиль (прозрачные правила + объяснение)
jf/track.py         трекер откликов: статусы, даты follow-up
jf/projects.py      поиск публичных GitHub-репозиториев по запросу
jf/outreach.py      шаблоны писем (EN/RU: apply/recruiter) с плейсхолдерами
jf/contacts.py      извлечение email, гипотезы, поисковые ссылки на людей
jf/osint_contacts.py бесплатный сбор опубликованных адресов с сайта компании
jf/domains.py       DoH MX-проверка + RDAP-возраст домена (идея web-check)
jf/db.py            SQLite: jobs / companies / contacts / applications / projects / runs
jf/report.py        отчёты CSV / XLS (SpreadsheetML) / HTML / Markdown
```

## Ограничения

- Ключевые слова фильтруют remotive/jobicy/remoteok; arbeitnow и ATS-борды отдаются целиком
  (фильтруйте в отчёте).
- Гипотезы контактов используют домен-«догадку» (`company.com`) — у компаний с неочевидным
  доменом сверяйте вручную через поисковые ссылки из отчёта.
- HN-ветки: берутся топ-комментарии двух свежайших тредов «Who is hiring?».

## Проверка дополнительных OSINT-инструментов

Браузерный сбор динамических страниц: **Research → Browser research**.
JavaScript, прокрутка, страницы выдачи, карточки и таблицы сохраняются в досье,
граф и библиотеку RAG; опциональный ИИ использует проверяемые цитаты.
[Возможности, запуск и ограничения](docs/CHROME_CRAWLER_INTEGRATION.md).

Живые прогоны 13 октября 2026: [результаты и границы проверки](docs/LIVE_OSINT_CHECK_20261013.md).
Работа внешнего сайта проверяется отдельно от установки инструмента. Заблокированные,
неавторизованные и завершившиеся по времени источники не считаются успешной пустой выдачей.
Пассивный адаптер Amass использует проверенный официальный EXE 3.23.3. Web-Check API
запускается на время запроса с его сетевым маршрутом; сервер интерфейса не сохраняет
временный адрес Apex. Старые отчёты и конфигурации сохраняются.

