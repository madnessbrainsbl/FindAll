# FindAll OSINT integration audit — updated 2026-10-03

## Current implementation

### Supplied company/domain analysis implemented, 2026-10-03

- `jf/careers.py` is called by domain/full and domain/email dossiers and bounded AI follow-up. It traverses company HTML/sitemaps, parses JobPosting data, extracts contact/career links and static JS candidates, verifies an observed company-page association before using the five existing ATS adapters, and retains request/page/byte/time/cancellation limits. Arbitrary JS endpoints are not invoked. Jobs preserve the fetched API/publication source independently from the application link. Robots/public-address/redirect restrictions and partial outcomes have fixture coverage. No headless renderer is installed in this change.
- CLI dossier persistence uses existing jobs/companies/people_contacts/osint_results tables. Published contacts are separate from hypotheses; repeat runs deduplicate existing records. `career_discovery` preserves bounds and AI coverage. Careers/jobs enter JSON, CSV, Markdown, the graph and final AI evidence with source attribution.
- `jf/domain_enrichment.py` normalizes DNS/RDAP/Web-Check, supports IPv6-only and null MX, reverse-address PTR, CAA, separate DNS states and redacted registration. DNSDumpster is connected through the official key-authenticated API and two-second start spacing. Registration events are domain dates, not company formation. httpx JSON retains selected HTTP/header/TLS/technology/timestamp fields, with signature uncertainty. A live neutral `example.org` DNS/RDAP call succeeded; a live httpx run returned no observations and remains an explicit source error. DNSDumpster account access was not tested with a key.
- `jf/dossier_history.py` adds source-dated timelines and bounded latest-prior same-target comparison. Incomplete checks do not establish deletion. Current and archived rows with the same URL remain distinct. SecurityTrails historical DNS queries are optional, key dependent and first-page bounded; real account access was not tested. Archived email graph links do not imply current contact validity.
- `jf/markdown_export.py` creates `dossier.md`; `dossier-export --path --vault` adds a new versioned Obsidian index/entity-note export using graph IDs and wikilinks. Existing notes are not overwritten. The UI provides readable DNS/registration/timeline/comparison fields, source links and export controls rather than raw JSON blocks.
- `jf/local_audit.py` and Advanced tools provide an explicit local Gitleaks action, independently of OSINT research. Installed official Windows release: v8.30.1, archive SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`; archive checksum and installed binary provenance retained. `--redact=100`, metadata allowlisting and suppressed scanner output keep secret values/matches/author contacts out of application reports. Missing/malformed scanner reports are partial, not a clean audit. The actual installed binary passed a disposable clean-file check.

The report's conditional AppSec import/advisory work and larger attack/C2 inventory are outside these integrations. No Katana/LinkFinder upstream clone or headless runtime is represented as installed; static link extraction is implemented natively. Live ATS/browser rendering, DNSDumpster/SecurityTrails account queries, rendered GUI layout and a BloodHound server import have not been verified. These changes do not solve external search-engine CAPTCHA or rate limits. Existing results were preserved.

Verification: final full suite passed **143 checks**. The synthetic citation benchmark passed **8/8**; Python sources compiled; the Rust release build passed. Final affected careers/Markdown/dossier checks also passed after the configured-limit/source-link corrections. The release binary was copied to the launcher location; root/release SHA-256 matched: `A9F0CE809C6578E7084554CE455096CB2C30FF2F5C5297B865AD58CD5DF612EB`. The build includes the structured domain/history display and explicit local audit UI. No rendered GUI verification was performed.

### Installed skills applied to the application, 2026-10-03

- Resilience: shared `jf/net.py` now uses `jf/resilience.py` for bounded transient GET retries, Retry-After, two in-flight requests per host, thread-safe start spacing and preserved final HTTP status. POST is never automatically replayed. Apex opener/routing remains covered by regression checks.
- Observability/security: `jf/diagnostics.py` writes an allowlisted, bounded collection trace and per-source timings beside each new dossier. No request bodies, authorization headers, query URLs or user queries enter the trace. HTTP failures use sanitized descriptions. External tool transports and AI follow-up have separate reporting.
- Async execution: UI/CLI `osint.search` uses `search_async`, four concurrent adapters, isolated source failures, source completion callbacks and ContextVar propagation. Async callers can await it directly; cancellation stops queued work, not already executing blocking adapters.
- Evaluation: `jf/research_quality.py` attaches offline citation/attribution/source-coverage checks to dossier JSON and exposes `dossier-quality --path` / `--benchmark`. The Rust UI displays **Evidence checks**, review notes and **Collection diagnostics**. The eight-case fictional benchmark makes no model or service calls; passing it does not certify truth or ownership.
- Maintenance: installed custom `findall-research-quality` skill and project `AGENTS.md` bind these workflows to future changes. A separate agent exercised the skill against invalid quotations, mismatched URLs and blocked sources, verified unchanged input hashes and CLI output-directory restrictions, and identified a UI source-index mismatch that was fixed.
- Verification: 101 offline regression checks passed, including 14 shared-HTTP tests, 7 evaluation tests and 7 new tracing/async tests. Synthetic benchmark: 8/8. Python compilation and `cargo check` passed. The release executable was rebuilt after the final UI correction and copied to root `findall-ui.exe`; launcher and release SHA-256 hashes match. Visual rendering and credential-dependent live services were not verified during this change.

These changes do not remove external CAPTCHA, rate limits or missing provider credentials. The HTTP budget governs scheduling/socket timeouts rather than hard cancellation of slowly streaming responses. Older dated audit tables below are historical; use the current implementation sections for later integrations.

### Reliability corrections verified 2026-10-03

- Reproduced the reported capture noise: a limit of one page previously produced 39 skipped checks for 40 inputs. It now makes one request and emits one aggregate page-limit notice. Unique URLs are selected across hosts, profiles are considered first, and capture uses a total time budget. Challenge pages are excluded from factual evidence.
- Final source checks replace earlier running/attempted entries for the same source and URL. Transition history remains in `source_events`; source URLs are retained in the CSV. Tool calls always emit a terminal aggregate outcome.
- Quick web research now requests 10 results per source, deep requests 40, and Wikipedia has a maximum of 20. Unrelated candidates are filtered and their counts retained.
- The installed DDGS release disables its Bing and Yandex backends. FindAll now uses an explicit same-engine fallback instead of allowing DDGS to silently substitute another source. Access challenges and unconfirmed empty pages are reported as source failures, not absence of information.
- AI tool planning respects applicable targets and required settings. Failed collector rows are excluded from factual evidence; candidate attribution and provenance are preserved. Unsupported numeric, email and domain anchors are rejected. A result with no accepted claims receives `no_conclusions`. Quote-anchor validation is not a complete semantic fact checker.
- Ahmia preserves the complete requested query up to 200 characters and verifies it against the returned form/query. Incorrect or unconfirmed query responses are source errors.

Validation: 69 regression tests plus four capture/status regressions passed (73 total). After the final export and progress changes, 39 affected tests passed again. Python compilation, `cargo check`, and the Rust release build passed. A fresh live `example.org` capture retained one page and four artifacts without errors. The rebuilt executable used by `start.bat` was deployed and its SHA-256 matched the release binary.

Live neutral search checks found Google and Brave HTTP 429 responses and Mojeek/Yandex CAPTCHA responses. Those external access failures remain unresolved and visible. DuckDuckGo returned three relevant results; unrelated Bing RSS and Wikipedia candidates were filtered. Saved historical dossiers were preserved; the corrections apply to subsequent collection. No new rendered GUI inspection or BloodHound server import was performed during this reliability pass.

The gaps identified in the historical baseline below have now been implemented as executable dossier steps:

- Full local Web-Check `/api` results are merged as `sections.webcheck_modules` with their raw JSON artifact.
- The vendored 2GIS parser runs when a city is selected; business records, contacts, source URLs, and raw JSON join the same dossier.
- OnionSearch now uses source-specific endpoints/parsers, selected-page bounds, index snapshots, and truthful engine statuses. Ahmia's browser form was verified live (30 parsed URLs from a neutral test query). Tor index failures remain visible.
- Selected public web/Telegram pages are actually downloaded, parsed, hashed, and retained. Public post text and contextual email evidence enter the dossier. SingleFile renders a safe offline preview; remote scripts are not executed in that preview.
- theHarvester, GHunt, Instaloader, PhoneInfoga and SingleFile were installed with callable adapters. GHunt requires explicit user login; no session was invented or borrowed from another project.
- OpenStreetMap Overpass and selected local EXIF/PDF/Office metadata are real collectors, with source/object URLs or file SHA-256 provenance.
- Direct public IP inputs now query InternetDB and the configured Shodan/Censys/ZoomEye paths; absent API keys produce skipped statuses.
- Quick/deep settings change engine site counts, time ceilings, repository/page limits, and source-page capture counts. Deep is broader bounded coverage, not a promise of every site in the world.
- AI now has a bounded allowlisted tool workflow for the original target, plus a final source-cited answer in the query language. Its requests, rejections and source outcomes are retained. Missing model credentials produce an explicit unconfigured state.
- The English Rust UI exposes these settings, consolidated report files, source ledger, artifacts and AI activity. Progress reflects completed scheduled tasks.
- Completed dossiers now produce an offline interactive relationship graph and a generic BloodHound OpenGraph JSON export. The graph separates observed relationships, candidate search matches and AI interpretations; each edge retains source links or evidence hashes when available. It does not assert identity, equipment ownership or Active Directory permissions. Graph bounds and omitted counts are included in the output. Existing dossiers can regenerate their graph without another network search.

Validation: 56 project regression checks passed; `cargo check` and the release build succeeded; the research-engine setup script succeeded. After the final capture provenance change, 25 affected checks passed again. PhoneInfoga executed on a fictional number, metadata provenance passed with synthetic documents, SingleFile archived a live public example page, and Ahmia returned 30 live public index results. The 2GIS parser collected one museum with published contacts and passed a forced timeout check. A live domain dossier contained full Web-Check modules, domain observations, artifacts and source statuses.

Authenticated Codex analysis succeeded with 80 evidence items and 12 cited claims. The bounded AI investigator executed two additional page captures against already indexed URLs; both returned HTTP 404, which the saved trace records. Commercial API calls and authenticated GHunt calls remain unverified without their own credentials. Google's live request returned HTTP 429; the adapter now reports the block explicitly. Live Overpass endpoints timed out, so map parsing is covered by offline checks but live map results are not claimed. theHarvester ran as a process but its certificate providers reported partial/transport failures, which are retained rather than reported as empty-success.

Closed Telegram bots, private/leaked databases, paid API entitlements and arbitrary repositories on the GitHub topic page are not represented as implemented or verified. The Arsenal repository is a catalog; its entries are not executable code. Existing job/email tools remain available separately from the research dossier.

Graph delivery: the saved neutral `example.org` dossier generated 129 nodes and 187 edges, including OpenGraph JSON. Python compilation, JavaScript syntax checking and Rust release compilation passed. The rebuilt launch executable matches the release binary by SHA-256. Rendered browser inspection was unavailable: Codex browser policy rejected the local `file:` URL; no alternate browser or localhost workaround was used. Import into a running BloodHound instance has not been performed. The generated HTML is delivered for opening from FindAll in the user's browser.

## Historical baseline (superseded where listed above)

Checked on 2026-10-03 against the current local source, installed dependencies, and the first page of [GitHub's OSINT topic](https://github.com/topics/osint).

## Result

FindAll has genuine executable integrations, but it does not contain every capability of every bundled repository. Installing or cloning an upstream project is not evidence that its entire functionality participates in the unified dossier. This audit checked code paths and local readiness; it did not run live investigations against people or claim current availability of external sites.

## Actual workflow

| Capability | Integration into Create dossier | Current limits / requirements |
| --- | --- | --- |
| Google, Yandex, Bing, DuckDuckGo, Brave, Mojeek, Bing RSS, Wikipedia, news, GitHub | Yes, `jf/dossier.py:204` and `jf/osint.py` | Source-specific transport, parsing, quotas and blocks still apply. A zero response is not proof that information does not exist. |
| Maigret | Yes, `jf/dossier.py:261`, `jf/github_tools.py:128` | Top 100 sites in the dossier, no recursion; installed 0.6.6. |
| Sherlock, Social Analyzer, Blackbird, WhatsMyName | Yes for Username, `jf/extra_osint.py:1450` | Sherlock 35-second ceiling; Social Analyzer top 25; Blackbird 40 seconds / retained 40 profiles; WhatsMyName 48 selected sites. These are bounded passes, not exhaustive upstream scans. |
| GitHub Email Hunter | Yes for Username, `jf/dossier.py:274`, `jf/github_tools.py:157` | Actual vendored engine. Dossier checks 5 repositories and one commit page; returns the first discovered email. No GitHub token configured. |
| TikTok Scraper | Yes for Username, `jf/github_tools.py:207` | Actual profile parser with oEmbed fallback. Video/feed download features are not wired into the dossier. Node and built scraper are present. |
| SpiderFoot | Yes, `jf/dossier.py:353`, `jf/spiderfoot_scan.py:317` | Actual in-process engine, 15 selected modules, default 120-second ceiling. This does not run the entire upstream module set. Import check passed. |
| Domain certificates, DNS/RDAP, observed services and technology | Yes, `jf/domain_recon.py:95` | Dossier limits 30 hostnames / 3 IPs for this pass; other hostname collectors add their results. |
| Shodan | InternetDB plus keyed DNS/host adapters, `jf/domain_recon.py:149` and `:195` | InternetDB needs no key. Shodan API key is absent, so keyed paths are skipped. Censys, ZoomEye and SecurityTrails keys are also absent. Direct IP input currently does not use this domain-only Shodan branch. |
| Subfinder, passive Amass, httpx | Yes for Domain, `jf/extra_osint.py:1463` | Executables are bundled; httpx requests the entered HTTPS site. These are not full active attack-surface scans. |
| urlscan, archive/CDX, Common Crawl, Anubis, RapidDNS, HackerTarget, Subdomain Center, Robtex, OTX | Yes for applicable Domain/IP targets, `jf/extra_osint.py:1463` | OTX requires its key. Existing provider records and snapshots are used; service availability was not live-tested in this audit. |
| Gravatar, Holehe, OpenPGP, Blackbird email | Yes for Email, `jf/extra_osint.py:1457` | Registration flags/profile links/public key existence; does not obtain mailbox contents. |
| Wikidata, public social pages, GLEIF | Yes for applicable Name/Username inputs, `jf/extra_osint.py:1445` | Social pages come from indexed public site searches. A bare Latin word is treated as a name; `@` or explicit Username enables all username collectors. |
| IP RDAP, RIPE, reverse DNS, network location | Yes for public IP, `jf/extra_osint.py:1479` | Public network observations do not establish a person's address or device ownership. |
| Phone | Numbering plan and indexed public pages, `jf/extra_osint.py:1476` | No comprehensive phone investigation engine. |
| OnionSearch / Tor | Optional dossier phase, `jf/github_tools.py:598` | Current adapter queries OnionLand page 1 only. Other engine selections are skipped. Hidden-service result pages are not parsed. UI text at `rust-ui/src/main.rs:2760` incorrectly names additional indexes. |
| Parser2GIS | Genuine vendored parser, `jf/two_gis.py:93` | Separate Tools/CLI action with Chrome. Not part of Create dossier; business records stay in separate exports. Parser import and Chrome presence confirmed. |
| Web-Check | Genuine local server, `jf/github_tools.py:102` | Full `/api` is separate Tools/CLI/legacy OSINT action. Unified domain dossier uses only `/api/tech-stack`. Node, dependencies and build are present. |
| Awesome OSINT Arsenal | Searchable catalog, `jf/github_tools.py:35` | 753 entries; only six IDs map to executable actions. Remaining catalog entries are not integrated collectors. |
| Apex / Xray | Actual command-scoped network routing, `jobfind.py:1308` | A transport rather than an evidence collector. It does not guarantee access to blocked search engines. |
| AI | Final evidence analysis, `jf/ai_agents.py` | Uses a balanced sample of up to 80 linked items, then appends every omitted source-linked PhoneInfoga finding/web result; existing citation IDs remain stable. Evidence excerpts are limited to 700 characters. Facts require a source URL or artifact SHA-256. |

## Defects corrected during this audit

1. Blackbird could not import its HTTP client because `chardet` was missing. Added `chardet>=5,<6` to `requirements.txt` and installed 5.2.0 in the project environment. Its `--help` entry point now exits successfully.
2. SpiderFoot replaced `sections.findings`, erasing facts from previous collectors. `merge_dossier` now appends its findings and preserves the existing records. A regression check verifies this behavior.
3. AI skipped source-linked records in `findings`. The evidence sampler now includes that section and its `event_type`, `value`, and `module` fields; the section counts also include it. The self-check verifies balanced sampling and rejection of records without source links.

These are Python backend changes and apply to new searches without rebuilding the Rust executable. Already saved dossiers are not modified. Facts erased from an old saved report cannot be restored by reanalyzing it; collection must run again.

## Remaining integration work

1. Consolidate the full Web-Check and 2GIS outputs into the same dossier when the selected target/settings make them applicable.
2. Replace the one-index onion adapter with individually verified engines and truthful per-engine status; add selected result-page parsing if required.
3. Expose quick/deep coverage settings and counts of attempted/completed/timed-out sites. Current time/site/result caps prevent exhaustive collection.
4. Add original-page evidence capture and extraction to the search workflow. Current contact parsing and archive links do not archive every collected result page or recover all publicly published contacts from search results.
5. Add tool orchestration if the intended AI behavior is to choose collectors, follow leads and request additional collection. Present AI only analyzes the completed evidence sample.
6. Automated maps/Overpass, photo/document EXIF, full Telegram post collection and closed bot integrations are not implemented. Public indexed Telegram links are not equivalent to those integrations.

## Relevant projects from the linked topic that are not integrated

| Project | Capability worth evaluating for the stated workflow |
| --- | --- |
| [theHarvester](https://github.com/laramies/theHarvester) | Additional passive email/domain discovery and normalized source outcomes. Some sources overlap existing collectors; their presence here does not mean the upstream engine is integrated. |
| [SingleFile CLI](https://github.com/gildas-lormeau/single-file-cli) | Preserve rendered evidence pages as self-contained HTML. Useful complement to source links and archive indexes. |
| [Instaloader](https://github.com/instaloader/instaloader) | Public Instagram content and metadata. Not supplied by current profile-existence checks; login/rate restrictions need separate runtime verification. |
| [GHunt](https://github.com/mxrch/GHunt) | Google-specific account/public asset investigation. Requires an explicit Google login/cookie setup; not a credential-free general search replacement. |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | Phone investigation workflows beyond the current numbering-plan description; actual source outputs and required credentials must be evaluated. |

The OSINT topic also contains curated lists, skills, duplicate capabilities and complete applications. A topic entry alone is not an executable integration contract. No repository in this final table was installed or integrated during this audit.

## Validation performed

- Import/readiness checks for vendored SpiderFoot, GitHub Email Hunter and Parser2GIS passed; required Node/Chrome/build artifacts were present.
- `.venv\Scripts\python.exe -m jf.ai_agents` passed, including source-linked findings sampling.
- `.venv\Scripts\python.exe -m unittest test_spiderfoot.SpiderFootNormalizeTest.test_merge_preserves_findings_from_previous_collectors` passed.
- From `third_party/blackbird`: `..\..\.venv\Scripts\python.exe blackbird.py --help` passed after dependency installation.
- Only credential-presence booleans were checked. No secret values were printed. Live Shodan/API access, Tor connectivity, and external profile coverage remain unverified in this audit.
