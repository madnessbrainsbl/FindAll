# FindAll live search check — 2026-10-12

## Fixed result loss

Arbeitnow ignored the query and applied `per-source` before the unified search
filtered jobs. The captured live API page contained 325 rows; Python vacancies
were at positions 121 and 218. A limit of ten discarded both before matching.

The adapter now applies the same role/query matcher as the unified search before
limiting results. Blank-query scans retain their previous behavior. The shared
matcher lives in `jf/sources.py`; the existing CLI function delegates to it.
Four regression tests cover late matches, all terms/case, blank scans and the
complete search/database/CSV path. Three failed before the fix; all four pass.

`test.bat` also now runs `tests.test_unified_osint` as a module. Its ten standalone
checks were previously omitted by unittest discovery. README instructions now
distinguish the complete runner from the Python unittest-only command.

## Executed live searches

All writes used `jobfind_out/search-live-20261012-1403/` and disposable databases.
The tests used the existing virtual environment and actual project backend.

- Unified `Python` search, five selected job boards, ten rows per source and
  three GitHub projects: **1 vacancy before / 3 after**, with the original
  vacancy retained and both Arbeitnow matches recovered. Three projects and ten
  web pages were saved. The captured public page also reproduces the recovered
  matches without another network request.
- Native UI: entered `Python` and pressed Enter with the default source settings.
  The actual executable showed **4 jobs, 10 projects, 10 web pages**, finished its
  busy state, displayed source errors, and saved four jobs and ten projects into
  the isolated database. CSV contains the same four jobs. The isolated launcher
  delegates to the actual backend; no production UI diagnostic code was added.
- `Ada Lovelace`, explicit person/profiles scope, quick coverage: 67 web rows and
  nine findings saved; nine successful source checks and five coverage gaps.
- `python.org`, explicit domain scope, quick coverage: DNS/registration data,
  domain results, 17 web rows, 41 findings and 36 Web-Check modules saved.
  53 source checks succeeded; individual gaps and key-dependent skips remain
  visible. A saved module/result does not mean every module succeeded.

The two dossier checks disabled SpiderFoot, additional-tool orchestration,
archive phases and page capture. They did not request AI analysis. Their
mechanical `dossier-quality` checks exited successfully with `needs_review`;
only source-coverage warnings remain, with no unfinished checks or invariant
failures. Candidate rows do not establish identity or ownership.

## Availability and verification

HeadHunter's public API returned HTTP 403. Google and Brave returned HTTP 429;
Yandex and Mojeek required human verification. Bing RSS, DuckDuckGo, Wikipedia,
GitHub and other responding adapters supplied results. Challenges were not
bypassed. Source failures are visible in both JSON and the native UI.

- Full `test.bat`: 199 Python unittest cases, the GitHub Email Hunter self-check,
  ten standalone unified-search checks and 11 Rust tests passed.
- 22 output/data assertions passed in `verification-results.json`.
- Original parent/project databases, profile and saved network state retained
  their prior hashes. Saved Apex routing was disabled; no route was changed.
- Python changes are used immediately by the existing launcher/executable;
  the installed native binary was not replaced.

Evidence: `jobs-result.json`, `jobs-after-result.json`,
`arbeitnow-public-page.json`, `person-result.json`, `domain-result.json`, their
progress/quality files, `all-tests.log`, and `verification-results.json` in the
disposable check directory. `ui-runtime/jobfind_out/` contains actual UI exports.

Unverified in this follow-up: authenticated providers, Tor/onion searches,
SpiderFoot, page capture, radio hardware and real email delivery. Wider coverage
and live-source completeness are not guaranteed by these checks.
