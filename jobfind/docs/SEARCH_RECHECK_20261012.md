# FindAll search recheck — 2026-10-12

## Fix and scope

Live result inspection found that `Grace Hopper` returned ten Bing RSS pages
about clothing, dictionaries and other Grace subjects with no Hopper mention.
The shared relevance helper previously accepted every multiword query.

Ordinary multiword queries now require each word in the returned title, snippet
or decoded URL. Matching is case insensitive and normalizes Russian ё/е.
Existing exact handle/domain matching and queries with search operators retain
their prior policy. This is a text relevance check; it cannot prove identity,
ownership or distinguish a person from products named after that person.

The company-site caller now searches the company name without appending
`официальный сайт`, so the helper does not require those artificial hint words
inside an English website result. Existing domain candidate checks still apply.
No dependencies, settings or native UI code were added.

Four regression tests cover live-shaped RSS noise and counts, English/Russian
names and URL evidence, search operators, and company-site discovery. The noise
and Russian-name tests failed before the fix. The company-site test caught the
caller compatibility issue and passes with the corrected query.

## Skills and plugin actually used

- `findall-research-quality`: collectors, attribution, terminal source states,
  saved dossier validation and the eight-case synthetic quality benchmark.
- `python-testing-patterns`: fixture regressions and full project test runner.
- `async-python-patterns`, `python-resilience`, `python-observability`:
  cancellation/concurrency, bounded transport failures and allowlisted traces.
- Computer Use plugin (`@oai/sky` through Node REPL): observed the native search
  page, expanded source settings, disabled Tor, entered a Cyrillic query and
  launched the actual backend from a disposable native runtime.

## Live results and saved evidence

All new writes are in `jobfind_out/search-recheck-20261012-144016/`.

| Check | Observed result |
| --- | --- |
| `Python backend`, five job boards, after final relevance fix | 5 jobs, 2 GitHub projects, 0 web rows, 0 contacts; CSV and database counts agree |
| `Grace Hopper`, quick person/profiles dossier | 66 web rows before / 56 after, 9 findings; the ten captured unrelated Bing URLs are absent afterward |
| `Анна Ахматова`, quick person/profiles dossier after fix | 35 web rows and 6 findings; terminal progress reaches 100% |
| Native Web search, `Анна Ахматова`, before relevance fix | 50 rows saved to JSON/CSV and the isolated database; SpiderFoot reached its limit and preserved one event |

The zero unified web count is explicit: Bing's unrelated candidates were
excluded, while Yandex was blocked and Brave returned 429. The job/project
results remain available. A filtered empty response is not proof that no
relevant public page exists.

Both final dossiers pass mechanical invariants with `needs_review`: five source
coverage warnings each, no unfinished source checks or invariant errors.
Progress, source attribution, exports and diagnostic allowlists were checked.
The eight synthetic quality cases pass; they do not measure factual accuracy.
The final focused suite passes 44 tests, including cancellation, bounded
concurrency, retry budgets, partial results, trace privacy and query matching.
Output/state verification passes 37 assertions.
The full `test.bat` runner also passes: 203 Python unittest cases, the GitHub
Email Hunter self-check, ten standalone unified-search checks and 11 Rust tests.

Evidence includes `jobs-after-result.json`, `person-result.json`,
`person-after-result.json`, `russian-after-result.json`, quality/progress files,
`quality-benchmark.json`, `focused-tests-final.log`, `verification-results.json`
and `all-tests-final.log`, plus native `ui-runtime/jobfind_out/osint_*.json`/CSV files. The unchanged
installed binary hash is
`42AD325363FC98BF6808F6843819B2EF0FF5D2CB1EE28295BAA0FA934CFDE0BD`.
The existing executable/launcher uses the updated Python backend immediately.

## Boundaries

HH returned 403; Google/Brave returned 429; some other engines requested human
verification. Challenges were not bypassed. The native Yandex attempt also
reported a file-not-found error; the separate final dossier checks classified
Yandex as blocked. This native-specific failure was not reproduced or resolved.

The native run exported its completed result, but a final visual inspection was
unavailable after the desktop/window changed; post-fix live checks used the CLI.
No screenshot containing other applications was saved or published. Original
parent/project databases, profile and saved network state retain baseline hashes.

Not exercised in this recheck: live AI semantic/citation quality, authenticated
or paid providers, Tor/onion sources, radio hardware and actual email delivery.
Dossier checks disabled SpiderFoot, additional-tool orchestration, archive phases
and page capture. Public supplementary collectors still run in that scope.
