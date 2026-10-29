# Flowsint capabilities in FindAll

Reviewed upstream: [reconurge/flowsint](https://github.com/reconurge/flowsint),
commit `4c05849bc6ca5055ad187d056ef26e61b3bc2fea`, Apache-2.0.
The source snapshot, LICENSE and NOTICE are retained in `third_party/flowsint`.
The Python/Rust adaptation preserves the typed enricher, branch and execution-trace
model, using FindAll's existing transport, dossiers and graph instead of deploying
Flowsint's PostgreSQL/Neo4j/Redis/Celery/Docker services.

## Implemented

- Ten typed enrichers: registrable domain, domain-to-HTTPS URL, website hostname,
  email domain, DNS A/AAAA, IP-to-ASN, ASN-to-announced-prefixes, bounded CIDR address
  sampling, page links and published tracking identifiers.
- Six reusable flows, including branching website analysis and domain → IP → ASN
  → CIDR. Custom JSON flows can connect compatible types in a DAG.
- Native **Research tools → Enrichment flows** and **Diagram → select entity →
  Enrich selected entity**. Work runs in the backend thread; full-screen diagrams
  keep the selected-node action available in the inspector.
- Results enter the same `relationship_graph.html` and standard dossier JSON/CSV/
  Markdown. Source URLs, collection times, HTML/input SHA-256, attribution and
  per-input status survive graph and AI evidence selection. Findings can be analyzed
  by the existing `dossier-analyze` command with the user's configured provider.
- Templates are validated completely before collection; unknown tools, incompatible
  types, cycles, duplicate step IDs, private IPs and credential-bearing URLs are
  rejected. Eight steps, 12 calls by default (maximum 24), and 1–100 results per call.
- Branches retain partial data. Exact duplicate requests, including blocked ones,
  are reused within one run. No saved search is substituted for a fresh run.
- CIDR sampling performs arithmetic only. Page links are extracted from one page,
  not followed automatically by the built-in flow. Tracking IDs remain candidate
  observations; a shared ID does not prove common ownership.

RIPE's [announced-prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes)
default query covers the previous two weeks. Its query window and visibility periods
are retained in the dossier, graph inspector and AI evidence; an old announcement
is not presented as currently active. [Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info)
is based on RIS eight-hour dumps, not a live connectivity test.

The upstream `get_root_domain` helper uses a short suffix list; FindAll instead
uses the bundled Public Suffix List, including private suffixes. The upstream
ASN enrichers use ProjectDiscovery's key-dependent ASNMap; FindAll explicitly
attributes these queries to the public RIPE Stat API. These are adaptations,
not claims that the entire upstream application is running.

## Windows CLI

```powershell
.\.venv\Scripts\python.exe jobfind.py enrich --catalog
.\.venv\Scripts\python.exe jobfind.py enrich --flow domain-network --value python.org
.\.venv\Scripts\python.exe jobfind.py enrich --flow ip-network --value 1.1.1.1
.\.venv\Scripts\python.exe jobfind.py enrich --flow website-evidence --value https://www.python.org/
.\.venv\Scripts\python.exe jobfind.py enrich --flow domain-network --save-flow my-domain-flow.json
.\.venv\Scripts\python.exe jobfind.py enrich --flow-file my-domain-flow.json --value python.org
```

`--save-flow` refuses to overwrite an existing file. A template contains only
`schema_version`, `name`, `input_kind` and `steps`; each step has `id`, `enricher`
and `from` (`seed` or another step ID). It cannot contain commands, provider URLs,
credentials or Python code. FindAll's JSON format is not the Flowsint canvas format.

## Scope of the reference

Existing FindAll integrations already cover passive subdomains, domain registration/
history, IP information, Maigret, Gravatar, public company records, captures and
source-aware graphs. This change adds their missing typed expansion/flow pattern.
Flowsint's collaborative accounts, encrypted server vault, arbitrary custom
enricher code, N8n connector, crypto/NFT providers, and its web canvas are not
installed or advertised as working. Key-dependent services and previously blocked
sources retain their actual status. This integration does not add OCR, GNN,
multimodal analysis or anomaly detection.

## Live verification

Fresh public requests on 13 October 2026 returned:

- `1.1.1.1` → `AS13335` → five public announced prefixes (explicit result cap).
- `python.org` → three DNS addresses → `AS54113`; a deliberately restricted five-call
  run retained results and marked the prefix step skipped when its budget ran out.
- `https://www.python.org/` → ten HTTPS page links, hostname and registrable domain.
  No supported tracking IDs were found on that page in this run.
- `https://www.nasa.gov/` → two published tracking identifiers, both candidate edges.

Results are isolated under `jobfind_out/flowsint-check-20261013`; the user's database
was not changed. Fixtures also verify failure classification, partial branches,
deduplication, offline PSL/CIDR operations, flow validation, privacy of diagnostics,
AI evidence inclusion and graph semantics. Native rendered checks and the final
regression result are recorded in that QA folder; rendered inspection is distinct
from a manual click-through.

Final checks: **280 Python tests**, AI evidence/CLI self-checks and **22 Rust tests**
passed. The release binary was built and installed as `findall-ui.exe`; SHA-256
matches `rust-ui/target/release/findall-ui.exe`:
`e35dfe9225684d2ef3c6d63d94bc94f56a20507b5196ad6faa0e97ee923b503d`.
The previous binary is preserved under the isolated QA folder.

The actual native Tools screen rendered at minimum window size, with no horizontal
overflow; see `native-tools/tools-native.png` and `native-tools/ui-smoke-result.json`.
A separate native graph-render launch was rejected by automatic approval review
(`blocked by policy`). No click-through of the new diagram actions is claimed.
The graph action's typed command generation and existing inspector behavior passed
Rust checks. New live model calls and the full upstream Flowsint server were not run.
