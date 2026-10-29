# FindAll functional verification — 2026-10-12

The checks used disposable databases and output directories under
`jobfind_out/functional-check-20261012/`. Existing databases, profile and saved
network state retained their SHA-256 hashes. The installed executable and
production UI source also retained their original hashes after removing the
temporary interactive diagnostic mode.

## Automated checks

- `test.bat`: 189 Python tests and 11 Rust tests passed.
- Six added SMTP regression tests passed separately: STARTTLS before credentials,
  verified SSL, invalid settings rejected before connection, authentication
  failure without sending, recipient rejection and connection loss without retry.
- Release build succeeded after restoring the production source.
- 21 output/data assertions passed; see `verification-results.json`.

## Native UI actions exercised

The native window was operated with the computer-use plugin, using an isolated
database. These were actual mouse/keyboard actions:

- Switch dark to light theme; navigate Research, Archives, Wireless and Contacts.
- Reject an empty archive domain, enter `example.org`, start a background search,
  and navigate while collection is running.
- Enter a synthetic telemetry file, import it, display its single observation
  and map point, and open its generated research dossier.
- Reject AI analysis before configuring the provider; expand and scroll settings,
  load the seven models returned by Codex, choose `gpt-5.6-luna`, verify the model,
  and analyze the saved synthetic dossier.
- Enter `python.org` and start contact search with Enter. It returned MX/SPF/DMARC
  information and no published addresses on the pages checked.

No email confirmation or delivery was triggered. A complete keyboard-only pass
and screen-reader operation were not checked.

## Live providers and saved outputs

- Codex: model catalogue succeeded; a separate `gpt-6.1-sol` probe succeeded.
  Native model verification and saved-dossier analysis also completed. The
  synthetic wireless answer remains `partial`: three unsupported claims were
  rejected, with no accepted claims. This is not verified identity/location.
- GitHub: two Python projects saved to the disposable database and CSV.
- Arbeitnow: two jobs saved to the disposable database; CSV, XLS, HTML and
  Markdown exports created. JSON report export succeeded separately.
- Archives: 13 URLs returned by URLScan. Wayback and Common Crawl timed out;
  OTX reported a connection error. The overall result correctly remained
  `partial` and retained successful records and individual source failures.
- Wireless: one fictional CSV observation imported with latitude/longitude
  `0,0`, RSSI `-65`, unknown observation time and candidate attribution preserved.
  CSV, JSON, GeoJSON, offline map and dossier artifacts were created.
- Dossier Markdown export succeeded through the CLI. Graph JSON and BloodHound
  OpenGraph parsed successfully; generated Markdown/graph files were nonempty.

## Evidence and limits

Logs: `regression-tests.log`, `mailer-tests.log`, `release-build.log`,
`ai-models.log`, `ai-check.log`, `projects.log`, `jobs.log`, `report-export.log`,
`dossier-export.log`. `ui/` contains the actual collection and analysis outputs.

Real email delivery, radio hardware discovery, every authenticated provider,
Tor/onion collection, 2GIS, dependency installation and publication were not
exercised. External-service failures remain a practical availability limit.
This verification does not establish that every third-party service works.
