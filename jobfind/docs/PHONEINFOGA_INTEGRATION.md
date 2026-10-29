# PhoneInfoga in FindAll

In **Dossier → Search settings → PhoneInfoga · phone research**, enter an international number in the main research field and choose **Run PhoneInfoga**. **Local analysis only** runs the number-plan and query generators without external requests. The normal dossier workflow also runs these scanners when **Run installed engines for this target** is enabled for a phone target.

The focused CLI saves a regular dossier with JSON, CSV, Markdown, source checks, evidence hashes and graph edges:

```powershell
.\.venv\Scripts\python.exe jobfind.py phone --number +12025550123
.\.venv\Scripts\python.exe jobfind.py phone --number +12025550123 --local-only
```

Saved results work with the existing native dossier, AI analysis and exports. The fictional NANP number above is for local demonstration.

AI evidence keeps the balanced sample of up to 80 records from all sources and then adds every source-linked PhoneInfoga finding or indexed web result omitted by that sample. This also recognises PhoneInfoga attribution on deduplicated web results. Other sources and existing citation IDs are retained; total evidence can exceed 80. Generated queries keep their explicit unexecuted-query attribution. Provider context limits still apply; no silent PhoneInfoga row sampling is used to meet them.

| Scanner | Data and coverage |
| --- | --- |
| local | Offline formats, numbering-plan country/code and any upstream carrier metadata |
| googlesearch | Generated queries for social media, reputation, individuals, disposable providers and general search; generation does not execute searches or prove a match |
| googlecse | Indexed titles and original URLs; needs GOOGLE_API_KEY and GOOGLECSE_CX; capped at 10 results for each of upstream's two queries |
| numverify | Validity, country, carrier, line type and numbering-area fields; needs NUMVERIFY_API_KEY for the upstream APILayer endpoint |
| ovh | Published number-range metadata; upstream supports codes 33, 32, 44, 34 and 41; other countries are skipped |

Credentials are read from the environment or existing `osint-keys.env`, without changing that file. Provider quotas/billing apply. Keys stay in child environment variables and are redacted before artifact persistence. Diagnostics do not contain response bodies, authenticated URLs or keys.

Each scanner has a 20-second request budget and a 25-second process deadline. HTTPS requests respect proxy environment settings and FindAll's active Apex proxy. This Go transport has its own deadline/body limit and does not share Python's retries/diagnostics. Failed providers do not discard completed scanners. Missing keys/unsupported countries, blocks, timeouts, errors, empty responses and partial coverage have distinct statuses.

Source: [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga), pinned v2.11.0, commit `5f6156f567613a07ea8e3f04b004864582060a57`. The upstream project is unmaintained. `third_party/phoneinfoga-bridge` imports its actual Go library and emits bounded JSON without starting a server. Rebuild with Go installed using `setup-phoneinfoga.bat`, also called by `setup-research-tools.bat`. Versions/checksums are in go.mod/go.sum; the upstream licence is retained beside the binary.

Number-plan/provider location fields describe numbering metadata, not current physical location. Search hits remain candidates; subscriber identity is unverified. Generated queries retain interpretation edges in the graph and explicit attribution in AI evidence.
