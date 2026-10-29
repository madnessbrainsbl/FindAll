# Contributing

Use Python 3.10+ and Rust 1.95+. Install requirements with `jobfind/setup.bat`
and run `jobfind/test.bat` before submitting a change. Use synthetic fixtures and
temporary output directories; keep live provider checks separate.

Preserve source URLs, collection times, hashes and explicit blocked/error/partial
outcomes. Account and infrastructure matches do not prove identity or ownership.
Keep the interface English and AI answers in the query language.

Do not commit credentials, profiles, research results, database files, model
weights, browser sessions or compiled binaries. Use example configuration files
and review `git diff --cached` before committing.

Keep third-party notices alongside source snapshots. Document local modifications
and upstream revisions. Updates must preserve application patches and pass the
affected regression checks.
