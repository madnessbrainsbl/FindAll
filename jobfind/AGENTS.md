# FindAll development

For dossier quality and collector changes, apply the installed `findall-research-quality` skill and inspect the current code.

- Integrate working collector capabilities into unified research, AI evidence, source checks and exports. A link or catalogue entry does not establish integration.
- Apply `python-resilience`, `python-observability`, `async-python-patterns`, `python-testing-patterns`, `llm-evaluation` and `security-best-practices` where their responsibilities match the change.
- Preserve source URL, timestamps, quotes and attribution. Candidate username/IP links do not establish ownership. Distinguish blocked/error/timeout/empty/partial/skipped results.
- Use synthetic fixtures and disposable output folders when the user authorizes verification. Report live and key-dependent checks separately.
- Keep UI English; generate the final AI answer in the query language.
- Preserve credentials, existing outputs and user processes. Do not copy secrets from other projects.
- Diagnostics contain allowlisted metadata, never bodies, keys, authorization headers or full query URLs.
