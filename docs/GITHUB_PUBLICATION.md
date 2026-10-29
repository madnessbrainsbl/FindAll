# Publishing FindAll

Publish a clean export, not the populated working installation. The exporter
copies an explicit source selection, keeps upstream license files and rejects
existing destinations. It excludes private state, nested Git metadata, upstream
workflows, virtual environments, installed tools, model weights and build output.
It does not publish anything or create a remote repository.

From the working installation's root, for a new export only (choose an unused
destination; the prepared repository already exists at `github-ready/FindAll-source`):

```powershell
python -m unittest discover -s scripts/tests -v
python scripts/prepare_github.py github-ready/FindAll-source
.\jobfind\third_party\gitleaks\gitleaks.exe dir .\github-ready\FindAll-source --config .\github-ready\FindAll-source\.gitleaks.toml --redact=100 --no-banner --log-level error
```

Gitleaks must exit 0 before publication. If the bundled scanner is unavailable,
use an installed [official Gitleaks](https://github.com/gitleaks/gitleaks). Review
all findings locally; do not paste matching secret values into issues or logs.
The committed scanner configuration retains default rules and narrowly allows
two verified public upstream constants, only at their specific source paths.
Upstream test keys and demonstration uploads are not included.

Validate the export using a prepared Python environment. For example, from the
export's `jobfind/` directory, run the working installation's `.venv/Scripts/python.exe`
with `-m unittest discover -s tests -v`, then run `cargo test --locked --manifest-path rust-ui/Cargo.toml`.
The GitHub workflow also runs these tests and the existing CLI self-checks.

Initialize and inspect the clean repository:

```powershell
cd github-ready/FindAll-source
git init -b main
git add --all
git diff --cached --check
git diff --cached --stat
git ls-files
```

The prepared copy may already have Git initialized and its sources staged. In
that case, review the staged files and commit them directly. Before creating the
first commit, verify that the effective Git email matches the authenticated
GitHub account's noreply address. Inspect author, committer, tagger and co-author
fields of every outgoing commit/tag, plus the exact staged files, for personal
contact addresses. Use `example.invalid` in contact examples. A passing secret
scan alone does not establish absence of personal data. Preserve third-party
copyright and author notices.

```powershell
git commit -m "Prepare FindAll source for GitHub"
gh repo create FindAll --private --source=. --remote=origin --push
```

The last command publishes a private repository and requires a working GitHub
account. Change visibility only deliberately. Alternatively, create an empty
repository on GitHub, add its actual URL as `origin`, and push `main` as described
in [GitHub's import guide](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github).

An overall license for FindAll has not been chosen. Keep all upstream notices,
including non-commercial restrictions. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
Blackbird and TikTok Scraper snapshots are omitted pending complete license notices.
GHunt, Instaloader and theHarvester are installed from pinned upstream checkouts
by the existing setup script; their Git metadata is needed for its revision checks.

CI uses read-only repository permissions, no persisted checkout credentials and
actions pinned to verified full commit SHAs, following
[GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).
