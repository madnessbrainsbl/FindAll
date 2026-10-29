# 🤝 Contributing

Thanks for helping keep this list alive — it's one person plus whoever pitches in, so good PRs genuinely matter.

A few rules so your PR doesn't stall or get closed:

## Adding a tool

- **One tool per PR, one section.** Don't spread the same tool across three sections.
- **Match the format.** Copy an existing row in that section — `| **Name** | short, factual description | link or install command |`. Keep the description to one line, no marketing copy.
- **The link has to work and stick around.** Reachable now *and* likely reachable in six months. No free `*.onrender.com` / ngrok / personal-lab subdomains — those go dead and I'm the one left cleaning up broken links.
- **Check it's not already here** before adding — `Ctrl+F` the README first.
- **If it installs** (pip / git / go / apt), also add it to `tools.json` and the right installer script (`osint.sh`, `redteam.sh`, …), and bump the tool counts in the header badge + stats table.

## Adding your own tool?

Totally fine — just **say so in the PR**. Undisclosed self-promo gets closed. Disclosed or not, it still has to clear the bar above: real, useful, durable, on-topic.

## Found a dead link?

Open an issue — takes a minute and it's genuinely helpful.

## What gets closed fast

- Off-topic stuff — this is **OSINT & recon**, not a general pentest/exploit dump.
- Tools already rejected before, or ones whose name clashes with an existing entry.
- Marketing fluff and "AI-powered" wrappers with nothing behind them.

## Not what this repo is for

Please don't open issues asking how to **find, track, or identify a specific person** — that's not something I'll help with here, and those get closed.

---

By contributing you agree your addition is for **authorized, educational security research** — see the [disclaimer](README.md#%EF%B8%8F-legal-disclaimer). Everything here ships under the [MIT License](LICENSE).
