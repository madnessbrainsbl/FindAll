# FindAll integration

Upstream: https://github.com/ir00nman/chrome-crawler
Pinned commit: `664f5fa9cc7c374638d07ae7eddcee9f282bebf3` (0.7.5).
Author: ir00nman (https://github.com/ir00nman).
License: [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/),
retained in LICENSE. Commercial use requires separate permission from the author.

Changes made for FindAll on 2026-10-22:

- Added `panel/findall-export.js` and an English **Export page to FindAll** button.
- Export uses the existing `page/extract-items.js` extractor in Chrome's isolated
  world: JSON-LD, microdata, or repeated listing cards. It also reads rendered
  page text, title, URL and observation time. It neither runs a model nor sends
  data to a server. Limits: 100,000 text characters, 100 items, 2 MB JSON.
- Disabled scheduled upstream update checks/self-update offers, which would
  overwrite these modifications. Update this pinned integration deliberately.
- Added `panel/findall-export.test.js`. Other upstream functionality is unchanged.

Install manually in Chrome at `chrome://extensions`: enable Developer mode,
select Load unpacked, choose this directory. Installation grants the upstream
extension its declared browser permissions; FindAll does not install it or copy
browser profiles, model keys or sessions. The new export action needs no API key.

Open an HTTPS page, click the extension icon and **Export page to FindAll**.
In FindAll choose Research tools → Network & Web → Chrome crawler → Import page
JSON. This creates a new dossier and adds it to the shared diagram and library.
Use the dossier's existing AI and export actions afterwards.

Alternatively, add up to ten exported page JSON files under Dossier → Search
settings → Selected local files before Create dossier. They join that research
run with the same source attribution. CLI: repeat `dossier --browser-file PATH`.
Malformed files do not discard other evidence; truncated files remain partial.

The JSON contains content from the selected tab, which may be private if you
are signed in. Inspect it before sharing or selecting AI analysis. Page content
is untrusted evidence. Form input values, screenshots, credentials, model chat
history, cookies and saved scripts are not exported. A page's rendered text can
still include personal information. The original agent's other modes retain
their upstream behavior and may transmit content to the configured provider.

The FindAll importer accepts HTTPS DNS hostnames, rejects credential-bearing or
sensitive-query URLs, does not resolve DNS or fetch any page, and preserves the
exact imported bytes with SHA-256. Import does not verify the page's public
visibility, authenticity, identity or current availability. Listing links are
recorded as unfetched links in observations of the source page. Challenge pages
are excluded from AI findings; empty and truncated exports retain their status.
