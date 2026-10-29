# Third-party components

Upstream license files and copyright notices accompany the included snapshots
under `jobfind/third_party/`. These components are not relicensed by FindAll.

| Component | Upstream | Retained license / notice |
| --- | --- | --- |
| Scrapling 0.5 | [D4Vinci/Scrapling](https://github.com/D4Vinci/Scrapling) | BSD-3-Clause; installed Python distribution includes its license |
| Apex parser | [Diversan313/apex-parser](https://github.com/Diversan313/apex-parser) | MIT, `apex-parser/LICENSE`; modifications in `INTEGRATION.md` |
| OSINT Arsenal catalog | [rawfilejson/awesome-osint-arsenal](https://github.com/rawfilejson/awesome-osint-arsenal) | `awesome-osint-arsenal/LICENSE` |
| Chrome Crawler | [ir00nman/chrome-crawler](https://github.com/ir00nman/chrome-crawler) | CC BY-NC 4.0, `chrome-crawler/LICENSE`; FindAll modifications in `FINDALL.md` |
| GitHub Email Hunter | [vahid56/github-email-hunter](https://github.com/vahid56/github-email-hunter) | MIT, `github-email-hunter/LICENCE`; attribution filtering modified locally |
| 2GIS parser | [interlark/parser-2gis](https://github.com/interlark/parser-2gis) | LGPL-3.0, `parser-2gis/LICENSE`; local browser/parser fixes retained |
| SpiderFoot | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | MIT, `spiderfoot/LICENSE`; local collector fixes retained |
| waymore 8.9 | [xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore) | MIT, `waymore/waymore-8.9.dist-info/licenses/LICENSE`; provenance in `PROVENANCE.md` |
| Web-Check | [lissy93/web-check](https://github.com/lissy93/web-check) | MIT, `web-check/LICENSE`; local integration changes retained |
| WireTapper | [h9zdev/WireTapper](https://github.com/h9zdev/WireTapper) | `wiretapper/LICENSE-NONCOMMERCIAL.md` |
| Flowsint reference | [reconurge/flowsint](https://github.com/reconurge/flowsint) | Apache-2.0, `flowsint/LICENSE` and `flowsint/NOTICE`; adaptation in `jf/flowsint.py` |
| PhoneInfoga bridge dependency | [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga) | `phoneinfoga/LICENSE`; bridge uses pinned Go modules |

The full Flowsint application is not bundled; its notices are retained for the
adaptation. Chrome Crawler and WireTapper have non-commercial restrictions in
their retained licenses. A combined distribution must respect these restrictions.

`setup-research-tools.ps1` downloads pinned GHunt, Instaloader and theHarvester
checkouts with their upstream licenses. Those installed checkouts are not part of
this publication. Executables, model weights and OCR data are installed separately
by the relevant setup commands.

Blackbird and TikTok Scraper are omitted because their local snapshots lack a
complete license file. TikTok Scraper declares MIT in `package.json`; that alone
does not supply its missing copyright and permission notice. Their local copies
remain untouched in the development installation.

Python, Rust, JavaScript and Go dependencies keep their own licenses. This is not
a dependency vulnerability audit or a completed legal review of a combined
distribution. No overall license for original FindAll code has been selected.
