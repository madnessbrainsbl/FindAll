"""Scrapling selection/relocation on already fetched HTML; never opens a URL."""
from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

VERSION = "0.5"
SOURCE = "Scrapling CSS extraction"


def validate(selector):
    if not isinstance(selector, str) or len(selector) > 500 or any(ord(c) < 32 for c in selector) or "::" in selector:
        raise ValueError("Use an element CSS selector of at most 500 characters")
    if selector:
        try:
            from scrapling import Selector
        except ImportError:
            raise RuntimeError("Scrapling is missing; run setup.bat") from None
        try:
            Selector("<html/>", huge_tree=False).css(selector)
        except Exception:
            raise ValueError("Invalid element CSS selector") from None
    return selector


def extract(html, url, selector, state_dir, limit):
    from scrapling import Selector

    validate(selector)
    if not selector or not 1 <= limit <= 100 or len(html.encode("utf-8")) > 2_000_000:
        raise ValueError("Scrapling requires a selector, 1–100 records and HTML up to 2 MB")
    # Manual relocation avoids a shared upstream SQLite cache and isolates exact URLs/selectors.
    baseline = Path(state_dir) / (hashlib.sha256((url + "\n" + selector).encode()).hexdigest() + ".html")
    page = Selector(html, url=url, huge_tree=False)
    matches = page.css(selector)
    relocated, baseline_hash = False, ""
    if not matches and baseline.is_file():
        with baseline.open("rb") as stream:
            saved = stream.read(2_000_001)
        if len(saved) > 2_000_000:
            raise ValueError("Scrapling baseline exceeds 2 MB")
        prior = Selector(saved, url=url, huge_tree=False).css(selector)
        if prior:
            # shortcut: tracks the first baseline match; use explicit templates for multi-field tracking.
            matches = page.relocate(prior[0], percentage=70, selector_type=True)
            relocated = bool(matches)
            baseline_hash = hashlib.sha256(saved).hexdigest()
    rows = []
    for node in matches[:limit]:
        text = " ".join(node.get_all_text(separator=" ", strip=True,
            ignore_tags=("script", "style", "noscript", "template", "input", "textarea", "select")).split())[:6000]
        if not text:
            continue
        rows.append(dict(kind="browser_scrapling", title=text[:200], value=text, source=SOURCE,
            method="adaptive relocation" if relocated else "exact CSS selection", selector=selector,
            baseline_sha256=baseline_hash, attribution=(
                "Candidate from heuristic Scrapling relocation; verify the current source; identity and ownership unverified"
                if relocated else "Observed CSS-selected page content; identity and ownership unverified")))
    if matches and not relocated:
        baseline.parent.mkdir(parents=True, exist_ok=True)
        temporary = baseline.with_suffix("." + uuid.uuid4().hex + ".tmp")
        try:
            temporary.write_text(html, encoding="utf-8")
            temporary.replace(baseline)
        finally:
            temporary.unlink(missing_ok=True)
    state = "partial" if relocated or len(matches) > limit else "ok" if rows else "empty"
    return rows, dict(source=SOURCE, url=url, state=state, count=len(rows),
        method="adaptive relocation" if relocated else "exact CSS selection",
        detail=("Heuristic relocation; review every match. Tracks the first saved element." if relocated else
                "Exact CSS selection; result limit reached" if len(matches) > limit else
                "Exact CSS selection retained" if rows else
                "No selector match; this does not establish absence of information"))
