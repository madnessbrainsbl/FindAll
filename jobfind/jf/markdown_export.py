"""Source-linked Markdown and non-destructive versioned Obsidian notes."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from . import evidence_graph


def _text(value):
    text = str("" if value is None else value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|<>])", r"\\\1", text)


def _link(url):
    safe = evidence_graph._url(url)
    return "[Source](<" + safe.replace("<", "%3C").replace(">", "%3E") + ">)" if safe else "Source unavailable"


def _value(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value or "")


def render(report):
    lines = ["# FindAll dossier: " + _text(report.get("query")), "",
             "- Input type: " + _text(report.get("kind")),
             "- Collected at: " + _text(report.get("observed_at")), "",
             "Observations are evidence leads. Matching handles do not establish ownership; historical contacts are not verified current contacts.", ""]
    analysis = report.get("ai_analysis") or {}
    if analysis:
        lines += ["## AI answer", "", _text(analysis.get("answer") or analysis.get("summary") or analysis.get("status")), ""]
        for row in analysis.get("claims") or []:
            if isinstance(row, dict):
                lines += ["- " + _text(row.get("statement") or row.get("claim")) + " — " + _link(row.get("source_url")),
                          "  - Quote: " + _text(row.get("quote")), ""]
    for section, data in (report.get("sections") or {}).items():
        if not data:
            continue
        lines += ["## " + _text(section.replace("_", " ").title()), ""]
        if not isinstance(data, list):
            lines += [_text(_value(data)), ""]
            continue
        lines += ["| Observation | Source | Collected | Status |", "| --- | --- | --- | --- |"]
        for row in data[:2000]:
            if not isinstance(row, dict):
                continue
            values = [row.get("title") or row.get("site") or row.get("name") or row.get("kind"),
                      row.get("email") or row.get("value") or row.get("snippet") or row.get("bio") or row.get("description")]
            label = " · ".join(str(value) for value in values if value)
            link = (row.get("source_url") or row.get("url")) if section in {"jobs", "findings"} else (row.get("url") or row.get("source_url"))
            source = _text(row.get("source") or row.get("provider") or "") + " " + _link(link)
            status = str(row.get("verification") or row.get("certainty") or row.get("status") or "")
            if row.get("archived") or "archive" in str(row.get("category", "")).lower():
                status += " · historical evidence; current validity unverified"
            lines += ["| " + " | ".join([_text(label), source, _text(row.get("observed_at", report.get("observed_at"))), _text(status)]) + " |"]
        if len(data) > 2000:
            lines += ["", "Markdown includes the first 2000 entries; the JSON retains the complete dossier."]
        lines += [""]
    if report.get("analytics"):
        from .analytics import summary
        lines += [summary(report["analytics"]).replace("# Statistical analysis", "## Statistical analysis", 1),
                  "[Full calculations](analytics.json) · [Statistical report](analytics.html)", ""]
    history = report.get("history") or {}
    if history:
        lines += ["## History", "", "Snapshot dates and provider first/last seen dates are distinct from collection time.", "",
                  "| Date | Event | Observation | Source |", "| --- | --- | --- | --- |"]
        for row in history.get("timeline") or []:
            lines += ["| " + " | ".join([_text(row.get("date")), _text(row.get("event")), _text(row.get("label")), _link(row.get("url"))]) + " |"]
        comparison = history.get("comparison") or {}
        lines += ["", "### Snapshot comparison", "", "Status: " + _text(comparison.get("status")), "",
                  _text(comparison.get("meaning")), ""]
        for change in ("added", "missing"):
            lines += ["#### " + change.title(), ""]
            for row in comparison.get(change) or []:
                lines += ["- " + _text(row.get("value")) + " · " + _text(row.get("change")) + " · " + _link(row.get("url"))]
            if not comparison.get(change):
                lines += ["No entries."]
            lines += [""]
    lines += ["## Source checks", "", "| Source | Outcome | Count | Detail |", "| --- | --- | --- | --- |"]
    for row in report.get("source_checks") or []:
        lines += ["| " + " | ".join(_text(row.get(key)) for key in ("source", "state", "count", "detail")) + " |"]
    quality = report.get("quality_report") or {}
    if quality:
        lines += ["", "## Evidence checks", "", "Status: " + _text(quality.get("status")), "",
                  "Citation checks test mechanical consistency, not factual truth or identity."]
    lines += ["", "## Local exports", "", "- [JSON dossier](dossier.json)", "- [CSV table](dossier.csv)",
              "- [Interactive evidence graph](relationship_graph.html)", ""]
    return "\n".join(lines)


def _safe(value):
    value = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value))[:64].strip("._-") or "query"
    if value.upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}:
        value = "_" + value
    return value


def _new_note(path, content):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def save(result, vault=None):
    path = Path(result["report_json"]).resolve()
    if path.name != "dossier.json" or not isinstance(result.get("sections"), dict):
        raise ValueError("Expected a dossier.json with evidence sections")
    markdown = path.with_suffix(".md")
    markdown.write_text(render(result), encoding="utf-8")
    info = {"markdown": str(markdown)}
    if vault is not None:
        vault = Path(vault).expanduser().resolve()
        if vault.exists() and not vault.is_dir():
            raise ValueError("Obsidian vault must be a directory")
        export_root = vault / "FindAll"
        if export_root.is_symlink():
            raise ValueError("FindAll vault export directory must not be a symlink")
        folder = export_root / (_safe(result.get("query")) + "-" + _safe(result.get("observed_at")) + "-" + uuid.uuid4().hex[:12])
        folder.mkdir(parents=True, exist_ok=False)
        graph = result.get("relationship_graph") or evidence_graph.build_graph(result)
        nodes = {row["id"]: row for row in graph.get("nodes", []) if isinstance(row, dict)
                 and re.fullmatch(r"FindAll_[A-Za-z0-9_]+", str(row.get("id", "")))}
        links = {ident: [] for ident in nodes}
        for edge in graph.get("edges", []):
            if edge.get("source") in nodes and edge.get("target") in nodes:
                links[edge["source"]].append((edge, edge["target"], "outgoing"))
                links[edge["target"]].append((edge, edge["source"], "incoming"))
        for ident, node in nodes.items():
            content = ["---", "findall_id: " + ident, "kind: " + json.dumps(str(node.get("kind", ""))), "---", "",
                       "# " + _text(node.get("label")), "", "[[index|Run index]]", "",
                       "## Evidence properties", ""]
            for key, value in (node.get("properties") or {}).items():
                content.append("- " + _text(key) + ": " + (_link(value) if key == "url" else _text(_value(value))))
            content += ["", "## Evidence connections", ""]
            for edge, target, direction in links[ident]:
                content += ["- " + direction + " · " + _text(edge.get("label")) + " · " + _text(edge.get("certainty"))
                            + " · [[" + target + "]]",
                            "  - " + " · ".join(_link(url) for url in edge.get("source_urls", []))]
            _new_note(folder / (ident + ".md"), "\n".join(content) + "\n")
        index = ["# FindAll run: " + _text(result.get("query")), "", "[[dossier|Consolidated dossier]]", "",
                 "Each connection retains evidence certainty. Matching handles are candidates, not confirmed identity.", "", "## Graph notes", ""]
        index.extend("- [[" + ident + "]] — " + _text(row.get("label")) for ident, row in nodes.items())
        _new_note(folder / "index.md", "\n".join(index) + "\n")
        # Use copied evidence exports so links remain portable inside the vault.
        _new_note(folder / "dossier.md", render(result))
        _new_note(folder / "dossier.json", json.dumps(result, ensure_ascii=False, indent=2))
        for name in ("dossier.csv", "relationship_graph.html", "relationship_graph.json"):
            original = path.with_name(name)
            if original.is_file():
                with (folder / name).open("xb") as stream:
                    stream.write(original.read_bytes())
        info.update(obsidian_directory=str(folder), obsidian_index=str(folder / "index.md"))
    result.setdefault("exported_paths", {}).update(info)
    return info
