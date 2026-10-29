"""Отчёты: CSV, XLSX (SpreadsheetML 2003), HTML, Markdown. Все файлы самодостаточные."""

from __future__ import annotations

import csv
import html
from pathlib import Path
from urllib.parse import urlsplit


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _href(value, schemes=("http", "https")) -> str:
    """Allow only web links from untrusted job-board data."""
    value = str(value or "").strip()
    try:
        return _esc(value) if urlsplit(value).scheme.lower() in schemes else ""
    except ValueError:
        return ""


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in columns})
    return path


# ------------------------------------------------------------- SpreadsheetML

def _xml_escape(x) -> str:
    return (str(x if x is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def write_xlsx_xml(path: Path, sheet_name: str, rows: list[list]) -> Path:
    """SpreadsheetML 2003 (.xls) — открывается Excel/LibreOffice без зависимостей."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cells_xml = []
    for row in rows:
        cells = []
        for v in row:
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                cells.append(f'<Cell><Data ss:Type="Number">{v}</Data></Cell>')
            else:
                cells.append(f'<Cell><Data ss:Type="String">{_xml_escape(v)}</Data></Cell>')
        cells_xml.append("<Row>" + "".join(cells) + "</Row>")
    xml = (
        '<?xml version="1.0"?>\n'
        '<?mso-application progid="Excel.Sheet"?>\n'
        '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" '
        'xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">'
        f'<Worksheet ss:Name="{_xml_escape(sheet_name)[:31]}"><Table>'
        + "".join(cells_xml) +
        "</Table></Worksheet></Workbook>"
    )
    path.write_text(xml, encoding="utf-8")
    return path


# -------------------------------------------------------------------- HTML

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; margin: 0;
       background: #f4f6fa; color: #16233b; line-height: 1.55; }
.wrap { max-width: 1200px; margin: 0 auto; padding: 28px 20px 60px; }
h1 { font-size: 26px; margin: 0 0 4px; }
.sub { color: #5b6b84; margin: 0 0 24px; font-size: 14px; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 26px; }
.metric { background: #fff; border: 1px solid #e3e8f0; border-radius: 12px; padding: 14px 16px; }
.metric .v { font-size: 26px; font-weight: 700; color: #1a4fd6; }
.metric .k { font-size: 12px; color: #5b6b84; text-transform: uppercase; letter-spacing: .04em; }
h2 { font-size: 19px; margin: 34px 0 12px; }
table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e3e8f0;
        border-radius: 10px; overflow: hidden; font-size: 13.5px; }
th { background: #eef2f9; text-align: left; padding: 9px 12px; font-size: 12px;
     text-transform: uppercase; letter-spacing: .05em; color: #44536b; border-bottom: 1px solid #e3e8f0; }
td { padding: 9px 12px; border-bottom: 1px solid #f0f3f8; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8fafd; }
.badge { display: inline-block; padding: 1px 9px; border-radius: 20px; font-size: 11.5px; font-weight: 600; }
.b-remote { background: #e5f6ec; color: #177245; }
.b-src { background: #e8eefc; color: #1a4fd6; }
.b-mail { background: #fdf1e2; color: #9a5b00; }
.b-tg { background: #e0f2fe; color: #0284c7; }
.b-skill { background: #e0e7ff; color: #4338ca; }
.b-grade { background: #f3e8ff; color: #7e22ce; }
.b-sal { background: #ecfdf5; color: #047857; }
.muted { color: #7b8798; }
a { color: #1a4fd6; text-decoration: none; }
.sec-note { font-size: 13px; color: #5b6b84; margin: -6px 0 12px; }
@media (prefers-color-scheme: dark) {
  :root { color-scheme: dark; }
  body { background: #0f172a; color: #e2e8f0; }
  .metric, table { background: #1e293b; border-color: #334155; }
  .metric .v { color: #60a5fa; }
  .metric .k, .sub, .sec-note, .muted { color: #94a3b8; }
  th { background: #1e293b; color: #cbd5e1; border-color: #334155; }
  td { border-color: #334155; }
  tr:hover td { background: #273549; }
  a { color: #60a5fa; }
  .b-remote { background: #064e3b; color: #6ee7b7; }
  .b-src { background: #1e3a8a; color: #93c5fd; }
  .b-mail { background: #78350f; color: #fde68a; }
  .b-tg { background: #075985; color: #7dd3fc; }
  .b-skill { background: #312e81; color: #a5b4fc; }
  .b-grade { background: #581c87; color: #d8b4fe; }
  .b-sal { background: #064e3b; color: #6ee7b7; }
}
"""

def _metric(v, k) -> str:
    return f'<div class="metric"><div class="v">{v}</div><div class="k">{_esc(k)}</div></div>'


def write_html_report(path: Path, data: dict) -> Path:
    """data: {jobs, emails, links, stats, generated} — как из contacts.enrich()."""
    from . import score as score_mod
    jobs = data.get("jobs", [])
    emails = data.get("emails", [])
    links = data.get("links", [])
    stats = data.get("stats", {})
    gen = data.get("generated", "")

    prof = data.get("profile")
    if not prof and Path("profile.json").exists():
        try:
            prof = score_mod.load_profile("profile.json")
        except Exception:
            prof = None

    # Группировка по компаниям
    companies = {}
    for j in jobs:
        c = j.get("company") or "(unknown)"
        companies.setdefault(c, []).append(j)

    job_rows = []
    for j in jobs:
        emails_html = ""
        if j.get("found_emails"):
            emails_html = "".join(
                f'<span class="badge {"b-tg" if str(e).startswith("@") else "b-mail"}">{_esc(e)}</span> '
                for e in j["found_emails"].split(", ") if e
            )
        remote = '<span class="badge b-remote">remote</span> ' if j.get("remote") else ""
        grade = j.get("grade") or score_mod.detect_grade(j.get("title") or "", j.get("description") or "")
        salary = j.get("salary") or score_mod.extract_salary(f"{j.get('title') or ''} {j.get('description') or ''}")
        grade_badge = f'<span class="badge b-grade">{_esc(grade)}</span> ' if grade else ""
        sal_badge = ""
        if salary and isinstance(salary, dict):
            sal_raw = salary.get("raw") or ""
            if sal_raw:
                sal_badge = f'<span class="badge b-sal">{_esc(sal_raw)}</span> '

        matched_skills = j.get("matched_skills")
        if matched_skills is None and prof and prof.get("skills"):
            blob = f"{j.get('title', '')} {j.get('description', '')[:2000]}".lower()
            matched_skills = [sk for sk in prof["skills"] if sk.lower() in blob]
        skills_badge = ""
        if matched_skills:
            skills_badge = "".join(f'<span class="badge b-skill">{_esc(sk)}</span> ' for sk in matched_skills[:6])

        job_rows.append(
            f"<tr><td>{_esc(j.get('title'))}<br><span class='muted'>{remote}{grade_badge}{sal_badge}{skills_badge}"
            f"<span class='badge b-src'>{_esc(j.get('source'))}</span></span></td>"
            f"<td>{_esc(j.get('company'))}</td>"
            f"<td>{_esc(j.get('location'))}</td>"
            f"<td>{emails_html or '<span class=muted>—</span>'}</td>"
            f"<td><a href='{_href(j.get('url'))}' target='_blank' rel='noopener'>open ↗</a></td></tr>"
        )

    email_rows = []
    for e in emails:
        raw_contact = str(e.get("email") or "")
        if raw_contact.startswith("@"):
            link_href = f"https://t.me/{raw_contact.lstrip('@')}"
            link_tag = f"<a href='{_href(link_href)}' target='_blank' rel='noopener'>{_esc(raw_contact)}</a>"
        else:
            link_tag = f"<a href='{_href('mailto:' + raw_contact, ('mailto',))}'>{_esc(raw_contact)}</a>"
        kind_name = str(e.get("kind") or "published")
        kind_cls = "b-tg" if kind_name.startswith("tg") else "b-src"
        email_rows.append(
            f"<tr><td>{link_tag}</td>"
            f"<td>{_esc(e.get('company'))}</td>"
            f"<td><span class='badge {kind_cls}'>{_esc(kind_name if kind_name.startswith('tg') else e.get('source'))}</span></td>"
            f"<td><a href='{_href(e.get('job_url'))}' target='_blank' rel='noopener'>job ↗</a></td></tr>"
        )

    link_rows = [
        f"<tr><td>{_esc(l.get('label'))}</td>"
        f"<td><a href='{_href(l.get('url'))}' target='_blank' rel='noopener'>{_esc(l.get('url')[:90])}…</a></td></tr>"
        for l in links
    ]

    src_counts = {}
    for j in jobs:
        src_counts[j.get("source", "?")] = src_counts.get(j.get("source", "?"), 0) + 1
    src_html = ", ".join(f"{_esc(k)}: {v}" for k, v in sorted(src_counts.items(), key=lambda x: -x[1]))

    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>FindAll — jobs and contacts report</title>",
        f"<style>{_CSS}</style></head><body><div class='wrap'>",
        "<h1>FindAll — jobs and contacts report</h1>",
        f"<p class='sub'>Generated {gen} · public API data · deduplicated by URL · "
        f"sources: {src_html}</p>",
        "<div class='metrics'>",
        _metric(len(jobs), "jobs"),
        _metric(len(companies), "companies"),
        _metric(len(emails), "emails found"),
        _metric(len(links), "people search links"),
        "</div>",
        "<h2>Jobs</h2>",
        "<p class='sec-note'>Select 'open' to view a posting. Email is shown only if the company published it in the posting.</p>",
        "<table><tr><th>Position</th><th>Company</th><th>Location</th><th>Email</th><th>Link</th></tr>"
        + "".join(job_rows) + "</table>",
        "<h2>Emails found</h2>",
        "<p class='sec-note'>Addresses companies published in job descriptions. Keep your message concise and relevant.</p>",
        "<table><tr><th>Email</th><th>Company</th><th>Source</th><th>Job</th></tr>"
        + ("".join(email_rows) or "<tr><td colspan=4 class=muted>none found</td></tr>") + "</table>",
        "<h2>People search links</h2>",
        "<p class='sec-note'>Ready searches for recruiters and hiring managers at specific companies. "
        "Review profiles and write personalized messages.</p>",
        "<table><tr><th>Search for</th><th>Link</th></tr>" + ("".join(link_rows) or "") + "</table>",
        "<p class='sec-note'>Data sources: <a href='https://remoteok.com'>RemoteOK</a> · "
        "<a href='https://jobicy.com'>Jobicy</a> · <a href='https://news.ycombinator.com'>HN Who is hiring</a> · "
        "Remotive · Arbeitnow · public company ATS boards (Greenhouse, Lever, Ashby, Workable). "
        "RemoteOK and Jobicy API terms require source attribution.</p>",
        "</div></body></html>",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(parts), encoding="utf-8")
    return path


def write_markdown(path: Path, data: dict) -> Path:
    from . import score as score_mod
    jobs = data.get("jobs", [])
    emails = data.get("emails", [])
    prof = data.get("profile")
    if not prof and Path("profile.json").exists():
        try:
            prof = score_mod.load_profile("profile.json")
        except Exception:
            prof = None
    lines = [
        "# FindAll — jobs and contacts",
        "",
        f"*Generated {data.get('generated', '')}*",
        "",
        "| # | Position | Company | Skills | Location | Email | Link |",
        "|---|---------|----------|--------|---------|-------|--------|",
    ]
    for i, j in enumerate(jobs, 1):
        matched_skills = j.get("matched_skills")
        if matched_skills is None and prof and prof.get("skills"):
            blob = f"{j.get('title', '')} {j.get('description', '')[:2000]}".lower()
            matched_skills = [sk for sk in prof["skills"] if sk.lower() in blob]
        skills_str = ", ".join(matched_skills[:5]) if matched_skills else "—"
        lines.append(f"| {i} | {j.get('title','')} | {j.get('company','')} | {skills_str} | {j.get('location','')} "
                     f"| {j.get('found_emails','')} | {j.get('url','')} |")
    lines += ["", "## Emails in job postings", ""]
    if emails:
        lines += ["| Email | Company | Source |", "|-------|---------|--------|"]
        lines += [f"| {e.get('email')} | {e.get('company')} | {e.get('source')} |" for e in emails]
    else:
        lines.append("_no emails found in descriptions_")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
