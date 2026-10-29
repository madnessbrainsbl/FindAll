#!/usr/bin/env python3
"""FindAll — search jobs, companies, and employment contacts.

Python 3.10+; install requirements.txt for multi-engine search.

Examples:
  python jobfind.py scan --sources jobicy,remoteok --kw python
  python jobfind.py scan --ats greenhouse:stripe ashby:ramp workable:epignosis lever:blackshark
  python jobfind.py report --limit 100
  python jobfind.py companies
  python jobfind.py contacts --hypotheses
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import quote_plus, urlsplit

# Самозагрузка: некоторые интерпретаторы (например, встроенный в приложения)
# имеют нестандартный sys.path — добавляем каталог скрипта первыми строкой.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Безопасный вывод в консоль и файлы в UTF-8
if sys.stdout is not None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from jf import contacts as contacts_mod
from jf import apex_network, db, domain_recon, domains, dossier, evidence_graph, extra_osint, github_tools, mailer, net, notify, osint, osint_contacts, outreach, projects as projects_mod, report, score as score_mod, sources, spiderfoot_scan, track, two_gis

DEFAULT_OUT = Path("jobfind_out")


def cmd_network(args) -> int:
    path = Path(args.network_state) if args.network_state else Path(args.db).resolve().parent / "network" / "apex-state.json"
    try:
        if args.action == "install":
            apex_network.install_core()
            result = apex_network.status(path)
        elif args.action == "refresh":
            result = apex_network.refresh(path, args.group, args.country, args.subscription, args.limit if args.limit is not None else 300)
        elif args.action == "check":
            result = apex_network.check(path, args.limit if args.limit is not None else 12, args.node, args.test_url)
        elif args.action in ("enable", "disable"):
            result = apex_network.configure(path, args.action == "enable", args.node)
        else:
            result = apex_network.status(path)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1


def cmd_network_ui(args) -> int:
    from jf.network_ui import open_window
    path = Path(args.network_state) if args.network_state else Path(args.db).resolve().parent / "network" / "apex-state.json"
    return open_window(path)


def cmd_dossier_quality(args) -> int:
    """Read-only quality inspection; benchmark uses fictional offline fixtures."""
    from jf import research_quality
    try:
        if args.benchmark:
            result = research_quality.run_benchmark()
        else:
            if not args.path:
                raise ValueError("Choose --path or --benchmark")
            path = Path(args.path).resolve()
            output_root = (Path(args.out) / "dossiers").resolve()
            if path.name != "dossier.json" or not path.is_relative_to(output_root) or not path.is_file():
                raise ValueError("Choose a saved dossier.json inside the results folder")
            result = research_quality.evaluate(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, OSError, TypeError, KeyError):
        print(json.dumps({"status": "error", "error": "Unable to inspect a valid local dossier or benchmark"}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return int(result["status"] in {"failed", "invariant_failures"})


def cmd_local_audit(args) -> int:
    from jf import local_audit
    try:
        result = local_audit.install() if args.install else local_audit.scan(
            args.path, Path(args.out) / "local_audits", history=args.history, timeout=args.timeout)
    except (ValueError, OSError, RuntimeError):
        print(json.dumps({"status": "error", "error": "Local audit or official tool installation failed"}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return int(result["status"] in {"error", "unavailable"})


def cmd_library(args) -> int:
    from jf import library, pdf_documents
    try:
        if args.action == 'setup':
            result = library.setup()
        elif args.action == 'status':
            result = library.status(args.out)
        elif args.action == 'index':
            result = library.refresh(args.out, args.dossier_root)
        elif args.action == 'pdf':
            password = ''
            if args.password_stdin:
                payload = json.loads(sys.stdin.read(10_000))
                if not isinstance(payload, dict) or set(payload) != {'password'} or not isinstance(payload['password'], str):
                    raise ValueError('Invalid PDF password input')
                password = payload['password']
            reports = []
            for path in args.file:
                try:
                    reports.append(pdf_documents.import_pdf(path, args.out, password=password,
                        languages=args.languages, source_url=args.source_url))
                except (ValueError, OSError, RuntimeError) as exc:
                    reports.append(dict(title=Path(path).name, status='error', errors=[str(exc) if isinstance(exc, ValueError) else 'PDF import failed']))
            if not reports:
                raise ValueError('Choose at least one PDF')
            result = dict(action='pdf', status='partial' if any(r['status'] != 'ok' for r in reports) else 'ok',
                          pdfs=reports, inventory=library.refresh(args.out, args.dossier_root))
        elif args.action == 'search':
            result = library.search(args.question, args.out, roots=args.dossier_root)
        else:
            result = library.ask(args.question, args.out, roots=args.dossier_root,
                                 provider=args.ai_provider or None, model=args.ai_model or None)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        print(json.dumps({'error': str(exc) if isinstance(exc, ValueError) else 'Library operation failed; check local files and setup-library.bat'}))
        return 1


def cmd_browser_research(args) -> int:
    from jf import browser_research
    try:
        result = browser_research.run(args.url, Path(args.out), question=args.question,
            pages=args.pages, items=args.items, ai=args.ai,
            provider=args.ai_provider or None, model=args.ai_model or None, selector=args.selector)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "Browser research failed; check the results folder and browser setup"}))
        return 1


def cmd_browser_import(args) -> int:
    from jf import chrome_crawler
    try:
        result = chrome_crawler.import_page(Path(args.file), Path(args.out), query=args.query)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "Could not read or save the selected browser export"}))
        return 1


def cmd_phone(args) -> int:
    from jf import phone_recon
    try:
        result = phone_recon.investigate(args.number, Path(args.out), local_only=args.local_only)
        print(json.dumps(result, ensure_ascii=False))
        return int(any(row['source'] == 'PhoneInfoga' and row['state'] in {'error', 'timeout', 'blocked', 'skipped'}
                       for row in result['source_checks']))
    except (ValueError, OSError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False))
        return 1


def cmd_statistics(args) -> int:
    from jf import analytics
    try:
        if args.install_model:
            from jf.analytics_models import install_bert
            print(json.dumps({"model_setup": install_bert()}, ensure_ascii=False))
            return 0
        if not args.path:
            raise ValueError("Choose a dataset or --install-model")
        result = analytics.run(args.path, Path(args.out), radius_km=args.radius, period=args.period)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError, UnicodeError, TypeError, KeyError) as exc:
        print(json.dumps({"error": "Statistics: " + type(exc).__name__ + "; choose a valid local CSV/JSON evidence file"}))
        return 1


def cmd_dossier_export(args) -> int:
    """Refresh local timeline/Markdown; explicit vault exports are versioned."""
    path = Path(args.path).resolve()
    output_root = (Path(args.out) / "dossiers").resolve()
    if path.name != "dossier.json" or not path.is_relative_to(output_root) or not path.is_file():
        print("Choose a saved dossier.json inside the results folder", file=sys.stderr)
        return 1
    try:
        from jf import markdown_export
        result = json.loads(path.read_text(encoding="utf-8"))
        dossier.save_relationship_graph(result)
        if args.vault:
            result.setdefault("exported_paths", {}).update(markdown_export.save(result, vault=Path(args.vault)))
            path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        print("Unable to export the selected dossier", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_archive_search(args) -> int:
    from jf import archives
    try:
        data = archives.collect(args.domain, Path(args.out) / 'archives',
            providers=[p.strip() for p in args.providers.split(',') if p.strip()],
            subs=not args.no_subdomains, from_date=args.from_date, to_date=args.to_date,
            limit=args.limit, captures=args.captures, category=args.category,
            status_codes=args.status_codes, mime=args.mime, collapse_parameters=args.collapse_parameters,
            imports=args.import_file, time_budget=args.time_budget, capture_urls=args.capture_url)
        saved = archives.save_dossier(data, Path(args.out) / 'dossiers')
        data['dossier'] = {key:saved.get(key) for key in ('report_json','report_csv','graph_path','quality_report','exported_paths')}
        Path(data['reports']['json']).with_name('archive-session.json').write_text(
            json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(data,ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=False))
        return 1


def cmd_wireless(args) -> int:
    from jf import wireless
    try:
        mappings = json.loads(args.mapping) if args.mapping else None
        if mappings is not None and not isinstance(mappings, dict):
            raise ValueError('Mapping must be a JSON object')
        data = wireless.collect(Path(args.out) / 'wireless', files=args.file,
            providers=[p.strip() for p in args.providers.split(',') if p.strip()],
            latitude=args.latitude, longitude=args.longitude, radius_km=args.radius,
            wifi=args.wifi, bluetooth=args.bluetooth, sdr=args.sdr, seconds=args.seconds, mappings=mappings)
        saved = wireless.save_dossier(data, Path(args.out) / 'dossiers', args.query)
        data['dossier'] = {key: saved.get(key) for key in ('report_json', 'report_csv', 'graph_path', 'quality_report', 'exported_paths')}
        Path(data['reports']['json']).with_name('wireless-session.json').write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(data, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False))
        return 1


def cmd_wireless_ui(args) -> int:
    import subprocess
    launcher = Path(__file__).resolve().parent / 'start.ps1'
    if not launcher.is_file():
        print('Restore start.ps1 to open the native Wireless workspace', file=sys.stderr)
        return 1
    powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        subprocess.Popen([str(powershell), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                          str(launcher), '--page', 'wireless'], cwd=str(launcher.parent),
                         creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    except OSError:
        print('Could not open FindAll. Check the launcher and installed executable.', file=sys.stderr)
        return 1
    return 0


def cmd_dossier(args) -> int:
    source_counts = {"completed": 0, "total": 0}
    def progress(event: dict) -> None:
        if str(event.get("stage", "")).startswith("ai"):
            event = {**event, "percent": int(source_counts["completed"] * 100 / max(1, source_counts["total"]))}
        if event.get("stage") == "complete" and (args.ai or args.ai_investigate):
            event = {**event, "completed": source_counts["total"], "percent": 100}
        source_counts.update({key: event[key] for key in source_counts if key in event})
        if args.progress_json:
            print(json.dumps({**source_counts, **event}, ensure_ascii=False), file=sys.stderr, flush=True)

    try:
        result = dossier.collect(args.query, args.kind, args.scope,
                                 Path(args.out) / "dossiers", progress,
                                 finish_progress=not (args.ai or args.ai_investigate), include_onion=args.onion,
                                 include_spiderfoot=not args.no_spiderfoot,
                                 spiderfoot_timeout=args.spiderfoot_timeout,
                                 coverage=args.coverage, capture_pages=args.capture_pages,
                                 city=args.city, business_query=args.business_query,
                                 two_gis_limit=args.two_gis_limit, map_location=args.map_location,
                                 metadata_files=args.metadata_file,
                                 include_extra_tools=not args.no_extra_tools,
                                 include_careers=not getattr(args, "no_careers", False),
                                 include_domain_card=not getattr(args, "no_domain_card", False),
                                 wireless_files=getattr(args, "wireless_file", []),
                                 browser_files=getattr(args, "browser_file", []),
                                 include_archives=not getattr(args, "no_archives", False),
                                 archive_options=dict(from_date=getattr(args, "archive_from", ""),
                                     to_date=getattr(args, "archive_to", ""),
                                     providers=getattr(args, "archive_providers", "wayback,commoncrawl,otx,urlscan").split(',')))
        if args.ai_investigate:
            from jf.research_agent import run_investigation
            run_investigation(result, lambda tool, parameters: dossier.run_tool(result, tool, parameters),
                progress=progress, coverage=args.coverage,
                provider=args.ai_provider or None, model=args.ai_model or None)
        if args.ai or args.ai_investigate:
            from jf import ai_agents
            progress({"stage": "ai", "detail": "Analyzing public evidence"})
            analysis = ai_agents.analyze_dossier(result,
                provider=args.ai_provider or None, model=args.ai_model or None)
            dossier.save_ai_analysis(result, analysis)
            progress({"percent": 100, "stage": "complete", "detail": "Saved dossier and AI analysis"})
        sections = result["sections"]
        published = [row for row in sections.get("emails", []) if isinstance(row, dict)
                     and row.get("verification") == "published" and row.get("email")]
        pages = [row for row in sections.get("web", []) if isinstance(row, dict) and row.get("url")]
        if sections.get("jobs") or published or pages:
            conn = db.connect(args.db)
            try:
                jobs = [{**row, "found_emails": ",".join(row["found_emails"]) if isinstance(row.get("found_emails"), list)
                         else row.get("found_emails", "")} for row in sections.get("jobs", [])]
                new, updated = db.save_jobs(conn, jobs)
                db.save_companies(conn, jobs)
                result["database_jobs"] = {"new": new, "updated": updated}
                new, updated = db.save_people_contacts(conn, published)
                result["database_contacts"] = {"new": new, "updated": updated}
                result["database_pages"] = {"new": db.save_osint_results(conn, result["query"], [
                    {"url": row["url"], "title": row.get("title", ""), "snippet": row.get("snippet", ""),
                     "source": row.get("source", "Public website"), "category": row.get("category", "Public page")}
                    for row in pages])}
            finally:
                conn.close()
        dossier.save_relationship_graph(result)
        if getattr(args, "vault", ""):
            from jf import markdown_export
            result.setdefault("exported_paths", {}).update(markdown_export.save(result, vault=Path(args.vault)))
        Path(result["report_json"]).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Dossier: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_dossier_analyze(args) -> int:
    from jf import ai_agents
    path = Path(args.path).resolve()
    output_root = (Path(args.out) / "dossiers").resolve()
    if path.name != "dossier.json" or not path.is_relative_to(output_root) or not path.is_file():
        print("Choose a saved dossier.json inside the results folder", file=sys.stderr)
        return 1
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or Path(result.get("report_json", "")).resolve() != path:
            raise ValueError("Invalid dossier path")
        analysis = ai_agents.analyze_dossier(result,
            provider=args.ai_provider or None, model=args.ai_model or None)
        dossier.save_ai_analysis(result, analysis)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"Dossier analysis: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_ai_check(args) -> int:
    from jf import ai_agents
    result = ai_agents.check_provider(provider=args.provider or None, model=args.model or None)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 1


def cmd_dossier_graph(args) -> int:
    """Regenerate a saved dossier's local graph without any network collection."""
    path = Path(args.path).resolve()
    output_root = (Path(args.out) / "dossiers").resolve()
    if path.name != "dossier.json" or not path.is_relative_to(output_root) or not path.is_file():
        print("Choose a saved dossier.json inside the results folder", file=sys.stderr)
        return 1
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or Path(result.get("report_json", "")).resolve() != path:
            raise ValueError("Invalid dossier path")
        dossier.save_relationship_graph(result)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"Dossier graph: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_ai_models(args) -> int:
    from jf import ai_agents

    result = ai_agents.list_models(provider=args.provider or None)
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _search_web(query: str, limit: int = 24) -> tuple[list[dict], str]:
    """Public pages are kept as web evidence, not mislabeled as vacancies."""
    rows, errors, _ = osint.search(query, ["bing", "yandex", "brave", "web"])
    return rows[:limit], "\n".join(errors)


def _parse_ats(specs: list[str]) -> dict[str, list[str]]:
    """['greenhouse:stripe', 'lever:x'] -> {'greenhouse': ['stripe', ...], 'lever': [...]}"""
    out: dict[str, list[str]] = {}
    for s in specs or []:
        if ":" not in s:
            print(f"  [!] ATS specification has no ':': skipping {s}", file=sys.stderr)
            continue
        kind, tenant = s.split(":", 1)
        kind, tenant = kind.strip().lower(), tenant.strip()
        if kind not in sources.SOURCE_ATS:
            print(f"  [!] unknown ATS type '{kind}' (available: {', '.join(sources.SOURCE_ATS)})", file=sys.stderr)
            continue
        out.setdefault(kind, []).append(tenant)
    return out


def _fetch_all(board_names: list[str], ats: dict[str, list[str]], kw: str, per_source: int) -> list[dict]:
    jobs: list[dict] = []
    total_sources = len(board_names) + sum(len(tenants) for tenants in ats.values())
    current_idx = 0

    cb = sources.CIRCUIT_BREAKER
    for name in board_names:
        current_idx += 1
        fn = sources.SOURCE_BOARD.get(name)
        if not fn:
            print(f"  [!] source '{name}' unavailable (available: {', '.join(sources.SOURCE_BOARD)})", file=sys.stderr)
            continue
        if not cb.is_available(name):
            print(f"  [!] source '{name}' skipped by Circuit Breaker (repeated errors/blocks)", file=sys.stderr)
            continue
        pct = int(current_idx / total_sources * 100) if total_sources else 100
        bar_len = 10
        filled = int(bar_len * current_idx / total_sources) if total_sources else bar_len
        bar = "=" * filled + (">" if filled < bar_len else "")
        bar = bar.ljust(bar_len)
        print(f"  [{bar}] {current_idx:>2}/{total_sources} ({pct:>2}%) -> {name} ...", flush=True)
        try:
            got = fn(kw, per_source)
            if got:
                cb.record_success(name)
        except Exception as exc:  # источник не должен валить весь прогон
            print(f"  [!] {name}: {exc}", file=sys.stderr)
            if cb.record_failure(name, str(exc)):
                print(f"  [!] Circuit Breaker tripped for '{name}' after {cb.failure_threshold} failures; skipping further queries", file=sys.stderr)
            got = []
        print(f"     {len(got)} jobs")
        jobs.extend(got)
    for kind, tenants in ats.items():
        fn = sources.SOURCE_ATS[kind]
        for t in tenants:
            current_idx += 1
            ats_key = f"{kind}:{t}"
            if not cb.is_available(kind):
                print(f"  [!] ATS platform '{kind}' skipped by Circuit Breaker", file=sys.stderr)
                continue
            pct = int(current_idx / total_sources * 100) if total_sources else 100
            bar_len = 10
            filled = int(bar_len * current_idx / total_sources) if total_sources else bar_len
            bar = "=" * filled + (">" if filled < bar_len else "")
            bar = bar.ljust(bar_len)
            print(f"  [{bar}] {current_idx:>2}/{total_sources} ({pct:>2}%) -> {ats_key} ...", flush=True)
            try:
                got = fn(t)
                if got:
                    cb.record_success(kind)
            except Exception as exc:
                print(f"  [!] {ats_key}: {exc}", file=sys.stderr)
                if cb.record_failure(kind, str(exc)):
                    print(f"  [!] Circuit Breaker tripped for ATS '{kind}'; skipping remaining tenants", file=sys.stderr)
                got = []
            print(f"     {len(got)} jobs")
            jobs.extend(got)
    return jobs


def _dedupe(jobs: list[dict]) -> list[dict]:
    return score_mod.deduplicate_jobs(jobs, threshold=0.8)


def _matches_job_query(job: dict, query: str) -> bool:
    return sources.matches_job_query(job, query)


def cmd_scan(args) -> int:
    out_dir = Path(args.out)
    boards = [s.strip() for s in (args.sources or "").split(",") if s.strip()]
    ats = _parse_ats(args.ats or [])
    if not boards and not ats:
        boards = ["hh", "remotive", "arbeitnow", "remoteok", "jobicy", "hn"]

    print(f"FindAll scan: boards={boards or '-'} ats={ats or '-'} kw={args.kw or '-'}")
    jobs = _fetch_all(boards, ats, args.kw or "", args.per_source)
    jobs = _dedupe(jobs)
    print(f"Unique jobs: {len(jobs)}")

    data = contacts_mod.enrich(jobs)

    conn = db.connect(Path(args.db))
    new, upd = db.save_jobs(conn, data["jobs"])
    n_comp = db.save_companies(conn, data["jobs"])
    n_mail = db.save_contacts(conn, data["emails"])
    db.log_run(conn, "scan", {"jobs": len(jobs), "emails": len(data["emails"]),
                              "links": len(data["links"]), "kw": args.kw or ""})

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_p = report.write_csv(out_dir / f"jobs_{stamp}.csv", data["jobs"],
                             ["title", "company", "location", "remote", "source", "found_emails", "url", "posted"])
    xls_p = report.write_xlsx_xml(out_dir / f"jobs_{stamp}.xls", "Jobs", [
        ["Position", "Company", "Location", "Remote", "Source", "Emails", "URL"],
        *[[j.get(c, "") for c in ("title", "company", "location", "remote", "source", "found_emails", "url")]
          for j in data["jobs"]],
    ])
    html_p = report.write_html_report(out_dir / f"report_{stamp}.html",
                                      {**data, "generated": stamp, "stats": {"kw": args.kw or ""}})
    md_p = report.write_markdown(out_dir / f"jobs_{stamp}.md", data)

    print("\n=== Summary ===")
    print(f"Jobs: {len(jobs)} (new in database: {new}, updated: {upd})")
    print(f"Companies: {n_comp} | Emails: {n_mail} | People search links: {len(data['links'])}")
    print(f"CSV:      {csv_p}")
    print(f"XLS:      {xls_p}")
    print(f"HTML:     {html_p}")
    print(f"Markdown: {md_p}")
    print(f"Database: {args.db}")

    if getattr(args, "notify_tg", False):
        prof = score_mod.load_profile(getattr(args, "profile", "profile.json"))
        scored = score_mod.score_all(data["jobs"], prof)
        token, chat_id = notify.resolve_telegram_credentials(args, prof)
        if not token or not chat_id:
            print("  [!] Telegram alert skipped: provide --tg-token/--tg-chat or set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID", file=sys.stderr)
        else:
            min_score = getattr(args, "tg_min_score", 60) or 60
            top_n = getattr(args, "tg_top", 5) or 5
            msg = notify.format_top_jobs_digest(scored, Path(getattr(args, "profile", "profile.json")).stem, top_n=top_n, min_score=min_score)
            if msg:
                ok, err = notify.send_telegram(token, chat_id, msg)
                if ok:
                    print(f"Telegram: digest sent to {chat_id}")
                else:
                    print(f"  [!] Telegram error: {err}", file=sys.stderr)
            else:
                print(f"Telegram: no jobs qualified for alert (score ≥ {min_score})")

    return 0


def cmd_search(args) -> int:
    """One query across vacancy boards, public projects, and published contacts."""
    query = " ".join(args.kw.split())
    boards = [name.strip() for name in args.sources.split(",") if name.strip()]
    source_log = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(source_log):
        jobs = _dedupe(_fetch_all(boards, {}, query, args.per_source))
        jobs = [job for job in jobs if _matches_job_query(job, query)]
        job_data = contacts_mod.enrich(jobs)
        try:
            found_projects = projects_mod.search(query, args.project_limit)
            project_error = ""
        except Exception as exc:
            found_projects = []
            project_error = str(exc)
        web_results, web_search_error = _search_web(query)

    conn = db.connect(Path(args.db))
    new_jobs, updated_jobs = db.save_jobs(conn, job_data["jobs"])
    new_companies = db.save_companies(conn, job_data["jobs"])
    new_emails = db.save_contacts(conn, job_data["emails"])
    new_projects, updated_projects = db.save_projects(conn, found_projects)
    db.log_run(conn, "search", {"query": query, "jobs": len(jobs),
                                 "projects": len(found_projects), "emails": len(job_data["emails"])})
    conn.close()

    query_q = quote_plus(query)
    telegram_q = quote_plus(f"{query} (работа OR вакансия OR заказ OR freelance OR project)")
    result = {
        "query": query,
        "jobs": job_data["jobs"],
        "projects": found_projects,
        "contacts": job_data["emails"],
        "company_links": job_data["links"],
        "web_results": web_results,
        "web_search_error": web_search_error,
        "web_links": [
            {"label": "HeadHunter", "url": f"https://hh.ru/search/vacancy?text={query_q}"},
            {"label": "Google · jobs", "url": f"https://www.google.com/search?q={query_q}+работа+вакансия+OR+job+OR+career"},
            {"label": "Google · projects and contracts", "url": f"https://www.google.com/search?q={query_q}+заказ+проект+OR+freelance+OR+contract"},
            {"label": "Telegram · public posts (Google CSE)", "url": f"https://cse.google.com/cse?cx=006368593537057042503%3Aefxu7xprihg#gsc.tab=0&gsc.q={telegram_q}"},
            {"label": "Bing · general search", "url": f"https://www.bing.com/search?q={query_q}+работа+OR+вакансия+OR+заказ+OR+проект"},
            {"label": "Ahmia · onion index", "url": f"https://ahmia.fi/search/?q={query_q}+jobs+OR+work+OR+projects"},
        ],
        "reports": {},
        "project_error": project_error,
        "source_errors": source_log.getvalue().strip(),
        "counts": {"jobs": len(jobs), "projects": len(found_projects), "contacts": len(job_data["emails"]),
                   "web_results": len(web_results),
                   "new_jobs": new_jobs, "updated_jobs": updated_jobs, "new_companies": new_companies,
                   "new_contacts": new_emails, "new_projects": new_projects, "updated_projects": updated_projects},
    }
    result["observed_at"] = db.now_iso()
    result.update(evidence_graph.accumulate(evidence_graph.from_search(result), Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_osint_search(args) -> int:
    """Собрать открытые публикации по теме и сохранить их происхождение."""
    query = " ".join(args.query.split())
    if not 2 <= len(query) <= 200:
        raise SystemExit("Query must contain 2–200 characters")
    enabled = list(dict.fromkeys(s.strip() for s in args.sources.split(",") if s.strip()))
    unknown = set(enabled) - set(osint.SOURCES)
    if args.mode == "full" and (not enabled or unknown):
        raise SystemExit(f"Select sources from: {', '.join(osint.SOURCES)}")
    domain_pattern = r"(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
    domain = args.domain.strip().lower()
    username = args.username.strip().lstrip("@")
    if not domain and not username:
        if re.fullmatch(domain_pattern, query.lower()):
            domain = query.lower()
        elif query.startswith("@") or re.fullmatch(r"[A-Za-z0-9_-]{2,39}", query) or args.mode == "email":
            username = query.lstrip("@")
    if domain and not re.fullmatch(domain_pattern, domain):
        raise SystemExit("Domain must look like example.org")
    if username and not re.fullmatch(r"[A-Za-z0-9._-]{2,39}", username):
        raise SystemExit("Enter a valid username or leave the field empty")
    if args.mode == "email":
        return cmd_osint_email_search(args, query, domain, username)

    rows, errors, statuses = osint.search(query, enabled)
    integrations = {}
    operations = []
    output = Path(args.out)
    if domain:
        operations.append(("domain_recon", lambda: domain_recon.investigate(domain, output)))
        operations.append(("company_site", lambda: {"rows": osint_contacts.find_public_emails(query, domain)}))
    if username:
        operations.extend([
            ("github_email", lambda: github_tools.github_email(username, output)),
            ("maigret", lambda: github_tools.maigret_search(username, output, 100)),
            ("tiktok", lambda: github_tools.tiktok_profile(username, output)),
        ])
    if args.onion:
        operations.append(("onion", lambda: github_tools.onion_search(query, output)))
    if operations:
        def run(operation):
            provider, getter = operation
            try:
                data = getter()
                if data.get("status") == "source_error":
                    return provider, {"status": "error", "error": "; ".join(data.get("errors", [])), "data": data}
                if provider == "onion" and data.get("warnings"):
                    return provider, {"status": "partial" if data.get("rows") else "error",
                                      "error": "; ".join(data["warnings"]), "data": data}
                return provider, {"status": "ok", "error": "", "data": data}
            except Exception as exc:
                return provider, {"status": "error", "error": str(exc), "data": {}}
        with ThreadPoolExecutor(max_workers=min(5, len(operations))) as pool:
            integrations = dict(pool.map(run, operations))
        if domain:
            provider, entry = run(("web_check", lambda: github_tools.web_check(domain, output)))
            integrations[provider] = entry
        for provider, entry in integrations.items():
            data = entry["data"]
            count = (int(data.get("event_count") or 0) if provider == "spiderfoot" else
                     len(data.get("rows", [])) if provider in ("maigret", "onion", "company_site") else
                     len(data.get("modules", [])) if provider == "web_check" else
                     len(data.get("assets", [])) if provider == "domain_recon" else
                     int(bool(data.get("email"))) if provider == "github_email" else
                     int(bool(data.get("url"))))
            statuses.append({"source": provider, "count": count, "error": entry["error"]})
            if provider == "onion":
                statuses.extend({**{key: value for key, value in item.items() if key != "name"},
                                 "source": item["name"]} for item in data.get("statuses", []))
            if entry["error"]:
                errors.append(f"{provider}: {entry['error']}")
        for row in integrations.get("maigret", {}).get("data", {}).get("rows", []):
            if row.get("url", "").startswith(("https://", "http://")):
                rows.append({"title": f"{row['site']} · {username}", "url": row["url"],
                             "snippet": f"Public profile of {username}",
                             "source": "Maigret", "category": "Profiles"})
        for row in integrations.get("onion", {}).get("data", {}).get("rows", []):
            if row.get("url", "").startswith(("https://", "http://")):
                rows.append({**row, "title": row.get("title") or row["url"], "url": row["url"],
                             "snippet": row.get("snippet", ""), "source": "OnionSearch",
                             "category": "Onion index"})
        tiktok = integrations.get("tiktok", {}).get("data", {})
        if tiktok.get("url"):
            rows.append({"title": tiktok.get("name") or username, "url": tiktok["url"],
                         "snippet": tiktok.get("bio", ""), "source": tiktok.get("source", "TikTok"),
                         "category": "Public profile"})
        rows = list({row["url"]: row for row in rows}.values())
    if domain or username:
        extra = extra_osint.supplement(domain or username, "domain" if domain else "username",
                                      include_public="public" not in enabled)
        public_error = "; ".join(extra.get("errors") or [])
        integrations["public"] = {"status": "error" if public_error else "ok",
                                  "error": public_error, "data": extra}
        statuses.append({"source": "public", "count": sum(len(extra.get(key) or [])
                         for key in ("profiles", "web", "hostnames", "findings")),
                         "error": public_error})
        statuses.extend(extra.get("statuses") or [])
        if public_error:
            errors.append(f"public: {public_error}")
        for row in extra.get("profiles") or []:
            if str(row.get("url", "")).startswith("https://"):
                rows.append({"title": f"{row.get('site') or 'Profile'} · {username or domain}",
                             "url": row["url"], "snippet": row.get("status", ""),
                             "source": row.get("source") or "public", "category": "Profiles"})
        for row in extra.get("web") or []:
            if str(row.get("url", "")).startswith(("https://", "http://")):
                rows.append({**row, "title": row.get("title") or row["url"], "url": row["url"],
                             "snippet": row.get("snippet", ""), "source": row.get("source") or "urlscan.io",
                             "category": row.get("category") or "Public scan"})
        recon = integrations.get("domain_recon", {}).get("data")
        if isinstance(recon, dict):
            known_hosts = {item.get("name"): item for item in recon.get("subdomains") or []}
            recon.setdefault("subdomains", [])
            for item in extra.get("hostnames") or []:
                host, source = extra_osint.hostname_item(item)
                if not host:
                    continue
                existing = known_hosts.get(host)
                if existing:
                    if source not in existing.setdefault("sources", []):
                        existing["sources"].append(source)
                    continue
                row = {"name": host, "ips": [], "sources": [source]}
                recon["subdomains"].append(row)
                known_hosts[host] = row
        rows = list({row["url"]: row for row in rows}.values())
    entry = _spiderfoot_entry(domain or username or query, output,
                              "domain" if domain else "username" if username else "")
    integrations["spiderfoot"] = entry
    statuses.append({"source": "spiderfoot", "count": len(entry["data"].get("rows", [])) + len(entry["data"].get("emails", [])),
                     "state": entry["status"], "error": entry["error"]})
    if entry["error"]:
        errors.append(f"spiderfoot: {entry['error']}")
    for row in entry["data"].get("rows", []):
        if row.get("url", "").startswith(("https://", "http://")):
            rows.append(row)
    rows = list({row["url"]: row for row in rows}.values())
    domain_info = None
    if domain:
        try:
            domain_info = domains.domain_report(domain)
        except Exception as exc:
            errors.append(f"Domain {domain}: {exc}")
        try:
            snapshot = osint.archived_homepage(domain)
            if snapshot:
                rows.append(snapshot)
        except Exception as exc:
            errors.append(f"Archive {domain}: {exc}")
        try:
            rows.extend(osint.breach_catalogue(domain))
        except Exception as exc:
            errors.append(f"Public breach catalog {domain}: {exc}")
    seen_at = db.now_iso()
    for row in rows:
        row["seen_at"] = seen_at
        row["query"] = query
    conn = db.connect(Path(args.db))
    new = db.save_osint_results(conn, query, rows)
    if integrations:
        db.save_osint_integrations(conn, query, integrations)
        published_contacts = [row for row in integrations.get("company_site", {}).get("data", {}).get("rows", [])
                              if row.get("verification") == "published"
                              and any(url.startswith("https://") for url in row.get("evidence", []))]
        if published_contacts:
            db.save_people_contacts(conn, published_contacts)
            for contact in published_contacts:
                for url in contact["evidence"]:
                    if url.startswith("https://"):
                        db.save_osint_emails(conn, query, url, [contact["email"]])
        github_email = integrations.get("github_email", {}).get("data", {})
        if github_email.get("email") and github_email.get("source_url"):
            db.save_osint_emails(conn, query, github_email["source_url"], [github_email["email"]])
        for item in integrations.get("spiderfoot", {}).get("data", {}).get("emails", []):
            if item.get("email") and str(item.get("url", "")).startswith("https://"):
                db.save_osint_emails(conn, query, item["url"], [item["email"]])
    db.log_run(conn, "osint-search", {"query": query, "results": len(rows), "new": new,
                                       "sources": enabled, "errors": errors})
    emails = [dict(row) for row in conn.execute(
        "SELECT email,url FROM osint_emails WHERE query=? ORDER BY first_seen DESC", (query,))]
    pages = [dict(row) for row in conn.execute(
        "SELECT url,title,excerpt,observed_at,html_sha256,snapshot FROM osint_pages "
        "WHERE query=? ORDER BY observed_at DESC", (query,))]
    conn.close()
    links = osint.manual_links(query)
    if domain:
        links.append({"label": "Domain archive", "url": f"https://web.archive.org/web/*/{domain}"})
        links.append({"label": "Web-Check", "url": "https://web-check.as93.net/"})
    result = {"query": query, "results": rows, "new": new, "errors": errors,
              "statuses": statuses,
              "emails": emails, "pages": pages, "integrations": integrations,
              "domain": domain_info, "links": links, "csv": "", "report": "", "observed_at": seen_at}
    result.update(evidence_graph.accumulate(evidence_graph.from_search(result), Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_osint_email_search(args, query: str, domain: str, username: str) -> int:
    """Find only emails with a public source URL; keep guesses out of results."""
    integrations = {}
    errors = []
    statuses = []
    found = []
    published_contacts = []
    if domain:
        try:
            contacts = osint_contacts.find_public_emails(query, domain)
            published_contacts = [row for row in contacts if row.get("verification") == "published"
                                  and any(url.startswith("https://") for url in row.get("evidence", []))]
            found.extend((row["email"], url) for row in published_contacts
                         for url in row["evidence"] if url.startswith("https://"))
            statuses.append({"source": "company_site", "count": len(found), "error": ""})
        except Exception as exc:
            errors.append(f"company_site: {exc}")
            statuses.append({"source": "company_site", "count": 0, "error": str(exc)})
    if username:
        try:
            data = github_tools.github_email(username, Path(args.out))
            error = "; ".join(data.get("errors", []))
            integrations["github_email"] = {"status": "error" if error else "ok", "error": error, "data": data}
            if data.get("email") and data.get("source_url", "").startswith("https://"):
                found.append((data["email"], data["source_url"]))
            statuses.append({"source": "github_email", "count": int(bool(data.get("email"))), "error": error})
            if error:
                errors.append(f"github_email: {error}")
        except Exception as exc:
            errors.append(f"github_email: {exc}")
            statuses.append({"source": "github_email", "count": 0, "error": str(exc)})
    target = domain or username or query
    entry = _spiderfoot_entry(target, Path(args.out), "domain" if domain else "username" if username else "")
    integrations["spiderfoot"] = entry
    data = entry["data"]
    for item in data.get("emails", []):
        if item.get("email") and str(item.get("url", "")).startswith("https://"):
            found.append((item["email"], item["url"]))
    statuses.append({"source": "spiderfoot", "count": len(data.get("rows", [])) + len(data.get("emails", [])),
                     "state": entry["status"], "error": entry["error"]})
    if entry["error"]:
        errors.append(f"spiderfoot: {entry['error']}")
    found = list(dict.fromkeys(found))
    conn = db.connect(Path(args.db))
    if published_contacts:
        db.save_people_contacts(conn, published_contacts)
    for email, url in found:
        db.save_osint_emails(conn, query, url, [email])
    if integrations:
        db.save_osint_integrations(conn, query, integrations)
    db.log_run(conn, "osint-search", {"query": query, "mode": "email", "emails": len(found), "errors": errors})
    conn.close()
    result = {"query": query, "mode": "email", "results": [], "new": len(found),
              "errors": errors, "statuses": statuses,
              "emails": [{"email": email, "url": url} for email, url in found],
              "pages": [], "integrations": integrations, "domain": None,
              "links": [], "csv": "", "report": "", "observed_at": db.now_iso()}
    result.update(evidence_graph.accumulate(evidence_graph.from_search(result), Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _spiderfoot_entry(target: str, output: Path, kind: str) -> dict:
    """One passive SpiderFoot scan, shaped like the other OSINT integrations."""
    try:
        data = spiderfoot_scan.scan(target, Path(output) / "spiderfoot", kind=kind,
                                    use_case="passive", modules=spiderfoot_scan.DOSSIER_MODULES, timeout=120)
        error = data.get("error") or ""
        if data.get("timed_out"):
            error = error or f"time limit reached; kept {data.get('event_count', 0)} events"
        stored = {key: data[key] for key in ("status", "target", "target_type", "use_case", "modules",
                                              "scan_id", "database", "timed_out", "event_count", "rows", "emails")}
        matches = len(data.get("rows", [])) + len(data.get("emails", []))
        state = ("partial" if matches else "timeout") if data.get("timed_out") else (
            "partial" if matches else "error") if error or data.get("status") == "error" else (
            "ok" if matches else "empty")
        return {"status": state,
                "error": error, "data": stored}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "data": {}}


def cmd_osint_history(args) -> int:
    query = " ".join(args.query.split())
    conn = db.connect(Path(args.db))
    rows = [dict(row) for row in conn.execute(
        "SELECT title,url,snippet,source,category,last_seen AS seen_at FROM osint_results "
        "WHERE query=? ORDER BY last_seen DESC LIMIT 500", (query,))]
    emails = [dict(row) for row in conn.execute(
        "SELECT email,url FROM osint_emails WHERE query=? ORDER BY first_seen DESC", (query,))]
    pages = [dict(row) for row in conn.execute(
        "SELECT url,title,excerpt,observed_at,html_sha256,snapshot FROM osint_pages "
        "WHERE query=? ORDER BY observed_at DESC", (query,))]
    integrations = {row["provider"]: json.loads(row["payload"]) for row in conn.execute(
        "SELECT provider,payload FROM osint_integrations WHERE query=?", (query,))}
    conn.close()
    print(json.dumps({"query": query, "results": rows, "emails": emails, "pages": pages,
                      "integrations": integrations, "errors": [], "statuses": [],
                      "domain": None, "links": osint.manual_links(query), "csv": "", "report": ""},
                     ensure_ascii=False))
    return 0


def cmd_workspace_graph(args) -> int:
    """Import saved evidence without network access and open the one workspace graph."""
    out = Path(args.out).resolve()
    conn = db.connect(Path(args.db))
    try:
        queries = {row[0] for table in ("osint_results", "osint_emails", "osint_pages")
                   for row in conn.execute(f"SELECT DISTINCT query FROM {table}")}
        for query in sorted(queries):
            result = {"query": query}
            for key, table in (("results", "osint_results"), ("emails", "osint_emails"), ("pages", "osint_pages")):
                result[key] = [dict(row) for row in conn.execute(f"SELECT * FROM {table} WHERE query=?", (query,))]
            evidence_graph.accumulate(evidence_graph.from_search(result), out)
        sections = {key: [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]
                    for key, table in (("jobs", "jobs"), ("web", "projects"), ("businesses", "directory_businesses"))}
        for row in sections["businesses"]:
            for key in ("emails", "phones", "websites", "categories"):
                row[key] = json.loads(row.get(key) or "[]")
        sections["emails"] = [{"email": row["email"], "url": url, "source": row["source"]}
                              for row in conn.execute("SELECT email,evidence,source FROM people_contacts WHERE verification='published'")
                              for url in json.loads(row["evidence"] or "[]")]
    finally:
        conn.close()
    errors = []
    for path in sorted((out / "dossiers").glob("*/*/dossier.json")):
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict) or not isinstance(saved.get("sections"), dict):
                raise ValueError("Invalid evidence sections")
            evidence_graph.accumulate(saved, out)
        except (ValueError, OSError) as exc:
            errors.append(f"Could not import {path.relative_to(out)}: {type(exc).__name__}")
    result = evidence_graph.accumulate({"query": "Saved jobs, projects and businesses", "sections": sections}, out)
    result["errors"] = errors
    if getattr(args, "export", False):
        with contextlib.closing(sqlite3.connect(out / ".research" / "graph.sqlite3")) as graph_db:
            graph = {"schema_version": 1, "query": "FindAll workspace", "root_id": evidence_graph._stable("Query", "workspace"),
                     "nodes": [], "edges": []}
            for kind, payload in graph_db.execute("SELECT kind,payload FROM graph_items ORDER BY id"):
                graph["nodes" if kind == "node" else "edges"].append(json.loads(payload))
        exports = out / "exports"
        # The shared HTML stays at the workspace root; explicit data exports are kept together.
        exports.mkdir(parents=True, exist_ok=True)
        (exports / "research.json").write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
        export_rows = [{key: ("'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value)
                        for key, value in row.items()} for row in graph["edges"]]
        report.write_csv(exports / "research.csv", export_rows,
                         ["source", "target", "kind", "certainty", "collector", "source_urls", "evidence_hashes", "observed_at"])
        result["export_folder"] = str(exports)
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_enrichment(args) -> int:
    from jf import flowsint
    if args.catalog:
        print(json.dumps({"enrichers": {name: {"input_kind": spec.input_kind, "output_kind": spec.output_kind,
            "title": spec.title, "network": spec.network} for name, spec in flowsint.ENRICHERS.items()},
            "flows": flowsint.FLOWS, "reference": flowsint.UPSTREAM, "reference_commit": flowsint.COMMIT}, ensure_ascii=False))
        return 0
    try:
        if args.flow_file:
            flow = flowsint.load_flow(Path(args.flow_file))
        elif args.enricher:
            spec = flowsint.ENRICHERS[args.enricher]
            flow = flowsint._flow(spec.title, spec.input_kind, [("enrich", args.enricher, "seed")])
        else:
            flow = flowsint.FLOWS[args.flow]
        if args.save_flow:
            path = Path(args.save_flow)
            # Explicit save never overwrites an existing investigation template.
            with path.open("x", encoding="utf-8") as stream:
                json.dump(flowsint.validate_flow(flow), stream, ensure_ascii=False, indent=2)
            print(json.dumps({"saved_flow": str(path.resolve())}, ensure_ascii=False))
            return 0
        if not args.value:
            raise ValueError("Enter an enrichment input value")
        progress = (lambda row: print(json.dumps({"type": "progress", **row}, ensure_ascii=False),
                                     file=sys.stderr, flush=True)) if args.progress_json else None
        result = flowsint.run(args.value, flow, Path(args.out), limit=args.limit, max_tasks=args.max_tasks, progress=progress)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError, UnicodeError) as exc:
        print(json.dumps({"error": f"Enrichment: {exc}"}, ensure_ascii=False))
        return 1


def cmd_osint_page(args) -> int:
    query = " ".join(args.query.split())
    page = osint_contacts.parse_public_page(args.url, capture_html=True)
    folder = Path(args.out).resolve() / ".research" / "pages"
    folder.mkdir(parents=True, exist_ok=True)
    snapshot = folder / (page["html_sha256"] + ".html.txt")
    snapshot.write_bytes(page.pop("_snapshot_html").encode("utf-8"))
    page["snapshot"] = str(snapshot)
    page["query"] = query
    conn = db.connect(Path(args.db))
    db.save_osint_page(conn, query, page)
    page["new_emails"] = db.save_osint_emails(conn, query, page["url"], page["emails"])
    db.log_run(conn, "osint-page", {"query": query, "url": page["url"],
                                    "emails": len(page["emails"])})
    conn.close()
    page["report"] = ""
    result = {"query": query, "observed_at": page["observed_at"], "pages": [page],
              "emails": [{"email": email, "url": page["url"], "html_sha256": page["html_sha256"],
                          "observed_at": page["observed_at"]} for email in page["emails"]]}
    page.update(evidence_graph.accumulate(evidence_graph.from_search(result), Path(args.out)))
    print(json.dumps(page, ensure_ascii=False))
    return 0


def cmd_tools_catalog(args) -> int:
    print(json.dumps(github_tools.catalog(args.query, args.limit, args.offset), ensure_ascii=False))
    return 0


def cmd_web_check(args) -> int:
    try:
        result = github_tools.web_check(args.domain, Path(args.out))
    except Exception as exc:
        print(f"Web-Check: {exc}", file=sys.stderr)
        return 1
    result.update(evidence_graph.accumulate({"query": args.domain, "kind": "domain", "observed_at": db.now_iso(),
                  "sections": {"webcheck_modules": result.get("modules", [])}}, Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_domain_recon(args) -> int:
    try:
        result = domain_recon.investigate(args.domain, Path(args.out), args.max_hosts, args.max_ips)
    except Exception as exc:
        print(f"Domain OSINT: {exc}", file=sys.stderr)
        return 1
    result.update(evidence_graph.accumulate({"query": args.domain, "kind": "domain", "observed_at": db.now_iso(),
                  "sections": {"domain": result}}, Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_maigret(args) -> int:
    try:
        result = github_tools.maigret_search(args.username, Path(args.out), args.top_sites)
    except Exception as exc:
        print(f"Maigret: {exc}", file=sys.stderr)
        return 1
    result.update(evidence_graph.accumulate({"query": args.username, "kind": "username", "observed_at": db.now_iso(),
                  "sections": {"profiles": result.get("rows", [])}}, Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_github_email(args) -> int:
    try:
        result = github_tools.github_email(args.username, Path(args.out), args.max_repos, args.max_commit_pages)
    except Exception as exc:
        print(f"GitHub Email Hunter: {exc}", file=sys.stderr)
        return 1
    if result["email"]:
        conn = db.connect(Path(args.db))
        db.save_osint_emails(conn, f"github:{result['username']}", result["source_url"], [result["email"]])
        db.log_run(conn, "github-email", {"username": result["username"], "source_url": result["source_url"]})
        conn.close()
    result.update(evidence_graph.accumulate({"query": args.username, "kind": "username", "observed_at": db.now_iso(),
                  "sections": {"emails": [{"email": result.get("email"), "url": result.get("source_url"), "source": "GitHub commit"}]}}, Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_tiktok_profile(args) -> int:
    try:
        result = github_tools.tiktok_profile(args.username, Path(args.out))
    except Exception as exc:
        print(f"TikTok Scraper: {exc}", file=sys.stderr)
        return 1
    conn = db.connect(Path(args.db))
    db.save_osint_results(conn, f"tiktok:{result['username']}", [{"url": result["url"],
        "title": result["name"] or result["username"], "snippet": result["bio"],
        "source": result["source"], "category": "Public profile"}])
    conn.close()
    result.update(evidence_graph.accumulate({"query": args.username, "kind": "username", "observed_at": db.now_iso(),
                  "sections": {"profiles": [result]}}, Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_spiderfoot(args) -> int:
    """Run SpiderFoot and store linked events in the same OSINT tables."""
    try:
        result = spiderfoot_scan.scan(args.target, Path(args.out) / "spiderfoot", kind=args.kind,
                                      use_case=args.use_case,
                                      modules=[item.strip() for item in args.modules.split(",") if item.strip()] or None,
                                      timeout=args.timeout)
    except Exception as exc:
        print(f"SpiderFoot: {exc}", file=sys.stderr)
        return 1
    query = result["target"]
    conn = db.connect(Path(args.db))
    rows = [row for row in result.get("rows", []) if row.get("url", "").startswith(("https://", "http://"))]
    for row in rows:
        row["seen_at"] = db.now_iso()
        row["query"] = query
    if rows:
        db.save_osint_results(conn, query, rows)
    for item in result.get("emails", []):
        if item.get("email") and str(item.get("url", "")).startswith("https://"):
            db.save_osint_emails(conn, query, item["url"], [item["email"]])
    stored = {key: result[key] for key in ("status", "target", "target_type", "use_case", "modules",
                                            "scan_id", "database", "timed_out", "event_count", "rows", "emails", "errors")}
    db.save_osint_integrations(conn, query, {"spiderfoot": {"status": result["status"], "error": result["error"], "data": stored}})
    db.log_run(conn, "spiderfoot-scan", {"target": query, "events": result["event_count"], "status": result["status"]})
    conn.close()
    sections = {"web": [], "profiles": [], "emails": []}
    spiderfoot_scan.merge_dossier(sections, result, db.now_iso())
    stored.update(evidence_graph.accumulate({"query": query, "sections": sections}, Path(args.out)))
    print(json.dumps(stored, ensure_ascii=False))
    return 0 if result["status"] != "error" else 1


def cmd_onion_search(args) -> int:
    try:
        result = github_tools.onion_search(args.query, Path(args.out), args.engines)
    except Exception as exc:
        print(f"OnionSearch: {exc}", file=sys.stderr)
        return 1
    result.update(evidence_graph.accumulate({"query": args.query, "observed_at": db.now_iso(),
                  "sections": {"web": result.get("rows", [])}}, Path(args.out)))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_report(args) -> int:
    conn = db.connect(Path(args.db))
    rows = conn.execute(
        "SELECT url, title, company, location, source, remote, description, posted, found_emails, first_seen "
        "FROM jobs ORDER BY first_seen DESC LIMIT ?", (args.limit,)
    ).fetchall()
    jobs = [
        {"url": r[0], "title": r[1], "company": r[2], "location": r[3], "source": r[4],
         "remote": bool(r[5]), "description": r[6], "posted": r[7], "found_emails": r[8]}
        for r in rows
    ]
    data = contacts_mod.enrich(jobs) if args.enrich else {"jobs": jobs, "emails": [], "links": []}
    if not args.enrich:
        emails = conn.execute(
            "SELECT email, company, source, job_url, kind FROM contacts "
            "WHERE kind in ('published', 'tg_contact', 'tg_bot', 'tg_channel') ORDER BY company"
        ).fetchall()
        data["emails"] = [{"email": e[0], "company": e[1], "source": e[2], "job_url": e[3], "kind": e[4]} for e in emails]
    conn.close()

    prof = score_mod.load_profile(getattr(args, "profile", "profile.json"))
    data["profile"] = prof
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    fmt = getattr(args, "format", "html").lower()
    if fmt in ("md", "markdown"):
        out_p = report.write_markdown(Path(args.out) / f"report_{stamp}.md", {**data, "generated": stamp})
        print(f"Markdown: {out_p}")
    elif fmt == "json":
        out_p = Path(args.out) / f"report_{stamp}.json"
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps({**data, "generated": stamp}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {out_p}")
    else:
        out_p = report.write_html_report(Path(args.out) / f"report_{stamp}.html",
                                          {**data, "generated": stamp})
        print(f"HTML: {out_p}")
    return 0


def cmd_domains(args) -> int:
    """Проверка доменов компаний: живой ли, принимает ли почту (MX), возраст (RDAP)."""
    conn = db.connect(Path(args.db))
    if args.limit:
        comps = [r[0] for r in conn.execute(
            "SELECT name FROM companies ORDER BY name LIMIT ?", (args.limit,)).fetchall()]
    else:
        comps = [r[0] for r in conn.execute("SELECT name FROM companies ORDER BY name").fetchall()]
    jobs_by_comp = {}
    for url, comp, fe in conn.execute("SELECT url, company, found_emails FROM jobs"):
        jobs_by_comp.setdefault(comp, []).append({"url": url, "found_emails": fe})
    print(f"Checking {len(comps)} domains (DoH MX + RDAP with SQLite cache, ~1 req/s)...")
    rows = []
    total = len(comps)
    for idx, c in enumerate(comps, 1):
        dom = contacts_mod.resolve_company_domain(c, jobs_by_comp.get(c, []))
        if not dom:
            continue
        try:
            rep = domains.domain_report(dom, conn=conn)
        except Exception:
            rep = {"domain": dom, "alive": False, "email_plausible": False, "age_years": None, "mx": [], "spf": [], "dmarc": []}
        rows.append({"company": c, **rep})
        flag = "OK" if rep.get("email_plausible") else ("alive" if rep.get("alive") else "DEAD")
        age = rep.get("age_years") if rep.get("age_years") is not None else "?"

        bar_len = 10
        filled = int(bar_len * idx / total) if total else bar_len
        bar = "=" * filled + (">" if filled < bar_len else "")
        bar = bar.ljust(bar_len)
        pct = int(idx / total * 100) if total else 100
        print(f"  [{bar}] {idx:>2}/{total} ({pct:>2}%) [{flag:5}] {c:24.24} {dom:28.28} age={age}", flush=True)
    csv_p = report.write_csv(Path(args.out) / "domains.csv", rows,
                             ["company", "domain", "alive", "email_plausible", "age_years", "mx", "spf", "dmarc"])
    ok = sum(1 for r in rows if r["email_plausible"])
    print(f"\nMail is possible on {ok} of {len(rows)} domains; address guesses can use these domains.")
    print(f"CSV: {csv_p}")
    return 0


def cmd_score(args) -> int:
    """Скоринг вакансий из БД под профиль (profile.json)."""
    conn = db.connect(Path(args.db))
    prof = score_mod.load_profile(args.profile)
    if getattr(args, "min_salary", 0):
        prof["min_salary"] = args.min_salary
    if getattr(args, "grade", ""):
        prof["grades"] = [args.grade]
    rows = conn.execute(
        "SELECT url, title, company, location, source, remote, description, posted, found_emails "
        "FROM jobs ORDER BY first_seen DESC LIMIT ?", (args.limit,)).fetchall()
    jobs = [{"url": r[0], "title": r[1], "company": r[2], "location": r[3], "source": r[4],
             "remote": bool(r[5]), "description": r[6], "posted": r[7], "found_emails": r[8]}
            for r in rows]
    scored = score_mod.score_all(jobs, prof)
    shown = 0
    for s in scored:
        if args.min and s["score"] < args.min:
            continue
        shown += 1
        if args.top == 0 or shown <= args.top:
            print(f"  [{s['score']:3}] {s['company'][:26]:26.26} | {s['title'][:52]:52.52} | {s['why'][:80]}")
    good = sum(1 for s in scored if s["score"] >= 60)
    print(f"\nScored {len(scored)}; score ≥{args.min}: {shown}; strong (≥60): {good}")

    track_top = getattr(args, "track_top", 0)
    if track_top > 0:
        added = 0
        for s in scored[:track_top]:
            if s["score"] >= getattr(args, "min", 0):
                contact = (s.get("found_emails") or "").split(",")[0].strip()
                app_id = track.add(conn, s.get("company", ""), s.get("title", ""), s.get("url", ""), contact, "new")
                added += 1
                print(f"  [+] Tracked #{app_id}: {s.get('company')} — {s.get('title')}")
        print(f"Added {added} top applications to tracker.")

    conn.close()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_p = report.write_csv(Path(args.out) / f"scored_{stamp}.csv", scored,
                             ["score", "why", "title", "company", "location", "remote",
                              "source", "found_emails", "url", "posted"])
    print(f"CSV: {csv_p}")

    if getattr(args, "notify_tg", False):
        token, chat_id = notify.resolve_telegram_credentials(args, prof)
        if not token or not chat_id:
            print("  [!] Telegram alert skipped: provide --tg-token/--tg-chat or set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID", file=sys.stderr)
        else:
            min_score = getattr(args, "tg_min_score", 60) or 60
            top_n = getattr(args, "tg_top", 5) or 5
            msg = notify.format_top_jobs_digest(scored, Path(args.profile).stem, top_n=top_n, min_score=min_score)
            if msg:
                ok, err = notify.send_telegram(token, chat_id, msg)
                if ok:
                    print(f"Telegram: digest sent to {chat_id}")
                else:
                    print(f"  [!] Telegram error: {err}", file=sys.stderr)
            else:
                print(f"Telegram: no jobs qualified for alert (score ≥ {min_score})")

    if not Path(args.profile).exists():
        score_mod.save_profile_template(args.profile)
        print(f"Profile not found; template created: {args.profile}. Edit it and rerun.")
    return 0


def cmd_track(args) -> int:
    """Трекер откликов: add / status / list / due."""
    conn = db.connect(Path(args.db))
    is_json = getattr(args, "json", False)
    if args.track_cmd == "add":
        app_id = track.add(conn, args.company, args.role, args.url, args.contact,
                           args.status, args.next_date, args.notes)
        if is_json:
            print(json.dumps({"ok": True, "id": app_id, "status": args.status, "company": args.company}, ensure_ascii=False))
        else:
            print(f"Application #{app_id} added: {args.company} — {args.role or '-'} [{args.status}]")
        return 0
    if args.track_cmd == "status":
        ok = track.update_status(conn, args.id, args.status, args.next_date, args.notes)
        if is_json:
            print(json.dumps({"ok": ok, "id": args.id, "status": args.status}, ensure_ascii=False))
        else:
            print(f"#{args.id}: {'updated' if ok else 'NOT found'} → {args.status}")
        return 0
    if is_json:
        rows = track.list_all(conn, getattr(args, "status", ""))
        due_rows = track.next_followups(conn)
        st = track.stats(conn)
        records = []
        for r in rows:
            records.append({
                "id": r["id"],
                "job_url": r["job_url"] or "",
                "company": r["company"] or "",
                "role": r["role"] or "",
                "contact": r["contact"] or "",
                "status": r["status"] or "new",
                "next_date": r["next_date"] or "",
                "notes": r["notes"] or "",
                "updated": r["updated"] or ""
            })
        due = []
        for r in due_rows:
            due.append({
                "id": r["id"],
                "company": r["company"] or "",
                "role": r["role"] or "",
                "contact": r["contact"] or "",
                "status": r["status"] or "",
                "next_date": r["next_date"] or "",
                "notes": r["notes"] or "",
                "updated": r["updated"] or ""
            })
        print(json.dumps({"stats": st, "records": records, "due": due, "total": len(records)}, ensure_ascii=False))
        return 0
    if args.track_cmd == "due":
        rows = track.next_followups(conn)
        if not rows:
            print("No active applications with a follow-up date.")
            return 0
        prof = None
        if getattr(args, "draft", False):
            prof = score_mod.load_profile(getattr(args, "profile", "profile.json"))
        for r in rows:
            print(f"  {r['next_date']}  #{r['id']} {r['company'][:24]:24.24} {r['role'][:34]:34.34} [{r['status']}] {r['contact']}")
            if getattr(args, "draft", False):
                job_mock = {
                    "company": r["company"],
                    "title": r["role"],
                    "url": r["job_url"],
                }
                raw_contact = (r["contact"] or "").strip()
                recipient_name = ""
                if "<" in raw_contact and ">" in raw_contact:
                    recipient_name = raw_contact.split("<")[0].strip()
                elif "@" not in raw_contact and raw_contact:
                    recipient_name = raw_contact

                prev_date = ""
                if r["updated"]:
                    try:
                        prev_date = r["updated"][:10]
                    except Exception:
                        pass

                extra = {}
                if recipient_name:
                    extra["recipient"] = recipient_name
                if prev_date:
                    extra["date"] = prev_date

                draft_text, leftover = outreach.draft_for_job(
                    job_mock,
                    prof or {},
                    name=getattr(args, "name", ""),
                    contacts=getattr(args, "contacts", ""),
                    lang=getattr(args, "lang", "en"),
                    kind="follow",
                    recipient=recipient_name,
                    extra=extra,
                )
                print("\n" + "-" * 50)
                print(f"Follow-up draft for #{r['id']} ({r['company']}):")
                print("-" * 50)
                print(draft_text.strip())
                if leftover:
                    print(f"  [!] Unfilled placeholders: {', '.join(sorted(leftover))}")
                print("-" * 50 + "\n")
        return 0
    # list
    rows = track.list_all(conn, args.status)
    if not rows:
        print("No applications. Add one: python jobfind.py track add --company ACME --role 'Python Dev'")
        return 0
    st = track.stats(conn)
    print(" ".join(f"{k}:{v}" for k, v in st.items() if v))
    print()
    for r in rows:
        print(f"  #{r['id']:<4} [{r['status']:9.9}] {r['company'][:24]:24.24} {r['role'][:34]:34.34} "
              f"{r['contact'][:28]:28.28} next:{r['next_date'] or '-'}")
    print(f"\nTotal: {len(rows)}")
    return 0


def cmd_doctor(args) -> int:
    """Быстрый аудит рабочего окружения (<1s): зависимости, инструменты, сеть, БД."""
    import os
    import shutil
    import socket
    import sys
    import time

    # 1. Python
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 9)

    # 2. SQLite Database
    db_path = Path(getattr(args, "db", "jobfind.db"))
    jobs_cnt = comps_cnt = 0
    db_status = "new"
    if db_path.is_file():
        try:
            c = db.connect(db_path)
            jobs_cnt = c.execute("SELECT count(*) FROM jobs").fetchone()[0]
            comps_cnt = c.execute("SELECT count(*) FROM companies").fetchone()[0]
            db_status = "ok"
        except Exception:
            db_status = "error"

    # 3. Internet & DoH (Cloudflare / Google)
    t0 = time.time()
    cf_ok = False
    try:
        r = net.get("https://cloudflare-dns.com/dns-query", {"name": "cloudflare.com", "type": "A"},
                    retries=0, extra_headers={"Accept": "application/dns-json"})
        cf_ok = r.status == 200 and isinstance(r.json(), dict) and r.json().get("Status") == 0
    except Exception:
        pass
    google_ok = False
    try:
        r2 = net.get("https://dns.google/resolve", {"name": "google.com", "type": "A"}, retries=0)
        google_ok = r2.status == 200 and isinstance(r2.json(), dict) and r2.json().get("Status") == 0
    except Exception:
        pass
    elapsed_ms = int((time.time() - t0) * 1000)
    doh_info = []
    if cf_ok: doh_info.append("Cloudflare DoH")
    if google_ok: doh_info.append("Google DoH")

    # 4. Chrome / Chromium
    chrome_path = shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome_path and sys.platform == "win32":
        for cp in [
            Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")) / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
        ]:
            if cp.is_file():
                chrome_path = str(cp)
                break

    # 5. Node.js
    node_path = shutil.which("node")

    # 6. Gitleaks
    local_gl = Path("third_party/gitleaks/gitleaks.exe") if sys.platform == "win32" else Path("third_party/gitleaks/gitleaks")
    gl_path = str(local_gl) if local_gl.is_file() else shutil.which("gitleaks")

    # 7. Xray Core
    local_xray = Path("third_party/xray/xray.exe") if sys.platform == "win32" else Path("third_party/xray/xray")
    xray_path = os.environ.get("JOBFIND_XRAY") or (str(local_xray) if local_xray.is_file() else shutil.which("xray"))

    # 8. Tor
    local_tor = Path("third_party/tor/tor.exe") if sys.platform == "win32" else Path("third_party/tor/tor")
    tor_bin = str(local_tor) if local_tor.is_file() else shutil.which("tor")
    tor_running = False
    for port in (9050, 9150):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                tor_running = port
                s.close()
                break
            s.close()
        except Exception:
            pass

    # 9. SpiderFoot
    sf_dir = Path("third_party/spiderfoot")
    sf_ok = sf_dir.is_dir() and (sf_dir / "sf.py").is_file()

    if getattr(args, "json", False):
        res = {
            "status": "ready" if (py_ok and (cf_ok or google_ok)) else "warning",
            "python": {"status": "ok" if py_ok else "warn", "version": py_ver, "path": sys.executable},
            "database": {"status": db_status, "path": str(db_path), "jobs": jobs_cnt, "companies": comps_cnt},
            "doh": {"status": "ok" if (cf_ok or google_ok) else "fail", "providers": doh_info, "latency_ms": elapsed_ms},
            "chrome": {"status": "ok" if chrome_path else "warn", "path": chrome_path or None},
            "node": {"status": "ok" if node_path else "warn", "path": node_path or None},
            "gitleaks": {"status": "ok" if gl_path else "info", "path": gl_path or None},
            "xray": {"status": "ok" if xray_path else "info", "path": xray_path or None},
            "tor": {"status": "ok" if tor_running else "inactive", "socks_port": tor_running or None, "path": tor_bin or None},
            "spiderfoot": {"status": "ok" if sf_ok else "info", "path": str(sf_dir / "sf.py") if sf_ok else None},
        }
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    print("================================================================================")
    print("                      JobFind / OSINT Environment Doctor                        ")
    print("================================================================================")
    print(f"  [{'OK' if py_ok else 'WARN':4}] Python runtime         : {py_ver} ({sys.executable})")
    if db_status == "ok":
        print(f"  [OK  ] SQLite database        : {db_path} ({jobs_cnt} jobs, {comps_cnt} companies)")
    elif db_status == "error":
        print(f"  [WARN] SQLite database        : {db_path} (database read error)")
    else:
        print(f"  [INFO] SQLite database        : {db_path} (will be created automatically on scan)")

    if cf_ok or google_ok:
        print(f"  [OK  ] Internet & DNS (DoH)   : {', '.join(doh_info)} ({elapsed_ms}ms)")
    else:
        print(f"  [FAIL] Internet & DNS (DoH)   : No response from DoH resolvers ({elapsed_ms}ms)")

    if chrome_path:
        print(f"  [OK  ] Google Chrome / Engine : {chrome_path}")
    else:
        print(f"  [WARN] Google Chrome / Engine : Not found (optional, used for dynamic crawling)")

    if node_path:
        print(f"  [OK  ] Node.js runtime        : {node_path}")
    else:
        print(f"  [WARN] Node.js runtime        : Not found in PATH (required for SingleFile/Waymore)")

    if gl_path:
        print(f"  [OK  ] Gitleaks (Secret audit): {gl_path}")
    else:
        print(f"  [INFO] Gitleaks (Secret audit): Not found (optional)")

    if xray_path:
        print(f"  [OK  ] Xray (Apex Proxy Core) : {xray_path}")
    else:
        print(f"  [INFO] Xray (Apex Proxy Core) : Not found (optional, used for Trojan/VLESS)")

    if tor_running:
        print(f"  [OK  ] Tor Service (SOCKS)    : Active on 127.0.0.1:{tor_running}")
    elif tor_bin:
        print(f"  [OK  ] Tor Binary             : {tor_bin} (daemon not running; run setup-tor.ps1)")
    else:
        print(f"  [INFO] Tor Service (SOCKS)    : Inactive (run setup-tor.ps1 to install)")

    if sf_ok:
        print(f"  [OK  ] SpiderFoot OSINT Suite : {sf_dir / 'sf.py'}")
    else:
        print(f"  [INFO] SpiderFoot OSINT Suite : Not installed in third_party (optional)")

    print("================================================================================")
    print("Environment audit completed. System ready for job search & OSINT operations.")
    return 0



def cmd_draft(args) -> int:
    """Черновик письма по вакансии из БД или по компании/роли."""
    is_json = getattr(args, "json", False)
    conn = db.connect(Path(args.db))
    job = None
    if getattr(args, "id", 0):
        row = conn.execute(
            "SELECT url, title, company, location, source, remote, description, posted, found_emails "
            "FROM jobs WHERE id=?", (args.id,)).fetchone()
        if row:
            job = {"url": row[0], "title": row[1], "company": row[2], "location": row[3], "source": row[4],
                   "remote": bool(row[5]), "description": row[6], "posted": row[7], "found_emails": row[8]}
    if not job:
        company = getattr(args, "company", "").strip()
        role = getattr(args, "role", "").strip()
        if not company and not role:
            if is_json:
                print(json.dumps({"ok": False, "error": "Job not found or company/role missing"}, ensure_ascii=False))
            else:
                print(f"Job id={getattr(args, 'id', 0)} not found. Specify --company and --role to draft directly.")
            return 1
        job = {
            "url": getattr(args, "url", ""),
            "title": role or "Candidate opening",
            "company": company or "Target Company",
            "location": "",
            "source": "Outreach",
            "remote": True,
            "description": "",
            "posted": "",
            "found_emails": getattr(args, "to", "")
        }
    prof = score_mod.load_profile(args.profile)
    text, leftover = outreach.draft_for_job(job, prof, args.name, args.contacts, args.lang, args.kind,
                                            getattr(args, "recipient", ""))
    if args.to:
        text = text.replace("[EMAIL]", args.to)
    if is_json:
        print(json.dumps({
            "ok": True,
            "draft": text,
            "leftover": list(sorted(leftover)),
            "emails": job.get("found_emails", "") or getattr(args, "to", ""),
            "company": job.get("company", ""),
            "role": job.get("title", "")
        }, ensure_ascii=False))
        return 0
    print(text)
    if leftover:
        print(f"\n[!] Unfilled placeholders: {', '.join(sorted(leftover))}; fill them manually.", file=sys.stderr)
    if job.get("found_emails"):
        print(f"\nContact emails found in the posting: {job['found_emails']}", file=sys.stderr)
    if not args.out:
        return 0
    p = Path(args.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text + "\n", encoding="utf-8")
    print(f"\nSaved: {p}", file=sys.stderr)
    return 0


def cmd_companies(args) -> int:
    conn = db.connect(Path(args.db))
    rows = conn.execute("SELECT name, source, first_seen FROM companies ORDER BY name").fetchall()
    for name, src, ts in rows:
        print(f"{name:40.40}  {src:24.24}  {ts}")
    print(f"\nTotal: {len(rows)} companies. Database: {args.db}")
    return 0


def cmd_contacts(args) -> int:
    conn = db.connect(Path(args.db))
    if args.hypotheses:
        comps = [r[0] for r in conn.execute("SELECT name FROM companies ORDER BY name").fetchall()]
        print(f"Generating guesses for {len(comps)} companies (domain DNS checks)...")
        hyp = []
        for c in comps:
            try:
                hyp.extend(contacts_mod.contact_hypotheses(c))
            except Exception:
                pass
        csv_p = report.write_csv(Path(args.out) / "contact_hypotheses.csv", hyp,
                                 ["email", "company", "kind", "verified", "domain_age"])
        alive = len({h["company"] for h in hyp if h.get("verified")})
        print(f"Active domains: {alive} of {len(comps)}; guesses: {len(hyp)}")
        print(f"CSV: {csv_p}")
        print("Guesses are not verified addresses. Review them manually; do not use them for bulk mail.")
    rows = conn.execute(
        "SELECT email, company, kind, source, job_url FROM contacts ORDER BY company, email"
    ).fetchall()
    if rows:
        print(f"\n{'Email':38.38} {'Company':24.24} {'Type':10.10} Source")
        for e, c, k, s, _u in rows:
            print(f"{e:38.38} {c or '-':24.24} {k:10.10} {s}")
        print(f"\nTotal: {len(rows)}")
    else:
        print("No contacts in the database yet; run scan.")
    return 0


def _company_site_candidates(company: str) -> tuple[list[dict], list[str]]:
    rows, errors, _ = osint.search(company, ["bing", "duckduckgo", "web"])
    name = "".join(char for char in company.casefold() if char.isalnum())
    if not name:
        return [], errors
    candidates = {}
    for row in rows:
        host = (urlsplit(row["url"]).hostname or "").lower().removeprefix("www.")
        host_name = "".join(char for char in host.split(".")[0] if char.isalnum())
        if (not osint_contacts.DOMAIN_RE.fullmatch(host) or
                name not in host_name or
                host.endswith(("github.com", "linkedin.com", "facebook.com", "wikipedia.org"))):
            continue
        candidates.setdefault(host, {"domain": host, "title": row["title"],
                                     "url": row["url"], "source": row["source"]})
        if len(candidates) >= 8:
            break
    return list(candidates.values()), errors


def cmd_contact_search(args) -> int:
    """Find a company site or collect emails published on a selected HTTPS host."""
    try:
        company = args.company.strip()
        domain = args.domain.strip().lower()
        if not company:
            raise ValueError("Enter a company name or domain")
        if not domain and osint_contacts.DOMAIN_RE.fullmatch(company):
            domain = company.lower()
        if not domain:
            candidates, errors = _company_site_candidates(company)
            print(json.dumps({"rows": [], "counts": [0, 0], "mail": {},
                              "candidates": candidates, "errors": errors,
                              "needs_domain": True}, ensure_ascii=False))
            return 0
        rows = osint_contacts.find_public_emails(company, domain, args.name)
        mail = domains.mail_config(domain)
        conn = db.connect(Path(args.db))
        counts = db.save_people_contacts(conn, rows)
        db.log_run(conn, "contact-search", {"company": company, "domain": domain,
                                            "contacts": len(rows)})
        conn.close()
        evidence_graph.accumulate({"query": company, "observed_at": db.now_iso(), "sections": {"emails": [
            {**row, "url": url} for row in rows if row.get("verification") == "published"
            for url in row.get("evidence", [])]}}, Path(args.out))
        print(json.dumps({"rows": rows, "counts": counts, "mail": mail,
                          "candidates": [], "errors": [], "needs_domain": False}, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"Could not find contacts: {exc}", file=sys.stderr)
        return 1


def cmd_email_send(_args) -> int:
    """Отправляет одно письмо только на опубликованный адрес с сохранённым источником."""
    payload = {}
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Expected one email's settings as JSON")
        recipient = str(payload.get("recipient", "")).strip().lower()
        subject = str(payload.get("subject", ""))
        company = str(payload.get("company", ""))
        conn = db.connect(Path(_args.db))
        row = conn.execute("SELECT verification, evidence FROM people_contacts WHERE email=?", (recipient,)).fetchone()
        evidence = json.loads(row["evidence"] or "[]") if row else []
        if not row or row["verification"] != "published" or not evidence:
            raise ValueError("Sending is allowed only to a published address with a source URL")
        mailer.send_one(recipient, subject, str(payload.get("body", "")),
                        str(payload.get("sender", "")), str(payload.get("sender_name", "")),
                        str(payload.get("smtp_user", "")), str(payload.get("password", "")),
                        str(payload.get("host", "")), int(payload.get("port", 0)),
                        str(payload.get("security", "")))
        db.log_email_send(conn, recipient, company, subject, "sent")
        conn.close()
        print("Email accepted by the SMTP server.")
        return 0
    except Exception as exc:
        try:
            if payload:
                conn = db.connect(Path(_args.db))
                db.log_email_send(conn, str(payload.get("recipient", "")),
                                  str(payload.get("company", "")),
                                  str(payload.get("subject", "")), "failed", str(exc))
                conn.close()
        except Exception:
            pass
        print(f"Email was not sent: {exc}", file=sys.stderr)
        return 1


def cmd_projects(args) -> int:
    """Ищет открытые GitHub-проекты по навыкам или ключевым словам."""
    try:
        found = projects_mod.search(args.kw, args.limit)
    except Exception as exc:
        print(f"Could not fetch projects: {exc}", file=sys.stderr)
        return 1
    conn = db.connect(Path(args.db))
    new, updated = db.save_projects(conn, found)
    db.log_run(conn, "projects", {"query": args.kw, "count": len(found)})
    conn.close()
    shared = evidence_graph.accumulate(evidence_graph.from_search({"query": args.kw, "projects": found}), Path(args.out))
    print(f"GitHub projects found: {len(found)}; new in database: {new}; updated: {updated}")
    print(f"Diagram: {shared['graph_path']}")
    print(f"Database: {args.db}")
    return 0


def cmd_2gis(args) -> int:
    try:
        if not 1 <= args.limit <= 500:
            raise ValueError("Limit must be between 1 and 500.")
        if not 0 <= args.delay_ms <= 5000:
            raise ValueError("Click delay must be between 0 and 5000 ms.")
        url, city = (two_gis.validate_url(args.url), args.city) if args.url else two_gis.search_url(args.query, args.city)
        query = (args.query or "").strip() or url
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        directory = Path(args.out) / "2gis"
        raw_path = directory / f"2gis_raw_{stamp}.json"
        timeout = max(180, min(900, 60 + args.limit * 25))
        rows = two_gis.collect(url, raw_path, args.limit, args.delay_ms, timeout=timeout)
        conn = db.connect(Path(args.db))
        new, updated = db.save_directory_businesses(conn, query, rows)
        email_by_address = {}
        for row in rows:
            for email in row["emails"]:
                contact = email_by_address.setdefault(email, {"email": email, "company": row["name"],
                    "domain": email.rsplit("@", 1)[1], "verification": "published", "evidence": [],
                    "source": "2GIS public listing"})
                contact["evidence"].append(row["url"])
        fresh_emails = []
        for email, contact in email_by_address.items():
            existing = conn.execute("SELECT evidence, source FROM people_contacts WHERE email=?", (email,)).fetchone()
            if existing is None:
                fresh_emails.append(contact)
                continue
            evidence = list(dict.fromkeys(json.loads(existing["evidence"] or "[]") + contact["evidence"]))
            source = existing["source"] or ""
            if "2GIS" not in source:
                source = f"{source}; 2GIS public listing".strip("; ")
            conn.execute("UPDATE people_contacts SET verification='published', evidence=?, source=?, last_seen=? WHERE email=?",
                         (json.dumps(evidence, ensure_ascii=False), source, db.now_iso(), email))
        conn.commit()
        email_new, _ = db.save_people_contacts(conn, fresh_emails)
        db.log_run(conn, "2gis-search", {"query": query, "city": city, "count": len(rows), "url": url})
        conn.close()
        shared = evidence_graph.accumulate({"query": query, "observed_at": db.now_iso(), "sections": {"businesses": rows}}, Path(args.out))
        print(json.dumps({"query": query, "city": city, "url": url, "rows": rows,
                          "new": new, "updated": updated, "new_emails": email_new,
                          "raw": str(raw_path.resolve()), "json": "", "csv": "", "xlsx": "", **shared}, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"2GIS search failed: {exc}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    raw_argv = sys.argv[1:] if argv is None else list(argv)
    global_flags = {"--db", "--network", "--network-state"}
    first_cmd = ""
    for index, arg in enumerate(raw_argv):
        if arg.startswith("-") or (index and raw_argv[index - 1] in global_flags | {"--out"}):
            continue
        first_cmd = arg
        break
    if first_cmd != "draft":
        global_flags.add("--out")
    hoisted, rest = [], []
    i = 0
    while i < len(raw_argv):
        arg = raw_argv[i]
        if arg in global_flags and i + 1 < len(raw_argv):
            hoisted.extend([arg, raw_argv[i + 1]])
            i += 2
        else:
            rest.append(arg)
            i += 1
    argv = hoisted + rest

    ap = argparse.ArgumentParser(prog="jobfind", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="jobfind.db", help="SQLite database path (default: jobfind.db)")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="report directory (default: jobfind_out)")
    ap.add_argument("--network", choices=("saved", "direct", "apex"), default="saved",
                    help="use saved Apex route, force direct access, or require Apex")
    ap.add_argument("--network-state", default="", help="Apex state path (default: next to --db/network)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("network", help="integrated Apex subscriptions and Xray routing")
    p.add_argument("action", choices=("status", "install", "refresh", "check", "enable", "disable"))
    p.add_argument("--group", choices=tuple(apex_network.FEEDS), default="full")
    p.add_argument("--country", default="", help="two-letter country code")
    p.add_argument("--subscription", action="append", help="custom public HTTPS subscription; repeatable")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--node", default="", help="node id to check or enable")
    p.add_argument("--test-url", default="", help="public HTTPS target instead of standard probes")
    p.set_defaults(func=cmd_network)

    p = sub.add_parser("network-ui", help="open Apex settings without rebuilding the existing UI executable")
    p.set_defaults(func=cmd_network_ui)

    p = sub.add_parser("archive-search", help="passive Wayback/Common Crawl/waymore URLs and selected historical responses")
    p.set_defaults(func=cmd_archive_search)
    p.add_argument("--domain", required=True)
    p.add_argument("--providers", default="wayback,commoncrawl,otx,urlscan")
    p.add_argument("--no-subdomains", action="store_true")
    p.add_argument("--from", dest="from_date", default="")
    p.add_argument("--to", dest="to_date", default="")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--captures", type=int, default=0, help="download up to twenty archived text responses")
    p.add_argument("--capture-url", action="append", default=[], help="select exact snapshot URLs from the imported/collected records")
    p.add_argument("--category", default="", help="comma-separated api,admin,debug,backup,config,javascript,parameters,other")
    p.add_argument("--status-codes", default="", help="match historical HTTP codes; unknown codes excluded")
    p.add_argument("--mime", default="", help="historical MIME prefix; unknown types excluded")
    p.add_argument("--collapse-parameters", action="store_true")
    p.add_argument("--import", dest="import_file", action="append", default=[], help="import waymore/gau/waybackurls URL lines or CDX JSON")
    p.add_argument("--time-budget", type=int, default=120)

    p = sub.add_parser("wireless-ui", help="integrated WireTapper telemetry and wireless workspace")
    p.set_defaults(func=cmd_wireless_ui)
    p = sub.add_parser("wireless", help="WireTapper telemetry, indexed area data and explicit local discovery")
    p.set_defaults(func=cmd_wireless)
    p.add_argument("--file", action="append", default=[], help="selected telemetry file; repeat for multiple files")
    p.add_argument("--mapping", default="", help="JSON mapping of lat/lon/ssid/bssid/signal/type/timestamp to column names")
    p.add_argument("--providers", default="", help="comma-separated wigle,opencellid,shodan,censys")
    p.add_argument("--latitude", type=float)
    p.add_argument("--longitude", type=float)
    p.add_argument("--radius", type=float, default=1.0)
    p.add_argument("--wifi", action="store_true", help="explicit Windows WLAN metadata discovery")
    p.add_argument("--bluetooth", action="store_true", help="explicit BLE advertisement discovery")
    p.add_argument("--sdr", action="store_true", help="check connected SDR USB hardware; no RF signal decoding")
    p.add_argument("--seconds", type=int, default=8)
    p.add_argument("--query", default="Wireless survey", help="label for the saved evidence dossier")

    p = sub.add_parser("local-audit", help="explicit local source audit with redacted Gitleaks results")
    p.set_defaults(func=cmd_local_audit)
    audit_input = p.add_mutually_exclusive_group(required=True)
    audit_input.add_argument("--path", help="local source directory; no remote target scanning")
    audit_input.add_argument("--install", action="store_true", help="install checksum-verified official Windows Gitleaks release")
    p.add_argument("--history", action="store_true", help="scan Git history instead of working files")
    p.add_argument("--timeout", type=int, default=120)

    p = sub.add_parser("phone", help="PhoneInfoga scanners with a saved evidence dossier")
    p.set_defaults(func=cmd_phone)
    p.add_argument("--number", required=True, help="International number, e.g. +12025550123")
    p.add_argument("--local-only", action="store_true", help="Number plan and generated queries without external requests")

    p = sub.add_parser("dossier", help="one public-evidence dossier as JSON and CSV")
    p.set_defaults(func=cmd_dossier)
    p.add_argument("--query", required=True, help="surname, person name, username, domain, or website URL")
    p.add_argument("--kind", choices=dossier.KINDS, default="auto")
    p.add_argument("--scope", choices=dossier.SCOPES, default="full")
    p.add_argument("--coverage", choices=("quick", "deep"), default="quick")
    p.add_argument("--capture-pages", type=int, default=0,
                   help="page captures: 0 selects 12 quick/40 deep; -1 disables; max 100")
    p.add_argument("--city", default="", help="2GIS city code or name; enables business collection")
    p.add_argument("--business-query", default="", help="2GIS category/query; defaults to research query")
    p.add_argument("--2gis-limit", dest="two_gis_limit", type=int, default=25)
    p.add_argument("--map-location", default="", help="city/place to constrain OpenStreetMap results")
    p.add_argument("--metadata-file", action="append", default=[], help="local file to inspect; may be repeated")
    p.add_argument("--wireless-file", action="append", default=[], help="selected WireTapper/field telemetry; import as candidate evidence")
    p.add_argument("--browser-file", action="append", default=[], help="selected Chrome crawler FindAll JSON export; repeat for up to 10 files")
    p.add_argument("--no-archives", action="store_true", help="disable passive historical URL collection")
    p.add_argument("--archive-from", default="", help="archive start date YYYY, YYYYMM or YYYYMMDD")
    p.add_argument("--archive-to", default="", help="archive end date YYYY, YYYYMM or YYYYMMDD")
    p.add_argument("--archive-providers", default="wayback,commoncrawl,otx,urlscan")
    p.add_argument("--no-extra-tools", action="store_true", help="skip additional installed collectors")
    p.add_argument("--no-careers", action="store_true", help="skip bounded company careers/ATS discovery")
    p.add_argument("--no-domain-card", action="store_true", help="skip additional structured DNS/registration sources")
    p.add_argument("--vault", default="", help="optional local Obsidian vault; creates a new versioned export")
    p.add_argument("--onion", action="store_true", help="include OnionSearch through local Tor in full research")
    p.add_argument("--no-spiderfoot", action="store_true",
                   help="skip the passive SpiderFoot scan that otherwise runs inside the dossier")
    p.add_argument("--spiderfoot-timeout", type=int, default=120,
                   help="seconds before the dossier scan keeps its events and stops (0 waits until finished)")
    p.add_argument("--progress-json", action="store_true", help="emit progress events on stderr")
    p.add_argument("--ai", action="store_true", help="analyze cited evidence with a configured AI provider")
    p.add_argument("--ai-investigate", action="store_true", help="let AI select bounded follow-up tools, then summarize evidence")
    p.add_argument("--ai-provider", default="", help="AI provider override")
    p.add_argument("--ai-model", default="", help="AI model override")

    p = sub.add_parser("dossier-analyze", help="analyze an existing dossier without searching again")
    p.set_defaults(func=cmd_dossier_analyze)
    p.add_argument("--path", required=True, help="path to a saved dossier.json")
    p.add_argument("--ai-provider", default="", help="AI provider override")
    p.add_argument("--ai-model", default="", help="AI model override")

    p = sub.add_parser("dossier-graph", help="build an interactive evidence graph and BloodHound OpenGraph export")
    p.set_defaults(func=cmd_dossier_graph)
    p.add_argument("--path", required=True, help="path to a saved dossier.json inside the results folder")

    p = sub.add_parser("dossier-quality", help="inspect evidence/citations offline or run synthetic regression cases")
    p.set_defaults(func=cmd_dossier_quality)
    quality_input = p.add_mutually_exclusive_group(required=True)
    quality_input.add_argument("--path", help="path to dossier.json inside the results folder; does not modify it")
    quality_input.add_argument("--benchmark", action="store_true", help="run fictional offline evaluation cases")

    p = sub.add_parser("dossier-export", help="refresh dossier timeline and Markdown or export versioned Obsidian notes")
    p.set_defaults(func=cmd_dossier_export)
    p.add_argument("--path", required=True, help="saved dossier.json inside the results folder")
    p.add_argument("--vault", default="", help="optional vault directory; existing user notes are preserved")

    p = sub.add_parser("ai-check", help="check the configured AI provider without sending dossier data")
    p.set_defaults(func=cmd_ai_check)
    p.add_argument("--provider", default="", help="AI provider override")
    p.add_argument("--model", default="", help="AI model override")

    p = sub.add_parser("ai-models", help="list models currently reported by an AI provider")
    p.set_defaults(func=cmd_ai_models)
    p.add_argument("--provider", default="", help="AI provider override")

    p = sub.add_parser("scan", help="collect and save jobs from sources")
    p.set_defaults(func=cmd_scan)
    p.add_argument("--sources", default="simplify,jobicy,remoteok,hn",
                   help="comma-separated boards: simplify,jobicy,remoteok,hn[,remotive,arbeitnow]")
    p.add_argument("--ats", nargs="*", default=[], metavar="TYPE:TENANT",
                   help="ATS boards: greenhouse:stripe ashby:ramp workable:epignosis lever:blackshark")
    p.add_argument("--kw", default="", help="keywords (remotive/jobicy/remoteok)")
    p.add_argument("--per-source", type=int, default=50, help="maximum jobs per board (default 50)")
    p.add_argument("--notify-tg", action="store_true", help="score and send top jobs digest to Telegram after scan")
    p.add_argument("--profile", default="profile.json", help="profile JSON path for scoring (default: profile.json)")
    p.add_argument("--tg-token", default="", help="Telegram Bot API token")
    p.add_argument("--tg-chat", default="", help="Telegram chat/channel ID")
    p.add_argument("--tg-min-score", type=int, default=60, help="min score for Telegram alert (default: 60)")
    p.add_argument("--tg-top", type=int, default=5, help="max top jobs in Telegram alert (default: 5)")

    p = sub.add_parser("search", help="search jobs, projects, and published contacts together")
    p.set_defaults(func=cmd_search)
    p.add_argument("--kw", required=True, help="profession, specialty, or skills")
    p.add_argument("--sources", default="hh,jobicy,remotive,arbeitnow,remoteok",
                   help="comma-separated job sources")
    p.add_argument("--per-source", type=int, default=50, help="maximum jobs per source")
    p.add_argument("--project-limit", type=int, default=12, help="number of GitHub projects to return")

    p = sub.add_parser("osint-search", help="search public sources and save provenance")
    p.set_defaults(func=cmd_osint_search)
    p.add_argument("--query", required=True, help="topic, organization, or place")
    p.add_argument("--mode", choices=("full", "email"), default="full",
                   help="full search or published emails only")
    p.add_argument("--sources", default=",".join(osint.SOURCES),
                   help=",".join(osint.SOURCES))
    p.add_argument("--domain", default="", help="organization domain for DNS/RDAP checks")
    p.add_argument("--username", default="", help="username for GitHub Email Hunter, Maigret, and TikTok")
    p.add_argument("--onion", action="store_true", help="enable OnionSearch through local Tor")

    p = sub.add_parser("osint-history", help="saved OSINT search results")
    p.set_defaults(func=cmd_osint_history)
    p.add_argument("--query", required=True, help="exact query from a previous search")

    p = sub.add_parser('browser-research', help='render public pages, extract records and save a cited dossier')
    p.set_defaults(func=cmd_browser_research)
    p.add_argument('--url', required=True)
    p.add_argument('--question', default='')
    p.add_argument('--selector', default='', help='optional Scrapling element CSS selector; heuristic relocation after layout changes')
    p.add_argument('--pages', type=int, default=3)
    p.add_argument('--items', type=int, default=50)
    p.add_argument('--ai', action='store_true')
    p.add_argument('--ai-provider', default='')
    p.add_argument('--ai-model', default='')

    p = sub.add_parser('library', help='local hybrid RAG over saved dossiers and page-addressable PDFs')
    p.set_defaults(func=cmd_library)
    p.add_argument('--action', choices=('status', 'index', 'pdf', 'search', 'ask', 'setup'), default='status')
    p.add_argument('--dossier-root', action='append', default=None)
    p.add_argument('--file', action='append', default=[])
    p.add_argument('--source-url', default='')
    p.add_argument('--languages', default='eng+rus')
    p.add_argument('--password-stdin', action='store_true')
    p.add_argument('--question', default='')
    p.add_argument('--ai-provider', default='')
    p.add_argument('--ai-model', default='')

    p = sub.add_parser("statistics", help="offline sample statistics from CSV/TSV/JSON/JSONL or a saved dossier")
    p.set_defaults(func=cmd_statistics)
    p.add_argument("--path", default="")
    p.add_argument("--install-model", action="store_true", help="download the pinned public BERT model once; never uploads dataset text")
    p.add_argument("--radius", type=float, default=5.0, help="DBSCAN/KDE radius in kilometres, 0.1–100")
    p.add_argument("--period", type=int, default=24, help="STL seasonal period in activity bins, 2–168")

    p = sub.add_parser("workspace-graph", help="merge saved research into the common diagram without network access")
    p.set_defaults(func=cmd_workspace_graph)
    p.add_argument("--export", action="store_true", help="explicitly export the accumulated graph as JSON and CSV")

    from jf import flowsint
    p = sub.add_parser("browser-import", help="import an explicitly exported Chrome crawler page into a new dossier (offline)")
    p.set_defaults(func=cmd_browser_import)
    p.add_argument("--file", required=True, help="FindAll JSON exported by the bundled Chrome crawler extension")
    p.add_argument("--query", default="", help="research question; defaults to the page title")

    p = sub.add_parser("enrich", help="typed node enrichment and reusable investigation flows (Flowsint adaptation)")
    p.set_defaults(func=cmd_enrichment)
    selection = p.add_mutually_exclusive_group()
    selection.add_argument("--flow", choices=tuple(flowsint.FLOWS), default="domain-network")
    selection.add_argument("--enricher", choices=tuple(flowsint.ENRICHERS))
    selection.add_argument("--flow-file", default="", help="explicitly selected FindAll JSON flow, not executable code")
    p.add_argument("--value", default="", help="domain, IP, ASN, CIDR, HTTPS URL or email, matching the chosen input type")
    p.add_argument("--catalog", action="store_true")
    p.add_argument("--save-flow", default="", help="save the selected definition to a new JSON file without running")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--max-tasks", type=int, default=12)
    p.add_argument("--progress-json", action="store_true")

    p = sub.add_parser("osint-page", help="extract published emails from one public page")
    p.set_defaults(func=cmd_osint_page)
    p.add_argument("--query", required=True, help="research query")
    p.add_argument("--url", required=True, help="HTTPS page URL")

    p = sub.add_parser("tools-catalog", help="search the full OSINT Arsenal catalog")
    p.set_defaults(func=cmd_tools_catalog)
    p.add_argument("--query", default="", help="search names, descriptions, and categories")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)

    p = sub.add_parser("web-check", help="run local Web-Check on a public domain")
    p.set_defaults(func=cmd_web_check)
    p.add_argument("--domain", required=True)

    p = sub.add_parser("domain-recon", help="passive domain OSINT: DNS, subdomains, Shodan, Censys, ZoomEye, and web")
    p.set_defaults(func=cmd_domain_recon)
    p.add_argument("--domain", required=True)
    p.add_argument("--max-hosts", type=int, default=100, help="number of names to resolve in DNS (up to 1000)")
    p.add_argument("--max-ips", type=int, default=10, help="number of IPs to check in InternetDB/Shodan/Censys (up to 50)")

    p = sub.add_parser("maigret", help="find public profiles by username with Maigret")
    p.set_defaults(func=cmd_maigret)
    p.add_argument("--username", required=True)
    p.add_argument("--top-sites", type=int, default=100)

    p = sub.add_parser("github-email", help="find a published GitHub commit author email")
    p.set_defaults(func=cmd_github_email)
    p.add_argument("--username", required=True)
    p.add_argument("--max-repos", type=int, default=10)
    p.add_argument("--max-commit-pages", type=int, default=2)

    p = sub.add_parser("tiktok-profile", help="public TikTok profile metadata")
    p.set_defaults(func=cmd_tiktok_profile)
    p.add_argument("--username", required=True)

    p = sub.add_parser("spiderfoot-scan", help="run SpiderFoot and save events in the FindAll database")
    p.set_defaults(func=cmd_spiderfoot)
    p.add_argument("--target", required=True, help="domain, IP, email, phone, username, or person name")
    p.add_argument("--kind", default="auto",
                   choices=("auto", "person", "username", "domain", "email", "ip", "phone", "asn", "bitcoin"))
    p.add_argument("--use-case", default="passive", choices=tuple(spiderfoot_scan.USE_CASES),
                   help="passive is the default; footprint, investigate, or all enable more modules")
    p.add_argument("--modules", default="", help="comma-separated SpiderFoot module names instead of a use case")
    p.add_argument("--timeout", type=int, default=180, help="seconds before the scan keeps its events and stops; 0 waits")

    p = sub.add_parser("onion-search", help="search onion indexes through local Tor and OnionSearch")
    p.set_defaults(func=cmd_onion_search)
    p.add_argument("--query", required=True)
    p.add_argument("--engines", default="onionland")

    p = sub.add_parser("report", help="HTML/Markdown/JSON report from database")
    p.set_defaults(func=cmd_report)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--enrich", action="store_true", help="extract emails from descriptions again")
    p.add_argument("--profile", default="profile.json", help="profile JSON path for skill match highlighting")
    p.add_argument("--format", default="html", choices=["html", "md", "markdown", "json"],
                   help="report format: html (default), md (markdown), json")

    p = sub.add_parser("companies", help="list companies in the database")
    p.set_defaults(func=cmd_companies)
    p = sub.add_parser("domains", help="check company domains (MX/mail/age)")
    p.add_argument("--limit", type=int, default=0, help="check the first N companies (0 = all)")
    p.set_defaults(func=cmd_domains)

    p = sub.add_parser("score", help="score jobs in the database against a profile")
    p.add_argument("--profile", default="profile.json", help="JSON profile (creates a template if missing)")
    p.add_argument("--limit", type=int, default=400, help="number of recent jobs to score")
    p.add_argument("--min", type=int, default=0, help="show only scores ≥ N")
    p.add_argument("--top", type=int, default=20, help="number of rows to print (0 = all)")
    p.add_argument("--min-salary", type=int, default=0, help="filter out jobs below minimum salary (e.g. 4000)")
    p.add_argument("--grade", default="", choices=["", "intern", "junior", "middle", "senior", "lead", "head"],
                   help="filter by target level/grade (e.g. senior)")
    p.add_argument("--track-top", type=int, default=0,
                   help="automatically add top N scored jobs to application tracker")
    p.add_argument("--notify-tg", action="store_true", help="send digest of top matching jobs to Telegram")
    p.add_argument("--tg-token", default="", help="Telegram Bot API token")
    p.add_argument("--tg-chat", default="", help="Telegram chat/channel ID")
    p.add_argument("--tg-min-score", type=int, default=60, help="min score for Telegram alert (default: 60)")
    p.add_argument("--tg-top", type=int, default=5, help="max top jobs in Telegram alert (default: 5)")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("track", help="application tracker (add/status/list/due)")
    track_sub = p.add_subparsers(dest="track_cmd", required=True)
    pa = track_sub.add_parser("add")
    pa.add_argument("--company", required=True)
    pa.add_argument("--role", default="")
    pa.add_argument("--url", default="")
    pa.add_argument("--contact", default="")
    pa.add_argument("--status", default="new", choices=track.STATUSES)
    pa.add_argument("--next-date", dest="next_date", default="", help="next action date, YYYY-MM-DD")
    pa.add_argument("--notes", default="")
    pa.add_argument("--json", action="store_true", help="output JSON")
    pa.set_defaults(func=cmd_track)
    ps = track_sub.add_parser("status")
    ps.add_argument("--id", type=int, required=True)
    ps.add_argument("--status", required=True, choices=track.STATUSES)
    ps.add_argument("--next-date", dest="next_date", default=None)
    ps.add_argument("--notes", default=None)
    ps.add_argument("--json", action="store_true", help="output JSON")
    ps.set_defaults(func=cmd_track)
    pl = track_sub.add_parser("list")
    pl.add_argument("--status", default="", choices=list(track.STATUSES) + [""])
    pl.add_argument("--json", action="store_true", help="output JSON")
    pl.set_defaults(func=cmd_track)
    pdue = track_sub.add_parser("due", help="show applications with next_date due")
    pdue.add_argument("--draft", action="store_true", help="generate follow-up email drafts for due applications")
    pdue.add_argument("--lang", default="en", choices=["en", "ru"], help="language of follow-up draft (en/ru)")
    pdue.add_argument("--profile", default="profile.json", help="profile JSON path")
    pdue.add_argument("--name", default="", help="your signature name")
    pdue.add_argument("--contacts", default="", help="your contact details (email/telegram/link)")
    pdue.add_argument("--json", action="store_true", help="output JSON")
    pdue.set_defaults(func=cmd_track)

    p = sub.add_parser("doctor", help="diagnose environment, external tools, network, and database health")
    p.add_argument("--json", action="store_true", help="output audit results as JSON for CI/CD and scripts")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("draft", help="draft an email for a job in the database or by company/role")
    p.add_argument("--id", type=int, default=0, help="job id in the jobs table")
    p.add_argument("--company", default="", help="company name if not specifying --id")
    p.add_argument("--role", default="", help="role/vacancy title if not specifying --id")
    p.add_argument("--url", default="", help="job URL if not specifying --id")
    p.add_argument("--profile", default="profile.json")
    p.add_argument("--name", default="", help="your name")
    p.add_argument("--contacts", default="", help="your contact details (email/Telegram)")
    p.add_argument("--lang", default="en", choices=["en", "ru"])
    p.add_argument("--kind", default="apply", choices=["apply", "recruiter", "follow"],
                   help="apply = job application, recruiter = outreach without a job, follow = follow-up")
    p.add_argument("--recipient", default="", help="recipient name, if known")
    p.add_argument("--to", default="", help="recipient email (shown as a hint)")
    p.add_argument("--out", default="", help="save draft to a file")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.set_defaults(func=cmd_draft)
    p = sub.add_parser("contacts", help="contacts in the database")
    p.set_defaults(func=cmd_contacts)
    p.add_argument("--hypotheses", action="store_true",
                   help="add generated careers@/jobs@/hr@ guesses for manual review")

    p = sub.add_parser("contact-search", help="find published emails on a company site")
    p.add_argument("--company", required=True)
    p.add_argument("--domain", default="", help="optional: without it, candidate sites are found")
    p.add_argument("--name", default="", help="optional name for separately labeled guesses")
    p.set_defaults(func=cmd_contact_search)

    p = sub.add_parser("email-send", help="send one confirmed email from JSON on stdin")
    p.set_defaults(func=cmd_email_send)

    p = sub.add_parser("projects", help="find GitHub projects by interests or skills")
    p.add_argument("--kw", required=True, help="GitHub query, for example python security")
    p.add_argument("--limit", type=int, default=30, help="number of projects to save (1–100)")
    p.set_defaults(func=cmd_projects)

    p = sub.add_parser("2gis-search", help="parse 2GIS businesses, addresses, and published contacts")
    p.add_argument("--query", default="", help="business name or category")
    p.add_argument("--city", default="moscow", help="2GIS city name or code (default: moscow)")
    p.add_argument("--url", default="", help="optional direct 2GIS search, firm, or building URL")
    p.add_argument("--limit", type=int, default=25, help="maximum businesses (1–500; default: 25)")
    p.add_argument("--delay-ms", type=int, default=150, help="delay between listing clicks (0–5000 ms)")
    p.set_defaults(func=cmd_2gis)

    args = ap.parse_args(argv)
    network_commands = {"scan", "search", "projects", "dossier", "dossier-analyze", "ai-check", "ai-models",
                        "osint-search", "osint-page", "contact-search", "domains", "domain-recon",
                        "github-email", "maigret", "2gis-search", "tiktok-profile", "web-check",
                        "spiderfoot-scan", "wireless", "archive-search", "onion-search", "enrich", "phone", "library", "browser-research"}
    if args.cmd == 'library' and args.action != 'ask':
        return args.func(args)
    if args.cmd == "phone" and args.local_only:
        return args.func(args)
    if args.cmd == "enrich" and (args.catalog or args.save_flow):
        return args.func(args)
    if args.cmd not in network_commands:
        return args.func(args)
    path = Path(args.network_state) if args.network_state else Path(args.db).resolve().parent / "network" / "apex-state.json"
    try:
        with apex_network.route(path, args.network):
            return args.func(args)
    except (ValueError, OSError, RuntimeError) as exc:
        print(json.dumps({"error": f"Network: {exc}"}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
