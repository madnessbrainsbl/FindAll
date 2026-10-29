"""Offline checks of dossier structure, citation integrity and collection coverage.

These checks cannot establish truth, identify a person or score factual accuracy.
Diagnostics deliberately contain indices and codes, never source text or secrets.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from . import ai_agents


_SUCCESS = {"ok", "completed", "complete", "success", "observed"}
_GAPS = {"blocked", "timeout", "error", "failed", "unavailable", "unconfigured", "missing_key", "rate_limited", "partial", "limited"}
_PENDING = {"running", "attempted", "pending", "queued"}
_KNOWN = _SUCCESS | _GAPS | _PENDING | {"empty", "skipped", "disabled", "no_results", "no_records", "nxdomain"}
_IDENTITY_ASSERTION = re.compile(
    r"\b(?:confirmed identity|same person|belongs to|owned by|owns|owner of|verified owner)\b|"
    r"(?:личность подтверждена|тот же человек|принадлежит|владелец|владеет)", re.I)
_UNCERTAINTY = re.compile(
    r"\b(?:unverified|unconfirmed|uncertain|candidate|possible|possibly|may|might|not proven|not verified)\b|"
    r"(?:не подтвержд|кандидат|возможно|предполож|не установлен)", re.I)
LIMITATIONS = [
    "Citation matching checks text and attribution only; it does not verify a statement's meaning or truth.",
    "A shared name or username and a search match do not prove identity or ownership.",
    "AI receives a balanced sample of up to 80 items plus all source-linked PhoneInfoga and bounded Browser research records; collection coverage is not complete internet coverage.",
    "Blocked, empty and skipped sources cannot prove that information does not exist.",
    "No factual accuracy percentage is calculated; human review is needed for identity and disputed claims.",
    "Identity assertion warnings use lexical patterns and can miss paraphrases or require manual dismissal.",
]


def _normal(value: object) -> str:
    return re.sub(r"\s+", " ", value.strip()) if isinstance(value, str) else ""


def _rows(value: object) -> list:
    return value if isinstance(value, list) else []


def evaluate(dossier: object) -> dict:
    """Return compact deterministic diagnostics, without calls, writes or mutation.

    ``citation_checks_passed`` counts mechanical checks, not verified facts.
    ``ready_for_review`` means no detected invariant failure, not factual approval.
    """
    issues: list[dict] = []
    issue_counts: Counter = Counter()
    severity_counts: Counter = Counter()

    def issue(code: str, severity: str = "warning", **location: int) -> None:
        issue_counts[code] += 1
        severity_counts[severity] += 1
        if len(issues) < 100:
            issues.append({"code": code, "severity": severity, **location})

    if not isinstance(dossier, dict):
        issue("invalid_dossier", "error")
        dossier = {}
    sections = dossier.get("sections")
    if not isinstance(sections, dict):
        issue("invalid_sections", "error")
        sections = {}
    safe_dossier = {**dossier, "sections": sections}
    try:
        evidence = ai_agents._evidence(safe_dossier)
    except (TypeError, ValueError, AttributeError):
        evidence = []
        issue("invalid_evidence_structure", "error")
    sources = {row["id"]: row for row in evidence}
    known_sections = {"web", "profiles", "emails", "findings", "businesses", "jobs", "careers", "webcheck_modules", "domain", "artifacts", "archives", "enrichments"}
    evidence_by_section = dict(sorted(Counter(row["section"] if row["section"] in known_sections else "other"
                                              for row in evidence).items()))
    candidates = sum(bool(_UNCERTAINTY.search(str(row.get("attribution") or ""))) or
                     row.get("provenance") in {"search_match", "profile_candidate"} for row in evidence)

    latest: dict[tuple[str, str], dict] = {}
    for index, row in enumerate(_rows(dossier.get("source_checks")), 1):
        if not isinstance(row, dict):
            issue("invalid_source_check", "error", check_index=index)
            continue
        # URLs participate in deduplication only; none are exported to diagnostics.
        key = (str(row.get("source") or row.get("name") or row.get("tool") or ""),
               str(row.get("url") or ""))
        latest[key] = row
    states = Counter()
    for index, row in enumerate(latest.values(), 1):
        state = str(row.get("state") or row.get("status") or "unknown").lower()
        if state not in _KNOWN:
            state = "unknown"
            issue("unknown_source_state", check_index=index)
        states[state] += 1
        if state in _GAPS:
            issue("source_coverage_gap", check_index=index)
        elif state in _PENDING:
            issue("unfinished_source_check", check_index=index)

    analysis = dossier.get("ai_analysis")
    if analysis is not None and not isinstance(analysis, dict):
        issue("invalid_ai_analysis", "error")
    analysis = analysis if isinstance(analysis, dict) else {}
    claims = analysis.get("claims", [])
    if not isinstance(claims, list):
        issue("invalid_claims", "error")
        claims = []
    passed = 0
    for index, claim in enumerate(claims[:1000], 1):
        errors_before = severity_counts["error"]
        if not isinstance(claim, dict):
            issue("invalid_claim", "error", claim_index=index)
            continue
        evidence_id = claim.get("evidence_id")
        source = sources.get(evidence_id) if isinstance(evidence_id, str) else None
        if source is None:
            issue("missing_evidence_id", "error", claim_index=index)
            continue
        quote, statement = _normal(claim.get("quote")), _normal(claim.get("statement"))
        if len(quote) < 4 or quote not in _normal(source["text"]):
            issue("quote_not_found", "error", claim_index=index)
        if not statement:
            issue("empty_statement", "error", claim_index=index)
        if claim.get("source_url") != source["url"]:
            issue("source_url_mismatch", "error", claim_index=index)
        if claim.get("section") != source.get("section"):
            issue("source_section_mismatch", "error", claim_index=index)
        if claim.get("provenance") != source.get("provenance"):
            issue("source_provenance_mismatch", "error", claim_index=index)
        if _normal(claim.get("attribution")) != _normal(source.get("attribution")):
            issue("source_attribution_mismatch", "error", claim_index=index)
        if any(not re.search(r"(?<![\w])" + re.escape(anchor.casefold()) + r"(?![\w])", quote.casefold())
               for anchor in ai_agents.claim_anchors(statement)):
            issue("identifier_absent_from_quote", "error", claim_index=index)
        # Public records and matching quotations can still overstate ownership.
        # This warning is a review request, not a judgment that the claim is false.
        if _IDENTITY_ASSERTION.search(statement) and not _UNCERTAINTY.search(statement):
            issue("identity_assertion_requires_review", claim_index=index)
        if severity_counts["error"] == errors_before:
            passed += 1
    if len(claims) > 1000:
        issue("claim_audit_limit", "error")
    if analysis.get("status") == "ok" and not claims:
        issue("successful_ai_without_claims", "error")
    if analysis.get("status") == "no_conclusions" and claims:
        issue("ai_status_claim_mismatch", "error")
    if analysis.get("status") in {"error", "failed", "unavailable", "unconfigured", "no_evidence", "no_conclusions", "partial", "running"}:
        issue("ai_answer_incomplete")
    failed = bool(severity_counts["error"])
    return {
        "schema_version": 1,
        "evaluation_type": "offline_invariant_checks",
        "status": "invariant_failures" if failed else "needs_review" if issue_counts else "ready_for_review",
        "metrics": {"evidence_sample_items": len(evidence), "candidate_evidence_items": candidates,
                    "claims_total": len(claims), "claims_checked": min(len(claims), 1000),
                    "citation_checks_passed": passed, "diagnostic_count": sum(issue_counts.values()),
                    "source_checks_total": len(latest)},
        "evidence_by_section": evidence_by_section,
        "coverage": {"states": dict(sorted(states.items())),
                     "successful_sources": sum(states[state] for state in _SUCCESS),
                     "sources_with_gaps": sum(states[state] for state in _GAPS),
                     "unfinished_sources": sum(states[state] for state in _PENDING)},
        "diagnostic_counts": dict(sorted(issue_counts.items())),
        "diagnostics": issues, "diagnostics_truncated": sum(issue_counts.values()) > len(issues),
        "limitations": list(LIMITATIONS),
    }


def run_benchmark(cases_path: Path | None = None) -> dict:
    """Check synthetic expected invariant outcomes; never invokes a model or service."""
    path = Path(cases_path) if cases_path is not None else Path(__file__).with_name("research_quality_cases.json")
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("Benchmark must be a nonempty list of synthetic cases")
    results = []
    for index, case in enumerate(cases, 1):
        report = evaluate(case["dossier"])
        expected = case["expected"]
        codes = set(report["diagnostic_counts"])
        checks = {"status": report["status"] == expected["status"],
                  "required_codes": set(expected.get("required_codes", [])) <= codes,
                  "forbidden_codes": not set(expected.get("forbidden_codes", [])) & codes}
        for key, value in expected.get("metrics", {}).items():
            checks["metric:" + key] = report["metrics"].get(key) == value
        results.append({"case_index": index, "passed": all(checks.values()), "checks": checks})
    return {"schema_version": 1, "evaluation_type": "synthetic_invariant_benchmark",
            "status": "passed" if all(row["passed"] for row in results) else "failed",
            "cases_total": len(results), "cases_passed": sum(row["passed"] for row in results),
            "results": results, "limitations": list(LIMITATIONS)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--benchmark", action="store_true", help="Run synthetic offline invariant cases")
    group.add_argument("--dossier", type=Path, help="Evaluate a saved dossier JSON without modifying it")
    args = parser.parse_args()
    try:
        report = run_benchmark() if args.benchmark else evaluate(json.loads(args.dossier.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"status": "error", "error": "Unable to read a valid evaluation input"}))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report["status"] in {"failed", "invariant_failures"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
