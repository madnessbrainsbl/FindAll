"""Скоринг вакансий под профиль пользователя.

Профиль — JSON-файл (по умолчанию profile.json рядом с БД):
{
  "titles":   ["python", "backend", "developer"],
  "skills":   ["python", "sql", "docker", "aws"],
  "exclude":  ["senior", "lead", "principal", "10+ years", "unpaid"],
  "remote_only": false,
  "locations": ["remote"]
}
Оценка 0–100 + объяснение. Без ML — прозрачные правила, чтобы было видно «почему».
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import re

DEFAULT_PROFILE = {
    "titles": [],
    "skills": [],
    "exclude": ["unpaid", "internship only"],
    "remote_only": False,
    "locations": [],
    "grades": [],
    "min_salary": 0,
    "role": "",
    "highlight": "",
    "team": "",
    "project": "",
    "metric": "",
}


GRADE_TITLE_PATTERNS = [
    ("lead", re.compile(r"\b(team[\s-]?lead|tech[\s-]?lead|principal|staff|lead|тимлид)\b", re.I)),
    ("head", re.compile(r"\b(head\s+of|director|vp[\s-]|chief|cto|cpo|руководитель)\b", re.I)),
    ("senior", re.compile(r"\b(senior|sr\.?|старший|ведущий|сеньор)\b", re.I)),
    ("middle", re.compile(r"\b(middle|intermediate|мидл)\b", re.I)),
    ("junior", re.compile(r"\b(junior|entry[\s-]level|grad|graduate|младший)\b", re.I)),
    ("intern", re.compile(r"\b(intern|internship|стажер|практикант)\b", re.I)),
]

GRADE_DESC_PATTERNS = [
    ("lead", re.compile(r"\b(team[\s-]?lead|tech[\s-]?lead|principal\s+engineer|staff\s+engineer|lead\s+(?:developer|engineer|architect|designer)|тимлид)\b", re.I)),
    ("head", re.compile(r"\b(head\s+of\s+[a-z]+|director\s+of\s+[a-z]+|vp\s+of\s+[a-z]+|cto|cpo)\b", re.I)),
    ("senior", re.compile(r"\b(senior\s+(?:developer|engineer|software|backend|frontend|fullstack|devops|data|analyst)|sr\.\s*(?:developer|engineer|software)|старший\s+(?:разработчик|инженер|программист)|ведущий\s+(?:разработчик|инженер|специалист))\b", re.I)),
    ("middle", re.compile(r"\b(middle\s+(?:developer|engineer|software|backend|frontend|fullstack)|мидл[\s-]+(?:разработчик|инженер))\b", re.I)),
    ("junior", re.compile(r"\b(junior\s+(?:developer|engineer|software|backend|frontend)|entry[\s-]level\s+(?:role|position|engineer|developer)|graduate\s+(?:program|scheme|developer)|младший\s+(?:разработчик|инженер))\b", re.I)),
    ("intern", re.compile(r"\b(internship|intern\s+(?:developer|engineer|position)|стажировк[а-я]|стажер)\b", re.I)),
]


def detect_grade(title: str, description: str = "") -> str:
    """Определяет грейд (intern, junior, middle, senior, lead, head)."""
    title_clean = (title or "").lower()
    is_sales_lead = bool(re.search(r"\b(lead\s*gen(?:eration)?|sales\s*lead)\b", title_clean, re.I))
    for grade, pat in GRADE_TITLE_PATTERNS:
        if grade == "lead" and is_sales_lead:
            continue
        if pat.search(title_clean):
            return grade
    desc_sample = (description or "")[:2000].lower()
    for grade, pat in GRADE_DESC_PATTERNS:
        if pat.search(desc_sample):
            return grade
    return ""


def extract_salary(text: str) -> dict | None:
    """Извлекает зарплатную вилку из текста вакансии (USD, EUR, RUB, GBP)."""
    if not text:
        return None
    sample = " ".join(text.split())[:3000]
    pattern = re.compile(
        r"""(?xi)
        (?P<c1>[\$€£₽]|usd|eur|rub|gbp)?\s*
        (?P<min>\d{1,3}(?:[,\s]\d{3})+|\d+)\s*(?P<k1>k|к)?\s*
        (?:[-–—toдо]+\s*(?P<c2>[\$€£₽]|usd|eur|rub|gbp)?\s*(?P<max>\d{1,3}(?:[,\s]\d{3})+|\d+)\s*(?P<k2>k|к)?)?\s*
        (?P<c3>[\$€£₽]|usd|eur|rub|gbp|руб(?:лей|\.)?)?\s*
        (?:(?:per\s+|/|\s+в\s+)?(?P<period>year|yr|month|mo|hour|hr|день|мес(?:яц|\.)?|год))?
        """
    )
    for m in pattern.finditer(sample):
        c1, c2, c3 = m.group("c1"), m.group("c2"), m.group("c3")
        currency_raw = c1 or c2 or c3
        if not currency_raw:
            continue

        after_match = sample[m.end():m.end() + 20].strip()
        if re.match(r"^(?:[mb]|млн|млрд|million|billion)\b", after_match, re.I):
            continue

        before_match = sample[max(0, m.start() - 35):m.start()].lower()
        if any(w in before_match for w in ("raised", "valuation", "revenue", "funding", "worth over", "paid out over")):
            continue

        if re.match(r"^(?:per\s+|/\s*)(?:word|page|token|article)\b", after_match, re.I):
            continue

        curr = currency_raw.upper().strip()
        if curr in ("$", "USD"):
            currency = "USD"
        elif curr in ("€", "EUR"):
            currency = "EUR"
        elif curr in ("£", "GBP"):
            currency = "GBP"
        elif curr in ("₽", "RUB") or "РУБ" in curr:
            currency = "RUB"
        else:
            currency = curr

        period_raw = (m.group("period") or "").lower()
        is_explicit_hour = any(p in period_raw for p in ("hr", "hour", "час")) or "/hr" in m.group(0).lower()

        has_k_in_range = bool(m.group("k1") or m.group("k2"))

        def parse_num(s, is_k):
            if not s:
                return None
            val = float(re.sub(r"[,\s]", "", s))
            if is_k or (has_k_in_range and val < 1000):
                val *= 1000
            elif val < 1000 and currency in ("USD", "EUR", "GBP") and not is_explicit_hour:
                return None
            return int(val)

        val_min = parse_num(m.group("min"), bool(m.group("k1")))
        val_max = parse_num(m.group("max"), bool(m.group("k2")))
        if val_min is None or val_min <= 0:
            continue
        if val_max and val_max < val_min:
            val_min, val_max = val_max, val_min

        if currency in ("USD", "EUR", "GBP") and val_min < 500 and not is_explicit_hour:
            continue
        if is_explicit_hour and (val_min < 10 or val_min > 500):
            continue

        if any(p in period_raw for p in ("yr", "year", "год")):
            period = "year"
        elif is_explicit_hour:
            period = "hour"
        elif any(p in period_raw for p in ("mo", "month", "мес")):
            period = "month"
        else:
            if currency in ("USD", "EUR", "GBP"):
                period = "year" if val_min >= 25000 else "month"
            else:
                period = "month" if val_min <= 1000000 else "year"

        if period == "year":
            monthly_min = round(val_min / 12)
            monthly_max = round(val_max / 12) if val_max else None
            annual_min = val_min
            annual_max = val_max
        elif period == "hour":
            monthly_min = round(val_min * 168)
            monthly_max = round(val_max * 168) if val_max else None
            annual_min = monthly_min * 12
            annual_max = monthly_max * 12 if monthly_max else None
        else:
            monthly_min = val_min
            monthly_max = val_max
            annual_min = val_min * 12
            annual_max = val_max * 12 if val_max else None

        return {
            "min": val_min,
            "max": val_max,
            "currency": currency,
            "period": period,
            "monthly_min": monthly_min,
            "monthly_max": monthly_max,
            "annual_min": annual_min,
            "annual_max": annual_max,
            "raw": m.group(0).strip(),
        }
    return None


CORP_SUFFIXES = {
    "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation",
    "gmbh", "co", "technologies", "technology", "tech", "group", "software",
    "solutions", "labs", "studio", "studios", "io", "ai", "ooo", "ооо", "зао", "пао"
}

TITLE_SYNONYMS = {
    "dev": "developer",
    "engineer": "developer",
    "programmer": "developer",
    "coder": "developer",
    "spec": "specialist",
    "mgr": "manager",
    "sr": "senior",
    "jr": "junior",
}


def deduplicate_jobs(jobs: list[dict], threshold: float = 0.65) -> list[dict]:
    """Семантическая дедупликация вакансий по нормализованной компании и ключевым словам заголовка."""
    deduped = []
    seen = []

    def norm_company(c: str) -> set[str]:
        words = re.findall(r"\b[a-z0-9а-яё]+\b", (c or "").lower())
        filtered = {w for w in words if w not in CORP_SUFFIXES}
        return filtered or set(words)

    def tokens(s: str) -> set[str]:
        cleaned = re.sub(r"[\[\]\(\)\-\|/]", " ", (s or "").lower())
        raw_words = re.findall(r"\b[a-z0-9а-яё]{2,}\b", cleaned)
        res = set()
        stop = {"remote", "hybrid", "onsite", "full", "time", "part", "emea", "latam", "apac", "us"}
        for w in raw_words:
            if w in stop:
                continue
            canonical = TITLE_SYNONYMS.get(w, w)
            res.add(canonical)
        return res

    for j in jobs:
        comp_words = norm_company(j.get("company") or "")
        j_tokens = tokens(j.get("title") or "")
        match_idx = None
        for i, (sc_words, sc_tokens, existing) in enumerate(seen):
            comp_match = bool(comp_words and sc_words and (comp_words == sc_words or comp_words.issubset(sc_words) or sc_words.issubset(comp_words)))
            if comp_match:
                if not j_tokens or not sc_tokens:
                    continue
                intersection = len(j_tokens & sc_tokens)
                union = len(j_tokens | sc_tokens)
                similarity = intersection / union if union else 0.0
                if similarity >= threshold:
                    match_idx = i
                    break

        if match_idx is not None:
            target = seen[match_idx][2]
            srcs = set(target.get("all_sources") or [target.get("source") or ""])
            if j.get("source"):
                srcs.add(j["source"])
            target["all_sources"] = sorted(s for s in srcs if s)
            urls = set(target.get("all_urls") or [target.get("url") or ""])
            if j.get("url"):
                urls.add(j["url"])
            target["all_urls"] = sorted(u for u in urls if u)
            if len(j.get("description") or "") > len(target.get("description") or ""):
                target["description"] = j.get("description")
            if (j.get("posted") or "") > (target.get("posted") or ""):
                target["posted"] = j.get("posted")
        else:
            j_copy = dict(j)
            j_copy["all_sources"] = [j.get("source")] if j.get("source") else []
            j_copy["all_urls"] = [j.get("url")] if j.get("url") else []
            seen.append((comp_words, j_tokens, j_copy))
            deduped.append(j_copy)

    return deduped


def load_profile(path: str | Path) -> dict:
    p = Path(path)
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            prof = dict(DEFAULT_PROFILE)
            prof.update({k: v for k, v in data.items() if k in DEFAULT_PROFILE})
            return prof
        except (ValueError, OSError):
            pass
    return dict(DEFAULT_PROFILE)


def save_profile_template(path: str | Path) -> None:
    p = Path(path)
    if not p.exists():
        p.write_text(json.dumps(DEFAULT_PROFILE, ensure_ascii=False, indent=2), encoding="utf-8")


def _days_since(posted: str) -> int | None:
    if not posted:
        return None
    s = str(posted)[:10]
    try:
        dt = datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


def score_job(job: dict, prof: dict) -> dict:
    """Возвращает {score: 0-100, reasons: [...], matched: {...}}."""
    score = 0
    reasons = []
    text_title = (job.get("title") or "").lower()
    text_blob = f"{text_title} {(job.get('description') or '')[:2000]}".lower()
    location_l = (job.get("location") or "").lower()
    matched = {"titles": [], "skills": []}

    # Исключения — сразу в ноль
    for ex in prof.get("exclude") or []:
        if ex.lower() in text_blob:
            return {"score": 0, "reasons": [f"excluded by term '{ex}'"], "matched": matched}

    # Совпадение позиции (до 40)
    title_hits = [t for t in (prof.get("titles") or []) if t.lower() in text_title]
    blob_hits = [t for t in (prof.get("titles") or []) if t.lower() in text_blob and t.lower() not in title_hits]
    matched["titles"] = title_hits + blob_hits
    if title_hits:
        score += 40
        reasons.append(f"title: {', '.join(title_hits[:3])}")
    elif blob_hits:
        score += 22
        reasons.append(f"mentioned in description: {', '.join(blob_hits[:3])}")

    # Навыки (до 25)
    skills = prof.get("skills") or []
    if skills:
        hit = [s for s in skills if s.lower() in text_blob]
        matched["skills"] = hit
        if hit:
            share = len(hit) / len(skills)
            pts = round(min(25, 8 + 17 * min(1.0, share * 2)))
            score += pts
            reasons.append(f"skills {len(hit)}/{len(skills)}: {', '.join(hit[:5])}")

    # Локация/remote (до 10)
    if prof.get("remote_only"):
        if job.get("remote") or "remote" in location_l:
            score += 10
            reasons.append("remote")
        else:
            return {"score": 0, "reasons": ["remote required, job is not remote"], "matched": matched}
    elif prof.get("locations"):
        if any(l.lower() in location_l or (job.get("remote") and l.lower() == "remote")
               for l in prof["locations"]):
            score += 10
            reasons.append("location matches")

    # Свежесть (до 15)
    days = _days_since(job.get("posted", ""))
    if days is not None:
        if days <= 3:
            score += 15
            reasons.append(f"recent ({days} days)")
        elif days <= 7:
            score += 12
            reasons.append(f"within a week ({days} days)")
        elif days <= 14:
            score += 8
            reasons.append(f"within two weeks ({days} days)")
        elif days <= 30:
            score += 4

    # Email в описании — практический плюс (до 10)
    if (job.get("found_emails") or "").strip():
        score += 10
        reasons.append("direct email provided")

    grade = detect_grade(job.get("title") or "", job.get("description") or "")
    salary = extract_salary(f"{job.get('title') or ''} {job.get('description') or ''}")

    if grade:
        reasons.append(f"grade: {grade}")
    if salary:
        reasons.append(f"salary: {salary.get('raw', '')}")

    # Фильтр по грейду (если задан в профиле)
    if prof.get("grades"):
        wanted_grades = [g.lower() for g in prof["grades"]]
        if grade and grade.lower() not in wanted_grades:
            return {"score": 0, "reasons": [f"grade '{grade}' not in wanted grades"], "matched": matched, "grade": grade, "salary": salary}

    # Фильтр по минимальной зарплате (если задан)
    min_sal = prof.get("min_salary")
    if min_sal and salary:
        try:
            target = float(min_sal)
            monthly = salary.get("monthly_min") or salary.get("monthly_max") or 0
            annual = salary.get("annual_min") or salary.get("annual_max") or 0
            if target > 15000:
                if annual and annual < target:
                    return {"score": 0, "reasons": [f"annual salary {annual} below min {target}"], "matched": matched, "grade": grade, "salary": salary}
            else:
                if monthly and monthly < target:
                    return {"score": 0, "reasons": [f"monthly salary {monthly} below min {target}"], "matched": matched, "grade": grade, "salary": salary}
        except (ValueError, TypeError):
            pass

    return {"score": min(100, score), "reasons": reasons, "matched": matched, "grade": grade, "salary": salary}


def score_all(jobs: list[dict], prof: dict, deduplicate: bool = True) -> list[dict]:
    if deduplicate:
        jobs = deduplicate_jobs(jobs)
    out = []
    for j in jobs:
        s = score_job(j, prof)
        row = dict(j)
        row["score"] = s["score"]
        row["grade"] = s.get("grade") or ""
        row["salary"] = s.get("salary")
        row["matched_skills"] = s.get("matched", {}).get("skills", [])
        row["matched_titles"] = s.get("matched", {}).get("titles", [])
        row["why"] = "; ".join(s["reasons"]) if s["reasons"] else "—"
        out.append(row)
    out.sort(key=lambda r: (-r["score"], r.get("company") or ""))
    return out
