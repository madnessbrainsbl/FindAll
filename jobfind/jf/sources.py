"""Источники вакансий: публичные job-board API + ATS-борды без ключей.

Каждая функция возвращает list[dict] унифицированного вида:
  {title, company, location, url, source, remote, description, posted}
Источник всегда указывается в поле "source", чтобы понимать происхождение.
"""

from __future__ import annotations

import datetime
import html as _html_mod
import re
import sys

from . import net
from .resilience import CircuitBreaker

CIRCUIT_BREAKER = CircuitBreaker(failure_threshold=2, recovery_timeout=300.0)

TAG = re.compile(r"<[^>]+>")


def strip_html(text: str, limit: int = 4000) -> str:
    if not text:
        return ""
    text = _html_mod.unescape(text)
    text = re.sub(r"<\s*br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<\s*/p\s*>", "\n", text, flags=re.I)
    text = TAG.sub(" ", text)
    text = re.sub(r"[ \t\r]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:limit]


def _job(title, company, url, source, location="", remote=False, description="", posted=""):
    return {
        "title": (title or "").strip(),
        "company": (company or "").strip(),
        "location": (location or "").strip(),
        "url": url or "",
        "source": source,
        "remote": bool(remote),
        "description": strip_html(description or ""),
        "posted": str(posted or ""),
    }


def matches_job_query(job: dict, query: str) -> bool:
    terms = query.casefold().split()
    title = str(job.get("title", "")).casefold()
    details = " ".join(str(job.get(field, "")) for field in ("title", "description", "location")).casefold()
    return bool(terms) and any(term in title for term in terms) and all(term in details for term in terms)


# ---------------------------------------------------------------- job boards

# ---------------------------------------------------------------- job boards

LISTINGS_URL = (
    "https://raw.githubusercontent.com/SimplifyJobs/New-Grad-Positions/dev/"
    ".github/scripts/listings.json"
)


def simplify(keywords: str = "", max_items: int = 200) -> list[dict]:
    """SimplifyJobs/New-Grad-Positions: 19k+ вакансий для джуниоров одним JSON.

    Поля: title, company_name, company_url, locations, active, is_visible, url,
    category, date_posted (unix), sponsorship, degrees. Фильтр: active+is_visible.
    Идея источника — репозиторий SimplifyJobs, подключено как публичный raw-файл.
    """
    out = []
    r = net.get(LISTINGS_URL)
    data = r.json()
    if not isinstance(data, list):
        print(f"  [!] simplify: {r.error or 'bad payload'}", file=sys.stderr)
        return out
    kw = keywords.lower().split() if keywords else []
    for j in data:
        if not (j.get("active") and j.get("is_visible")):
            continue
        title = str(j.get("title", ""))
        blob = f"{title} {j.get('category', '')} {' '.join(j.get('locations') or [])}".lower()
        if kw and not any(k in blob for k in kw):
            continue
        posted = j.get("date_posted") or 0
        posted_s = datetime.datetime.fromtimestamp(int(posted), datetime.timezone.utc).strftime(
            "%Y-%m-%d") if posted else ""
        locs = ", ".join(j.get("locations") or [])
        out.append(_job(title, j.get("company_name"), j.get("url"), "simplify", locs,
                        any("remote" in l.lower() for l in (j.get("locations") or [])),
                        f"{j.get('category', '')} | sponsorship: {j.get('sponsorship', '')} | "
                        f"degrees: {', '.join(j.get('degrees') or [])}", posted_s))
    out.sort(key=lambda x: x.get("posted") or "", reverse=True)
    return out[:max_items]


def arbeitnow(keywords: str = "", max_items: int = 50) -> list[dict]:
    """Arbeitnow job board API (бесплатный, без ключа)."""
    out = []
    r = net.get("https://arbeitnow.com/api/job-board-api")
    data = r.json()
    if not isinstance(data, dict):
        print(f"  [!] arbeitnow: {r.error or 'bad payload'}", file=sys.stderr)
        return out
    slug_re = re.compile(r"[a-z0-9\-]+")
    for j in data.get("data", []):
        url = j.get("url") or ""
        if not url and j.get("slug"):
            slug = "".join(slug_re.findall(str(j["slug"]).lower().replace("_", "-")))[:80]
            url = f"https://www.arbeitnow.com/view/{slug}"
        job = _job(j.get("title"), j.get("company_name"), url, "arbeitnow",
                   j.get("location"), j.get("remote"), j.get("description"), j.get("created_at"))
        if not keywords.strip() or matches_job_query(job, keywords):
            out.append(job)
    return out[:max_items]


def remotive(keywords: str = "", max_items: int = 50) -> list[dict]:
    """Remotive public API: https://remotive.com/api/remote-jobs"""
    out = []
    params = {"limit": min(max_items, 100)}
    if keywords:
        params["search"] = keywords
    r = net.get("https://remotive.com/api/remote-jobs", params)
    data = r.json()
    if not isinstance(data, dict):
        print(f"  [!] remotive: {r.error or 'bad payload'}", file=sys.stderr)
        return out
    for j in data.get("jobs", []):
        out.append(_job(j.get("title"), j.get("company_name"), j.get("url"), "remotive",
                        j.get("candidate_required_location"), True, j.get("description"), j.get("publication_date")))
    return out[:max_items]


def jobicy(keywords: str = "", max_items: int = 50) -> list[dict]:
    """Jobicy public API v2: https://jobicy.com/api/v2/remote-jobs"""
    out = []
    params = {"count": min(max_items, 50)}
    tag = " ".join(keywords.split())[:50]
    if len(tag) >= 3:
        params["tag"] = tag
    r = net.get("https://jobicy.com/api/v2/remote-jobs", params)
    data = r.json()
    if not isinstance(data, dict):
        print(f"  [!] jobicy: {r.error or 'bad payload'}", file=sys.stderr)
        return out
    for j in data.get("jobs", []):
        out.append(_job(j.get("jobTitle"), j.get("companyName"), j.get("url"), "jobicy",
                        j.get("jobGeo"), True, j.get("jobDescription"), j.get("pubDate")))
    return out[:max_items]


def hh(keywords: str = "", max_items: int = 50) -> list[dict]:
    """HeadHunter's public vacancy API; searches Russian and neighboring markets."""
    if not keywords.strip():
        return []
    limit = min(max_items, 100)
    r = net.get(
        "https://api.hh.ru/vacancies",
        {"text": keywords, "per_page": limit, "page": 0, "order_by": "publication_time"},
        extra_headers={"HH-User-Agent": "FindAll/1.7 (public vacancy search)"},
    )
    data = r.json()
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        print(f"  [!] hh: {r.error or 'bad payload'}", file=sys.stderr)
        return []
    out = []
    for item in data["items"]:
        snippet = item.get("snippet") or {}
        employer = item.get("employer") or {}
        schedule = item.get("schedule") or {}
        out.append(_job(
            item.get("name"), employer.get("name"), item.get("alternate_url"), "hh",
            (item.get("area") or {}).get("name", ""),
            (schedule.get("id") == "remote"),
            " ".join(filter(None, (snippet.get("requirement"), snippet.get("responsibility")))),
            item.get("published_at", ""),
        ))
    return out


def remoteok(keywords: str = "", max_items: int = 50) -> list[dict]:
    """RemoteOK API: https://remoteok.com/api (первый элемент — легальный дисклеймер)."""
    out = []
    r = net.get("https://remoteok.com/api")
    data = r.json()
    if not isinstance(data, list):
        print(f"  [!] remoteok: {r.error or 'bad payload'}", file=sys.stderr)
        return out
    kw = keywords.lower().split() if keywords else []
    for j in data:
        if not isinstance(j, dict) or "position" not in j:
            continue  # нулевой элемент — legal notice
        title = str(j.get("position", ""))
        if kw and not any(k in title.lower() or k in str(j.get("description", "")).lower() for k in kw):
            continue
        slug = j.get("slug") or j.get("id") or ""
        url = j.get("url") or (f"https://remoteok.com/remote-jobs/{slug}" if slug else "")
        out.append(_job(title, j.get("company"), url, "remoteok",
                        j.get("location"), True, j.get("description"), j.get("date")))
        if len(out) >= max_items:
            break
    return out


def hackernews_whoishiring(max_items: int = 60) -> list[dict]:
    """Свежие треды 'Ask HN: Who is hiring?' через Algolia API, комментарии компаний.

    Кто ищет людей сам — самые тёплые контакты. Комментарий = пост компании.
    Поиск Algolia нечёткий: приплетает 'Show HN' и прочее — фильтруем по заголовку.
    """
    out = []
    r = net.get("https://hn.algolia.com/api/v1/search_by_date",
                {"query": "Ask HN: Who is hiring", "tags": "story", "hitsPerPage": 20})
    data = r.json()
    if not isinstance(data, dict):
        print(f"  [!] hn: {r.error or 'bad payload'}", file=sys.stderr)
        return out
    wanted = ("ask hn: who is hiring", "ask hn: who wants to be hired")
    threads = [h for h in data.get("hits", [])
               if str(h.get("title", "")).lower().startswith(wanted)]
    if not threads:
        print("  [!] hn: Who is hiring threads were not found", file=sys.stderr)
        return out
    for story in threads[:2]:  # последний месяц + предыдущий
        sid = story.get("objectID")
        if not sid:
            continue
        rc = net.get(f"https://hn.algolia.com/api/v1/items/{sid}")
        item = rc.json()
        if not isinstance(item, dict):
            continue
        for c in item.get("children", [])[:max_items]:
            text = c.get("text") or ""
            plain = strip_html(text, 3000)
            if not plain:
                continue
            # Компания обычно первой строкой или в начале текста
            first_line = plain.split("\n", 1)[0]
            company = re.split(r"\s*[\|(—–-]\s*", first_line)[0].strip()[:60] or "(HN comment)"
            out.append(_job(f"HN: {first_line[:120]}", company,
                            f"https://news.ycombinator.com/item?id={c.get('id')}",
                            "hn-whoishiring", story.get("title", ""), False, plain,
                            c.get("created_at", "")[:10]))
    return out[:max_items]


# ------------------------------------------------------------- ATS job boards

def greenhouse(tenant: str, *, fetch=None) -> list[dict]:
    """Greenhouse board: https://boards-api.greenhouse.io/v1/boards/{t}/jobs?content=true"""
    out = []
    r = (fetch or net.get)(f"https://boards-api.greenhouse.io/v1/boards/{tenant}/jobs", {"content": "true"})
    data = r.json()
    if not isinstance(data, dict) or not data.get("jobs"):
        print(f"  [!] greenhouse/{tenant}: {r.error or 'empty'}", file=sys.stderr)
        return out
    for j in data["jobs"]:
        out.append(_job(j.get("title"), j.get("company_name") or tenant,
                        j.get("absolute_url"), f"greenhouse:{tenant}",
                        (j.get("location") or {}).get("name"), False,
                        j.get("content"), j.get("first_published") or j.get("updated_at")))
    return out


def lever(tenant: str, *, fetch=None) -> list[dict]:
    """Lever board: US api.lever.co, фолбэк на EU api.eu.lever.co (часть компаний только там)."""
    out = []
    r = (fetch or net.get)(f"https://api.lever.co/v0/postings/{tenant}", {"mode": "json"})
    data = r.json()
    if not isinstance(data, list) or not data:
        r = (fetch or net.get)(f"https://api.eu.lever.co/v0/postings/{tenant}", {"mode": "json"})
        data = r.json()
        if not isinstance(data, list):
            print(f"  [!] lever/{tenant}: {r.error or 'empty'}", file=sys.stderr)
            return out
    for j in data:
        cats = j.get("categories") or {}
        out.append(_job(j.get("text"), tenant, j.get("hostedUrl") or j.get("applyUrl"),
                        f"lever:{tenant}", cats.get("location"), False,
                        (j.get("descriptionPlain") or "") + "\n" + (j.get("additionalPlain") or ""),
                        j.get("createdAt")))
    return out


def workable(tenant: str, *, fetch=None) -> list[dict]:
    """Workable widget API (GET): https://apply.workable.com/api/v1/widget/accounts/{t}?details=true"""
    out = []
    r = (fetch or net.get)(f"https://apply.workable.com/api/v1/widget/accounts/{tenant}", {"details": "true"})
    data = r.json()
    if not isinstance(data, dict) or not data.get("jobs"):
        print(f"  [!] workable/{tenant}: {r.error or 'empty'}", file=sys.stderr)
        return out
    for j in data["jobs"]:
        loc = j.get("location") or {}
        if isinstance(loc, dict):
            loc_s = f"{loc.get('city', '')} {loc.get('country', '')}".strip()
        else:
            loc_s = str(loc)
        out.append(_job(j.get("title"), data.get("name") or tenant,
                        j.get("url"), f"workable:{tenant}", loc_s,
                        False, j.get("description"), j.get("published_on")))
    return out


def ashby(tenant: str, *, fetch=None) -> list[dict]:
    """Ashby board: https://api.ashbyhq.com/posting-api/job-board/{t}"""
    out = []
    r = (fetch or net.get)(f"https://api.ashbyhq.com/posting-api/job-board/{tenant}")
    data = r.json()
    if not isinstance(data, dict) or not data.get("jobs"):
        print(f"  [!] ashby/{tenant}: {r.error or 'empty'}", file=sys.stderr)
        return out
    for j in data["jobs"]:
        loc = j.get("location") or ""
        out.append(_job(j.get("title"), tenant, j.get("jobUrl") or j.get("applyUrl"),
                        f"ashby:{tenant}", loc, False, "", j.get("updatedAt")))
    return out


def smartrecruiters(tenant: str, max_items: int = 100, *, fetch=None) -> list[dict]:
    """SmartRecruiters: https://api.smartrecruiters.com/v1/companies/{t}/postings"""
    out = []
    r = (fetch or net.get)(f"https://api.smartrecruiters.com/v1/companies/{tenant}/postings",
                {"limit": min(max_items, 100)})
    data = r.json()
    if not isinstance(data, dict):
        print(f"  [!] smartrecruiters/{tenant}: {r.error or 'empty'}", file=sys.stderr)
        return out
    for j in data.get("content", []):
        loc = j.get("location") or {}
        city = loc.get("city", "")
        country = loc.get("country", "")
        out.append(_job(j.get("name"), data.get("company", {}).get("name", tenant),
                        f"https://jobs.smartrecruiters.com/{tenant}/{j.get('id')}",
                        f"smartrecruiters:{tenant}", f"{city} {country}".strip(),
                        False, j.get("releasedDate", ""), j.get("releasedDate")))
    return out


SOURCE_BOARD = {
    "hh": lambda kw, n: hh(kw, n),
    "simplify": lambda kw, n: simplify(kw, n),
    "arbeitnow": lambda kw, n: arbeitnow(kw, n),
    "remotive": lambda kw, n: remotive(kw, n),
    "jobicy": lambda kw, n: jobicy(kw, n),
    "remoteok": lambda kw, n: remoteok(kw, n),
    "hn": lambda kw, n: hackernews_whoishiring(n),
}

SOURCE_ATS = {
    "greenhouse": greenhouse,
    "lever": lever,
    "workable": workable,
    "ashby": ashby,
    "smartrecruiters": smartrecruiters,
}
