"""Контакты: извлечение email из текста вакансий + генерация гипотез и ссылок.

Важно: мы ничего не взламываем — только:
  1) читаем emails, которые компании сами опубликовали в вакансиях/на страницах;
  2) строим правдоподобные гипотезы (careers@, jobs@, hr@...) и проверяем ДОМЕН
     через DoH (MX-записи) — принимает ли он вообще почту;
  3) генерируем готовые поисковые ссылки (LinkedIn, Google, X) по людям компании.
"""

from __future__ import annotations

import re
import urllib.parse

from . import domains as _domains
from .sources import strip_html

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
# Отфильтровать мусор: картинки, example.com, очевидные спам-ловушки
BAD_EMAIL_PARTS = ("example.", "noreply", "no-reply", "donotreply", ".png", ".jpg", ".webp",
                   "sentry", "wixpress", "godaddy", "sentry.io")

HYPOTHESIS_LOCAL = ["careers", "jobs", "hr", "recruit", "recruiting", "recruitment", "talent", "hiring", "people", "work"]

ROLE_HINTS = {
    "recruiter": ["recruit", "talent", "hiring", "people", "HR", "sourc"],
    "hr": ["HR", "human resources", "люди", "кадр"],
    "hiring_manager": ["head of", "lead", "director", "manager", "CTO", "CEO", "founder", "команды"],
}


def extract_emails(text: str) -> list[str]:
    """Вытащить все правдоподобные email из текста (вакансии/страницы).

    Ловим и mailto:-ссылки в HTML-описаниях ATS — там часто "написать нам".
    Поддерживает декодирование HTML-сущностей, URL-кодирования (%40) и обфускаций ([at], (at), [dot]).
    """
    if not text:
        return []
    cleaned_text = (text.replace("&#64;", "@")
                        .replace("&#x40;", "@")
                        .replace("%40", "@")
                        .replace("&#46;", ".")
                        .replace("&#x2e;", ".")
                        .replace("%2e", "."))
    cleaned_text = re.sub(r"\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}", "@", cleaned_text, flags=re.I)
    cleaned_text = re.sub(r"\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", ".", cleaned_text, flags=re.I)
    cleaned_text = re.sub(r"([a-zA-Z0-9._%+\-]+)\s*@\s*([a-zA-Z0-9.\-]+)\s*\.\s*([a-zA-Z]{2,})", r"\1@\2.\3", cleaned_text)

    found = []
    candidates = (EMAIL_RE.findall(text) +
                  EMAIL_RE.findall(cleaned_text) +
                  re.findall(r"mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", cleaned_text))
    for m in candidates:
        e = m.strip(".").lower()
        if (not e[0].isalnum() or
                e.split("@", 1)[1].endswith((".example", ".test", ".invalid", ".localhost")) or
                any(b in e for b in BAD_EMAIL_PARTS)):
            continue
        if e not in found:
            found.append(e)
    return found[:10]


TG_HANDLE_RE = re.compile(
    r"""(?xi)
    (?:
        https?://(?:t(?:elegram)?\.me)/(?:s/)?(?P<u1>[a-zA-Z0-9_]{4,32})
        |(?:\b(?:tg|telegram|тг|телеграм)\s*[:=–—\-]?\s*)@?(?P<u2>[a-zA-Z0-9_]{4,32})
        |(?<=[^\w@/])@(?P<u3>[a-zA-Z0-9_]{4,32})
    )
    """
)

TG_IGNORED_HANDLES = {
    "property", "staticmethod", "classmethod", "dataclass", "override",
    "pytest", "fixture", "app", "router", "route", "abstractmethod",
    "param", "return", "returns", "see", "author", "version", "deprecated",
    "type", "id", "name", "join", "share", "channel", "group", "contact",
    "contacts", "jobs", "careers", "about", "team", "support", "help", "admin",
    "gmail", "yahoo", "yandex", "mail", "outlook", "icloud"
}


def extract_telegrams(text: str) -> list[dict]:
    """Извлекает Telegram-контакты из описания вакансии или страницы.

    Классифицирует сущности:
      - bot: имя оканчивается на 'bot' (например, @recruiter_bot)
      - channel: публичный канал (ссылки t.me/s/...)
      - contact: личный аккаунт (@hr_username)
    """
    if not text:
        return []
    found = []
    seen = set()
    for m in TG_HANDLE_RE.finditer(text):
        handle = m.group("u1") or m.group("u2") or m.group("u3")
        if not handle:
            continue
        h_lower = handle.lower()
        if (h_lower in TG_IGNORED_HANDLES or
                h_lower.isdigit() or
                len(h_lower) < 4 or
                len(h_lower) > 32):
            continue

        start = m.start()
        if start > 0 and text[start - 1] in ("@", "."):
            continue
        end = m.end()
        if end < len(text) and text[end] == "@":
            continue

        if h_lower in seen:
            continue
        seen.add(h_lower)

        if h_lower.endswith("bot"):
            kind = "tg_bot"
        elif f"t.me/s/{h_lower}" in text.lower():
            kind = "tg_channel"
        else:
            kind = "tg_contact"

        found.append({
            "handle": f"@{handle}",
            "raw_handle": handle,
            "url": f"https://t.me/{handle}",
            "kind": kind,
        })
    return found[:10]


def domain_from_email(email: str) -> str:
    return email.split("@", 1)[1] if "@" in email else ""


def company_domain_guess(company: str) -> str:
    """Транслитерация имени компании в правдоподобный домен."""
    slug = re.sub(r"[^a-z0-9]+", "", company.lower().replace(" ", ""))
    return f"{slug}.com" if slug else ""


def resolve_company_domain(company: str, jobs: list[dict]) -> str:
    """Лучший домен компании: сначала реальный из найденных email, иначе догадка.

    jobs — вакансии этой компании (можно пустой).
    """
    for j in jobs:
        for e in (j.get("found_emails") or "").split(", "):
            if "@" in e:
                dom = e.split("@", 1)[1]
                if dom and not any(b in dom for b in ("gmail.", "outlook.", "yandex.", "mail.ru")):
                    return dom
    return company_domain_guess(company)


def mx_exists(domain: str) -> bool:
    """Принимает ли домен почту (MX через DoH). Резервный путь — A-запись."""
    if not domain:
        return False
    try:
        rep = _domains.domain_report(domain)
        return bool(rep.get("email_plausible")) or _domains.domain_alive(domain)
    except Exception:
        try:
            return _domains.domain_alive(domain)
        except Exception:
            return False


def contact_hypotheses(company: str, domain: str = "") -> list[dict]:
    """Сгенерировать гипотезы контактов для компании (careers@domain и т.п.)."""
    dom = domain or company_domain_guess(company)
    if not dom:
        return []
    try:
        rep = _domains.domain_report(dom)
    except Exception:
        rep = {"email_plausible": False, "age_years": None}
    out = []
    for local in HYPOTHESIS_LOCAL:
        email = f"{local}@{dom}"
        out.append({
            "email": email,
            "company": company,
            "kind": "hypothesis",
            "verified": bool(rep.get("email_plausible")),
            "domain_age": rep.get("age_years") if rep.get("age_years") is not None else "",
        })
    return out


def people_search_links(company: str, role: str = "") -> list[dict]:
    """Готовые ссылки для ручного поиска живых людей: рекрутеры, нанимающие менеджеры."""
    q_base = urllib.parse.quote
    role_part = f" {role}" if role else ""
    company_q = q_base(company)
    email_query = q_base(f'"{company}" (email OR contact) (recruiting OR hr OR careers)')
    return [
        {
            "label": "LinkedIn: company recruiters",
            "url": f"https://www.linkedin.com/search/results/people/?keywords={q_base('recruiter')}%20{company_q}",
        },
        {
            "label": "LinkedIn: hiring manager",
            "url": f"https://www.linkedin.com/search/results/people/?keywords={q_base(role or 'hiring manager')}%20{company_q}",
        },
        {
            "label": "Google: company site + careers",
            "url": f"https://www.google.com/search?q={q_base(company_domain_guess(company) + ' careers OR jobs OR join us')}",
        },
        {
            "label": "Google: company email",
            "url": f"https://www.google.com/search?q={email_query}",
        },
        {
            "label": "X/Twitter: recruiters",
            "url": f"https://x.com/search?q={q_base(f'{company} recruiter OR hiring')}&f=live",
        },
    ]


def enrich(jobs: list[dict]) -> dict:
    """Обогащение вакансий контактами.

    Возвращает {"jobs": [...], "emails": [...], "links": [...]}:
      jobs — с добавленными found_emails (реальные из описаний);
      emails — сводный список реальных адресов;
      links — поисковые ссылки по компаниям.
    """
    seen_jobs = []
    all_emails = []
    seen_emails = set()
    all_links = []
    seen_companies = set()
    for j in jobs:
        desc = j.get("description", "")
        emails = extract_emails(desc)
        telegrams = extract_telegrams(desc)
        j = dict(j)
        j["found_emails"] = ", ".join(emails)
        if telegrams:
            tg_str = ", ".join(t["handle"] for t in telegrams)
            j["found_telegrams"] = tg_str
            if not j["found_emails"]:
                j["found_emails"] = tg_str
            else:
                j["found_emails"] += f", {tg_str}"
        seen_jobs.append(j)
        for e in emails:
            if e not in seen_emails:
                seen_emails.add(e)
                all_emails.append({"email": e, "company": j.get("company", ""), "source": j.get("source", ""),
                                   "job_url": j.get("url", ""), "kind": "published", "verified": ""})
        for t in telegrams:
            t_handle = t["handle"]
            if t_handle not in seen_emails:
                seen_emails.add(t_handle)
                all_emails.append({"email": t_handle, "company": j.get("company", ""), "source": j.get("source", ""),
                                   "job_url": j.get("url", ""), "kind": t["kind"], "verified": ""})
        comp = j.get("company", "")
        if comp and comp not in seen_companies and not comp.startswith("("):
            seen_companies.add(comp)
            all_links.extend(people_search_links(comp, j.get("title", "")))
    # дедупликация ссылок
    uniq_links = []
    seen_urls = set()
    for l in all_links:
        if l["url"] not in seen_urls:
            seen_urls.add(l["url"])
            uniq_links.append(l)
    return {"jobs": seen_jobs, "emails": all_emails, "links": uniq_links}
