"""Проверка доменов компаний: MX (реальная, через DoH), возраст (RDAP), карьерные адреса.

Идея и вдохновение: Lissy93/web-check (OSINT-панель домена), упрощено до stdlib.
DoH: https://cloudflare-dns.com/dns-query (Accept: application/dns-json)
RDAP: https://rdap.org/domain/{domain} (редирект на权威ный registry)
"""

from __future__ import annotations

import datetime
import json
import urllib.parse

from . import net

DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_PROVIDERS = [
    ("Cloudflare", "https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
    ("Google", "https://dns.google/resolve", {"Accept": "application/json"}),
]
RDAP_URL = "https://rdap.org/domain/"


def _dns_query(name: str, rtype: str) -> dict:
    for provider, url, headers in DOH_PROVIDERS:
        try:
            r = net.get(url, {"name": name, "type": rtype}, extra_headers=headers)
            if r.status == 200 and not r.error:
                data = r.json()
                if isinstance(data, dict) and "Status" in data:
                    return data
        except Exception:
            continue
    return {}


def mx_records(domain: str) -> list[str]:
    """Реальные MX-записи домена (пусто = домен не принимает почту)."""
    if not domain or "." not in domain:
        return []
    d = _dns_query(domain, "MX")
    if d.get("Status") != 0:
        return []
    out = []
    for a in d.get("Answer", []):
        if a.get("type") == 15:
            data = str(a.get("data", "")).strip()
            # "10 aspmx.l.google.com." -> приоритет + хост
            parts = data.split(None, 1)
            if len(parts) == 2:
                priority, host = parts
                # RFC 7505 null MX: явное объявление, что домен не принимает почту.
                if priority == "0" and host == ".":
                    continue
                out.append(f"{priority} {host.rstrip('.')}".strip())
            elif data:
                out.append(data.rstrip("."))
    return out


def txt_records(name: str) -> list[str]:
    """Публичные TXT-записи: используется для SPF и DMARC, без проверки политики."""
    if not name or "." not in name:
        return []
    data = _dns_query(name, "TXT")
    if data.get("Status") != 0:
        return []
    return [str(a.get("data", "")).strip().strip('"') for a in data.get("Answer", [])
            if a.get("type") == 16]


def mail_config(domain: str) -> dict:
    """Показывает наличие MX/SPF/DMARC; наличие записи не подтверждает доставку."""
    txt = txt_records(domain)
    dmarc_txt = txt_records(f"_dmarc.{domain}")
    return {
        "mx": mx_records(domain),
        "spf": [record for record in txt if record.lower().startswith("v=spf1")],
        "dmarc": [record for record in dmarc_txt if record.lower().startswith("v=dmarc1")],
    }


def domain_alive(domain: str) -> bool:
    """Домен вообще существует (ANY-ответ без NXDOMAIN)."""
    if not domain or "." not in domain:
        return False
    d = _dns_query(domain, "A")
    status = d.get("Status")
    return status == 0


def domain_age_years(domain: str) -> float | None:
    """Возраст домена в годах по RDAP (registration event). None = не удалось."""
    r = net.get(RDAP_URL + urllib.parse.quote(domain.lower()),
                extra_headers={"Accept": "application/rdap+json"})
    data = r.json()
    if not isinstance(data, dict):
        return None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                dt = datetime.datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00"))
                return round((datetime.datetime.now(datetime.timezone.utc) - dt).days / 365.25, 1)
            except (ValueError, KeyError):
                return None
    return None


def domain_report(domain: str, conn=None) -> dict:
    """Structured DNS/registration with the original mail-summary keys retained.
    Uses SQLite domain_cache with 24h TTL if conn is provided."""
    clean_domain = (domain or "").strip().lower()
    if conn and clean_domain:
        from . import db
        cached = db.cache_get_domain(conn, clean_domain, "domain_card")
        if cached:
            return cached
    from .domain_enrichment import domain_card
    card = domain_card(domain)
    if conn and clean_domain:
        from . import db
        db.cache_set_domain(conn, clean_domain, "domain_card", card, ttl_seconds=86400)
    return card


def verify_company_domains(companies: list[str], guess_fn) -> list[dict]:
    """Для списка компаний: домен-догадка -> отчёт. guess_fn(company) -> domain."""
    out = []
    for c in companies:
        dom = guess_fn(c)
        if not dom:
            continue
        rep = domain_report(dom)
        rep["company"] = c
        out.append(rep)
    return out


if __name__ == "__main__":  # ручной тест: python -m jf.domains stripe.com
    import sys
    for d in sys.argv[1:]:
        print(json.dumps(domain_report(d), ensure_ascii=False, indent=2))
