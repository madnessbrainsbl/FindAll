"""Telegram notifications for FindAll job matches and scans.

Sends compact HTML digests of top-scoring vacancies via the Telegram Bot API.
Credentials can be passed via CLI arguments, environment variables, or profile.json.
"""

from __future__ import annotations

import html
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


def resolve_telegram_credentials(args: Any = None, profile: dict | None = None) -> tuple[str, str]:
    """Resolves Telegram Bot token and target chat/channel ID from CLI, env, or profile."""
    token = ""
    chat_id = ""

    if args:
        token = getattr(args, "tg_token", "") or ""
        chat_id = getattr(args, "tg_chat", "") or ""

    if not token:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not chat_id:
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if profile and isinstance(profile, dict):
        if not token:
            token = str(profile.get("telegram_bot_token", "")).strip()
        if not chat_id:
            chat_id = str(profile.get("telegram_chat_id", "")).strip()

    return token, chat_id


def send_telegram(token: str, chat_id: str, text: str, *, parse_mode: str = "HTML") -> tuple[bool, str]:
    """Sends a message via the Telegram Bot API."""
    token = token.strip()
    chat_id = chat_id.strip()
    if not token:
        return False, "Telegram bot token is missing"
    if not chat_id:
        return False, "Telegram chat ID is missing"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "FindAll-Notifier/1.0"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            res = json.loads(resp_body)
            if res.get("ok"):
                return True, "OK"
            return False, res.get("description", "Unknown Telegram API error")
    except urllib.error.HTTPError as exc:
        err_msg = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
        try:
            parsed = json.loads(err_msg)
            return False, parsed.get("description", str(exc))
        except Exception:
            return False, f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, str(exc)


def format_top_jobs_digest(
    scored_jobs: list[dict],
    profile_name: str = "",
    top_n: int = 5,
    min_score: int = 60,
) -> str:
    """Formats an HTML digest of top-scoring jobs for Telegram."""
    qualifying = [j for j in scored_jobs if (j.get("score") or 0) >= min_score][:top_n]
    if not qualifying:
        return ""

    header_parts = ["🎯 <b>FindAll: Подборка вакансий</b>"]
    if profile_name:
        header_parts.append(f"👤 Профиль: <b>{html.escape(profile_name)}</b>")
    header_parts.append("")

    cards = []
    for idx, j in enumerate(qualifying, 1):
        title = html.escape(str(j.get("title") or "Unknown Position"))
        comp = html.escape(str(j.get("company") or "Unknown Company"))
        score = j.get("score", 0)

        meta_parts = [f"⭐ <b>{score}/100</b>"]
        sal = j.get("salary")
        if sal and isinstance(sal, dict) and sal.get("raw"):
            meta_parts.append(f"💰 {html.escape(sal['raw'])}")
        grade = j.get("grade")
        if grade:
            meta_parts.append(f"🏷 {html.escape(str(grade))}")
        if j.get("remote"):
            meta_parts.append("🌐 remote")

        loc = (j.get("location") or "").strip()
        loc_str = f"📍 {html.escape(loc)}" if loc else ""

        skills = j.get("matched_skills") or []
        skills_str = ""
        if skills:
            skills_str = "🛠 " + ", ".join(f"<code>{html.escape(sk)}</code>" for sk in skills[:5])

        contact = (j.get("found_emails") or "").strip()
        contact_str = ""
        if contact:
            contact_str = f"📬 <i>{html.escape(contact)}</i>"

        url = j.get("url") or ""
        url_str = f'🔗 <a href="{html.escape(url)}">Открыть вакансию</a>' if url else ""

        lines = [
            f"{idx}. <b>{title}</b> — {comp}",
            " | ".join(meta_parts),
        ]
        if loc_str:
            lines.append(loc_str)
        if skills_str:
            lines.append(skills_str)
        if contact_str:
            lines.append(contact_str)
        if url_str:
            lines.append(url_str)

        cards.append("\n".join(lines))

    footer = f"\n📊 <i>Всего отобрано {len(qualifying)} позиций с оценкой ≥{min_score}</i>"
    return "\n\n".join(header_parts + cards) + footer
