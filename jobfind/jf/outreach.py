"""Генератор писем: черновики холодных сообщений по вакансии/компании.

Шаблоны построены по выводам исследования холодного аутрича (см. README и
.cluster/osint-job-finder/subagent_04.md):
  - тело ~100 слов (50–150), «5 строк, ским за 2 минуты»;
  - тема 6–10 слов, формула «{role} — {highlight}»;
  - ровно один мягкий CTA («отправить резюме?», «15 минут?»);
  - без вложения резюме в первом письме;
  - фоллоу-ап через 3–7 дней, 1–2 раза, тема Re:.
Отправляет всё равно человек — это черновики.
"""

from __future__ import annotations

import re

TEMPLATES = {
    # ---------------------------------------------------------------- EN
    "apply_en": (
        "Subject: {role} — {highlight_short}\n"
        "\n"
        "Hi {name},\n"
        "\n"
        "I saw {company}'s {role} opening and wanted to write directly. {highlight} — "
        "most recently I {metric} while working on {project}.\n"
        "\n"
        "That maps closely to what your{team_phrase} team is building.\n"
        "\n"
        "Would it be useful if I sent my resume, or is there a better person to reach out to?\n"
        "\n"
        "Thanks for your time,\n"
        "{your_name} · {link}"
    ),
    "recruiter_en": (
        "Subject: {role} · quick question about {company}\n"
        "\n"
        "Hi {name},\n"
        "\n"
        "I've been following {company}'s work on {project} — it's exactly the space I work in. "
        "{highlight}.\n"
        "\n"
        "I don't know if you have something open on the{team_phrase} team, but I'd love to stay on "
        "your radar for when you do.\n"
        "\n"
        "Worth a 15-minute chat in the next couple of weeks?\n"
        "\n"
        "Best,\n"
        "{your_name} · {link}"
    ),
    "follow_en": (
        "Subject: Re: {role} — {highlight_short}\n"
        "\n"
        "Hi {name},\n"
        "\n"
        "Just circling back on my note from {date} — I know inboxes get busy.\n"
        "\n"
        "Quick recap: {highlight}, and I think it fits what {company}'s{team_phrase} team is working on.\n"
        "\n"
        "Would you like me to send my resume? Either way, thanks for your time.\n"
        "\n"
        "{your_name} · {link}"
    ),
    # ---------------------------------------------------------------- RU
    "apply_ru": (
        "Тема: {role} — {highlight_short}\n"
        "\n"
        "Здравствуйте, {name}!\n"
        "\n"
        "Откликаюсь на вакансию {role} в {company}. {highlight} — на прошлом месте я {metric} "
        "в рамках проекта {project}.\n"
        "\n"
        "Кажется, это близко к задачам команды{team_phrase}.\n"
        "\n"
        "Подскажите, отправить резюме ответом на это письмо или лучше написать коллеге?\n"
        "\n"
        "Спасибо за время,\n"
        "{your_name} · {link}"
    ),
    "recruiter_ru": (
        "Тема: {role} · вопрос про {company}\n"
        "\n"
        "Здравствуйте, {name}!\n"
        "\n"
        "Слежу за тем, что {company} делает с {project}, — это ровно та задача, в которой я сейчас "
        "работаю. Сейчас я {highlight}.\n"
        "\n"
        "Не знаю, есть ли открытая позиция в команде{team_phrase}, но хотел(а) бы остаться на радаре.\n"
        "\n"
        "Удобно ли созвониться на 15 минут в ближайшие недели?\n"
        "\n"
        "С уважением,\n"
        "{your_name} · {link}"
    ),
    "follow_ru": (
        "Тема: Re: {role} — {highlight_short}\n"
        "\n"
        "Здравствуйте, {name}!\n"
        "\n"
        "Возвращаюсь к своему письму от {date} — понимаю, что почта забита.\n"
        "\n"
        "Коротко: {highlight}, и, кажется, это хорошо ложится на задачи команды{team_phrase} в {company}.\n"
        "\n"
        "Отправить вам резюме? В любом случае спасибо за время.\n"
        "\n"
        "{your_name} · {link}"
    ),
}


def render(template: str, ctx: dict) -> tuple[str, set]:
    tpl = TEMPLATES[template]
    out = tpl
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", str(v or ""))
    leftover = set(re.findall(r"\{(\w+)\}", out))
    return out, leftover


def build_ctx(job: dict, profile: dict, name: str, contacts: str, extra: dict | None = None,
              lang: str = "en") -> dict:
    import datetime
    skills = ", ".join((profile.get("skills") or [])[:6]) or "—"
    highlight = (profile.get("highlight") or "").strip() or ("relevant experience in this field" if lang == "en" else "релевантный опыт в этой области")
    short = highlight.split(",")[0].split(".")[0][:48] if highlight else "relevant experience"
    titles = profile.get("titles") or []
    role = job.get("title") or (titles[0] if titles else ("your opening" if lang == "en" else "ваша вакансия"))
    recipient = (extra or {}).get("recipient") or ("there" if lang == "en" else "коллеги")
    team = (profile.get("team") or "").strip()
    team_phrase = (" " + team) if (lang == "en" and team) else (f" «{team}»" if team else "")
    ctx = {
        "company": job.get("company") or ("your company" if lang == "en" else "компания"),
        "role": role,
        "name": recipient,
        "your_name": name or "—",
        "skills": skills,
        "highlight": highlight,
        "highlight_short": short,
        "metric": (profile.get("metric") or ("improved key metrics" if lang == "en" else "улучшил(а) ключевые метрики")),
        "project": (profile.get("project") or ("a key product" if lang == "en" else "ключевой продукт")),
        "team": team,
        "team_phrase": team_phrase,
        "link": contacts or "",
        "date": (extra or {}).get("date") or datetime.date.today().strftime("%d.%m.%Y"),
    }
    return ctx


def draft_for_job(job: dict, profile: dict, name: str, contacts: str, lang: str = "en",
                  kind: str = "apply", recipient: str = "", extra: dict | None = None) -> tuple[str, set]:
    merged_extra = {"recipient": recipient}
    if extra:
        merged_extra.update(extra)
    ctx = build_ctx(job, profile, name, contacts, merged_extra, lang)
    tpl = f"{kind}_{lang}"
    if tpl not in TEMPLATES:
        raise ValueError(f"No template {tpl}; available: {', '.join(TEMPLATES)}")
    return render(tpl, ctx)
