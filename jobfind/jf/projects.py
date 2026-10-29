"""Поиск публичных GitHub-проектов по навыкам или интересам."""

from __future__ import annotations

from . import net


def search(query: str, limit: int = 30) -> list[dict]:
    query = " ".join(query.split())
    if not query:
        return []
    result = net.get(
        "https://api.github.com/search/repositories",
        {"q": query, "sort": "stars", "order": "desc", "per_page": min(max(limit, 1), 100)},
        extra_headers={"Accept": "application/vnd.github+json"},
    )
    data = result.json()
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise RuntimeError(f"GitHub API: {result.error or 'unexpected response'}")
    projects = [
        {
            "name": item.get("full_name") or item.get("name") or "",
            "url": item.get("html_url") or "",
            "description": item.get("description") or "",
            "language": item.get("language") or "",
            "stars": item.get("stargazers_count") or 0,
            "updated": item.get("updated_at") or "",
            "query": query,
        }
        for item in data["items"]
        if isinstance(item, dict) and item.get("html_url")
    ]
    # GitHub searches READMEs by default; only keep repositories that match the
    # actual project name or description to avoid unrelated keyword mentions.
    terms = [term.casefold() for term in query.split()]
    return [
        project for project in projects
        if all(term in f"{project['name']} {project['description']} {project['language']}".casefold()
               for term in terms)
    ]
