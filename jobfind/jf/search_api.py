"""Optional official search APIs; credentials stay in the environment/osint-keys.env."""
import base64
import os
from pathlib import Path

from dotenv import dotenv_values
from defusedxml import ElementTree as ET

from . import net


def settings() -> dict:
    saved = dotenv_values(Path(__file__).resolve().parents[1] / "osint-keys.env")
    names = ("BRAVE_SEARCH_API_KEY", "YANDEX_SEARCH_API_KEY", "YANDEX_SEARCH_FOLDER_ID")
    return {name: os.environ.get(name, saved.get(name) or "").strip() for name in names}


def configured(backend: str) -> bool:
    values = settings()
    return (bool(values["BRAVE_SEARCH_API_KEY"]) if backend == "brave" else
            bool(values["YANDEX_SEARCH_API_KEY"] and values["YANDEX_SEARCH_FOLDER_ID"]) if backend == "yandex" else False)


def search(query: str, backend: str, limit: int):
    from .osint import SearchRows, _relevant, _result
    values = settings()
    limit = max(1, min(int(limit), 100))
    rows, candidates, filtered = [], 0, 0
    if backend == "brave":
        for offset in range((limit + 19) // 20):
            response = net.get("https://api.search.brave.com/res/v1/web/search",
                {"q": query, "count": min(limit, 20), "offset": offset, "extra_snippets": "true"},
                retries=1, extra_headers={"X-Subscription-Token": values["BRAVE_SEARCH_API_KEY"], "Accept": "application/json"})
            payload = response.json(log_errors=False)
            items = (payload.get("web") or {}).get("results") if isinstance(payload, dict) else None
            if response.status != 200 or not isinstance(items, list):
                error = f"Brave Search API: HTTP {response.status}; check osint-keys.env credentials/quota" if response.status else "Brave Search API: request failed"
                if rows:
                    rows[0]["_source_warning"] = error
                    break
                raise RuntimeError(error)
            for item in items:
                if not isinstance(item, dict):
                    continue
                row = _result(item.get("title"), item.get("url"), item.get("description"), "Brave", "Web")
                if row:
                    candidates += 1
                    if _relevant(row, query):
                        rows.append(row)
                    else:
                        filtered += 1
            if len(rows) >= limit or not payload.get("query", {}).get("more_results_available"):
                break
    elif backend == "yandex":
        response = net.post_json("https://searchapi.api.cloud.yandex.net/v2/web/search",
            {"query": {"searchType": "ru", "queryText": query},
             "groupSpec": {"groupsOnPage": str(limit), "docsInGroup": "1"},
             "folderId": values["YANDEX_SEARCH_FOLDER_ID"], "responseFormat": "XML"}, retries=0,
            extra_headers={"Authorization": "Api-Key " + values["YANDEX_SEARCH_API_KEY"]})
        payload = response.json(log_errors=False)
        if response.status != 200 or not isinstance(payload, dict) or not isinstance(payload.get("rawData"), str):
            raise RuntimeError(f"Yandex Search API: HTTP {response.status}; check osint-keys.env credentials/quota")
        try:
            root = ET.fromstring(base64.b64decode(payload["rawData"], validate=True))
        except Exception as exc:
            raise RuntimeError("Yandex Search API: invalid XML response") from exc
        if root.find(".//error") is not None:
            raise RuntimeError("Yandex Search API: source returned an error; check quota and query")
        for item in root.findall(".//doc"):
            row = _result(" ".join(item.find("title").itertext()) if item.find("title") is not None else "",
                item.findtext("url"), " ".join(item.find("passages").itertext()) if item.find("passages") is not None else "",
                "Yandex", "Web")
            if row:
                candidates += 1
                if _relevant(row, query):
                    rows.append(row)
                else:
                    filtered += 1
    else:
        raise ValueError("Unsupported official search API")
    return SearchRows(rows[:limit], candidates=candidates, filtered=filtered, method=f"{backend.capitalize()} official Search API")
