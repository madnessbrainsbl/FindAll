"""Small attribution check for the bundled GitHub Email Hunter."""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "third_party" / "github-email-hunter"))
from ghmail.cli import GithubEmailHunter


def test_author_attribution():
    hunter = GithubEmailHunter(token="local-check")
    hunter.get_public_repos = lambda username, **kwargs: [{"name": "demo", "pushed_at": "2026-09-29"}]
    hunter.get_commits = lambda *args, **kwargs: [
        {"sha": "other", "author": {"login": "collaborator"}},
        {"sha": "owner", "author": {"login": "Target"}},
    ]
    fetched = []
    def fake_get(url, **kwargs):
        fetched.append(url)
        return SimpleNamespace(status_code=200, text="From: Target <target@example.org>\n\n+<stranger@example.org>")
    hunter.session.get = fake_get
    result = hunter.find_email("target", max_repos=1, max_commit_pages=1)
    assert result is not None and result.email == "target@example.org"
    assert len(fetched) == 1 and "/owner.patch" in fetched[0]
    assert hunter.extract_email_from_patch("target", "demo", "none") == "target@example.org"
    hunter.session.get = lambda *args, **kwargs: SimpleNamespace(
        status_code=200, text="Subject: <stranger@example.org>\n\n+<other@example.org>")
    assert hunter.extract_email_from_patch("target", "demo", "none") is None
    hunter.session.close()


if __name__ == "__main__":
    test_author_attribution()
