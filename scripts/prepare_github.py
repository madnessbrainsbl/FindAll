"""Export selected source files without modifying the working installation."""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
import shutil


ROOT_FILES = (
    "README.md", ".gitignore", ".gitattributes", "CONTRIBUTING.md", "SECURITY.md",
    "THIRD_PARTY_NOTICES.md", ".gitleaks.toml", "start.bat", "docs/GITHUB_PUBLICATION.md",
)
SOURCE_DIRS = (
    ".github", "scripts", "docs/media", "jobfind/jf", "jobfind/tests", "jobfind/docs",
    "jobfind/examples", "jobfind/rust-ui/src", "jobfind/third_party/phoneinfoga-bridge",
)
VENDORS = {
    "apex-parser": "LICENSE",
    "awesome-osint-arsenal": "LICENSE",
    "chrome-crawler": "LICENSE",
    "github-email-hunter": "LICENCE",
    "parser-2gis": "LICENSE",
    "spiderfoot": "LICENSE",
    "waymore": "waymore-8.9.dist-info/licenses/LICENSE",
    "web-check": "LICENSE",
    "wiretapper": "LICENSE-NONCOMMERCIAL.md",
}
SKIP_DIRS = {
    ".git", ".venv", ".tools-venv", ".harvester-venv", "__pycache__",
    "node_modules", "target", "dist", "build", "logs", "coverage",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache", ".idea", ".vscode",
    "jobfind_out", "network", "_archive", "github-ready", ".research",
}
SKIP_SUFFIXES = {
    ".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".log", ".exe", ".dll",
    ".pdb", ".zip", ".7z", ".gz", ".tar", ".whl", ".safetensors",
    ".traineddata", ".pem", ".key",
}


def publishable(path: Path) -> bool:
    parts = tuple(part.lower() for part in path.parts)
    name = parts[-1]
    if any(part in SKIP_DIRS for part in parts):
        return False
    if "third_party" in parts and any(part in {".github", "test", "tests", "uploads"} for part in parts):
        return False
    if name in {"profile.json", "session.json", ".ds_store", "thumbs.db"}:
        return False
    if name.startswith("cookies") and path.suffix.lower() in {".json", ".txt"}:
        return False
    if not name.endswith(".example") and (
        name == ".env" or name.startswith(".env.") or name.endswith(".env")
    ):
        return False
    return path.suffix.lower() not in SKIP_SUFFIXES and not name.endswith((".db-wal", ".db-shm", ".sqlite3-wal", ".sqlite3-shm"))


def source_files(root: Path):
    paths = [root / name for name in ROOT_FILES]
    paths += list((root / "jobfind").glob("*.bat"))
    paths += list((root / "jobfind").glob("*.ps1"))
    paths += list((root / "jobfind").glob("requirements*.txt"))
    paths += [root / "jobfind" / name for name in (
        ".gitignore", "AGENTS.md", "README.md", "jobfind.py", "profile.example.json",
        "osint-keys.env.example", "rust-ui/Cargo.toml", "rust-ui/Cargo.lock",
        "third_party/flowsint/LICENSE", "third_party/flowsint/NOTICE",
        "third_party/phoneinfoga/LICENSE",
    )]
    directories = [root / name for name in SOURCE_DIRS]
    for name, license_path in VENDORS.items():
        vendor = root / "jobfind/third_party" / name
        if not (vendor / license_path).is_file():
            raise ValueError(f"Missing required upstream notice: {name}/{license_path}")
        directories.append(vendor)
    for directory in directories:
        if not directory.is_dir():
            raise ValueError(f"Missing source directory: {directory.relative_to(root)}")
        for current, dirs, files in os.walk(directory, followlinks=False):
            current = Path(current)
            dirs[:] = sorted(d for d in dirs if publishable((current / d).relative_to(root)))
            for name in dirs + files:
                if (current / name).is_symlink():
                    raise ValueError(f"Refusing symbolic link: {(current / name).relative_to(root)}")
            paths.extend(current / name for name in sorted(files))
    for path in sorted(set(paths)):
        relative = path.relative_to(root)
        if not publishable(relative):
            continue
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError(f"Invalid source file: {relative}")
        if path.stat().st_size > 45 * 1024 * 1024:
            raise ValueError(f"Unexpected large source file: {relative}")
        yield path


def prepare(root: Path, destination: Path):
    root, destination = root.resolve(), destination.resolve()
    if destination.exists() or root.is_relative_to(destination):
        raise ValueError("Choose a new destination, outside the source's parent directories")
    files = list(source_files(root))
    destination.mkdir(parents=True)
    for source in files:
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if relative.as_posix() == "jobfind/AGENTS.md":
            text = target.read_text(encoding="utf-8")
            text = re.sub(r"`[A-Za-z]:[^`]+` is read-only\. Do not copy its secrets\.",
                          "Do not copy secrets from other projects.", text)
            target.write_text(text, encoding="utf-8")
    return len(files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New, empty publication directory")
    args = parser.parse_args()
    try:
        count = prepare(Path(__file__).resolve().parents[1], args.destination)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Publication export failed: {error}\n")
    print(f"Exported {count} source files to {args.destination.resolve()}")
    print("Scan with Gitleaks and review the file list before committing or uploading.")
