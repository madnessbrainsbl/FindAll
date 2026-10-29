"""Explicit local source audit. Secret values never enter FindAll reports."""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from . import net

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "third_party" / "gitleaks" / "gitleaks.exe"
UPSTREAM = "https://github.com/gitleaks/gitleaks"


def install():
    if os.name != "nt":
        raise ValueError("Bundled installation supports Windows; use an installed Gitleaks elsewhere")
    data = net.get("https://api.github.com/repos/gitleaks/gitleaks/releases/latest", retries=0).json(log_errors=False)
    if not isinstance(data, dict):
        # A verified upstream release pin remains usable when GitHub's API quota
        # is exhausted. Download and checksum still come from that exact tag.
        version = "8.30.1"
        data = {"tag_name": "v" + version, "assets": [
            {"name": f"gitleaks_{version}_{suffix}", "browser_download_url":
             f"{UPSTREAM}/releases/download/v{version}/gitleaks_{version}_{suffix}"}
            for suffix in ("windows_x64.zip", "checksums.txt")]}
    assets = {item["name"]: item["browser_download_url"] for item in data.get("assets", []) if isinstance(item, dict)}
    package = next((name for name in assets if name.endswith("windows_x64.zip")), "")
    checksum = next((name for name in assets if name.endswith("checksums.txt")), "")
    if not package or not checksum:
        raise RuntimeError("Official Windows archive/checksum missing")
    if any(not assets[name].startswith(UPSTREAM + "/releases/download/") for name in (package, checksum)):
        raise RuntimeError("Unexpected release asset location")
    checksum_result = net.get(assets[checksum], retries=0)
    archive_result = net.get(assets[package], retries=0)
    if checksum_result.error or archive_result.error:
        raise RuntimeError("Unable to download the official release assets")
    checksum_rows = [line.split() for line in checksum_result.text.splitlines()]
    expected = next((parts[0].lower() for parts in checksum_rows if len(parts) == 2 and parts[1].lstrip("*") == package), "")
    actual = hashlib.sha256(archive_result.body).hexdigest()
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or expected != actual:
        raise RuntimeError("Release archive checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(archive_result.body)) as archive:
        entry = next((info for info in archive.infolist() if info.filename == "gitleaks.exe"), None)
        if entry is None or entry.file_size > 80_000_000:
            raise RuntimeError("Invalid Gitleaks executable archive")
        payload = archive.read(entry)
        license_entry = next((info for info in archive.infolist() if info.filename in {"LICENSE", "LICENSE.txt"}
                              and info.file_size < 100_000), None)
        license_text = archive.read(license_entry) if license_entry else None
    BIN.parent.mkdir(parents=True, exist_ok=True)
    BIN.write_bytes(payload)
    if license_text:
        (BIN.parent / "LICENSE").write_bytes(license_text)
    metadata = {"upstream": UPSTREAM, "version": data.get("tag_name"), "archive_sha256": actual,
                "binary_sha256": hashlib.sha256(payload).hexdigest(),
                "verification": "Archive matches upstream checksum downloaded over HTTPS; not a signature verification"}
    (BIN.parent / "INTEGRATION.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {"status": "installed", **metadata}


def scan(path, output, *, history=False, timeout=120):
    target = Path(path).resolve()
    if not target.is_dir():
        raise ValueError("Choose an existing local source directory")
    if history and not (target / ".git").exists():
        raise ValueError("Git history audit requires a Git repository")
    executable = str(BIN) if BIN.is_file() else shutil.which("gitleaks")
    if not executable:
        return {"status": "unavailable", "error": "Install Gitleaks with local-audit --install"}
    timeout = max(5, min(int(timeout), 600))
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="findall-local-audit-") as scratch:
        report = Path(scratch) / "redacted.json"
        argv = [executable, "git" if history else "dir", str(target), "--redact=100", "--no-banner",
                "--no-color", "--log-level", "error", "--max-target-megabytes", "5", "--timeout", str(timeout),
                "--report-format", "json", "--report-path", str(report)]
        env = {key: value for key, value in os.environ.items() if key not in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")}
        timed_out = False
        try:
            process = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout + 5, env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out, code = True, None
        raw = []
        report_valid = False
        if report.is_file() and report.stat().st_size <= 20_000_000:
            try:
                raw = json.loads(report.read_text(encoding="utf-8"))
                report_valid = isinstance(raw, list)
            except (ValueError, OSError):
                timed_out = True
        if not report_valid or (code == 1 and not raw):
            timed_out = True
        findings = [{key: row[key] for key in ("RuleID", "File", "StartLine", "EndLine", "Commit", "Date") if key in row}
                    for row in raw[:1000] if isinstance(row, dict)] if isinstance(raw, list) else []
    result = {"status": "partial" if timed_out else "error" if code not in (0, 1) else "findings" if findings else "no_findings",
              "scope": "git_history" if history else "local_files", "findings": findings,
              "truncated": isinstance(raw, list) and len(raw) > len(findings),
              "limitations": "Findings are unverified candidates. Values, matches, authors and emails are excluded; tokens are never validated."}
    destination = output / ("gitleaks-" + os.urandom(8).hex() + ".json")
    result["report"] = str(destination)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
