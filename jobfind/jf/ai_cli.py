"""Read-only text adapters for locally installed Codex, Claude, and Grok CLIs.

Authentication belongs to each CLI. FindAll passes prompts through stdin or a
temporary file, never through a shell command line.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


PROVIDERS = ("codex", "claude", "grok")
_MODEL = re.compile(r"[A-Za-z0-9._/:-]{1,120}\Z")


def _executable(provider: str) -> str:
    if provider not in PROVIDERS:
        return ""
    for name in (provider, f"{provider}.exe", f"{provider}.cmd"):
        path = shutil.which(name)
        if path:
            return path
    return ""


def available(provider: str) -> bool:
    """Report local CLI presence; this does not prove login or model access."""
    return bool(_executable(provider))


def _prompt(messages: list[dict], max_tokens: int) -> str:
    if not isinstance(messages, list) or not 1 <= max_tokens <= 4096:
        raise ValueError("Invalid messages or max_tokens")
    parts = [f"Return only the requested text. Use at most {max_tokens} tokens. "
             "Do not browse, inspect local files, or run tools."]
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("Invalid message")
        role = message.get("role")
        content = message.get("content")
        if role not in ("system", "developer", "user", "assistant") or not isinstance(content, str):
            raise ValueError("Only text messages with standard roles are supported")
        parts.append(f"{role.upper()}:\n{content}")
    prompt = "\n\n".join(parts).strip()
    if len(prompt) > 128_000:
        raise ValueError("Prompt exceeds 128000 characters")
    return prompt


def chat(provider: str, model: str, messages: list[dict], max_tokens: int) -> str:
    """Call one installed CLI in a disposable, read-only working directory.

    max_tokens is an instruction to the CLI model; these CLIs do not expose a
    shared hard output-token cap. The caller should validate structured output.
    """
    provider = str(provider).strip().lower()
    exe = _executable(provider)
    if not exe:
        raise RuntimeError(f"{provider or 'Unknown'} CLI is not installed")
    model = str(model or "").strip()
    if model and not _MODEL.fullmatch(model):
        raise ValueError("Invalid model name")
    prompt = _prompt(messages, max_tokens)
    env = os.environ.copy()
    env.pop("JOBFIND_AI_API_KEY", None)
    with tempfile.TemporaryDirectory(prefix="jobfind-ai-") as work:
        root = Path(work)
        if provider == "codex":
            answer_file = root / "answer.txt"
            command = [exe, "exec", "--skip-git-repo-check", "--sandbox", "read-only",
                       "--ephemeral", "--ignore-user-config", "--ignore-rules", "--cd", work,
                       "--output-last-message", str(answer_file), "--color", "never"]
            if model:
                command.extend(("--model", model))
            command.append("-")
            stdin = prompt
        elif provider == "claude":
            command = [exe, "-p", "--system-prompt",
                       "Return only the final answer. Do not use tools or inspect files.",
                       "--output-format", "json", "--permission-mode", "plan",
                       "--tools", "", "--no-session-persistence", "--safe-mode"]
            if model:
                command.extend(("--model", model))
            stdin = prompt
        else:
            prompt_file = root / "prompt.txt"
            prompt_file.write_text(prompt, encoding="utf-8")
            command = [exe, "--prompt-file", str(prompt_file), "--no-memory",
                       "--no-subagents", "--disable-web-search", "--max-turns", "1",
                       "--permission-mode", "plan", "--tools", "",
                       "--output-format", "plain", "--verbatim", "--cwd", work]
            if model:
                command.extend(("--model", model))
            stdin = None
        try:
            input_arg = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
            proc = subprocess.run(command, **input_arg, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=75, cwd=work,
                                  env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{provider} CLI timed out") from exc
        except OSError as exc:
            raise RuntimeError(f"{provider} CLI could not start ({type(exc).__name__})") from exc
        if proc.returncode:
            raise RuntimeError(f"{provider} CLI failed (exit {proc.returncode})")
        if provider == "codex":
            answer = answer_file.read_text(encoding="utf-8", errors="replace").strip() if answer_file.exists() else ""
        elif provider == "claude":
            try:
                data = json.loads(proc.stdout)
                answer = str(data.get("result") or "").strip() if not data.get("is_error") else ""
            except (ValueError, AttributeError):
                answer = ""
        else:
            answer = proc.stdout.strip()
        if not answer:
            raise RuntimeError(f"{provider} CLI returned no answer")
        return answer


def _self_check() -> None:
    from unittest.mock import patch

    assert not available("unknown")
    assert "USER:\nhello" in _prompt([{"role": "user", "content": "hello"}], 20)
    assert not _MODEL.fullmatch("model; whoami")
    with patch(__name__ + ".shutil.which", return_value="C:/fake/grok.exe"), patch(
        __name__ + ".subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, stdout="OK", stderr=""),
    ) as run:
        assert chat("grok", "", [{"role": "user", "content": "secret prompt"}], 32) == "OK"
        args = run.call_args.args[0]
        assert "secret prompt" not in " ".join(args)
        assert args[1] == "--prompt-file"


if __name__ == "__main__":
    _self_check()
    print("AI CLI checks passed")
