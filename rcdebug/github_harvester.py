"""
GitHub Open-Source Luau Experiment Harvester (zero-dependency stdlib).

Fetches public .luau/.lua files from GitHub repositories, extracts structural
Context + Sink + Guard idioms, and distills them into FlawBrain and learned_flaws.json.
"""

from __future__ import annotations

import json
import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from .learner import FlawBrain
from .models import Finding

GITHUB_SEARCH_REPOS_URL = "https://api.github.com/search/repositories"
USER_AGENT = "rcdebug-luau-harvester/1.0"

_REMOTE_RE = re.compile(r"(\w+)\.(?:OnServerEvent|OnServerInvoke)")
_DS_RE = re.compile(r":\s*(UpdateAsync|SetAsync|GetAsync)\s*\(")
_CLEANUP_RE = re.compile(r"\b(Trove|Janitor|Maid|Debris:AddItem)\b")
_GUARD_RE = re.compile(r"\b(typeof|os\.clock|pcall|math\.clamp)\b")


@dataclass(frozen=True, slots=True)
class HarvestResult:
    repos_scanned: int
    files_distilled: int
    patterns_learned: int
    offline_fallback: bool
    message: str


def _ssl_context() -> ssl.SSLContext:
    macos_ca = Path("/etc/ssl/cert.pem")
    if macos_ca.exists():
        return ssl.create_default_context(cafile=str(macos_ca))
    return ssl.create_default_context()


def _github_get_json(url: str, timeout: float = 5.0) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _github_get_text(url: str, timeout: float = 5.0) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    with urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
        return resp.read().decode("utf-8", errors="replace")


def distill_luau_source(source: str, repo_name: str, file_path: str, brain: FlawBrain) -> int:
    """
    Extracts Context + Sink + Guard patterns from a Luau source file and
    ingests them into `brain`. Returns count of distilled records.
    """
    distilled = 0
    has_guard = bool(_GUARD_RE.search(source))
    has_cleanup = bool(_CLEANUP_RE.search(source))

    for m in _REMOTE_RE.finditer(source):
        remote_name = m.group(1)
        sev = "INFO" if has_guard else "CRITICAL"
        brain.ingest_flaw_record(
            domain="RemoteSecurity",
            severity=sev,
            text=f"{remote_name} OnServerEvent {repo_name} {file_path}",
            fix=f"Validate typeof() and os.clock() cooldowns on {remote_name}.",
        )
        distilled += 1

    for m in _DS_RE.finditer(source):
        op = m.group(1)
        sev = "INFO" if op == "UpdateAsync" else "CRITICAL"
        brain.ingest_flaw_record(
            domain="Platform",
            severity=sev,
            text=f"DataStore {op} {repo_name} {file_path}",
            fix="Use DataStore:UpdateAsync() inside pcall() with session locking.",
        )
        distilled += 1

    if has_cleanup:
        brain.ingest_flaw_record(
            domain="Performance",
            severity="INFO",
            text=f"Lifecycle cleanup Trove Janitor Debris {repo_name}",
            fix="Bind RBXScriptConnections and transient instances to Trove/Janitor.",
        )
        distilled += 1

    return distilled


def harvest_github_luau(
    query: str = "roblox luau",
    brain: FlawBrain | None = None,
    max_repos: int = 3,
    max_files_per_repo: int = 3,
) -> HarvestResult:
    """
    Searches public GitHub repositories for Luau code, downloads sample .luau/.lua
    files, and distills idioms into `FlawBrain`. Gracefully handles offline/rate-limit errors.
    """
    target_brain = brain or FlawBrain()
    q = quote_plus(f"{query} language:Luau")
    search_url = f"{GITHUB_SEARCH_REPOS_URL}?q={q}&sort=stars&order=desc&per_page={max_repos}"

    try:
        search_data = _github_get_json(search_url)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return HarvestResult(
            repos_scanned=0,
            files_distilled=0,
            patterns_learned=0,
            offline_fallback=True,
            message=f"GitHub API unavailable ({exc}); using local 120k flaw corpus & FlawBrain.",
        )

    items = search_data.get("items", []) if isinstance(search_data, dict) else []
    repos_scanned = 0
    files_distilled = 0
    patterns_learned = 0

    for repo in items[:max_repos]:
        full_name = repo.get("full_name")
        default_branch = repo.get("default_branch", "main")
        if not full_name:
            continue
        repos_scanned += 1
        tree_url = f"https://api.github.com/repos/{full_name}/git/trees/{default_branch}?recursive=1"
        try:
            tree_data = _github_get_json(tree_url)
        except Exception:
            continue

        tree = tree_data.get("tree", []) if isinstance(tree_data, dict) else []
        luau_paths = [
            node["path"]
            for node in tree
            if isinstance(node, dict)
            and node.get("type") == "blob"
            and str(node.get("path", "")).endswith((".luau", ".lua"))
        ][:max_files_per_repo]

        for fpath in luau_paths:
            raw_url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{fpath}"
            try:
                src = _github_get_text(raw_url)
            except Exception:
                continue
            files_distilled += 1
            patterns_learned += distill_luau_source(src, full_name, fpath, target_brain)

    if patterns_learned > 0:
        target_brain.save()

    return HarvestResult(
        repos_scanned=repos_scanned,
        files_distilled=files_distilled,
        patterns_learned=patterns_learned,
        offline_fallback=False,
        message=f"Harvested {files_distilled} Luau files across {repos_scanned} GitHub repo(s).",
    )
