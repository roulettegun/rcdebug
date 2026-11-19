"""
Rich ANSI terminal rendering, dashboard widgets, and macOS clipboard helpers.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime

from .models import AuditSession, Finding, MemorySnapshot, SeverityFilter, format_filter_label, matches_filter

# ANSI Color & Style Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def severity_color(severity: str) -> str:
    sev = severity.upper()
    if sev == "CRITICAL":
        return RED
    if sev == "WARN":
        return YELLOW
    return CYAN


def severity_badge(severity: str) -> str:
    sev = severity.upper()
    color = severity_color(sev)
    return f"{BOLD}{color}[{sev}]{RESET}"


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the macOS clipboard via pbcopy."""
    if not shutil.which("pbcopy"):
        return False
    try:
        subprocess.run(
            ["pbcopy"],
            input=text.encode("utf-8"),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def print_banner(mode_title: str, subtitle: str = "") -> None:
    width = 74
    border = "═" * width
    print(f"\n{BOLD}{CYAN}╔{border}╗{RESET}")
    title_line = f"  rcdebug v1.0.0 — Revan Cool Debugger ({mode_title})"
    pad = max(0, width - len(title_line))
    print(f"{BOLD}{CYAN}║{WHITE}{title_line}{' ' * pad}{CYAN}║{RESET}")
    if subtitle:
        sub_line = f"  {subtitle}"
        sub_pad = max(0, width - len(sub_line))
        print(f"{BOLD}{CYAN}║{DIM}{WHITE}{sub_line}{' ' * sub_pad}{RESET}{BOLD}{CYAN}║{RESET}")
    print(f"{BOLD}{CYAN}╚{border}╝{RESET}")


def print_finding(finding: Finding, filter_level: SeverityFilter = None) -> None:
    if not matches_filter(finding.severity, filter_level):
        return

    badge = severity_badge(finding.severity)
    cat_tag = f"{MAGENTA}[{finding.category}]{RESET} " if finding.category else ""
    print(f"\n{badge} {cat_tag}{BOLD}{WHITE}{finding.title}{RESET} {DIM}({finding.timestamp}){RESET}")
    print(f"  {BOLD}Instance:{RESET} {CYAN}{finding.path}{RESET}")
    print(f"  {BOLD}Flaw:{RESET}     {finding.flaw}")
    print(f"  {BOLD}Abuse:{RESET}    {YELLOW}{finding.abuse}{RESET}")
    print(f"  {GREEN}{BOLD}Fix:{RESET}      {finding.fix}")
    if finding.code_example:
        print(f"  {DIM}Example Server Pattern:{RESET}")
        for line in finding.code_example.strip().splitlines():
            print(f"    {DIM}{GREEN}{line}{RESET}")
    print(f"{DIM}{'─' * 74}{RESET}")
    sys.stdout.flush()


def print_memory_diff(prev: MemorySnapshot | None, curr: MemorySnapshot) -> None:
    if prev is None:
        print(
            f"\n{BOLD}{BLUE}[TELEMETRY]{RESET} {DIM}({curr.timestamp}){RESET} "
            f"Baseline Snapshot — Workspace: {BOLD}{curr.workspace_instances}{RESET} inst | "
            f"Players: {BOLD}{curr.player_instances}{RESET} inst | "
            f"Memory: {BOLD}{curr.total_memory_mb:.1f} MB{RESET}"
        )
        return

    ws_diff = curr.workspace_instances - prev.workspace_instances
    pl_diff = curr.player_instances - prev.player_instances
    mem_diff = curr.total_memory_mb - prev.total_memory_mb

    ws_str = f"{ws_diff:+d}"
    pl_str = f"{pl_diff:+d}"
    mem_str = f"{mem_diff:+.2f} MB"

    ws_col = RED if ws_diff > 150 else (YELLOW if ws_diff > 40 else GREEN)
    mem_col = RED if mem_diff > 25.0 else (YELLOW if mem_diff > 8.0 else GREEN)

    print(
        f"\n{BOLD}{BLUE}[INSTANCE & MEMORY DIFF]{RESET} {DIM}({curr.timestamp}){RESET} "
        f"Workspace: {BOLD}{curr.workspace_instances}{RESET} ({ws_col}{ws_str}{RESET}) | "
        f"Players: {BOLD}{curr.player_instances}{RESET} ({pl_str}) | "
        f"Memory: {BOLD}{curr.total_memory_mb:.1f} MB{RESET} ({mem_col}{mem_str}{RESET})"
    )
    sys.stdout.flush()


def print_remote_traffic_update(remote_path: str, rate_per_sec: float, total_calls: int) -> None:
    color = RED if rate_per_sec >= 30.0 else (YELLOW if rate_per_sec >= 12.0 else CYAN)
    print(
        f"{BOLD}{MAGENTA}[REMOTE PROFILER]{RESET} {CYAN}{remote_path}{RESET} -> "
        f"{color}{BOLD}{rate_per_sec:.1f} calls/sec{RESET} (total: {total_calls})"
    )
    sys.stdout.flush()


def print_session_summary(session: AuditSession, filter_level: SeverityFilter = None) -> None:
    counts = session.counts_by_severity()
    total = len(session.findings)
    print(f"\n{BOLD}{CYAN}═══════════════════════ AUDIT SESSION SUMMARY ═══════════════════════{RESET}")
    print(f"  {BOLD}Mode:{RESET}          {session.mode.upper()}")
    print(f"  {BOLD}Target:{RESET}        {session.target_name}")
    print(f"  {BOLD}Started At:{RESET}    {session.started_at}")
    if filter_level:
        print(f"  {BOLD}Active Filter:{RESET} {normalize_filter_label(filter_level)}")
    print(
        f"  {BOLD}Findings:{RESET}      {total} total — "
        f"{RED}{BOLD}{counts.get('CRITICAL', 0)} CRITICAL{RESET}, "
        f"{YELLOW}{BOLD}{counts.get('WARN', 0)} WARN{RESET}, "
        f"{CYAN}{BOLD}{counts.get('INFO', 0)} INFO{RESET}"
    )
    if session.memory_snapshots:
        first = session.memory_snapshots[0]
        last = session.memory_snapshots[-1]
        ws_delta = last.workspace_instances - first.workspace_instances
        mem_delta = last.total_memory_mb - first.total_memory_mb
        print(
            f"  {BOLD}Snapshots:{RESET}     {len(session.memory_snapshots)} recorded "
            f"(Δ Workspace: {ws_delta:+d} instances, Δ Memory: {mem_delta:+.2f} MB)"
        )
    if session.remote_traffic:
        print(f"  {BOLD}Remotes Tracked:{RESET} {len(session.remote_traffic)} endpoints profiled")
    print(f"{BOLD}{CYAN}═════════════════════════════════════════════════════════════════════{RESET}\n")


def normalize_filter_label(filter_level: SeverityFilter) -> str:
    return format_filter_label(filter_level)
