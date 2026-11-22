"""
CLI entrypoint for rcdebug (Revan Cool Debugger).
"""

from __future__ import annotations

import argparse
import sys
import time

from pathlib import Path

from . import __version__
from .client_bridge import DebugReportHandler, RobloxLogTailer, RuntimeBridgeServer, run_client_mode
from .debugger_pack import get_debugger_pack
from .flaw_catalog import get_catalog
from .github_harvester import harvest_github_luau
from .learner import AutonomousBrainSync, CommandHistory, seed_training_history
from .mcp_inspector import audit_local_path, find_studio_mcp, run_live_mcp_audit, run_server_mode
from .models import AuditSession, SeverityFilter, matches_filter, normalize_filter_set, normalize_severity
from .terminal import BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW, print_banner, severity_badge
from .ui import run_ui_mode
from .ui_web import run_ui_web_mode
from .web_catalog import get_web_catalog


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rcdebug",
        description=(
            "rcdebug (Revan Cool Debugger) - Cross-platform (Windows, macOS, Linux) security "
            "and developer auditor for Roblox Studio (600,000 flaws) and Websites (150,000 flaws)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  rcdebug --ui                               Launch Roblox Workbench (600,000 flaws)\n"
            "  rcdebug --ui-web                           Launch Website Workbench (150,000 flaws)\n"
            "  rcdebug --client                           Start local bridge on 127.0.0.1:8765 & copy Studio QA script\n"
            "  rcdebug --server --place ./src --export static_audit.md\n"
            "  rcdebug --catalog datastore --critical     Search 600,000 Roblox flaws\n"
            "  rcdebug --web-catalog xss --critical       Search 150,000 Website flaws\n"
        ),
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"rcdebug {__version__}",
    )

    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument(
        "--client",
        action="store_true",
        help="Start Studio Runtime Bridge listener (127.0.0.1:8765) & auto-copy Luau diagnostic snippet via pbcopy",
    )
    mode_group.add_argument(
        "--server",
        action="store_true",
        help="Auto-discover Roblox Studio MCP config & perform static scene/script security audits",
    )
    mode_group.add_argument(
        "--catalog",
        nargs="?",
        const="",
        default=None,
        metavar="QUERY",
        help="Search or inspect the 120,000-flaw database loaded from flaws_120000.txt",
    )
    mode_group.add_argument(
        "--learn",
        nargs="?",
        const="",
        default=None,
        metavar="PATH",
        help="Learn flaw patterns from a local place/scripts path, live Studio MCP, or recent Roblox logs",
    )
    mode_group.add_argument(
        "--history",
        action="store_true",
        help="Show JSON terminal command history & learned brain statistics (~/.rcdebug/command_history.json)",
    )
    mode_group.add_argument(
        "--pack",
        nargs="?",
        const="",
        default=None,
        metavar="QUERY",
        help="Search or inspect the 120-source Light Luau Debugger Pack",
    )
    mode_group.add_argument(
        "--watch",
        action="store_true",
        help="Run continuous autonomous brain sync watching command_history.json & Roblox logs",
    )
    mode_group.add_argument(
        "--ui",
        action="store_true",
        help="Launch graphical Roblox Web Workbench interface (http://127.0.0.1:8765/ui)",
    )
    mode_group.add_argument(
        "--ui-web",
        dest="ui_web",
        action="store_true",
        help="Launch Website & Web App Security Workbench (http://127.0.0.1:8765/ui) with 150,000 website flaws",
    )
    mode_group.add_argument(
        "--web-catalog",
        dest="web_catalog",
        nargs="?",
        const="",
        default=None,
        metavar="QUERY",
        help="Search or inspect the 150,000-flaw website security database (RCW-000001..RCW-150000)",
    )

    parser.add_argument(
        "--export",
        metavar="FILE.md",
        type=str,
        default=None,
        help="Generate a clean Markdown security & QA audit report after the session",
    )
    parser.add_argument(
        "--filter",
        metavar="SEVERITY",
        type=str,
        choices=["CRITICAL", "WARN", "WARNING", "INFO", "critical", "warn", "warning", "info"],
        default=None,
        help="Filter terminal & exported findings by severity (CRITICAL, WARN, or INFO)",
    )
    parser.add_argument(
        "--critical",
        action="store_true",
        help="Show only CRITICAL flaws (combine with --warning / --info to include multiple levels)",
    )
    parser.add_argument(
        "--warning",
        "--warn",
        action="store_true",
        help="Show only WARN flaws (combine with --critical / --info to include multiple levels)",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show only INFO flaws (combine with --critical / --warning to include multiple levels)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address for --client HTTP/WebSocket listener (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for --client HTTP/WebSocket listener (default: 8765)",
    )
    parser.add_argument(
        "--place",
        metavar="PATH",
        type=str,
        default=None,
        help="Optional path to a local .rbxlx/.rbxmx place file or Luau scripts folder for --server static audit",
    )
    parser.add_argument(
        "--no-clipboard",
        action="store_true",
        help="Disable automatic pbcopy clipboard copy in --client mode",
    )
    parser.add_argument(
        "--no-log-tail",
        action="store_true",
        help="Disable automatic ~/Library/Logs/Roblox/ log bridge tailing in --client mode",
    )
    parser.add_argument(
        "--replay-log",
        action="store_true",
        help="Replay existing [rcdebug-wire]/[rcdebug-console] lines from the newest Roblox log file on startup",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run a self-contained simulation of Studio telemetry or MCP static audit for testing/preview",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="In --learn mode, harvest open-source Luau repositories from GitHub into FlawBrain",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum results to display in --catalog mode (default: 20)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the web browser when launching --ui",
    )

    return parser


def resolve_filter_levels(args: argparse.Namespace) -> SeverityFilter:
    levels: set[str] = set()
    if getattr(args, "filter", None):
        levels.add(normalize_severity(args.filter))
    if getattr(args, "critical", False):
        levels.add("CRITICAL")
    if getattr(args, "warning", False):
        levels.add("WARN")
    if getattr(args, "info", False):
        levels.add("INFO")
    return frozenset(levels) if levels else None


def _run_catalog_mode(query: str, filter_level: SeverityFilter, limit: int) -> int:
    catalog = get_catalog()
    print_banner(
        "FLAW KNOWLEDGE BASE",
        subtitle=f"{catalog.signature_count():,} Domain Signatures + {catalog.static_rule_count()} Static Rules ({catalog.count():,} total)",
    )
    results = catalog.search(query, limit=max(1, limit * 5))
    if filter_level:
        results = [r for r in results if matches_filter(r.severity, filter_level)]
    results = results[: max(1, limit)]

    if not results:
        print(f"\n{YELLOW}No flaw signatures matched query '{query}'.{RESET}\n")
        return 0

    print(f"\n{BOLD}Showing {len(results)} matching signatures{f' for {query!r}' if query else ''}:{RESET}\n")
    for sig in results:
        print(f"{severity_badge(sig.severity)} {BOLD}{CYAN}{sig.code}{RESET} {BOLD}{sig.title}{RESET}")
        print(f"  {DIM}Flaw:{RESET}  {sig.flaw}")
        print(f"  {DIM}Abuse:{RESET} {sig.abuse}")
        print(f"  {GREEN}Fix:{RESET}   {sig.fix}\n")
    return 0


def _run_learn_mode(target_path: str, filter_level: SeverityFilter, limit: int) -> int:
    catalog = get_catalog()
    print_banner(
        "ADAPTIVE PLACE LEARNER",
        subtitle=f"{catalog.count():,} Base Flaws + {len(catalog.learner.learned_tokens)} Learned Patterns",
    )

    session = AuditSession(mode="learn", target_name="Place Learning Session")
    if target_path:
        p = Path(target_path).expanduser().resolve()
        if not p.exists():
            print(f"{RED}✖ Path does not exist: {p}{RESET}\n")
            return 1
        session.target_name = f"Place ({p.name})"
        print(f"\n{CYAN}→ Learning from place/scripts:{RESET} {BOLD}{p}{RESET}")
        audit_local_path(p, session, filter_level=filter_level)
    else:
        print(f"\n{CYAN}→ Scanning recent Roblox logs & Studio MCP for learnable patterns...{RESET}")
        temp_srv = RuntimeBridgeServer(("127.0.0.1", 0), DebugReportHandler, session=session, filter_level=filter_level)
        try:
            tailer = RobloxLogTailer(temp_srv, replay_latest=True)
            tailer._init_offsets()
            tailer.poll_once()
        finally:
            temp_srv.server_close()

        mcp_info = find_studio_mcp()
        if mcp_info:
            run_live_mcp_audit(mcp_info["config"], session, filter_level=filter_level)

    new_tokens = catalog.learner.learn_from_session(session, catalog)
    print(f"\n{GREEN}{BOLD}✔ Learning Complete:{RESET} +{new_tokens} new token(s) learned from {len(session.findings)} finding(s).")
    print(f"  {BOLD}Total Learned Patterns:{RESET} {len(catalog.learner.learned_tokens)}")
    print(f"  {BOLD}Knowledge Store:{RESET}        {CYAN}{catalog.learner.store_path}{RESET}")
    print(f"  {BOLD}Text Export:{RESET}            {CYAN}{catalog.learner.txt_path}{RESET}")

    if catalog.learner.learned_tokens:
        print(f"\n{BOLD}Top Learned Game Patterns:{RESET}")
        top = sorted(
            catalog.learner.learned_tokens.items(),
            key=lambda kv: (-int(kv[1].get("seen_count", 1)), kv[0]),
        )[: max(1, limit)]
        for tok, info in top:
            print(
                f"  {severity_badge(str(info.get('severity', 'WARN')))} {BOLD}{tok}{RESET} "
                f"{DIM}(seen {info.get('seen_count', 1)}x, domain: {info.get('domain', 'Learned')}){RESET}"
            )
    print()
    return 0


def _run_history_mode(history: CommandHistory, limit: int) -> int:
    catalog = get_catalog()
    print_banner(
        "COMMAND HISTORY & BRAIN",
        subtitle=f"{len(history.entries)} Logged Commands | {len(catalog.learner.learned_tokens)} Learned Tokens | {catalog.count():,} Base Flaws",
    )
    print(f"\n{BOLD}History JSON:{RESET} {CYAN}{history.history_path}{RESET}")
    print(f"{BOLD}Learned JSON:{RESET} {CYAN}{catalog.learner.store_path}{RESET}")
    print(
        f"{BOLD}Flaw Brain:{RESET}   {CYAN}{catalog.brain.brain_path}{RESET} "
        f"{DIM}({catalog.brain.total_flaws_learned:,} flaws learned, {len(catalog.brain.token_domain_weights):,} concepts){RESET}"
    )

    if history.domain_weights:
        top_doms = sorted(history.domain_weights.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        dom_str = ", ".join(f"{d} ({n}x)" for d, n in top_doms)
        print(f"{BOLD}Top Domains:{RESET}  {dom_str}")

    recent = history.entries[-max(1, limit):]
    print(f"\n{BOLD}Recent {len(recent)} Command(s):{RESET}\n")
    for item in reversed(recent):
        tag = f"{DIM}[SEED]{RESET} " if item.get("synthetic") else f"{GREEN}[LIVE]{RESET} "
        print(
            f"  {tag}{DIM}{item.get('timestamp', '')}{RESET}  {BOLD}{item.get('command', '')}{RESET} "
            f"{DIM}({item.get('findings_count', 0)} findings, +{item.get('learned_tokens_added', 0)} learned, {item.get('duration_ms', 0):.1f}ms){RESET}"
        )
    print()
    return 0


def _run_pack_mode(query: str, filter_level: SeverityFilter, limit: int) -> int:
    pack = get_debugger_pack()
    print_banner(
        "LIGHT LUAU DEBUGGER PACK",
        subtitle=f"{pack.count()} Compiled Luau Probes (Selene, luau-lsp, luau-lang, Trove, Janitor, Iris, Cmdr, TestEZ, Roblox)",
    )
    results = pack.search(query, limit=max(1, limit * 4))
    if filter_level:
        results = [p for p in results if matches_filter(p.severity, filter_level)]
    results = results[: max(1, limit)]

    if not results:
        print(f"\n{YELLOW}No debugger probes matched '{query}'.{RESET}\n")
        return 0

    print(f"\n{BOLD}Showing {len(results)} probe(s){f' for {query!r}' if query else ''}:{RESET}\n")
    for p in results:
        print(f"{severity_badge(p.severity)} {BOLD}{CYAN}{p.id}{RESET} {BOLD}{p.name}{RESET} {DIM}[{p.source}]{RESET}")
        print(f"  {DIM}Cause:{RESET} {p.root_cause}")
        print(f"  {GREEN}Fix:{RESET}   {p.fix}\n")
    return 0


def _run_watch_mode(catalog, history: CommandHistory, sync: AutonomousBrainSync) -> int:
    print_banner(
        "AUTONOMOUS BRAIN WATCHER",
        subtitle="Continuously learning from command_history.json & ~/Library/Logs/Roblox/ (Ctrl+C to stop)",
    )
    print(f"\n{GREEN}● Watching:{RESET} {CYAN}{history.history_path}{RESET}")
    print(f"{GREEN}● Watching:{RESET} {CYAN}{sync.log_dir}{RESET}")
    print(f"{DIM}  Current learned tokens: {len(catalog.learner.learned_tokens)} | Base flaws: {catalog.count():,}{RESET}\n")
    try:
        while True:
            added = sync.sync_once(catalog, history)
            if added > 0:
                print(
                    f"{GREEN}[brain-sync]{RESET} Learned +{added} new token(s) "
                    f"({len(catalog.learner.learned_tokens)} total)"
                )
            time.sleep(2.0)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[rcdebug] Autonomous watcher stopped.{RESET}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    t0 = time.perf_counter()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if (
        not args.client
        and not args.server
        and not args.ui
        and not getattr(args, "ui_web", False)
        and args.catalog is None
        and getattr(args, "web_catalog", None) is None
        and args.learn is None
        and not args.history
        and args.pack is None
        and not args.watch
    ):
        args.client = True

    filter_level = resolve_filter_levels(args)
    filter_list = sorted(normalize_filter_set(filter_level) or ())

    catalog = get_catalog()
    history = CommandHistory()
    if not history.entries:
        seed_training_history(catalog, history=history, count=24)

    # Always read command_history.json & Roblox logs to learn automatically on every run
    brain_sync = AutonomousBrainSync()
    brain_sync.sync_once(catalog, history)

    if args.watch:
        return _run_watch_mode(catalog, history, brain_sync)

    if args.pack is not None:
        rc = _run_pack_mode(args.pack, filter_level=filter_level, limit=args.limit)
        history.record_run(
            argv=raw_argv,
            mode="pack",
            target=args.pack or "*",
            filters=filter_list,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return rc

    if args.history:
        rc = _run_history_mode(history, limit=args.limit)
        history.record_run(
            argv=raw_argv,
            mode="history",
            filters=filter_list,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return rc

    if args.learn is not None:
        if args.github:
            res = harvest_github_luau(query=args.learn or "roblox luau", brain=catalog.brain)
            print(f"\n{GREEN}{BOLD}✔ GitHub Harvester:{RESET} {res.message} (+{res.patterns_learned} distilled)\n")
            return 0
        before_learned = len(catalog.learner.learned_tokens)
        rc = _run_learn_mode(args.learn, filter_level=filter_level, limit=args.limit)
        history.record_run(
            argv=raw_argv,
            mode="learn",
            target=args.learn or "RobloxLogs/StudioMCP",
            filters=filter_list,
            learned_added=max(0, len(catalog.learner.learned_tokens) - before_learned),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return rc

    if args.catalog is not None:
        rc = _run_catalog_mode(args.catalog, filter_level=filter_level, limit=args.limit)
        history.record_run(
            argv=raw_argv,
            mode="catalog",
            target=args.catalog or "*",
            filters=filter_list,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return rc

    if getattr(args, "web_catalog", None) is not None:
        wcat = get_web_catalog()
        print_banner(
            "WEBSITE FLAW KNOWLEDGE BASE (150,000 FLAWS)",
            subtitle=f"{wcat.signature_count():,} Website Signatures + {wcat.static_rule_count()} Static Web Rules",
        )
        results = wcat.search(args.web_catalog, limit=max(1, args.limit * 5))
        if filter_level:
            results = [r for r in results if matches_filter(r.severity, filter_level)]
        results = results[: max(1, args.limit)]
        for sig in results:
            print(f"{severity_badge(sig.severity)} {BOLD}{CYAN}{sig.code}{RESET} {BOLD}{sig.title}{RESET}")
            print(f"  {DIM}Flaw:{RESET}  {sig.flaw}")
            print(f"  {DIM}Abuse:{RESET} {sig.abuse}")
            print(f"  {GREEN}Fix:{RESET}   {sig.fix}\n")
        return 0

    if getattr(args, "ui_web", False):
        wcat = get_web_catalog()
        before_learned = len(wcat.learner.learned_tokens)
        session = run_ui_web_mode(
            host=args.host,
            port=args.port,
            filter_level=filter_level,
            export_path=args.export,
            auto_clipboard=not args.no_clipboard,
            simulate=args.simulate,
            open_browser=not args.no_browser,
        )
        history.record_run(
            argv=raw_argv,
            mode="ui-web",
            target=session.target_name,
            filters=filter_list,
            findings_count=len(session.findings),
            severity_counts=session.counts_by_severity(),
            domains_seen=[str(f.metadata.get("domain", f.category)) for f in session.findings],
            learned_added=max(0, len(wcat.learner.learned_tokens) - before_learned),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return 0

    if args.ui:
        before_learned = len(catalog.learner.learned_tokens)
        session = run_ui_mode(
            host=args.host,
            port=args.port,
            filter_level=filter_level,
            export_path=args.export,
            auto_clipboard=not args.no_clipboard,
            simulate=args.simulate,
            enable_log_tail=not args.no_log_tail,
            replay_latest_log=args.replay_log,
            open_browser=not args.no_browser,
        )
        history.record_run(
            argv=raw_argv,
            mode="ui",
            target=session.target_name,
            filters=filter_list,
            findings_count=len(session.findings),
            severity_counts=session.counts_by_severity(),
            domains_seen=[str(f.metadata.get("domain", f.category)) for f in session.findings],
            learned_added=max(0, len(catalog.learner.learned_tokens) - before_learned),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return 0

    if args.client:
        before_learned = len(catalog.learner.learned_tokens)
        session = run_client_mode(
            host=args.host,
            port=args.port,
            filter_level=filter_level,
            export_path=args.export,
            auto_clipboard=not args.no_clipboard,
            simulate=args.simulate,
            enable_log_tail=not args.no_log_tail,
            replay_latest_log=args.replay_log,
        )
        history.record_run(
            argv=raw_argv,
            mode="client",
            target=session.target_name,
            filters=filter_list,
            findings_count=len(session.findings),
            severity_counts=session.counts_by_severity(),
            domains_seen=[str(f.metadata.get("domain", f.category)) for f in session.findings],
            learned_added=max(0, len(catalog.learner.learned_tokens) - before_learned),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return 0

    if args.server:
        before_learned = len(catalog.learner.learned_tokens)
        session = run_server_mode(
            filter_level=filter_level,
            export_path=args.export,
            place_path=args.place,
            simulate=args.simulate,
        )
        history.record_run(
            argv=raw_argv,
            mode="server",
            target=session.target_name,
            filters=filter_list,
            findings_count=len(session.findings),
            severity_counts=session.counts_by_severity(),
            domains_seen=[str(f.metadata.get("domain", f.category)) for f in session.findings],
            learned_added=max(0, len(catalog.learner.learned_tokens) - before_learned),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
