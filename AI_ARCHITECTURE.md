# `rcdebug` — AI Architecture & Mechanics Reference

> **Living Document:** Update this file whenever a module, CLI flag, data file, or learning mechanic changes in `rcdebug`. It is designed so any AI coding assistant can understand the entire codebase, data flow, and invariants in a single read.

---

## 1. High-Level Overview

**`rcdebug` (Revan Cool Debugger)** is a zero-dependency macOS CLI developer and security-auditing tool for **Roblox Studio & Roblox Client**, written in Python 3 (`>=3.10`) and installed globally at `~/.local/bin/rcdebug` (symlinked to `bin/rcdebug`).

It operates across **7 CLI modes** (invoking bare `rcdebug` with no mode flag defaults to `--client`):
1. `--client` (default): 100% client-sided Luau runtime bridge (HTTP/WS listener on `127.0.0.1:8765` with automatic port-collision fallback to `8766+` if occupied by third-party tools like MacSploit, or `POST /shutdown` reclamation for stale `rcdebug` listeners + real-time macOS Roblox Log Bridge tailing `~/Library/Logs/Roblox/*_last.log`).
2. `--server`: Roblox Studio MCP inspector (auto-discovers StudioMCP config, runs static scene/script audits, or audits local `.rbxlx`/`.rbxmx`/`.luau` paths in parallel via `--place`).
3. `--catalog [QUERY]`: Searches the **120,000-flaw** database (`rcdebug/data/flaws_120000.txt`) via a sub-10ms binary/mmap index (`~/.rcdebug/index_cache.bin`).
4. `--pack [QUERY]`: Searches the **120-probe** Light Luau Debugger Pack (`rcdebug/data/luau_debugger_pack_120.json`).
5. `--learn [PATH]` (and `--learn --github [QUERY]`): Learns custom game tokens & flaw patterns from a local place/scripts directory, recent Roblox logs, live Studio MCP, or open-source GitHub Luau repositories (`rcdebug/github_harvester.py`).
6. `--history`: Displays `~/.rcdebug/command_history.json` and `FlawBrain` statistics.
7. `--watch`: Continuous autonomous background learner watching `command_history.json` and `~/Library/Logs/Roblox/*_last.log`.

---

## 2. Repository & Data File Map

```text
rcdebug/
├── bin/rcdebug                          # Global executable wrapper (~/.local/bin/rcdebug)
├── pyproject.toml                       # Package metadata, console_scripts, package-data (data/*.txt, data/*.json)
├── AI_ARCHITECTURE.md                   # This living AI-onboarding & mechanics reference
├── README.md                            # User-facing quickstart
├── rcdebug/
│   ├── __init__.py                      # __version__ = "1.0.0"
│   ├── cli.py                           # CLI parser, multi-severity filter resolver, command history logging, startup brain sync
│   ├── models.py                        # Finding, MemorySnapshot, RemoteTrafficStat, AuditSession, SeverityFilter
│   ├── terminal.py                      # ANSI dashboard rendering, pbcopy clipboard integration
│   ├── exporter.py                      # Markdown report generator (--export <file.md>)
│   ├── luau_payload.py                  # 100% client-sided Luau scanner (chunked Workspace scan, OnClientEvent profiler, 10s telemetry)
│   ├── client_bridge.py                 # HTTP/WS server (127.0.0.1:8765), RobloxLogTailer, wire/console log parser
│   ├── mcp_inspector.py                 # StudioMCP stdio/HTTP JSON-RPC client, static .rbxlx/.luau auditor
│   ├── flaw_catalog.py                  # 120,000-flaw binary/mmap-indexed catalog + 12 static regex rules + FlawBrain integration
│   ├── debugger_pack.py                 # 120-probe Light Luau Debugger Pack loader & static scanner
│   ├── github_harvester.py              # Zero-dependency GitHub Luau harvester (--learn --github)
│   ├── learner.py                       # AdaptiveLearner, CommandHistory, AutonomousBrainSync, FlawBrain (25k IDF concepts)
│   └── data/
│       ├── flaws_120000.txt             # Exact 120,000 strictly ordered flaw records (RCD-000001..RCD-120000)
│       └── luau_debugger_pack_120.json  # Exact 120 lightweight Luau debugger/linter/profiler probes (LDP-001..LDP-120)
├── scripts/
│   └── build_120k_corpus.py             # Deterministic generator for rcdebug/data/flaws_120000.txt
└── tests/
    └── test_rcdebug.py                  # 14-test unit & integration suite
```

### Persistent User Brain (`~/.rcdebug/`)
- `index_cache.bin`: Binary marshal-serialized byte-offset & inverted-posting-list cache for `flaws_120000.txt` (keyed by file size and `mtime_ns`), enabling sub-10ms `FlawCatalog` cold/warm queries via `mmap`.
- `command_history.json`: Every CLI invocation (`timestamp`, `command`, `argv`, `mode`, `target`, `filters`, `findings_count`, `severity_counts`, `domains_seen`, `learned_tokens_added`, `duration_ms`), capped at the most recent 500 entries, plus `domain_weights`.
- `learned_flaws.json` & `learned_patterns.txt`: Custom game-specific tokens (`seen_count`, `severity`, `category`, `domain`, `places`, `flaw`, `abuse`, `fix`) and `catalog_hits` frequency counts.
- `flaw_brain.json`: `FlawBrain` statistical co-occurrence model trained on all **120,000 flaws** + **120 probes** + live findings (`token_domain_weights`, `token_severity_counts`, `domain_fixes`, top 25,000 IDF-weighted concepts).
- `brain_sync_state.json`: Tracks `synced_history_count` and byte offsets for `~/Library/Logs/Roblox/*_last.log` so `AutonomousBrainSync` never re-reads old bytes.
- `config.json`: Saved Studio MCP endpoint/command if auto-discovery didn't find one.

---

## 3. Core Mechanics

### A. 100% Client-Sided Luau Bridge (`luau_payload.py` + `client_bridge.py`)
1. **Zero Server APIs**: The generated Luau snippet uses only client-accessible Roblox APIs (`Players.LocalPlayer`, `ReplicatedStorage`, `ReplicatedFirst`, `Workspace`, `StarterGui`, `StarterPack`, `Lighting`, `SoundService`, `Teams`, `Stats`, `RunService`). It never calls `ServerScriptService`, `RunService:IsServer()`, `OnServerEvent`, or `GetNetworkOwner()`.
2. **Chunked Scanning**: `Workspace:GetDescendants()` is iterated in chunks of `SCAN_CHUNK_SIZE = 1500` with `task.wait()` yields so 30k–100k+ instance maps do not freeze the client.
3. **Bind-First Port Collision Resolution (`bind_runtime_bridge_server`)**:
   - Binds `RuntimeBridgeServer` **before** generating and copying the Luau snippet to the clipboard.
   - If `127.0.0.1:8765` is occupied by an older `rcdebug` session (verified via `GET /health` returning `{"service": "rcdebug"}`), sends `POST /shutdown` to reclaim port `8765`.
   - If `127.0.0.1:8765` is occupied by another application (such as MacSploit's local IPC server), automatically falls back to the next free port (`8766`, `8767`, etc.) and embeds that exact port in the clipboard Luau snippet.
4. **Dual Transport**:
   - Attempts `HttpService:PostAsync` to `http://127.0.0.1:<bound_port>/report` and `/telemetry`.
   - Because Roblox blocks `HttpService:PostAsync` in live Client contexts, `postJSON` automatically falls back to `print("[rcdebug-wire:report] " .. encoded)` / `print("[rcdebug-wire:telemetry] " .. encoded)`.
   - `RobloxLogTailer` in `client_bridge.py` tails `~/Library/Logs/Roblox/*_Player_*_last.log` and `*_Studio_*_last.log` every `0.2s`, parsing `[rcdebug-wire:*]` JSON frames and `[rcdebug-console]` fallback lines into `process_report_payload` / `process_telemetry_payload`.

### B. 120,000-Flaw Catalog & 120-Probe Debugger Pack (`flaw_catalog.py` + `debugger_pack.py`)
1. **Binary/Mmap Inverted Keyword Index**: `_build_or_load_index()` builds or loads `~/.rcdebug/index_cache.bin` for `flaws_120000.txt` (enforcing `EXPECTED_FLAW_COUNT = 120000` ordered strictly `RCD-000001` CRITICAL rank 1 down to `RCD-120000` INFO rank 120000), seek-reading only top-K matched lines via `mmap`.
2. **Fast Cached Matching**: `FlawCatalog.match_name()` splits camelCase leaf identifiers via `@lru_cache(maxsize=16384)`, prioritizes domain-specific leaf matches over generic structural words (`remote`, `tool`, `attribute`), boosts scores using `learned_flaws.json` `catalog_hits`, and caches results in `_match_cache` (up to 4,096 entries).
3. **Static Code Auditing (`mcp_inspector.py`)**: `audit_luau_script_source()` runs:
   - `STATIC_CODE_RULES` (`12` compiled regexes with literal pre-filters in `flaw_catalog.py`: `loadstring`, Discord webhooks, unwrapped `HttpService`, `DataStore:SetAsync`, `ProcessReceipt`, `ProximityPrompt.Triggered`, `Touched`, `TeleportService`, `TextService`, `Debris`, numeric `require`, `TakeDamage`).
   - `LuauDebuggerPack.scan_source()` (`120` probes in `luau_debugger_pack_120.json` from Selene, `luau-lsp`, `luau-lang`, Trove, Janitor, Iris, Cmdr, TestEZ, Roblox).
   - Guard-aware `OnServerEvent` / `OnServerInvoke` parameter `typeof()`, `math.clamp`, NaN (`x ~= x`), and cooldown/debounce checks.

### C. Always-On Autonomous Learning (`learner.py` + `github_harvester.py`)
On every `rcdebug` startup:
1. `get_catalog()` opens `flaws_120000.txt` via `mmap` and ensures `FlawBrain.train_from_corpus()` is trained on all `120,120` base flaws/probes.
2. `CommandHistory` loads `~/.rcdebug/command_history.json` (seeding 24 multi-genre sessions via `seed_training_history()` if empty).
3. `AutonomousBrainSync.sync_once()` ingests any new `command_history.json` entries and new bytes in `~/Library/Logs/Roblox/*_last.log`.
4. `FlawCatalog.enrich_finding()` resolves findings via: (1) `flaws_120000.txt` strong match → (2) `AdaptiveLearner.learned_tokens` → (3) `FlawBrain.predict()` IDF-weighted statistical inference for unseen patterns, and feeds every finding back into `FlawBrain.ingest_flaw_record()`.
5. `rcdebug --learn --github [QUERY]` queries GitHub's public REST API for open-source Luau repositories and distills security/guard patterns into `FlawBrain`.

### D. Multi-Severity Filtering (`cli.py` + `models.py`)
`--critical`, `--warning` (`--warn`), `--info`, and `--filter` combine into a `frozenset[str] | None` via `resolve_filter_levels(args)` and filter `--client`, `--server`, `--catalog`, `--pack`, `--learn`, and `--export` uniformly.

---

## 4. Verification & Maintenance Checklist

Before finishing any future change to `rcdebug`:
1. Run the full test suite:
   ```bash
   python3 -m unittest discover -s /Users/revanveroka/Music/rcdebug/tests -v
   ```
2. Verify exact data file counts if touched:
   - `wc -l rcdebug/data/flaws_120000.txt` → `120000`
   - `luau_debugger_pack_120.json` → `120` entries
3. Update this `AI_ARCHITECTURE.md` whenever modules, CLI flags, or data schemas change.
