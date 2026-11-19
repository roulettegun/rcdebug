# rcdebug Architecture Reference

<!-- Badgen.net (20px): Package & Build Status -->
[![PyPI Version](https://badgen.net/pypi/v/rcdebug?icon=pypi&label=pypi)](https://pypi.org/project/rcdebug/)
[![Python Versions](https://badgen.net/pypi/python/rcdebug?icon=terminal)](https://pypi.org/project/rcdebug/)
[![MIT License](https://badgen.net/pypi/license/rcdebug)](LICENSE)
[![Last Commit](https://badgen.net/github/last-commit/roulettegun/rcdebug?icon=git)](https://github.com/roulettegun/rcdebug/commits/main)

Maintainer and AI contributor reference for `rcdebug`. Update this document whenever CLI flags, modules, data schemas, or runtime invariants change. See [README.md](README.md) for installation and end-user examples.

---

## 1. CLI Entrypoints & Routing (`rcdebug/cli.py`)

<!-- Shieldcn (32px shadcn buttons): Repository Overview -->
[![GitHub Release](https://shieldcn.dev/github/release/roulettegun/rcdebug.svg?variant=secondary)](https://github.com/roulettegun/rcdebug/releases)
[![GitHub Stars](https://shieldcn.dev/github/stars/roulettegun/rcdebug.svg?variant=secondary)](https://github.com/roulettegun/rcdebug/stargazers)
[![GitHub Forks](https://shieldcn.dev/github/forks/roulettegun/rcdebug.svg?variant=outline)](https://github.com/roulettegun/rcdebug/network/members)
[![GitHub Issues](https://shieldcn.dev/github/issues/roulettegun/rcdebug.svg?variant=outline)](https://github.com/roulettegun/rcdebug/issues)

Running `rcdebug` with no mode flag defaults to `--client`.

| Mode Flag | Handler Module | Behavior |
| :--- | :--- | :--- |
| `--client` (default) | `rcdebug/client_bridge.py` | Binds `127.0.0.1:8765` (falls back to `8766+` on conflict), copies Luau scanner via `pbcopy`, and tails `~/Library/Logs/Roblox/*_last.log`. |
| `--server` | `rcdebug/mcp_inspector.py` | Connects to StudioMCP over stdio/HTTP, or audits local `.rbxlx`/`.rbxmx`/`.luau`/`.lua` files in parallel via `--place <path>`. |
| `--catalog [QUERY]` | `rcdebug/flaw_catalog.py` | Queries 120,000 flaw records (`flaws_120000.txt`) via `~/.rcdebug/index_cache.bin` and `mmap`. |
| `--pack [QUERY]` | `rcdebug/debugger_pack.py` | Queries 120 static Luau probes (`luau_debugger_pack_120.json`, `LDP-001`..`LDP-120`). |
| `--learn [PATH]` | `rcdebug/learner.py` | Learns custom identifiers from local paths, Roblox logs, live StudioMCP, or GitHub (`--learn --github [QUERY]`). |
| `--history` | `rcdebug/learner.py` | Prints `~/.rcdebug/command_history.json` entries and `FlawBrain` stats. |
| `--watch` | `rcdebug/learner.py` | Runs `AutonomousBrainSync.sync_once()` every 2 seconds on command history and Roblox logs. |

On every invocation, `main()` initializes `FlawCatalog`, loads `CommandHistory` (seeding 24 training entries if empty), and runs `AutonomousBrainSync.sync_once()` before dispatching the selected mode.

---

## 2. Repository & Runtime State Map

```text
rcdebug/
├── bin/rcdebug                          # Wrapper executable (linked to ~/.local/bin/rcdebug)
├── pyproject.toml                       # PEP 621 metadata & console_scripts entrypoint
├── setup.py                             # Setuptools sdist/bdist_wheel entrypoint
├── MANIFEST.in                          # Package data includes (rcdebug/data/*)
├── LICENSE                              # MIT License
├── README.md                            # User guide & PyPI landing page
├── AI_ARCHITECTURE.md                   # Architecture & invariant reference (this file)
├── .github/workflows/
│   ├── ci.yml                           # Corpus build check & unittest CI (Python 3.10-3.12)
│   └── publish.yml                      # Release & PyPI upload workflow on v* tags
├── assets/
│   ├── roblox-devconsole.jpg            # Developer Console output screenshot
│   └── cli-listener.jpg                 # CLI bridge terminal screenshot
├── rcdebug/
│   ├── __init__.py                      # __version__ = "1.0.0"
│   ├── cli.py                           # CLI parser, severity filter resolver, history logging
│   ├── models.py                        # Finding, MemorySnapshot, RemoteTrafficStat, AuditSession
│   ├── terminal.py                      # ANSI formatting & pbcopy integration
│   ├── exporter.py                      # Markdown report generator (--export)
│   ├── luau_payload.py                  # Client-only Luau scanner script builder
│   ├── client_bridge.py                 # RuntimeBridgeServer, port fallback & RobloxLogTailer
│   ├── mcp_inspector.py                 # StudioMCP client & parallel local file scanner
│   ├── flaw_catalog.py                  # Binary-indexed 120,000-flaw catalog + 12 static regex rules
│   ├── debugger_pack.py                 # 120-probe Luau debugger pack loader
│   ├── github_harvester.py              # GitHub REST API Luau pattern harvester
│   ├── learner.py                       # AdaptiveLearner, CommandHistory, AutonomousBrainSync, FlawBrain
│   └── data/
│       ├── flaws_120000.txt             # 120,000 ordered pipe-delimited records (RCD-000001..RCD-120000)
│       └── luau_debugger_pack_120.json  # 120 static Luau probes (LDP-001..LDP-120)
├── scripts/
│   └── build_120k_corpus.py             # Deterministic generator for flaws_120000.txt
└── tests/
    └── test_rcdebug.py                  # 15 unit & integration tests
```

### Persistent State (`~/.rcdebug/`)

| File | Role |
| :--- | :--- |
| `index_cache.bin` | `marshal` byte-offset table and inverted posting lists for `flaws_120000.txt`, invalidated by `(st_size, st_mtime_ns)`. |
| `command_history.json` | Rolling 500-entry CLI execution log plus per-domain frequency weights. |
| `learned_flaws.json` | Custom game tokens (`seen_count`, severity, domain, fix) and `catalog_hits`. |
| `learned_patterns.txt` | Human-readable export synced alongside `learned_flaws.json`. |
| `flaw_brain.json` | Token-to-domain and severity co-occurrence weights (capped at 25,000 concepts) trained on all 120,000 flaws, 120 probes, and live findings. |
| `brain_sync_state.json` | Tracks synced `command_history.json` count and per-file byte offsets for `~/Library/Logs/Roblox/*_last.log`. |

---

## 3. Core Mechanics & Invariants

<!-- SpaceBadgers (20px): Engine & Corpus Invariants -->
[![Flaw Corpus](https://badgers.space/badge/corpus/120,000%20flaws/e11d48)](rcdebug/data/flaws_120000.txt)
[![Debugger Pack](https://badgers.space/badge/probes/120%20luau%20rules/f59e0b)](rcdebug/data/luau_debugger_pack_120.json)
[![Lookup Latency](https://badgers.space/badge/mmap%20lookup/sub-10ms/10b981)](rcdebug/flaw_catalog.py)
[![FlawBrain](https://badgers.space/badge/flaw%20brain/25k%20concepts/6366f1)](rcdebug/learner.py)
[![Stdlib Only](https://badgers.space/badge/dependencies/zero/3b82f6)](pyproject.toml)

### Client-Only Luau Runtime Bridge (`luau_payload.py`)
- Only accesses client-safe services (`Players.LocalPlayer`, `ReplicatedStorage`, `ReplicatedFirst`, `Workspace`, `StarterGui`, `StarterPack`, `Lighting`, `SoundService`, `Teams`, `Stats`, `RunService`).
- Never calls server-only APIs (`ServerScriptService`, `ServerStorage`, `OnServerEvent`, `RunService:IsServer()`, `GetNetworkOwner()`) or executor metamethod hooks (`hookmetamethod`, `getnamecallmethod`).
- Iterates `Workspace:GetDescendants()` in chunks of `1500` with `task.wait()` yields so large maps do not stall the client.
- Emits both HTTP POST requests (when permitted) and `[rcdebug-wire:report]` / `[rcdebug-wire:telemetry]` / `[rcdebug-console]` log frames so `RobloxLogTailer` ingests data strictly in `O(new bytes)`.

### Bind-First Port Collision Handling (`client_bridge.py`)
- `bind_runtime_bridge_server()` binds the TCP listener **before** generating and copying the Luau script.
- If `127.0.0.1:8765` responds to `GET /status` with `{"tool": "rcdebug"}`, it sends `POST /shutdown` to reclaim port `8765`.
- If port `8765` is held by another local process (such as MacSploit), it steps upward (`8766`, `8767`, ..., fallback `0`) and embeds the bound port directly into the copied Luau payload.

### 120,000-Flaw Schema, Ordering & Binary Index (`flaw_catalog.py`)
- Line schema: `CODE|SEVERITY|CATEGORY|DOMAIN|KEYWORDS_CSV|TITLE|FLAW|ABUSE|FIX|RANK`
- Strictly monotonic ordering by severity and rank (`1` to `120000`):
  - `RCD-000001` to `RCD-025000`: `CRITICAL`
  - `RCD-025001` to `RCD-065000`: `WARN`
  - `RCD-065001` to `RCD-120000`: `INFO`
- `FlawCatalog` keeps startup under 10ms by loading `~/.rcdebug/index_cache.bin` and seek-reading matched offsets from `flaws_120000.txt` via `mmap`, with explicit `close()` lifecycle cleanup.
- Findings sort deterministically by `(severity_tier, rank_asc, -confidence, path)` across CLI output and Markdown exports.

---

## 4. Verification Checklist

<!-- Shields.io (20px flat-square): CI & Test Gate -->
[![CI Status](https://img.shields.io/github/actions/workflow/status/roulettegun/rcdebug/ci.yml?branch=main&style=flat-square&logo=githubactions&logoColor=white&label=CI)](https://github.com/roulettegun/rcdebug/actions)
[![Test Suite](https://img.shields.io/badge/unit_tests-15_passing-10B981?style=flat-square)](tests/test_rcdebug.py)
[![Platform macOS](https://img.shields.io/badge/platform-macOS-000000?style=flat-square&logo=apple&logoColor=white)](https://github.com/roulettegun/rcdebug)

Run before committing changes:

```bash
python3 -m unittest discover -s /Users/revanveroka/Music/rcdebug/tests -v
```
