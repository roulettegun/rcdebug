# rcdebug Architecture Reference

[![PyPI](https://badgen.net/pypi/v/rcdebug?icon=pypi&label=pypi)](https://pypi.org/project/rcdebug/)
[![Flaw Corpus](https://badgers.space/badge/corpus/120,000%20flaws/e11d48)](rcdebug/data/flaws_120000.txt)
[![Debugger Pack](https://badgers.space/badge/probes/120%20luau%20rules/f59e0b)](rcdebug/data/luau_debugger_pack_120.json)
[![Lookup Latency](https://badgers.space/badge/mmap%20lookup/sub-10ms/10b981)](rcdebug/flaw_catalog.py)

Internal architecture and mechanics reference for `rcdebug`. Update this file whenever CLI flags, modules, data schemas, or runtime invariants change. See [README.md](README.md) for installation and usage.

## 1. CLI Dispatch (`rcdebug/cli.py`)

Invoking `rcdebug` with no mode flag defaults to `--client`.

| Mode Flag | Module | Mechanics |
| :--- | :--- | :--- |
| `--client` (default) | `rcdebug/client_bridge.py` | Binds `127.0.0.1:8765` (or `8766+` if occupied), copies the client Luau payload via `pbcopy`, and tails `~/Library/Logs/Roblox/*_last.log`. |
| `--server` | `rcdebug/mcp_inspector.py` | Queries Roblox Studio MCP over stdio/HTTP, or scans local `.rbxlx`, `.rbxmx`, `.luau`, and `.lua` files in parallel via `--place <path>`. |
| `--catalog [QUERY]` | `rcdebug/flaw_catalog.py` | Searches `rcdebug/data/flaws_120000.txt` via the binary offset cache in `~/.rcdebug/index_cache.bin`. |
| `--pack [QUERY]` | `rcdebug/debugger_pack.py` | Searches `rcdebug/data/luau_debugger_pack_120.json` (`LDP-001` to `LDP-120`). |
| `--learn [PATH]` | `rcdebug/learner.py` | Learns custom game tokens from a local path, recent Roblox logs, Studio MCP, or GitHub (`--learn --github [QUERY]`). |
| `--history` | `rcdebug/learner.py` | Displays `~/.rcdebug/command_history.json` and `~/.rcdebug/flaw_brain.json` statistics. |
| `--watch` | `rcdebug/learner.py` | Polls `command_history.json` and `~/Library/Logs/Roblox/*_last.log` every 2 seconds. |

## 2. Module & Data Map

```text
rcdebug/
├── bin/rcdebug                          # Global CLI entrypoint wrapper
├── pyproject.toml                       # PEP 621 package definition (zero external dependencies)
├── setup.py                             # Setuptools sdist/bdist_wheel entrypoint
├── MANIFEST.in                          # Includes data/*.txt and data/*.json in builds
├── LICENSE                              # MIT License
├── README.md                            # User documentation
├── AI_ARCHITECTURE.md                   # This architecture reference
├── .github/workflows/
│   ├── ci.yml                           # Unit test suite on push/PR
│   └── publish.yml                      # Wheel/sdist release & PyPI publish workflow on v* tags
├── assets/
│   ├── roblox-devconsole.jpg            # In-game Developer Console screenshot (999x843)
│   └── cli-listener.jpg                 # macOS terminal listener screenshot (1080x513)
├── rcdebug/
│   ├── __init__.py                      # __version__ = "1.0.0"
│   ├── cli.py                           # CLI parser, severity filter resolver & history logger
│   ├── models.py                        # Finding, MemorySnapshot, RemoteTrafficStat, AuditSession
│   ├── terminal.py                      # ANSI terminal formatting & pbcopy helper
│   ├── exporter.py                      # Markdown audit report generator (--export)
│   ├── luau_payload.py                  # Client-only Luau scanner & 10s telemetry generator
│   ├── client_bridge.py                 # RuntimeBridgeServer, port reclamation/fallback & RobloxLogTailer
│   ├── mcp_inspector.py                 # StudioMCP client & ThreadPoolExecutor file scanner
│   ├── flaw_catalog.py                  # mmap-indexed 120,000-flaw catalog & 12 static regex rules
│   ├── debugger_pack.py                 # 120 static Luau probes
│   ├── github_harvester.py              # GitHub REST API Luau pattern harvester
│   ├── learner.py                       # AdaptiveLearner, CommandHistory, AutonomousBrainSync & FlawBrain
│   └── data/
│       ├── flaws_120000.txt             # 120,000 ordered pipe-delimited records (RCD-000001..RCD-120000)
│       └── luau_debugger_pack_120.json  # 120 static Luau probes (LDP-001..LDP-120)
├── scripts/
│   └── build_120k_corpus.py             # Deterministic builder for flaws_120000.txt
└── tests/
    └── test_rcdebug.py                  # 15 unit and integration tests
```

### Persistent State (`~/.rcdebug/`)

- `index_cache.bin`: `marshal` binary cache storing line byte offsets and inverted keyword posting lists for `flaws_120000.txt`, keyed by `(st_size, st_mtime_ns)`.
- `command_history.json`: Rolling 500-entry log of CLI invocations and domain weights.
- `learned_flaws.json` & `learned_patterns.txt`: Game-specific tokens and catalog hit frequencies.
- `flaw_brain.json`: IDF-weighted token-to-domain and severity model trained on all 120,000 flaws, 120 probes, and live findings.
- `brain_sync_state.json`: Incremental file byte offsets for `AutonomousBrainSync`.

## 3. Core Invariants

### A. 100% Client-Sided Luau Payload (`rcdebug/luau_payload.py`)
- Accesses only client-visible services: `Players.LocalPlayer`, `ReplicatedStorage`, `ReplicatedFirst`, `Workspace`, `StarterGui`, `StarterPack`, `Lighting`, `SoundService`, `Teams`, `Stats`, `RunService`.
- Never calls server-only APIs (`ServerScriptService`, `ServerStorage`, `OnServerEvent`, `RunService:IsServer()`, `GetNetworkOwner()`) or custom executor hooks (`hookmetamethod`, `getnamecallmethod`).
- Iterates `Workspace:GetDescendants()` in chunks of `1500` with `task.wait()` yields so large maps do not stall the client frame loop.
- Emits `[rcdebug-wire:report]` and `[rcdebug-wire:telemetry]` lines to the client log whenever `HttpService:PostAsync` is blocked, allowing `RobloxLogTailer` to ingest findings from `~/Library/Logs/Roblox/*_last.log`.

### B. Socket Bind Before Clipboard Copy (`rcdebug/client_bridge.py`)
- `bind_runtime_bridge_server()` binds the listening socket before generating the Luau script.
- If `127.0.0.1:8765` is occupied by an older `rcdebug` process (`GET /status` returns `{"tool": "rcdebug"}`), it sends `POST /shutdown` to reclaim port `8765`.
- If `127.0.0.1:8765` is occupied by another process (such as MacSploit), it increments to the next free port (`8766+`) and embeds that port in the clipboard Luau script.

### C. 120,000-Flaw Ordering & `mmap` Lookup (`rcdebug/flaw_catalog.py`)
- Record format: `CODE|SEVERITY|CATEGORY|DOMAIN|KEYWORDS_CSV|TITLE|FLAW|ABUSE|FIX|RANK`
- Strictly ordered by rank `1` to `120000`:
  - `RCD-000001` to `RCD-025000`: `CRITICAL`
  - `RCD-025001` to `RCD-065000`: `WARN`
  - `RCD-065001` to `RCD-120000`: `INFO`
- `FlawCatalog` never parses all 120,000 lines on startup; it loads `~/.rcdebug/index_cache.bin` and seek-reads matched byte offsets from `flaws_120000.txt` via `mmap`.
- Findings sort by `(severity_tier, rank_asc, -confidence, path)`.

## 4. Verification

```bash
python3 -m unittest discover -s /Users/revanveroka/Music/rcdebug/tests -v
```
