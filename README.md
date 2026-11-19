# `rcdebug` — Revan Cool Debugger

**`rcdebug`** is a zero-dependency macOS CLI developer and security-auditing tool for **Roblox Studio**. It helps Roblox developers audit their games for replication flaws, insecure `RemoteEvent` patterns, `NetworkOwnership` abuse vectors, memory/instance leaks, and static script vulnerabilities across two core modes:

1. **`rcdebug --client` (Studio Runtime Bridge)** — Starts a local HTTP & WebSocket listener on `127.0.0.1:8765`, renders a color-coded terminal dashboard, and automatically copies a self-contained Luau diagnostic & telemetry script to your macOS clipboard (`pbcopy`).
2. **`rcdebug --server` (Roblox Studio MCP Inspector)** — Automatically discovers your active **Roblox Studio MCP** configuration on macOS (`~/.gemini/config/mcp_config.json`, `~/.cursor/mcp.json`, Claude Desktop, or `~/.rcdebug/config.json`) and performs static scene and script security audits without needing to start a playtest.

---

## Features

- **Exposed Remote Auditing (`ReplicatedStorage` & `Workspace`)**: Flags exposed `RemoteEvent`, `RemoteFunction`, and `UnreliableRemoteEvent` instances—highlighting high-risk endpoints (currency, admin, damage, inventory, purchases) and providing copy-pasteable server validation patterns.
- **Remote Traffic Profiler**: Tracks live firing rates (`calls/sec`) for each `RemoteEvent` on the server and automatically triggers `WARN`/`CRITICAL` alerts when endpoints lack server-side cooldown/debounce checks.
- **Instance & Memory Diffing (10s Snapshots)**: Captures `Workspace` instance count, `Players` instance count, and `Stats:GetTotalMemoryUsageMb()` every 10 seconds to catch memory leaks or uncleaned projectile/VFX debris (`Debris:AddItem`).
- **`NetworkOwnership` Anomaly Detection**: Detects unanchored non-character `BasePart` instances in `Workspace` where nearby exploiters can seize client physics authority (`part:SetNetworkOwner(nil)` fix).
- **Client-Modifiable `ValueBase` State Scanner**: Flags sensitive `IntValue`/`NumberValue`/`BoolValue` objects (e.g., `Cash`, `Stamina`, `Health`, `Mana`, `XP`, `Admin`) parented inside `Player` or `Character` hierarchies.
- **Static MCP Scene & Script Inspector (`--server`)**: Audits `ServerScriptService.LoadStringEnabled`, `loadstring()` usage, hardcoded Discord webhooks or unthrottled `HttpService` calls, unanchored parts, and `OnServerEvent` handlers missing `typeof()` parameter checks.
- **Markdown Security & QA Reports (`--export <file.md>`)**: Generates a structured Markdown report containing an executive summary, severity breakdown, per-finding remediation code blocks, remote traffic tables, and memory diff timelines.
- **Severity Filtering (`--filter <CRITICAL|WARN|INFO>`)**: Filters both live terminal output and exported Markdown reports.

---

## Quick Usage

### 1. Runtime Playtest Bridge (`--client`)

```bash
# Start listener on 127.0.0.1:8765 and auto-copy the Luau snippet to your clipboard
rcdebug --client

# Filter by CRITICAL findings only and export a Markdown report on exit (Ctrl+C)
rcdebug --client --filter CRITICAL --export playtest_audit.md

# Run a self-contained simulation of Studio playtest telemetry
rcdebug --client --simulate --export client_demo_report.md
```

Once `--client` is running, press **`Cmd+V`** inside the **Roblox Studio Command Bar** during a playtest.

### 2. Static MCP & Place Inspector (`--server`)

```bash
# Auto-discover Roblox Studio MCP config and run static scene/script audit
rcdebug --server

# Audit a local directory of .luau/.lua scripts or an .rbxlx/.rbxmx place file
rcdebug --server --place ./src --export static_audit.md

# Run a simulated static MCP audit and export the report
rcdebug --server --simulate --export server_demo_report.md
```

---

## Project Layout

```text
rcdebug/
├── bin/
│   └── rcdebug              # Global CLI executable entrypoint
├── pyproject.toml           # Python package metadata & console_scripts definition
├── rcdebug/
│   ├── __init__.py          # Package version and metadata
│   ├── cli.py               # Argument parser (--client, --server, --export, --filter, etc.)
│   ├── client_bridge.py     # HTTP & WebSocket listener (127.0.0.1:8765) + telemetry processor
│   ├── exporter.py          # Markdown security & QA audit report generator
│   ├── luau_payload.py      # Self-contained Luau diagnostic & 10s telemetry profiler script
│   ├── mcp_inspector.py     # macOS MCP config auto-discovery + stdio/HTTP MCP & static script auditor
│   ├── models.py            # Finding, MemorySnapshot, RemoteTrafficStat, and AuditSession models
│   └── terminal.py          # Rich ANSI terminal dashboard & pbcopy clipboard integration
└── tests/
    └── test_rcdebug.py      # Unit & integration test suite
```
