# rcdebug

<!-- Badgen.net (20px height): Top Release & Package Bar -->
[![PyPI Version](https://badgen.net/pypi/v/rcdebug?icon=pypi&label=pypi)](https://pypi.org/project/rcdebug/)
[![Python Version](https://badgen.net/pypi/python/rcdebug?icon=terminal)](https://pypi.org/project/rcdebug/)
[![License](https://badgen.net/pypi/license/rcdebug)](LICENSE)
[![GitHub Release](https://badgen.net/github/release/roulettegun/rcdebug?icon=github)](https://github.com/roulettegun/rcdebug/releases)
[![Last Commit](https://badgen.net/github/last-commit/roulettegun/rcdebug?icon=git)](https://github.com/roulettegun/rcdebug/commits/main)

`rcdebug` (Revan Cool Debugger) is a macOS command-line debugger and security auditor for Roblox games. It finds exposed remotes, unanchored parts that leak network ownership, replicated player stats, memory spikes, and server script vulnerabilities.

It runs on Python's standard library with zero external packages.

![Roblox Developer Console running rcdebug](assets/roblox-devconsole.jpg)

![rcdebug terminal listener](assets/cli-listener.jpg)

---

## Install

<!-- Shieldcn (32px shadcn buttons): Package & Repository Status -->
[![GitHub Release](https://shieldcn.dev/github/release/roulettegun/rcdebug.svg?variant=secondary)](https://github.com/roulettegun/rcdebug/releases)
[![GitHub Stars](https://shieldcn.dev/github/stars/roulettegun/rcdebug.svg?variant=secondary)](https://github.com/roulettegun/rcdebug/stargazers)
[![GitHub Forks](https://shieldcn.dev/github/forks/roulettegun/rcdebug.svg?variant=outline)](https://github.com/roulettegun/rcdebug/network/members)
[![GitHub Issues](https://shieldcn.dev/github/issues/roulettegun/rcdebug.svg?variant=outline)](https://github.com/roulettegun/rcdebug/issues)
[![GitHub License](https://shieldcn.dev/github/license/roulettegun/rcdebug.svg?variant=outline)](LICENSE)

Install globally from [PyPI](https://pypi.org/project/rcdebug/):

```bash
pip install rcdebug
```

Or install from source:

```bash
git clone https://github.com/roulettegun/rcdebug.git
cd rcdebug
pip install -e .
```

---

## Quick Start

### 1. Live Game / Client Audit (`--client`)

Run `rcdebug` in your terminal:

```bash
rcdebug
```

What happens:
1. Starts a local listener on `127.0.0.1:8765` (if port `8765` is used by MacSploit or another process, it automatically switches to `8766`).
2. Copies the 100% client-sided Luau scanner to your macOS clipboard (`pbcopy`).
3. Tails `~/Library/Logs/Roblox/*_last.log` in real time so findings still stream to your terminal even when Roblox blocks `HttpService:PostAsync` on the client.

Paste (`Cmd+V`) the copied script into your executor, Roblox Developer Console, or Studio Command Bar.

### 2. Static Place & Studio MCP Audit (`--server`)

Scan local `.luau` / `.lua` scripts, `.rbxlx` / `.rbxmx` place files, or an open Roblox Studio session over MCP:

```bash
# Scan a local folder or .rbxlx place file
rcdebug --server --place ./src --export audit.md

# Connect to Roblox Studio MCP
rcdebug --server
```

---

## Commands & Flags

| Command | What it does |
| :--- | :--- |
| `rcdebug` or `rcdebug --client` | Start the live client bridge, copy the Luau scanner, and tail Roblox logs. |
| `rcdebug --server` | Audit an active Roblox Studio MCP session or a local `--place <path>`. |
| `rcdebug --catalog [query]` | Search the 120,000-flaw database (`RCD-000001` to `RCD-120000`). |
| `rcdebug --pack [query]` | Search the 120 Luau debugger probes (`LDP-001` to `LDP-120`). |
| `rcdebug --learn [path]` | Learn custom remote, attribute, and folder names from a place or recent logs. |
| `rcdebug --learn --github [query]` | Pull public Luau scripts from GitHub and train `~/.rcdebug/flaw_brain.json`. |
| `rcdebug --history` | View terminal command history and learned brain stats. |
| `rcdebug --watch` | Watch `command_history.json` and Roblox logs in the background. |

### Filtering & Exporting

```bash
# Show only CRITICAL findings
rcdebug --client --critical

# Show CRITICAL and WARNING findings
rcdebug --client --critical --warning

# Search the 120,000-flaw catalog for DataStore flaws
rcdebug --catalog datastore --critical --limit 10

# Save a Markdown audit report when you stop the session
rcdebug --client --export report.md
```

---

## What It Checks

<!-- SpaceBadgers (badgers.space): Auditing Engine Specs -->
[![Flaw Signatures](https://badgers.space/badge/flaw%20signatures/120,000/e11d48)](rcdebug/data/flaws_120000.txt)
[![Luau Probes](https://badgers.space/badge/luau%20probes/120/f59e0b)](rcdebug/data/luau_debugger_pack_120.json)
[![Mmap Lookup](https://badgers.space/badge/mmap%20lookup/sub-10ms/10b981)](rcdebug/flaw_catalog.py)
[![FlawBrain](https://badgers.space/badge/flaw%20brain/25k%20concepts/6366f1)](rcdebug/learner.py)
[![Client Bridge](https://badgers.space/badge/runtime%20bridge/100%25%20client/0ea5e9)](rcdebug/luau_payload.py)

- **Remotes (`ReplicatedStorage` & `Workspace`)**: Lists every client-visible `RemoteEvent`, `RemoteFunction`, and `UnreliableRemoteEvent`, ranked by risk (`Admin`, `Economy`, `DataStore`, `Combat`, `Inventory`), plus live `OnClientEvent` call rates (`calls/sec`).
- **Network Ownership**: Finds unanchored non-character `BasePart` instances in `Workspace` that nearby clients can move locally.
- **Player & Character State**: Flags `ValueBase` objects (`IntValue`, `NumberValue`, `BoolValue`, `StringValue`), player attributes, and `Tool` configs replicated to the client.
- **10s Memory & Instance Diffs**: Logs `Workspace` instance count, `LocalPlayer` instance count, and `Stats:GetTotalMemoryUsageMb()` every 10 seconds to spot leaks.
- **Static Server Checks (`--server`)**: Flags `loadstring()`, numeric `require(assetId)`, hardcoded Discord webhooks, `DataStore:SetAsync` without `UpdateAsync`, `ProcessReceipt` missing `PurchaseId` checks, unguarded `ProximityPrompt.Triggered` / `BasePart.Touched` handlers, and `OnServerEvent` listeners missing `typeof()` or cooldown guards.

---

## Project Structure

```text
rcdebug/
├── bin/rcdebug                          # CLI executable
├── assets/                              # Screenshots
├── rcdebug/
│   ├── cli.py                           # CLI parser and command router
│   ├── client_bridge.py                 # Local HTTP/WS listener + macOS Roblox log tailer
│   ├── luau_payload.py                  # Client-sided Luau scanner & 10s telemetry script
│   ├── mcp_inspector.py                 # Roblox Studio MCP client & static .rbxlx/.luau scanner
│   ├── flaw_catalog.py                  # mmap-indexed 120,000-flaw lookup engine
│   ├── debugger_pack.py                 # 120 static Luau probes
│   ├── learner.py                       # Adaptive pattern learner & command history tracker
│   ├── github_harvester.py              # GitHub Luau pattern harvester (--learn --github)
│   ├── exporter.py                      # Markdown report writer (--export)
│   └── data/
│       ├── flaws_120000.txt             # 120,000 flaw signatures (RCD-000001..RCD-120000)
│       └── luau_debugger_pack_120.json  # 120 Luau probes (LDP-001..LDP-120)
├── scripts/build_120k_corpus.py         # Generator for flaws_120000.txt
└── tests/test_rcdebug.py                # Unit test suite
```

---

## Running Tests & CI

<!-- Shields.io: CI & Runtime Environment -->
[![CI Status](https://img.shields.io/github/actions/workflow/status/roulettegun/rcdebug/ci.yml?branch=main&style=flat-square&logo=githubactions&logoColor=white&label=CI)](https://github.com/roulettegun/rcdebug/actions)
[![Test Suite](https://img.shields.io/badge/unit_tests-15_passing-10B981?style=flat-square)](tests/test_rcdebug.py)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-3B82F6?style=flat-square)](pyproject.toml)
[![Platform macOS](https://img.shields.io/badge/platform-macOS-000000?style=flat-square&logo=apple&logoColor=white)](https://github.com/roulettegun/rcdebug)

```bash
python3 -m unittest discover -s tests -v
```
