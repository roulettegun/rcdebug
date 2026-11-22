# rcdebug Design Direction (`DESIGN.md`)

## Identity & Character
- **Product:** `rcdebug` (Revan Cool Debugger), a macOS Roblox Luau runtime telemetry bridge, static place/script security auditor, and 120,000-flaw index inspector.
- **Visual Persona:** Industrial Warm-Carbon Telemetry Inspector. Built like a hardware logic analyzer and security vulnerability ledger rather than a SaaS marketing dashboard.
- **Dial:** `ENERGY 2 / RHYTHM 2 / MOTION 1`

## Color Palette (R-29: 2 Core Neutrals + 1 Deliberate Accent)
- **Dark Theme (Default for terminal/debugger parity, R-21):**
  - Core Base: `#121210` (Warm Carbon)
  - Core Surface: `#1A1916` / `#22201C` (Elevated Graphite)
  - Text Primary: `#F4F1EA` (Warm Parchment, WCAG AAA 15.8:1 against `#121210`)
  - Text Secondary: `#B5B0A4` (Muted Stone, WCAG AA 7.8:1 against `#121210`)
  - Hairline Rule: `#33302A`
  - Deliberate Accent: `#E85D2A` (Signal Vermilion, reserved strictly for the primary action trigger and active workspace focus marker)
- **Light Theme (Paper Audit Ledger, R-34):**
  - Core Base: `#F6F4EE` (Archival Paper)
  - Core Surface: `#FFFFFF` / `#ECE9E0` (Ledger Stone)
  - Text Primary: `#141412` (Carbon Ink, WCAG AAA 16.2:1 against `#F6F4EE`)
  - Text Secondary: `#57534A` (Graphite Ink, WCAG AA 7.1:1 against `#F6F4EE`)
  - Hairline Rule: `#CFCBC0`
  - Deliberate Accent: `#C84314` (Signal Vermilion Dark, WCAG AA 5.1:1 with `#FFFFFF`)
- **Semantic Severity Markers (Data-driven only):**
  - `CRITICAL`: Dark `#421118` bg / `#FDA4AF` text (`#E11D48` border) | Light `#FFE4E6` bg / `#881337` text
  - `WARN`: Dark `#3B2307` bg / `#FCD34D` text (`#D97706` border) | Light `#FEF3C7` bg / `#78350F` text
  - `INFO`: Dark `#1F242D` bg / `#CBD5E1` text (`#64748B` border) | Light `#E2E8F0` bg / `#1E293B` text

## Typography & Motif (R-06, Part 3 Levers)
- **UI Body & Prose:** System grotesque (`-apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif`) for scannable flaw explanations and remediation steps.
- **Technical Data & Code:** Tabular monospace (`"SF Mono", "Menlo", "Monaco", "Consolas", monospace`) with `font-variant-numeric: tabular-nums` restricted to instance paths, `[RCD-XXXXXX]` catalog codes, call rates (`calls/sec`), memory deltas (`MB`), and Luau code blocks.
- **Identity Motif:** Bracketed index coordinates (`[RCD-000001]`, `[LDP-001]`, `[RANK #1]`) paired with `2px` sharp technical corners (`border-radius: 2px`) and exposed `1px solid` hairline cell borders.

## Layout & Rhythm (R-05, C-3: Content-Driven Composition)
- **Focal Point:** The split-pane **Vulnerability Ledger & Remediation Drawer** is the primary decision surface (`62%` findings ledger on the left, `38%` sticky Luau remediation & payload drawer on the right).
- **Rhythm Variation (`RHYTHM 2`):**
  1. **Command Header Bar:** Single compact strip housing the active socket coordinates (`127.0.0.1:8765`), corpus counters, primary clipboard action, and theme switch.
  2. **Primary Asymmetric Split Workspace:** Triage filter strip + dense keyboard-navigable findings ledger paired with a sticky remediation & Luau code inspector.
  3. **Secondary Telemetry Strip:** Full-width horizontal dual-ledger below the fold for live `OnClientEvent` call rates (`calls/sec`) and 10-second `Workspace`/memory delta timelines.
  4. **On-Demand Modes:** Static `.luau`/`.rbxlx` source auditor, 120,000-flaw `mmap` search ledger, 120 Luau probe table, and `FlawBrain` token history switch cleanly inside the workspace.

## Written Reasons for Major Decisions (R-31)
- **Why this color?** Warm carbon (`#121210`), parchment (`#F4F1EA`), and a single signal-vermilion accent (`#E85D2A`) avoid the AI-default blue/cyan/purple palette while keeping severity tags immediately distinguishable.
- **Why this layout?** A 62%/38% master-detail vulnerability ledger keeps the finding list and its copy-pasteable server Luau fix visible side-by-side without modal popups or card-grid fluff.
- **Why this typography?** System sans-serif keeps multi-sentence flaw descriptions readable while tabular monospace aligns `[RCD-XXXXXX]` rank codes, instance paths, and `calls/sec` columns vertically.
- **Why this spacing?** Compact `8px`/`14px` table cells and `16px` structural gaps maximize visible findings above the fold on a laptop screen.
- **Why no feature cards or decorative icons?** Findings, remote rates, and memory snapshots are tabular engineering records; rendering them in hairline tables with zero decorative icons maximizes data density.
