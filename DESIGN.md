# rcdebug Design Direction (`DESIGN.md`)

## Identity & Character
- **Product:** `rcdebug` (Revan Cool Debugger), a macOS Roblox Luau runtime telemetry bridge, static place/script security auditor, and 120,000-flaw index inspector.
- **Visual Persona:** Precision Aerospace & Defense Telemetry Command Deck (Palantir Gotham / Teenage Engineering TP-7 / Anduril Lattice tactile hardware feel). High-craft choreographed motion, spring-physics micro-interactions, real-time SVG telemetry waveforms, and an interactive `Cmd+K` command palette.
- **Dial:** `ENERGY 3 / RHYTHM 3 / MOTION 3`

## Color Palette (R-29: 3 Core Surfaces + 1 Deliberate Accent)
- **Dark Theme (Obsidian Telemetry Deck, Default R-21):**
  - Core Base: `#08090C` (Deep Obsidian)
  - Core Surface: `#101217` (Tactile Slate)
  - Core Elevated: `#171A21` (Instrument Module)
  - Text Primary: `#F4F5F8` (Crisp Titanium, WCAG AAA 17.4:1 against `#08090C`)
  - Text Secondary: `#9CA3B5` (Anodized Silver, WCAG AA 7.4:1 against `#08090C`)
  - Hairline Rule: `#232733` / `#2E3444`
  - Deliberate Accent: `#FF4F18` (Aerospace Signal Orange, used on the primary action trigger, active view glider, and interactive telemetry cursor)
- **Light Theme (Ceramic Engineering Deck, R-34):**
  - Core Base: `#F3F4F6` (Machined Ceramic)
  - Core Surface: `#FFFFFF` (Pure Surface)
  - Core Elevated: `#E8EAEF` (Recessed Well)
  - Text Primary: `#0D0F14` (Carbon Black, WCAG AAA 17.8:1 against `#FFFFFF`)
  - Text Secondary: `#4A5264` (Tempered Steel, WCAG AA 7.6:1 against `#FFFFFF`)
  - Hairline Rule: `#D0D5E0`
  - Deliberate Accent: `#D93800` (Deep Signal Orange, WCAG AA 5.3:1 with `#FFFFFF`)
- **Semantic Severity Tokens (Data-driven only):**
  - `CRITICAL`: Dark `#360D15` bg / `#FDA4AF` text (`#F43F5E` border) | Light `#FFE4E6` bg / `#9F1239` text
  - `WARN`: Dark `#331F06` bg / `#FCD34D` text (`#F59E0B` border) | Light `#FEF3C7` bg / `#92400E` text
  - `INFO`: Dark `#162032` bg / `#93C5FD` text (`#3B82F6` border) | Light `#DBEAFE` bg / `#1E40AF` text

## Typography & Motif (R-06, Part 3 Levers)
- **Display & UI Prose:** Geometric neo-grotesque (`-apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif`) with tight `-0.025em` display tracking for scannable titles and architectural remediation prose.
- **Telemetry & Luau Code:** Tabular technical monospace (`"SF Mono", "JetBrains Mono", Menlo, Monaco, Consolas, monospace`) with `font-variant-numeric: tabular-nums` for live `calls/sec`, `MB` memory deltas, `[RCD-XXXXXX]` rank coordinates, and Luau code.
- **Identity Motif:** Precision corner-reticle brackets (`┌ ┐ └ ┘` CSS pseudo-element crosshairs on active modules), animated sliding nav glider, and interactive live SVG telemetry waveforms.

## Layout & Rhythm (`RHYTHM 3`: Distinct Asymmetric Compositions per Zone)
1. **Zone 1 (Single-Line Precision Command Deck):** Single non-wrapping horizontal deck with brand coordinate, animated sliding mode switcher, `Cmd+K` command launcher button, live sync pause/resume control, and theme switch.
2. **Zone 2 (Asymmetric Interactive Telemetry Strip):** Full-width visual telemetry console pairing an interactive dual-axis SVG Memory & Instance Waveform Chart (hoverable nodes showing exact snapshot diffs) with a live Severity Distribution Bar and quick-launch onboarding trigger.
3. **Zone 3 (Split Master-Detail Vulnerability Matrix & Tabbed Inspector):**
   - Left (`60%`): Interactive triage toolbar (severity pills, instant search, keyboard-navigable rows with staggered spring entry animation) + interactive 3-Card Guided Action Launcher when 0 findings are present.
   - Right (`40%`): Sticky multi-tabbed Inspector Drawer (`[Remediation & Abuse]`, `[Server Luau Fix]`, `[Client Bridge Payload]`) with one-click copy and animated confirmation.
4. **Zone 4 (Full-Bleed Live Remote Rate Matrix):** Horizontal bar-visualized remote traffic profiler where each `RemoteEvent` renders an animated proportional rate bar (`calls/sec` vs threshold) alongside its guard status.
5. **Interactive Command Palette Modal (`Cmd+K` / `Ctrl+K`):** Instant keyboard-driven modal overlay to jump to any tab, trigger a simulated playtest, copy the Luau payload, download the Markdown report, or search the 120,000-flaw index from anywhere.

## Choreographed Motion (`MOTION 3` with `prefers-reduced-motion` support)
- **Sliding Tab Glider:** Active navigation pill smoothly glides across tabs using `cubic-bezier(0.22, 1, 0.36, 1)` transform choreography.
- **Staggered Row & View Choreography:** Switching modes or receiving new findings animates rows in with a subtle `translateY(6px)` + opacity spring cascade (`--row-idx` stagger delay).
- **Interactive SVG Waveform Scrubbing:** Hovering or focusing data points on the 10-second Memory & Instance SVG chart highlights the node and updates a live readout bar.
- **Spring Number Interpolation:** Severity and corpus counters animate smoothly when new findings arrive.
- **Pause Control (`R-39`):** All continuous live polling and waveform updates pause immediately via the `Pause Live Sync` button and respect `@media (prefers-reduced-motion: reduce)`.

## Written Reasons for Major Decisions (R-31)
- **Why this color?** Deep obsidian (`#08090C`), tactile slate (`#101217`), and a single aerospace signal-orange accent (`#FF4F18`) deliver high-contrast hardware clarity without generic blue-purple AI gradients.
- **Why this layout?** Separating the top command deck, the visual SVG telemetry strip, and the 60/40 master-detail vulnerability matrix gives each engineering task (monitoring memory spikes, triaging remotes, copying Luau fixes) its own tailored spatial structure (`RHYTHM 3`).
- **Why this typography?** High-contrast neo-grotesque headings establish visual hierarchy while tabular monospace locks numeric telemetry columns and Luau code into vertical alignment.
- **Why this motion?** Spring-physics tab gliding, staggered row entry, and interactive SVG chart scrubbing provide immediate tactile feedback during live playtest debugging (`MOTION 3`).
- **Why the 3-action interactive empty state?** When 0 findings exist on first launch, interactive action cards (`1. Copy & Paste Client Luau Payload`, `2. Launch Simulated Live Playtest`, `3. Scan Local .rbxlx / .luau Directory`) let the developer populate or test the workbench in one click instead of staring at a blank box.
