# rcdebug Design Direction (`DESIGN.md`)

## Identity & Character
- **Product:** `rcdebug` (Revan Cool Debugger), a macOS Roblox Luau runtime telemetry bridge, static place/script security auditor, and 120,000-flaw index inspector.
- **Visual Persona:** Calm Modern Mac App Shell. Clean, breathable, ultra-simple left-rail desktop studio with zero box-soup clutter, whisper-quiet hairline separators, generous whitespace, and smooth spring-driven slide-over inspection.
- **Dial:** `ENERGY 2 / RHYTHM 2 / MOTION 3`

## Color Palette (R-29: Neutral Charcoal + 1 Calm Emerald Accent)
- **Dark Theme (Default, R-21):**
  - Canvas: `#09090B`
  - Surface / Sidebar: `#111114`
  - Surface Hover / Active: `#18181D`
  - Subtle Divider: `rgba(255, 255, 255, 0.08)`
  - Control Border: `#3F3F46` (soft hover `#71717A`)
  - Text Primary: `#EDEDEF` (`17.02:1` on `#09090B`, `16.12:1` on `#111114`)
  - Text Muted: `#94949E` (`6.62:1` on `#09090B`, `6.27:1` on `#111114`)
  - Deliberate Accent: `#10B981` (Calm Studio Emerald, `#051411` foreground = `7.43:1`)
- **Light Theme (Clean Studio Paper, R-34):**
  - Canvas: `#FAFAFA`
  - Surface / Sidebar: `#FFFFFF`
  - Surface Hover / Active: `#F4F4F5`
  - Subtle Divider: `rgba(0, 0, 0, 0.08)`
  - Control Border: `#A1A1AA`
  - Text Primary: `#111113` (`18.07:1` on `#FAFAFA`, `18.86:1` on `#FFFFFF`)
  - Text Muted: `#5A5A66` (`6.80:1` on `#FFFFFF`)
  - Deliberate Accent: `#047857` (`#FFFFFF` foreground = `5.48:1`)
- **Semantic Severity Dots & Text (Subtle, never loud solid blocks):**
  - `CRITICAL`: `#FB7185` (Dark) / `#BE123C` (Light)
  - `WARN`: `#FBBF24` (Dark) / `#B45309` (Light)
  - `INFO`: `#60A5FA` (Dark) / `#1D4ED8` (Light)

## Layout Architecture (Simple & Feature-Rich)
1. **Left Navigation Rail (`236px` fixed on desktop, collapsible slide-out drawer on mobile `< 860px`):**
   - Clean brand header (`rcdebug` + `v1.0.0`), subtle connection indicator (`127.0.0.1:8766`).
   - 6 clean views with smooth active pill indicator:
     - **Live Audit** (clean findings list + 1-click slide-over remediation drawer)
     - **Telemetry** (smooth Bézier memory waveform + live RemoteEvent rate bars)
     - **Static Scanner** (scan `.rbxlx`/`.luau` paths or paste Luau code directly)
     - **Flaw Catalog** (sub-10ms search across all 120,000 flaws)
     - **Luau Probes** (all 120 compiled probes)
     - **Brain & History** (learned game tokens + command log)
   - Bottom pinned rail footer: Live Sync toggle switch, Theme toggle switch, and `Cmd+K` shortcut button.
2. **Focused Main Canvas (Zero Visual Noise):**
   - Single minimal top bar (`56px` height): Current view title on the left; 2 clean actions on the right (**Copy Luau Script** primary button + **Run Demo** / **Export .md** secondary actions).
   - Spacious content area (`max-width: 1120px`, `32px` breathing room) showing only what matters for the active view.
   - **Zero nested boxes:** Findings render as a sleek, borderless list with hairline row dividers and subtle hover elevation.
3. **Smooth Slide-Over Inspector Drawer (Right Sheet):**
   - Clicking any finding smoothly glides in a clean right-hand detail sheet (`translateX(100%) -> translateX(0)` via `cubic-bezier(0.22, 1, 0.36, 1)`) with `Flaw & Abuse`, `Server Fix` (with one-click copy), and `Client Script` tabs. Closes cleanly via `Esc`, backdrop click, or close button.

## Written Reasons for Major Decisions (R-31)
- **Why a left sidebar + slide-over sheet instead of stacked top bars?** Stacking 4 rows of buttons, tabs, and charts above the fold created cramped box-soup. A `236px` left rail leaves 100% of vertical screen height for the active task while keeping every feature one click away.
- **Why calm charcoal (`#09090B`) + emerald (`#10B981`) with hairline dividers?** Removing bright borders around every element makes the panel immediately calm and readable for long debugging sessions.
- **Why separate Live Audit and Telemetry into dedicated sidebar views?** Separating the findings list from the memory oscilloscope removes empty chart boxes from the initial view and gives both views full room to breathe.
