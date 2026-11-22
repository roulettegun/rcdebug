# rcdebug Design Direction (`DESIGN.md`)

## Identity & Character
- **Product:** `rcdebug` (Revan Cool Debugger), a macOS Roblox Luau runtime telemetry bridge, static place/script security auditor, and 120,000-flaw index inspector.
- **Visual Persona:** Calm Biometric & Acoustic Telemetry Studio. High-precision, low-fatigue deep botanical slate surfaces paired with Uiverse-inspired tactile micro-controls (3D spring-elevation buttons, sliding segmented glider tracks, animated morphing theme/sync switches, and pointer-tracked surface spotlight physics).
- **Dial:** `ENERGY 3 / RHYTHM 3 / MOTION 3`

## Color Palette (R-29: 3 Core Surfaces + 1 Deliberate Accent)
- **Dark Theme (Botanical Slate Studio, Default R-21):**
  - Core Base: `#0B0F14` (Deep Calm Slate)
  - Core Surface: `#111720` (Studio Panel)
  - Core Elevated: `#161E2A` (Tactile Well)
  - Text Primary: `#EDF2F7` (Soft Alabaster, verified `17.06:1` on `#0B0F14` and `15.97:1` on `#111720` via `contrast-check.py`)
  - Text Secondary: `#98A6B8` (Calm Mist, verified `7.76:1` on `#0B0F14`, `7.27:1` on `#111720`, and `6.77:1` on `#161E2A`)
  - Interactive Control Border: `#63768D` (verified `3.86:1` non-text contrast against `#111720`, passing WCAG 1.4.11 `3.0:1`)
  - Deliberate Accent: `#2DD4BF` (Seafoam Mint, verified `10.32:1` on `#0B0F14`, with `#071312` text at `10.15:1`)
- **Light Theme (Warm Studio Day, R-34):**
  - Core Base: `#F4F6F8` (Calm Daylight)
  - Core Surface: `#FFFFFF` (Pure Sheet)
  - Core Elevated: `#E8EDF2` (Recessed Track)
  - Text Primary: `#0F1722` (Deep Ink, verified `18.01:1` on `#FFFFFF` and `16.63:1` on `#F4F6F8`)
  - Text Secondary: `#465365` (Slate Ink, verified `7.82:1` on `#FFFFFF` and `6.64:1` on `#E8EDF2`)
  - Interactive Control Border: `#6C7A8E` (verified `4.36:1` non-text contrast against `#FFFFFF`, passing WCAG 1.4.11 `3.0:1`)
  - Deliberate Accent: `#0F766E` (Deep Botanical Teal, verified `5.47:1` with `#FFFFFF` text)
- **Semantic Severity Tokens (Data-driven only):**
  - `CRITICAL`: Dark `#38111C` bg / `#FDA4AF` text (`#F43F5E` border) | Light `#FFE4E6` bg / `#9F1239` text
  - `WARN`: Dark `#362107` bg / `#FCD34D` text (`#F59E0B` border) | Light `#FEF3C7` bg / `#92400E` text
  - `INFO`: Dark `#12263A` bg / `#93C5FD` text (`#38BDF8` border) | Light `#E0F2FE` bg / `#075985` text

## Typography & Responsive Scale (R-03, R-06)
- **UI & Prose:** Fluid neo-grotesque (`-apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif`) using `clamp()` scaling (`clamp(0.95rem, 0.9rem + 0.25vw, 1.15rem)` for section titles, `clamp(1.1rem, 1rem + 0.45vw, 1.4rem)` for deck headers) so text scales smoothly across phone, tablet, and desktop and resizes to 200% zoom without clipping.
- **Telemetry & Luau Code:** Tabular technical monospace (`"SF Mono", "JetBrains Mono", Menlo, Monaco, Consolas, monospace`) with `font-variant-numeric: tabular-nums` for `[RCD-XXXXXX]` rank codes, instance paths, `calls/sec` rates, and Luau code blocks.
- **Identity Motif:** Uiverse-inspired tactile pill-track gliders, subtle `border-radius: 10px` outer frames paired with `6px` nested controls (`R-11` radius hierarchy), and cursor-tracked radial surface highlight (`--mx`, `--my`) on interactive workflow cards.

## Layout, Multi-State Responsive Reflow & Rhythm (`RHYTHM 3`, `antislop-layoutmobile`)
- **Three-State Responsive Reflow (`R-03`):**
  - **Desktop (`> 1120px`):** Asymmetric 60% / 40% Master-Detail Vulnerability Matrix + Dual-Column Telemetry Waveform & Distribution Strip + 3-Column Guided Workflow Launcher.
  - **Tablet / Small Laptop (`680px – 1120px`):** 2-column intermediate reflow for workflow cards and telemetry panels, stacked master-detail inspector with full-width code view.
  - **Mobile (`< 680px`):** Single-column reflow with reduced mobile spacing register (`12px` padding), horizontally scrollable pill track with snap alignment, and `44px x 44px` minimum touch targets with `>= 8px` gap spacing.
- **Asymmetric Section Rhythm (`RHYTHM 3`):**
  1. **Zone 1 (Tactile Studio Header & Glider Track):** Compact header bar with Uiverse-style 3D spring buttons, morphing toggle switches for Live Sync and Theme, and a sliding pill-glider navigation track.
  2. **Zone 2 (Interactive Bézier Spline Telemetry Oscilloscope & Distribution Bar):** Smooth cubic-Bézier SVG memory/instance curve with animated stroke-dashoffset draw-in and keyboard/touch-scrubbable nodes paired with a spring-animated severity ratio bar.
  3. **Zone 3 (60/40 Master-Detail Vulnerability Matrix & 3-Tab Inspector Drawer):** Interactive severity filter pills, floating-focus search field, pointer-spotlight guided workflow cards when 0 findings are present, and a 3-tab Luau remediation drawer.
  4. **Zone 4 (Proportional Rate-Bar Remote Matrix & 10s Snapshot Delta Ledger):** Dual horizontal telemetry tables below the fold.

## Choreographed Motion & Uiverse Micro-Interactions (`MOTION 3`, `R-19`, `R-39`)
1. **Uiverse Tactile Spring Buttons (`.uiv-btn`):** Physical 3D press depth (`translateY(-2px)` hover lift, `translateY(1px)` active press) with an animated inner sheen sweep on interaction.
2. **Uiverse Sliding Segmented Glider (`.tab-glider`):** Smooth `cubic-bezier(0.22, 1, 0.36, 1)` pill indicator that glides behind the active view tab and drawer sub-tab.
3. **Uiverse Interactive Toggle Switches (`.uiv-switch`):** Native `<button role="switch">` controls with sliding thumb physics for **Live Sync** and **Theme** switching.
4. **Pointer-Tracked Spotlight Cards (`.workflow-card`):** Mouse/touch position updates CSS variables (`--mx`, `--my`) to project a soft seafoam-mint radial border highlight under the cursor.
5. **Smooth Cubic-Bézier SVG Waveform & Staggered Row Cascade:** SVG telemetry curve draws smoothly and table rows cascade in with `--row-idx` spring delays. All motion respects `@media (prefers-reduced-motion: reduce)` and pauses via the **Live Sync** switch (`R-39`).

## Written Reasons for Major Decisions (R-31)
- **Why this color?** Deep botanical slate (`#0B0F14` / `#111720`) and a single calm seafoam-mint accent (`#2DD4BF`) create a low-fatigue, soothing engineering environment while exceeding WCAG AAA text contrast (`17.06:1`) and WCAG 1.4.11 non-text control contrast (`3.86:1`).
- **Why this layout?** A 3-state responsive reflow (desktop asymmetric 60/40 matrix -> tablet 2-column grid -> mobile single-column stack) ensures every viewport from 360px phone to 1600px monitor has a purpose-built layout.
- **Why this typography?** Fluid `clamp()` neo-grotesque headings scale smoothly across viewports and 200% zoom, while tabular monospace aligns numeric rates, ranks, and Luau code.
- **Why this motion?** Uiverse-style spring buttons, sliding tab gliders, pointer-tracked card spotlights, and smooth SVG Bézier curves make every click, hover, and tap feel responsive and tactile without endless looping noise.
- **Why the radius hierarchy (`10px` panels / `6px` buttons / `4px` tags)?** Distinct radii separate outer containers from interactive controls and inline data tags (`R-11`).
