"""
Interactive Web Workbench for rcdebug (rcdebug --ui).

Follows DESIGN.md (Industrial Warm-Carbon Telemetry Inspector, Dial: ENERGY 2 / RHYTHM 2 / MOTION 1).
Serves both the live Roblox Luau runtime bridge (/report, /telemetry, /ws, /status, /shutdown)
and the browser workbench (/ui, /api/*) on the same local port using only the Python standard library.
"""

from __future__ import annotations

import json
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .client_bridge import (
    ROBLOX_LOGS_DIR,
    DebugReportHandler,
    RobloxLogTailer,
    RuntimeBridgeServer,
    simulate_studio_playtest_traffic,
)
from .debugger_pack import get_debugger_pack
from .exporter import generate_markdown_report
from .flaw_catalog import get_catalog
from .learner import CommandHistory
from .luau_payload import build_luau_bridge_script
from .mcp_inspector import audit_local_path, audit_luau_script_source
from .models import AuditSession, SeverityFilter, matches_filter
from .terminal import BOLD, CYAN, DIM, GREEN, RESET, YELLOW, copy_to_clipboard, normalize_filter_label, print_banner


UI_HTML_DOCUMENT = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>rcdebug Workbench</title>
  <style>
    :root, [data-theme="dark"] {
      --bg: #121210;
      --surface: #1a1916;
      --surface-alt: #22201c;
      --border: #33302a;
      --text: #f4f1ea;
      --text-muted: #b5b0a4;
      --accent: #e85d2a;
      --accent-fg: #121210;
      --crit-bg: #421118;
      --crit-fg: #fda4af;
      --crit-border: #e11d48;
      --warn-bg: #3b2307;
      --warn-fg: #fcd34d;
      --warn-border: #d97706;
      --info-bg: #1f242d;
      --info-fg: #cbd5e1;
      --info-border: #64748b;
      --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
      --font-mono: "SF Mono", Menlo, Monaco, Consolas, monospace;
    }

    [data-theme="light"] {
      --bg: #f6f4ee;
      --surface: #ffffff;
      --surface-alt: #ece9e0;
      --border: #cfcbc0;
      --text: #141412;
      --text-muted: #57534a;
      --accent: #c84314;
      --accent-fg: #ffffff;
      --crit-bg: #ffe4e6;
      --crit-fg: #881337;
      --crit-border: #e11d48;
      --warn-bg: #fef3c7;
      --warn-fg: #78350f;
      --warn-border: #d97706;
      --info-bg: #e2e8f0;
      --info-fg: #1e293b;
      --info-border: #64748b;
    }

    *, *::before, *::after {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.45;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    a[href], button, summary, select, label[for], input[type="checkbox"], [role="button"], [role="tab"] {
      cursor: pointer;
    }

    button:disabled, input:disabled, select:disabled, textarea:disabled {
      cursor: not-allowed;
      opacity: 0.5;
    }

    :focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }

    header.cmd-bar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 10px 18px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .brand-cluster {
      display: flex;
      align-items: baseline;
      gap: 14px;
      flex-wrap: wrap;
    }

    .brand-cluster h1 {
      margin: 0;
      font-family: var(--font-mono);
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .coord-tag {
      font-family: var(--font-mono);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
      color: var(--text-muted);
      background: var(--surface-alt);
      border: 1px solid var(--border);
      padding: 3px 8px;
      border-radius: 2px;
    }

    .action-cluster {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

    .ctrl-btn {
      min-height: 44px;
      padding: 8px 13px;
      border-radius: 2px;
      border: 1px solid var(--border);
      background: var(--surface-alt);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 600;
    }

    .ctrl-btn:hover:not(:disabled) {
      background: var(--surface);
      border-color: var(--text);
    }

    .ctrl-btn:active:not(:disabled) {
      transform: translateY(1px);
    }

    .ctrl-btn-accent {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--accent);
      font-weight: 700;
    }

    .ctrl-btn-accent:hover:not(:disabled) {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--text);
    }

    nav.mode-strip {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }

    .tab-list {
      display: flex;
      gap: 2px;
      overflow-x: auto;
    }

    .mode-tab {
      min-height: 44px;
      padding: 10px 14px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
    }

    .mode-tab:hover {
      color: var(--text);
      background: var(--surface-alt);
    }

    .mode-tab[aria-selected="true"] {
      color: var(--text);
      border-bottom-color: var(--accent);
      background: var(--surface-alt);
    }

    .poll-controls {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px 0;
    }

    main.workbench {
      flex: 1;
      width: 100%;
      max-width: 1560px;
      margin: 0 auto;
      padding: 16px 18px 28px;
    }

    .status-notice {
      display: none;
      margin-bottom: 14px;
      padding: 10px 14px;
      background: var(--surface-alt);
      border: 1px solid var(--accent);
      border-radius: 2px;
      font-family: var(--font-mono);
      font-size: 12px;
    }

    .status-notice.visible {
      display: block;
    }

    .view-section {
      display: none;
    }

    .view-section.active {
      display: block;
    }

    .triage-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 14px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-bottom: none;
    }

    .sev-group, .search-cluster {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .field-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
    }

    .sev-btn {
      min-height: 44px;
      padding: 6px 12px;
      border-radius: 2px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }

    .sev-btn[aria-pressed="true"].sev-CRITICAL {
      background: var(--crit-bg);
      color: var(--crit-fg);
      border-color: var(--crit-border);
    }

    .sev-btn[aria-pressed="true"].sev-WARN {
      background: var(--warn-bg);
      color: var(--warn-fg);
      border-color: var(--warn-border);
    }

    .sev-btn[aria-pressed="true"].sev-INFO {
      background: var(--info-bg);
      color: var(--info-fg);
      border-color: var(--info-border);
    }

    .text-field, .select-field, .code-area {
      min-height: 44px;
      padding: 8px 12px;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 2px;
      font-family: var(--font-sans);
      font-size: 13px;
    }

    .code-area {
      font-family: var(--font-mono);
      width: 100%;
      min-height: 190px;
      resize: vertical;
      line-height: 1.45;
    }

    /* RHYTHM 2: Section 1 is an asymmetric 62% / 38% split master-detail ledger */
    .ledger-split {
      display: grid;
      grid-template-columns: minmax(0, 1.65fr) minmax(340px, 1fr);
      border: 1px solid var(--border);
      background: var(--surface);
    }

    @media (max-width: 1024px) {
      .ledger-split {
        grid-template-columns: 1fr;
      }
    }

    .ledger-pane {
      border-right: 1px solid var(--border);
      min-width: 0;
    }

    @media (max-width: 1024px) {
      .ledger-pane {
        border-right: none;
        border-bottom: 1px solid var(--border);
      }
    }

    .drawer-pane {
      background: var(--surface);
      min-width: 0;
    }

    .pane-head {
      padding: 10px 14px;
      background: var(--surface-alt);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }

    .pane-head h2 {
      margin: 0;
      font-size: 13px;
      font-weight: 700;
    }

    .scroll-ledger {
      overflow-x: auto;
      max-height: 540px;
      overflow-y: auto;
    }

    table.ledger-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }

    table.ledger-table th,
    table.ledger-table td {
      padding: 9px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }

    table.ledger-table th {
      background: var(--surface-alt);
      color: var(--text-muted);
      font-size: 12px;
      font-weight: 600;
      position: sticky;
      top: 0;
      z-index: 1;
    }

    table.ledger-table tbody tr.finding-row {
      cursor: pointer;
    }

    table.ledger-table tbody tr.finding-row:hover {
      background: var(--surface-alt);
    }

    table.ledger-table tbody tr.finding-row.active-row {
      background: var(--surface-alt);
      box-shadow: inset 3px 0 0 var(--accent);
    }

    .sev-tag {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 2px;
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      border: 1px solid transparent;
      font-variant-numeric: tabular-nums;
    }

    .sev-tag-CRITICAL {
      background: var(--crit-bg);
      color: var(--crit-fg);
      border-color: var(--crit-border);
    }

    .sev-tag-WARN {
      background: var(--warn-bg);
      color: var(--warn-fg);
      border-color: var(--warn-border);
    }

    .sev-tag-INFO {
      background: var(--info-bg);
      color: var(--info-fg);
      border-color: var(--info-border);
    }

    .mono-cell {
      font-family: var(--font-mono);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
      word-break: break-word;
    }

    .drawer-content {
      padding: 14px;
    }

    .spec-block {
      margin-bottom: 14px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }

    .spec-block:last-child {
      border-bottom: none;
      margin-bottom: 0;
      padding-bottom: 0;
    }

    .spec-label {
      margin: 0 0 4px 0;
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
    }

    .spec-value {
      margin: 0;
      font-size: 13px;
    }

    pre.luau-code {
      margin: 6px 0 0 0;
      padding: 10px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 2px;
      font-family: var(--font-mono);
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      max-height: 300px;
      overflow-y: auto;
    }

    /* RHYTHM 2: Section 2 below the fold is a full-width stacked telemetry strip */
    .telemetry-strip {
      margin-top: 22px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    @media (max-width: 960px) {
      .telemetry-strip {
        grid-template-columns: 1fr;
      }
    }

    .ledger-frame {
      background: var(--surface);
      border: 1px solid var(--border);
    }

    .state-panel {
      padding: 22px 16px;
      color: var(--text-muted);
    }

    .state-panel h3 {
      margin: 0 0 6px 0;
      font-size: 14px;
      color: var(--text);
    }

    .state-panel p {
      margin: 0;
      font-size: 13px;
    }

    /* RHYTHM 2: Static Scanner uses a vertical workbench flow */
    .scanner-stack {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    @media (max-width: 960px) {
      .scanner-stack {
        grid-template-columns: 1fr;
      }
    }

    footer.status-footer {
      background: var(--surface);
      border-top: 1px solid var(--border);
      padding: 10px 18px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }
  </style>
</head>
<body>
  <header class="cmd-bar">
    <div class="brand-cluster">
      <h1>rcdebug [v__VERSION__]</h1>
      <span class="coord-tag" id="bridge-coord-tag">[BRIDGE 127.0.0.1:8765]</span>
      <span class="coord-tag" id="corpus-coord-tag">[CORPUS 120,000 FLAWS | 120 PROBES]</span>
    </div>
    <div class="action-cluster">
      <button type="button" class="ctrl-btn ctrl-btn-accent" id="btn-copy-luau">Copy Client Luau Payload</button>
      <button type="button" class="ctrl-btn" id="btn-simulate">Inject Sample Playtest</button>
      <button type="button" class="ctrl-btn" id="btn-export-md">Export Report (.md)</button>
      <button type="button" class="ctrl-btn" id="btn-clear-session">Reset Session</button>
      <button type="button" class="ctrl-btn" id="btn-theme-toggle" aria-label="Switch color theme">Theme: Carbon Dark</button>
    </div>
  </header>

  <nav class="mode-strip" aria-label="Inspector Modes">
    <div class="tab-list" role="tablist">
      <button type="button" class="mode-tab" role="tab" aria-selected="true" aria-controls="view-live" id="tab-live">[01] Vulnerability Ledger &amp; Telemetry</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-static" id="tab-static">[02] Static Place &amp; Luau Auditor</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-catalog" id="tab-catalog">[03] 120,000 Flaw Index (mmap)</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-pack" id="tab-pack">[04] 120 Luau Probes</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-brain" id="tab-brain">[05] FlawBrain &amp; CLI History</button>
    </div>
    <div class="poll-controls">
      <span class="mono-cell" id="sync-status-label">[SYNC: LIVE 1.5s]</span>
      <button type="button" class="ctrl-btn" id="btn-toggle-sync" aria-pressed="true">Pause Live Sync</button>
    </div>
  </nav>

  <main class="workbench">
    <div class="status-notice" id="notice-banner" role="status" aria-live="polite"></div>

    <section class="view-section active" id="view-live" role="tabpanel" aria-labelledby="tab-live">
      <div class="triage-bar">
        <div class="sev-group" role="group" aria-label="Severity Filters">
          <span class="field-label">Triage Severity:</span>
          <button type="button" class="sev-btn sev-CRITICAL" data-sev="CRITICAL" aria-pressed="true">CRITICAL [<span id="cnt-crit">0</span>]</button>
          <button type="button" class="sev-btn sev-WARN" data-sev="WARN" aria-pressed="true">WARN [<span id="cnt-warn">0</span>]</button>
          <button type="button" class="sev-btn sev-INFO" data-sev="INFO" aria-pressed="true">INFO [<span id="cnt-info">0</span>]</button>
        </div>
        <div class="search-cluster">
          <label class="field-label" for="input-live-filter">Filter Ledger:</label>
          <input type="search" id="input-live-filter" class="text-field" placeholder="Remote name, instance path, or [RCD-XXXXXX]..." />
        </div>
      </div>

      <div class="ledger-split">
        <div class="ledger-pane">
          <div class="pane-head">
            <h2>Ordered Findings Ledger (<span id="visible-findings-cnt">0</span> shown)</h2>
            <span class="mono-cell" id="session-target-text">Target: Roblox Client Runtime Bridge</span>
          </div>
          <div class="scroll-ledger" id="findings-ledger-box">
            <div class="state-panel">
              <h3>Loading active audit session...</h3>
              <p>Querying local rcdebug runtime bridge state.</p>
            </div>
          </div>
        </div>

        <aside class="drawer-pane" aria-label="Remediation & Luau Payload Drawer">
          <div class="pane-head">
            <h2>Remediation &amp; Luau Inspector</h2>
            <span class="mono-cell" id="inspector-code-tag">[CLIENT PAYLOAD]</span>
          </div>
          <div class="drawer-content" id="remediation-drawer">
            <div class="spec-block">
              <p class="spec-label">[INSPECTOR READY]</p>
              <p class="spec-value">Select any finding row on the left to inspect its root architectural flaw, client abuse vector, and server-side Luau fix. Copy the client diagnostic payload below to run inside Roblox Developer Console or Studio Command Bar.</p>
            </div>
            <div class="spec-block">
              <p class="spec-label">[100% CLIENT-SIDED LUAU BRIDGE PAYLOAD]</p>
              <pre class="luau-code" id="luau-script-box">Loading client Luau payload...</pre>
            </div>
          </div>
        </aside>
      </div>

      <div class="telemetry-strip">
        <div class="ledger-frame">
          <div class="pane-head">
            <h2>Remote Traffic Rate Ledger (OnClientEvent calls/sec)</h2>
          </div>
          <div class="scroll-ledger" id="remotes-ledger-box"></div>
        </div>

        <div class="ledger-frame">
          <div class="pane-head">
            <h2>10s Instance &amp; Memory Delta Ledger</h2>
          </div>
          <div class="scroll-ledger" id="snapshots-ledger-box"></div>
        </div>
      </div>
    </section>

    <section class="view-section" id="view-static" role="tabpanel" aria-labelledby="tab-static">
      <div class="scanner-stack">
        <div class="ledger-frame">
          <div class="pane-head">
            <h2>Scan Local Place (.rbxlx / .rbxmx) or Luau Directory</h2>
          </div>
          <div class="drawer-content">
            <form id="form-scan-path">
              <div class="spec-block">
                <label class="field-label" for="input-scan-path">Filesystem path to .rbxlx place file or .luau scripts folder:</label>
                <div class="search-cluster" style="margin-top:8px;">
                  <input type="text" id="input-scan-path" class="text-field" style="flex:1;" placeholder="./place.rbxlx or ./src/ServerScriptService" />
                  <button type="submit" class="ctrl-btn ctrl-btn-accent">Audit Path</button>
                </div>
              </div>
            </form>

            <form id="form-scan-source">
              <div class="spec-block">
                <label class="field-label" for="input-luau-source">Paste Luau script source for immediate static analysis:</label>
                <textarea id="input-luau-source" class="code-area" style="margin-top:8px;" placeholder="-- Paste Luau server or client script source here to test against 12 static rules and 120 probes"></textarea>
                <div style="margin-top:10px;">
                  <button type="submit" class="ctrl-btn ctrl-btn-accent">Audit Luau Source</button>
                </div>
              </div>
            </form>
          </div>
        </div>

        <div class="ledger-frame">
          <div class="pane-head">
            <h2>Static Audit Execution Log</h2>
          </div>
          <div class="drawer-content" id="static-audit-log">
            <div class="state-panel" style="padding:8px 0;">
              <h3>No static scan executed in this view yet</h3>
              <p>Submit a local file/directory path or paste a Luau script on the left. Discovered findings are merged directly into the [01] Vulnerability Ledger and ranked by severity.</p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="view-section" id="view-catalog" role="tabpanel" aria-labelledby="tab-catalog">
      <div class="triage-bar">
        <form id="form-catalog-search" class="search-cluster" style="flex:1;">
          <label class="field-label" for="input-catalog-q">Query 120,000 Flaws:</label>
          <input type="search" id="input-catalog-q" class="text-field" style="flex:1;" placeholder="datastore, processreceipt, networkowner, remoteevent, cframe..." />
          <label class="field-label" for="select-catalog-sev">Tier:</label>
          <select id="select-catalog-sev" class="select-field">
            <option value="">ALL TIERS</option>
            <option value="CRITICAL">CRITICAL (RCD-000001..025000)</option>
            <option value="WARN">WARN (RCD-025001..065000)</option>
            <option value="INFO">INFO (RCD-065001..120000)</option>
          </select>
          <button type="submit" class="ctrl-btn ctrl-btn-accent">Query Index</button>
        </form>
      </div>
      <div class="ledger-frame">
        <div class="pane-head">
          <h2>120,000-Flaw Corpus Matches (<span id="catalog-match-cnt">0</span>)</h2>
          <span class="mono-cell" id="catalog-latency-tag">[MMAP SEEK: READY]</span>
        </div>
        <div class="scroll-ledger" id="catalog-ledger-box"></div>
      </div>
    </section>

    <section class="view-section" id="view-pack" role="tabpanel" aria-labelledby="tab-pack">
      <div class="triage-bar">
        <form id="form-pack-search" class="search-cluster" style="flex:1;">
          <label class="field-label" for="input-pack-q">Filter 120 Luau Debugger Probes:</label>
          <input type="search" id="input-pack-q" class="text-field" style="flex:1;" placeholder="selene, luau-lsp, trove, janitor, heartbeat, task.wait..." />
          <button type="submit" class="ctrl-btn ctrl-btn-accent">Filter Probes</button>
        </form>
      </div>
      <div class="ledger-frame">
        <div class="pane-head">
          <h2>Compiled Luau Debugger Probes (<span id="pack-match-cnt">0</span>)</h2>
        </div>
        <div class="scroll-ledger" id="pack-ledger-box"></div>
      </div>
    </section>

    <section class="view-section" id="view-brain" role="tabpanel" aria-labelledby="tab-brain">
      <div class="telemetry-strip" style="margin-top:0;">
        <div class="ledger-frame">
          <div class="pane-head">
            <h2>Learned Game Tokens (~/.rcdebug/learned_flaws.json)</h2>
          </div>
          <div class="scroll-ledger" id="brain-tokens-box"></div>
        </div>
        <div class="ledger-frame">
          <div class="pane-head">
            <h2>Logged CLI &amp; UI Invocations (~/.rcdebug/command_history.json)</h2>
          </div>
          <div class="scroll-ledger" id="brain-history-box"></div>
        </div>
      </div>
    </section>
  </main>

  <footer class="status-footer">
    <span>rcdebug v__VERSION__ | Zero-Dependency Python Standard Library Engine</span>
    <span>Log Tailer Source: ~/Library/Logs/Roblox/*_last.log</span>
  </footer>

  <script>
    (function() {
      const uiState = {
        theme: "dark",
        syncEnabled: true,
        syncTimer: null,
        sevFilter: { CRITICAL: true, WARN: true, INFO: true },
        textFilter: "",
        selectedIdx: -1,
        session: null,
        luauScript: "",
        bridgeError: null
      };

      function esc(val) {
        return String(val == null ? "" : val)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      }

      function notify(msg) {
        const banner = document.getElementById("notice-banner");
        banner.textContent = msg;
        banner.classList.add("visible");
        clearTimeout(banner._t);
        banner._t = setTimeout(function() {
          banner.classList.remove("visible");
        }, 4500);
      }

      const tabs = Array.from(document.querySelectorAll(".mode-tab"));
      const sections = Array.from(document.querySelectorAll(".view-section"));
      tabs.forEach(function(tab) {
        tab.addEventListener("click", function() {
          tabs.forEach(function(t) { t.setAttribute("aria-selected", "false"); });
          sections.forEach(function(s) { s.classList.remove("active"); });
          tab.setAttribute("aria-selected", "true");
          const targetId = tab.getAttribute("aria-controls");
          const sec = document.getElementById(targetId);
          if (sec) sec.classList.add("active");
          if (targetId === "view-catalog" && !sec._initialized) {
            sec._initialized = true;
            queryCatalog("", "");
          } else if (targetId === "view-pack" && !sec._initialized) {
            sec._initialized = true;
            queryPack("");
          } else if (targetId === "view-brain") {
            queryBrainHistory();
          }
        });
      });

      const themeBtn = document.getElementById("btn-theme-toggle");
      themeBtn.addEventListener("click", function() {
        uiState.theme = uiState.theme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", uiState.theme);
        themeBtn.textContent = uiState.theme === "dark" ? "Theme: Carbon Dark" : "Theme: Paper Ledger";
      });

      const syncBtn = document.getElementById("btn-toggle-sync");
      const syncLabel = document.getElementById("sync-status-label");
      syncBtn.addEventListener("click", function() {
        uiState.syncEnabled = !uiState.syncEnabled;
        syncBtn.setAttribute("aria-pressed", uiState.syncEnabled ? "true" : "false");
        syncBtn.textContent = uiState.syncEnabled ? "Pause Live Sync" : "Resume Live Sync";
        syncLabel.textContent = uiState.syncEnabled ? "[SYNC: LIVE 1.5s]" : "[SYNC: PAUSED]";
        if (uiState.syncEnabled) fetchBridgeState();
      });

      document.querySelectorAll(".sev-btn").forEach(function(btn) {
        btn.addEventListener("click", function() {
          const sev = btn.getAttribute("data-sev");
          uiState.sevFilter[sev] = !uiState.sevFilter[sev];
          btn.setAttribute("aria-pressed", uiState.sevFilter[sev] ? "true" : "false");
          renderSessionView();
        });
      });

      document.getElementById("input-live-filter").addEventListener("input", function(e) {
        uiState.textFilter = e.target.value.trim().toLowerCase();
        renderSessionView();
      });

      function getFilteredFindings() {
        if (!uiState.session || !Array.isArray(uiState.session.findings)) return [];
        return uiState.session.findings.filter(function(f) {
          if (!uiState.sevFilter[f.severity]) return false;
          if (!uiState.textFilter) return true;
          const hay = (f.title + " " + f.path + " " + f.category + " " + f.flaw).toLowerCase();
          return hay.indexOf(uiState.textFilter) !== -1;
        });
      }

      function renderDrawer(finding) {
        const drawer = document.getElementById("remediation-drawer");
        const tag = document.getElementById("inspector-code-tag");
        if (!finding) {
          tag.textContent = "[CLIENT PAYLOAD]";
          drawer.innerHTML =
            '<div class="spec-block">' +
              '<p class="spec-label">[INSPECTOR READY]</p>' +
              '<p class="spec-value">Select any finding row on the left to inspect its architectural flaw, client abuse vector, and server-side Luau remediation code.</p>' +
            '</div>' +
            '<div class="spec-block">' +
              '<p class="spec-label">[100% CLIENT-SIDED LUAU BRIDGE PAYLOAD]</p>' +
              '<pre class="luau-code">' + esc(uiState.luauScript || "Loading...") + '</pre>' +
            '</div>';
          return;
        }
        const rankStr = finding.rank && finding.rank < 999999 ? ("RANK #" + finding.rank) : finding.category;
        tag.textContent = "[" + rankStr + "]";
        const codeHtml = finding.code_example
          ? '<div class="spec-block"><p class="spec-label">[SERVER LUAU REMEDIATION PATTERN]</p><pre class="luau-code">' + esc(finding.code_example) + '</pre></div>'
          : '';
        drawer.innerHTML =
          '<div class="spec-block">' +
            '<span class="sev-tag sev-tag-' + esc(finding.severity) + '">' + esc(finding.severity) + '</span> ' +
            '<span class="mono-cell">[' + esc(finding.category) + ']</span>' +
            '<h3 style="margin:8px 0 0 0;font-size:15px;">' + esc(finding.title) + '</h3>' +
          '</div>' +
          '<div class="spec-block"><p class="spec-label">[INSTANCE / SCRIPT COORDINATE]</p><p class="mono-cell">' + esc(finding.path) + '</p></div>' +
          '<div class="spec-block"><p class="spec-label">[ARCHITECTURAL FLAW]</p><p class="spec-value">' + esc(finding.flaw) + '</p></div>' +
          '<div class="spec-block"><p class="spec-label">[CLIENT ABUSE VECTOR]</p><p class="spec-value">' + esc(finding.abuse) + '</p></div>' +
          '<div class="spec-block"><p class="spec-label">[RECOMMENDED FIX]</p><p class="spec-value">' + esc(finding.fix) + '</p></div>' +
          codeHtml;
      }

      function renderSessionView() {
        const box = document.getElementById("findings-ledger-box");
        if (uiState.bridgeError) {
          box.innerHTML =
            '<div class="state-panel">' +
              '<h3>Runtime bridge connection interrupted</h3>' +
              '<p>Error: ' + esc(uiState.bridgeError) + '. Confirm that rcdebug --ui is running in your terminal or click Resume Live Sync.</p>' +
            '</div>';
          return;
        }
        if (!uiState.session) return;

        const counts = uiState.session.severity_counts || { CRITICAL: 0, WARN: 0, INFO: 0 };
        document.getElementById("cnt-crit").textContent = counts.CRITICAL || 0;
        document.getElementById("cnt-warn").textContent = counts.WARN || 0;
        document.getElementById("cnt-info").textContent = counts.INFO || 0;
        document.getElementById("session-target-text").textContent = "Target: " + (uiState.session.target_name || "");

        const visible = getFilteredFindings();
        document.getElementById("visible-findings-cnt").textContent = visible.length;

        if (visible.length === 0) {
          const total = (uiState.session.findings || []).length;
          if (total === 0) {
            box.innerHTML =
              '<div class="state-panel">' +
                '<h3>0 findings recorded in the active session</h3>' +
                '<p>Paste (Cmd+V) the client Luau payload into Roblox Developer Console / Studio Command Bar, or click "Inject Sample Playtest" in the top bar to populate test telemetry.</p>' +
              '</div>';
          } else {
            box.innerHTML =
              '<div class="state-panel">' +
                '<h3>0 findings match the current filter</h3>' +
                '<p>' + total + ' finding(s) are hidden by the active severity toggles or search query. Re-enable CRITICAL/WARN/INFO or clear the filter box.</p>' +
              '</div>';
          }
          renderDrawer(null);
        } else {
          let rows = "";
          visible.forEach(function(f, idx) {
            const activeCls = idx === uiState.selectedIdx ? " active-row" : "";
            const rankBadge = f.rank && f.rank < 999999 ? ("#" + f.rank) : "-";
            rows +=
              '<tr class="finding-row' + activeCls + '" data-idx="' + idx + '" tabindex="0">' +
                '<td><span class="sev-tag sev-tag-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
                '<td class="mono-cell">' + esc(rankBadge) + '</td>' +
                '<td class="mono-cell">' + esc(f.category) + '</td>' +
                '<td><strong>' + esc(f.title) + '</strong></td>' +
                '<td class="mono-cell">' + esc(f.path) + '</td>' +
                '<td class="mono-cell">' + esc(f.timestamp) + '</td>' +
              '</tr>';
          });
          box.innerHTML =
            '<table class="ledger-table">' +
              '<thead><tr><th>Severity</th><th>Rank</th><th>Category</th><th>Finding</th><th>Instance Path</th><th>Time</th></tr></thead>' +
              '<tbody>' + rows + '</tbody>' +
            '</table>';

          box.querySelectorAll("tr.finding-row").forEach(function(tr) {
            function pick() {
              uiState.selectedIdx = parseInt(tr.getAttribute("data-idx"), 10);
              renderSessionView();
              renderDrawer(visible[uiState.selectedIdx]);
            }
            tr.addEventListener("click", pick);
            tr.addEventListener("keydown", function(e) {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                pick();
              }
            });
          });
          if (uiState.selectedIdx >= 0 && uiState.selectedIdx < visible.length) {
            renderDrawer(visible[uiState.selectedIdx]);
          }
        }

        const remBox = document.getElementById("remotes-ledger-box");
        const remotes = uiState.session.remote_traffic || [];
        if (remotes.length === 0) {
          remBox.innerHTML =
            '<div class="state-panel">' +
              '<h3>No RemoteEvent traffic sampled yet</h3>' +
              '<p>Live OnClientEvent call rates (calls/sec) populate every 10 seconds once the client Luau bridge is running.</p>' +
            '</div>';
        } else {
          let rRows = "";
          remotes.forEach(function(r) {
            const flagHtml = r.has_cooldown_warning
              ? '<span class="sev-tag sev-tag-CRITICAL">UNTHROTTLED</span>'
              : '<span class="sev-tag sev-tag-INFO">NOMINAL</span>';
            rRows +=
              '<tr>' +
                '<td class="mono-cell">' + esc(r.remote_path) + '</td>' +
                '<td class="mono-cell">' + esc(r.remote_type) + '</td>' +
                '<td class="mono-cell">' + esc(r.last_rate_per_sec.toFixed(1)) + '/s</td>' +
                '<td class="mono-cell">' + esc(r.peak_rate_per_sec.toFixed(1)) + '/s</td>' +
                '<td class="mono-cell">' + esc(r.total_calls) + '</td>' +
                '<td>' + flagHtml + '</td>' +
              '</tr>';
          });
          remBox.innerHTML =
            '<table class="ledger-table">' +
              '<thead><tr><th>Remote Path</th><th>Class</th><th>Current</th><th>Peak</th><th>Total Calls</th><th>Guard State</th></tr></thead>' +
              '<tbody>' + rRows + '</tbody>' +
            '</table>';
        }

        const snapBox = document.getElementById("snapshots-ledger-box");
        const snaps = uiState.session.memory_snapshots || [];
        if (snaps.length === 0) {
          snapBox.innerHTML =
            '<div class="state-panel">' +
              '<h3>No 10s memory snapshots recorded yet</h3>' +
              '<p>Workspace instance count, Player instance count, and total memory (MB) are logged every 10 seconds during an active playtest.</p>' +
            '</div>';
        } else {
          let sRows = "";
          snaps.forEach(function(s, i) {
            const prev = i > 0 ? snaps[i - 1] : null;
            const wsD = prev ? (s.workspace_instances - prev.workspace_instances) : 0;
            const memD = prev ? (s.total_memory_mb - prev.total_memory_mb) : 0;
            const deltaStr = prev
              ? ((wsD >= 0 ? "+" : "") + wsD + " inst / " + (memD >= 0 ? "+" : "") + memD.toFixed(2) + " MB")
              : "[BASELINE]";
            sRows +=
              '<tr>' +
                '<td class="mono-cell">' + esc(s.timestamp) + '</td>' +
                '<td class="mono-cell">' + esc(s.elapsed_sec.toFixed(1)) + 's</td>' +
                '<td class="mono-cell">' + esc(s.workspace_instances) + '</td>' +
                '<td class="mono-cell">' + esc(s.player_instances) + '</td>' +
                '<td class="mono-cell">' + esc(s.total_memory_mb.toFixed(2)) + ' MB</td>' +
                '<td class="mono-cell">' + esc(deltaStr) + '</td>' +
              '</tr>';
          });
          snapBox.innerHTML =
            '<table class="ledger-table">' +
              '<thead><tr><th>Time</th><th>Elapsed</th><th>Workspace</th><th>Players</th><th>Memory</th><th>10s Delta</th></tr></thead>' +
              '<tbody>' + sRows + '</tbody>' +
            '</table>';
        }
      }

      function fetchBridgeState() {
        if (!uiState.syncEnabled) return;
        fetch("/api/state")
          .then(function(r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(function(data) {
            uiState.bridgeError = null;
            uiState.session = data.session;
            if (!uiState.luauScript && data.luau_script) {
              uiState.luauScript = data.luau_script;
            }
            document.getElementById("bridge-coord-tag").textContent =
              "[BRIDGE " + data.host + ":" + data.port + "]";
            document.getElementById("corpus-coord-tag").textContent =
              "[CORPUS " + data.catalog_count.toLocaleString() + " FLAWS | " +
              data.learned_count.toLocaleString() + " LEARNED | " +
              data.brain_concepts.toLocaleString() + " CONCEPTS]";
            renderSessionView();
          })
          .catch(function(err) {
            uiState.bridgeError = err.message || "Bridge unreachable";
            renderSessionView();
          });
      }

      document.getElementById("btn-copy-luau").addEventListener("click", function() {
        fetch("/api/copy-luau", { method: "POST" })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            if (navigator.clipboard && uiState.luauScript) {
              navigator.clipboard.writeText(uiState.luauScript).catch(function() {});
            }
            notify(res.message || "Copied client Luau script to clipboard.");
          })
          .catch(function(err) { notify("Clipboard error: " + err.message); });
      });

      document.getElementById("btn-simulate").addEventListener("click", function() {
        notify("Injecting simulated Studio playtest findings and 10s telemetry snapshots...");
        fetch("/api/simulate", { method: "POST" })
          .then(function() { setTimeout(fetchBridgeState, 400); })
          .catch(function(err) { notify("Simulation error: " + err.message); });
      });

      document.getElementById("btn-export-md").addEventListener("click", function() {
        window.location.href = "/api/export.md";
      });

      document.getElementById("btn-clear-session").addEventListener("click", function() {
        fetch("/api/clear", { method: "POST" })
          .then(function() {
            uiState.selectedIdx = -1;
            fetchBridgeState();
            notify("Cleared active session findings and telemetry.");
          });
      });

      document.getElementById("form-scan-path").addEventListener("submit", function(e) {
        e.preventDefault();
        const rawPath = document.getElementById("input-scan-path").value.trim();
        const logBox = document.getElementById("static-audit-log");
        if (!rawPath) {
          logBox.innerHTML = '<div class="state-panel"><h3>Missing target path</h3><p>Enter a local .rbxlx place file or .luau folder path before running Audit Path.</p></div>';
          return;
        }
        logBox.innerHTML = '<div class="state-panel"><h3>Auditing path...</h3><p class="mono-cell">' + esc(rawPath) + '</p></div>';
        fetch("/api/scan-path", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: rawPath })
        })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            if (res.error) {
              logBox.innerHTML = '<div class="state-panel"><h3>Path scan failed</h3><p>' + esc(res.error) + '</p></div>';
            } else {
              logBox.innerHTML =
                '<div class="state-panel">' +
                  '<h3>Static path scan complete</h3>' +
                  '<p>Added <strong>' + esc(res.added) + '</strong> finding(s) from <span class="mono-cell">' + esc(res.path) + '</span> (' + esc(res.total_findings) + ' total in session). Open [01] Vulnerability Ledger to inspect them.</p>' +
                '</div>';
              fetchBridgeState();
            }
          })
          .catch(function(err) {
            logBox.innerHTML = '<div class="state-panel"><h3>Request failed</h3><p>' + esc(err.message) + '</p></div>';
          });
      });

      document.getElementById("form-scan-source").addEventListener("submit", function(e) {
        e.preventDefault();
        const src = document.getElementById("input-luau-source").value;
        const logBox = document.getElementById("static-audit-log");
        if (!src.trim()) {
          logBox.innerHTML = '<div class="state-panel"><h3>Empty Luau source</h3><p>Paste a Luau script into the editor before running Audit Luau Source.</p></div>';
          return;
        }
        logBox.innerHTML = '<div class="state-panel"><h3>Running 12 static rules and 120 Luau probes...</h3></div>';
        fetch("/api/scan-source", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source: src, script_name: "WorkbenchBuffer.luau" })
        })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            logBox.innerHTML =
              '<div class="state-panel">' +
                '<h3>Luau source audit complete</h3>' +
                '<p>Matched <strong>' + esc(res.matched) + '</strong> flaw(s) (' + esc(res.added) + ' new finding(s) added to [01] Vulnerability Ledger).</p>' +
              '</div>';
            fetchBridgeState();
          });
      });

      function queryCatalog(q, sev) {
        const box = document.getElementById("catalog-ledger-box");
        box.innerHTML = '<div class="state-panel"><h3>Seeking 120,000-flaw mmap index...</h3></div>';
        const url = "/api/catalog?q=" + encodeURIComponent(q) + "&severity=" + encodeURIComponent(sev) + "&limit=50";
        fetch(url)
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("catalog-match-cnt").textContent = res.results.length;
            document.getElementById("catalog-latency-tag").textContent =
              "[MMAP SEEK: " + res.elapsed_ms.toFixed(2) + " ms]";
            if (res.results.length === 0) {
              box.innerHTML =
                '<div class="state-panel"><h3>0 signatures matched "' + esc(q) + '"</h3><p>Search by Roblox service name, instance class, or RCD-XXXXXX code.</p></div>';
              return;
            }
            let rows = "";
            res.results.forEach(function(item) {
              rows +=
                '<tr>' +
                  '<td class="mono-cell"><strong>[' + esc(item.code) + ']</strong><br/>Rank #' + esc(item.rank) + '</td>' +
                  '<td><span class="sev-tag sev-tag-' + esc(item.severity) + '">' + esc(item.severity) + '</span></td>' +
                  '<td class="mono-cell">' + esc(item.domain) + '<br/>' + esc(item.category) + '</td>' +
                  '<td><strong>' + esc(item.title) + '</strong><br/><span style="color:var(--text-muted)">' + esc(item.flaw) + '</span></td>' +
                  '<td>' + esc(item.fix) + '</td>' +
                '</tr>';
            });
            box.innerHTML =
              '<table class="ledger-table">' +
                '<thead><tr><th>Code / Rank</th><th>Severity</th><th>Domain</th><th>Signature &amp; Architectural Flaw</th><th>Server Remediation</th></tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
              '</table>';
          });
      }

      document.getElementById("form-catalog-search").addEventListener("submit", function(e) {
        e.preventDefault();
        queryCatalog(
          document.getElementById("input-catalog-q").value.trim(),
          document.getElementById("select-catalog-sev").value
        );
      });

      function queryPack(q) {
        const box = document.getElementById("pack-ledger-box");
        box.innerHTML = '<div class="state-panel"><h3>Loading 120 compiled Luau probes...</h3></div>';
        fetch("/api/pack?q=" + encodeURIComponent(q) + "&limit=120")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("pack-match-cnt").textContent = res.results.length;
            if (res.results.length === 0) {
              box.innerHTML = '<div class="state-panel"><h3>0 Luau probes matched "' + esc(q) + '"</h3></div>';
              return;
            }
            let rows = "";
            res.results.forEach(function(p) {
              rows +=
                '<tr>' +
                  '<td class="mono-cell"><strong>[' + esc(p.id) + ']</strong></td>' +
                  '<td><span class="sev-tag sev-tag-' + esc(p.severity) + '">' + esc(p.severity) + '</span></td>' +
                  '<td class="mono-cell">' + esc(p.source) + '</td>' +
                  '<td><strong>' + esc(p.name) + '</strong><br/><span style="color:var(--text-muted)">' + esc(p.root_cause) + '</span></td>' +
                  '<td>' + esc(p.fix) + '</td>' +
                '</tr>';
            });
            box.innerHTML =
              '<table class="ledger-table">' +
                '<thead><tr><th>Probe ID</th><th>Severity</th><th>Upstream Source</th><th>Diagnostic &amp; Root Cause</th><th>Remediation</th></tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
              '</table>';
          });
      }

      document.getElementById("form-pack-search").addEventListener("submit", function(e) {
        e.preventDefault();
        queryPack(document.getElementById("input-pack-q").value.trim());
      });

      function queryBrainHistory() {
        fetch("/api/history")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            const tokBox = document.getElementById("brain-tokens-box");
            if (!res.learned_tokens || res.learned_tokens.length === 0) {
              tokBox.innerHTML = '<div class="state-panel"><h3>0 custom game tokens learned yet</h3><p>Run an audit session or rcdebug --learn to populate custom place tokens.</p></div>';
            } else {
              let tRows = "";
              res.learned_tokens.forEach(function(t) {
                tRows +=
                  '<tr>' +
                    '<td class="mono-cell"><strong>' + esc(t.token) + '</strong></td>' +
                    '<td><span class="sev-tag sev-tag-' + esc(t.severity) + '">' + esc(t.severity) + '</span></td>' +
                    '<td class="mono-cell">' + esc(t.domain) + '</td>' +
                    '<td class="mono-cell">' + esc(t.seen_count) + 'x</td>' +
                  '</tr>';
              });
              tokBox.innerHTML =
                '<table class="ledger-table">' +
                  '<thead><tr><th>Token</th><th>Severity</th><th>Domain</th><th>Frequency</th></tr></thead>' +
                  '<tbody>' + tRows + '</tbody>' +
                '</table>';
            }

            const histBox = document.getElementById("brain-history-box");
            if (!res.history || res.history.length === 0) {
              histBox.innerHTML = '<div class="state-panel"><h3>0 commands logged yet</h3></div>';
            } else {
              let hRows = "";
              res.history.forEach(function(h) {
                hRows +=
                  '<tr>' +
                    '<td class="mono-cell">' + esc(h.timestamp) + '</td>' +
                    '<td class="mono-cell"><strong>' + esc(h.command) + '</strong></td>' +
                    '<td class="mono-cell">' + esc(h.findings_count) + ' findings</td>' +
                    '<td class="mono-cell">' + esc(h.duration_ms) + ' ms</td>' +
                  '</tr>';
              });
              histBox.innerHTML =
                '<table class="ledger-table">' +
                  '<thead><tr><th>Timestamp</th><th>Invocation</th><th>Findings</th><th>Duration</th></tr></thead>' +
                  '<tbody>' + hRows + '</tbody>' +
                '</table>';
            }
          });
      }

      fetchBridgeState();
      uiState.syncTimer = setInterval(fetchBridgeState, 1500);
    })();
  </script>
</body>
</html>
"""


def build_ui_html() -> str:
    return UI_HTML_DOCUMENT.replace("__VERSION__", __version__)


class UIWorkbenchHandler(DebugReportHandler):
    """
    Serves both the Roblox Luau runtime bridge (/report, /telemetry, /ws, /status, /shutdown)
    and the browser workbench (/ui, /api/*) on the same local port.
    """

    def _send_html(self, status_code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_markdown(self, filename: str, md_text: str) -> None:
        body = md_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._handle_websocket()
            return

        parsed = urlparse(self.path)
        route = parsed.path
        qs = parse_qs(parsed.query)

        if route in ("/", "/ui"):
            accept = self.headers.get("Accept", "")
            if route == "/ui" or "text/html" in accept:
                self._send_html(200, build_ui_html())
                return

        if route in ("/", "/status", "/health"):
            counts = self.server.session.counts_by_severity()
            self._send_json(
                200,
                {
                    "status": "ok",
                    "tool": "rcdebug",
                    "mode": self.server.session.mode,
                    "findings_count": len(self.server.session.findings),
                    "severity_counts": counts,
                    "snapshots_count": len(self.server.session.memory_snapshots),
                    "remotes_profiled": len(self.server.session.remote_traffic),
                },
            )
            return

        if route == "/api/state":
            catalog = get_catalog()
            host, port = self.server.server_address[0], int(self.server.server_address[1])
            with self.server.lock:
                sorted_findings = sorted(self.server.session.findings, key=lambda f: f.sort_key())
                findings_data = [{**f.to_dict(), "rank": f.rank} for f in sorted_findings]
                snapshots_data = [
                    {
                        "timestamp": s.timestamp,
                        "elapsed_sec": s.elapsed_sec,
                        "workspace_instances": s.workspace_instances,
                        "player_instances": s.player_instances,
                        "total_memory_mb": s.total_memory_mb,
                    }
                    for s in self.server.session.memory_snapshots
                ]
                remotes_data = [
                    {
                        "remote_path": r.remote_path,
                        "remote_type": r.remote_type,
                        "total_calls": r.total_calls,
                        "peak_rate_per_sec": r.peak_rate_per_sec,
                        "last_rate_per_sec": r.last_rate_per_sec,
                        "has_cooldown_warning": r.has_cooldown_warning,
                    }
                    for r in sorted(
                        self.server.session.remote_traffic.values(),
                        key=lambda s: (-s.peak_rate_per_sec, -s.total_calls),
                    )
                ]
                counts = self.server.session.counts_by_severity()

            self._send_json(
                200,
                {
                    "status": "ok",
                    "version": __version__,
                    "host": host,
                    "port": port,
                    "catalog_count": catalog.count(),
                    "learned_count": len(catalog.learner.learned_tokens),
                    "brain_concepts": len(catalog.brain.token_domain_weights),
                    "luau_script": build_luau_bridge_script(host=host, port=port),
                    "session": {
                        "mode": self.server.session.mode,
                        "started_at": self.server.session.started_at,
                        "target_name": self.server.session.target_name,
                        "severity_counts": counts,
                        "findings": findings_data,
                        "memory_snapshots": snapshots_data,
                        "remote_traffic": remotes_data,
                    },
                },
            )
            return

        if route == "/api/catalog":
            t0 = time.perf_counter()
            catalog = get_catalog()
            q = (qs.get("q", [""])[0] or "").strip()
            sev = (qs.get("severity", [""])[0] or "").strip().upper()
            limit = min(200, max(1, int(qs.get("limit", ["50"])[0] or 50)))
            raw_hits = catalog.search(q, limit=limit * 4 if sev else limit)
            if sev in ("CRITICAL", "WARN", "INFO"):
                raw_hits = [s for s in raw_hits if matches_filter(s.severity, sev)]
            hits = raw_hits[:limit]
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self._send_json(
                200,
                {
                    "query": q,
                    "elapsed_ms": round(elapsed_ms, 3),
                    "results": [
                        {
                            "code": s.code,
                            "rank": s.rank,
                            "severity": s.severity,
                            "category": s.category,
                            "domain": s.domain,
                            "title": s.title,
                            "flaw": s.flaw,
                            "abuse": s.abuse,
                            "fix": s.fix,
                        }
                        for s in hits
                    ],
                },
            )
            return

        if route == "/api/pack":
            pack = get_debugger_pack()
            q = (qs.get("q", [""])[0] or "").strip()
            limit = min(120, max(1, int(qs.get("limit", ["120"])[0] or 120)))
            probes = pack.search(q, limit=limit)
            self._send_json(
                200,
                {
                    "query": q,
                    "results": [
                        {
                            "id": p.id,
                            "source": p.source,
                            "category": p.category,
                            "severity": p.severity,
                            "name": p.name,
                            "root_cause": p.root_cause,
                            "fix": p.fix,
                        }
                        for p in probes
                    ],
                },
            )
            return

        if route == "/api/history":
            catalog = get_catalog()
            history = CommandHistory()
            top_learned = sorted(
                catalog.learner.learned_tokens.items(),
                key=lambda kv: (-int(kv[1].get("seen_count", 1)), kv[0]),
            )[:50]
            self._send_json(
                200,
                {
                    "learned_tokens": [
                        {
                            "token": tok,
                            "severity": info.get("severity", "WARN"),
                            "domain": info.get("domain", "Learned"),
                            "seen_count": info.get("seen_count", 1),
                        }
                        for tok, info in top_learned
                    ],
                    "history": list(reversed(history.entries[-40:])),
                },
            )
            return

        if route == "/api/export.md":
            with self.server.lock:
                md_text = generate_markdown_report(
                    self.server.session,
                    filter_level=self.server.filter_level,
                )
            self._send_markdown("rcdebug_audit_report.md", md_text)
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path

        if route in ("/report", "/telemetry", "/shutdown"):
            super().do_POST()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""
        try:
            data: dict[str, Any] = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return

        if route == "/api/copy-luau":
            host, port = self.server.server_address[0], int(self.server.server_address[1])
            script = build_luau_bridge_script(host=host, port=port)
            copied = copy_to_clipboard(script)
            self._send_json(
                200,
                {
                    "status": "ok",
                    "copied": copied,
                    "message": "Copied client Luau diagnostic script to macOS clipboard (pbcopy)."
                    if copied
                    else "Clipboard helper unavailable; copy the script from the right-hand drawer.",
                },
            )
            return

        if route == "/api/simulate":
            host, port = self.server.server_address[0], int(self.server.server_address[1])
            threading.Thread(
                target=simulate_studio_playtest_traffic,
                args=(host, port),
                daemon=True,
            ).start()
            self._send_json(200, {"status": "started"})
            return

        if route == "/api/clear":
            with self.server.lock:
                self.server.session.findings.clear()
                self.server.session.memory_snapshots.clear()
                self.server.session.remote_traffic.clear()
            self._send_json(200, {"status": "cleared"})
            return

        if route == "/api/scan-path":
            raw_path = str(data.get("path", "")).strip()
            if not raw_path:
                self._send_json(400, {"error": "Missing path parameter."})
                return
            target = Path(raw_path).expanduser().resolve()
            if not target.exists():
                self._send_json(404, {"error": f"Path does not exist: {target}"})
                return
            before = len(self.server.session.findings)
            audit_local_path(target, self.server.session, filter_level=self.server.filter_level)
            added = len(self.server.session.findings) - before
            get_catalog().learner.learn_from_session(self.server.session, get_catalog())
            self._send_json(
                200,
                {
                    "status": "ok",
                    "path": str(target),
                    "added": added,
                    "total_findings": len(self.server.session.findings),
                },
            )
            return

        if route == "/api/scan-source":
            source = str(data.get("source", ""))
            script_name = str(data.get("script_name", "WorkbenchBuffer.luau"))
            found = audit_luau_script_source(script_name, source)
            added = 0
            with self.server.lock:
                for f in found:
                    if self.server.session.add_finding(f):
                        added += 1
            if added > 0:
                get_catalog().learner.learn_from_session(self.server.session, get_catalog())
            self._send_json(
                200,
                {
                    "status": "ok",
                    "matched": len(found),
                    "added": added,
                },
            )
            return

        self._send_json(404, {"error": "not_found"})


def bind_ui_workbench_server(
    host: str,
    preferred_port: int,
    session: AuditSession,
    filter_level: SeverityFilter = None,
    max_tries: int = 50,
) -> tuple[RuntimeBridgeServer, int, bool]:
    """
    Binds RuntimeBridgeServer with UIWorkbenchHandler, falling back to the next
    available port when preferred_port is occupied by another process.
    """
    try:
        srv = RuntimeBridgeServer(
            (host, preferred_port),
            UIWorkbenchHandler,
            session=session,
            filter_level=filter_level,  # type: ignore[arg-type]
        )
        return srv, int(srv.server_address[1]), False
    except OSError:
        pass

    for offset in range(1, max_tries + 1):
        candidate = preferred_port + offset
        if candidate > 65535:
            break
        try:
            srv = RuntimeBridgeServer(
                (host, candidate),
                UIWorkbenchHandler,
                session=session,
                filter_level=filter_level,  # type: ignore[arg-type]
            )
            return srv, int(srv.server_address[1]), True
        except OSError:
            continue

    srv = RuntimeBridgeServer(
        (host, 0),
        UIWorkbenchHandler,
        session=session,
        filter_level=filter_level,  # type: ignore[arg-type]
    )
    return srv, int(srv.server_address[1]), True


def run_ui_mode(
    host: str = "127.0.0.1",
    port: int = 8765,
    filter_level: SeverityFilter = None,
    export_path: str | None = None,
    auto_clipboard: bool = True,
    simulate: bool = False,
    enable_log_tail: bool = True,
    replay_latest_log: bool = False,
    open_browser: bool = True,
) -> AuditSession:
    catalog = get_catalog()
    session = AuditSession(
        mode="ui",
        target_name=f"Roblox UI Workbench ({host}:{port})",
    )
    server, actual_port, used_fallback = bind_ui_workbench_server(
        host=host,
        preferred_port=port,
        session=session,
        filter_level=filter_level,
    )
    session.target_name = f"Roblox UI Workbench ({host}:{actual_port})"
    ui_url = f"http://{host}:{actual_port}/ui"

    print_banner(
        "GRAPHICAL WEB WORKBENCH (--ui)",
        subtitle=f"{ui_url} | {catalog.count():,} Flaw Signatures | Filter: {normalize_filter_label(filter_level)}",
    )
    if used_fallback:
        print(
            f"\n{YELLOW}{BOLD}⚠ Port {port} is in use by another process; "
            f"UI Workbench bound to {host}:{actual_port}.{RESET}"
        )

    luau_script = build_luau_bridge_script(host=host, port=actual_port)
    if auto_clipboard:
        if copy_to_clipboard(luau_script):
            print(f"\n{GREEN}{BOLD}✔ Client Luau diagnostic script copied to macOS clipboard (pbcopy)!{RESET}")

    print(f"\n{BOLD}{GREEN}● Web Interface active at:{RESET} {BOLD}{CYAN}{ui_url}{RESET}")
    print(f"{BOLD}{GREEN}● Runtime Bridge endpoint:{RESET} {BOLD}{CYAN}http://{host}:{actual_port}/report{RESET}")

    log_tailer: RobloxLogTailer | None = None
    if enable_log_tail:
        log_tailer = RobloxLogTailer(server, replay_latest=replay_latest_log)
        log_tailer.start()
        print(f"{BOLD}{GREEN}● Roblox Log Bridge active:{RESET} {BOLD}{CYAN}{ROBLOX_LOGS_DIR}{RESET}")

    print(f"{DIM}  Press Ctrl+C to stop the UI server.{RESET}\n")

    if open_browser and not simulate:
        threading.Timer(0.25, lambda: webbrowser.open(ui_url)).start()

    if simulate:
        sim_thread = threading.Thread(
            target=simulate_studio_playtest_traffic,
            args=(host, actual_port),
            daemon=True,
        )
        sim_thread.start()

        def auto_stop() -> None:
            sim_thread.join(timeout=5.0)
            time.sleep(0.25)
            server.shutdown()

        threading.Thread(target=auto_stop, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[rcdebug] Stopping UI Workbench...{RESET}")
    finally:
        if log_tailer is not None:
            log_tailer.stop()
        server.server_close()

    if session.findings:
        catalog.learner.learn_from_session(session, catalog)

    if export_path:
        from .exporter import export_markdown_report

        saved = export_markdown_report(session, export_path, filter_level=filter_level)  # type: ignore[arg-type]
        print(f"{GREEN}{BOLD}✔ Exported Markdown audit report to:{RESET} {CYAN}{saved}{RESET}\n")

    return session
