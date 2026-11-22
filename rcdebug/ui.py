"""
Interactive Web Interface for rcdebug (rcdebug --ui).

Provides a zero-dependency local HTTP + WebSocket UI workbench on top of
RuntimeBridgeServer and RobloxLogTailer so users can run live client audits,
simulate traffic, scan local .luau/.rbxlx files, search the 120,000-flaw
catalog and 120 Luau probes, inspect FlawBrain history, and export Markdown
reports from a graphical interface while preserving full CLI compatibility.
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
    bind_runtime_bridge_server,
    process_report_payload,
    process_telemetry_payload,
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
      --bg: #0f1115;
      --surface: #171a21;
      --surface-elevated: #1e222b;
      --border: #2c313d;
      --text: #f3f4f6;
      --text-muted: #a1a8b8;
      --accent: #38bdf8;
      --accent-fg: #09131c;
      --crit-bg: #3b1219;
      --crit-fg: #fda4af;
      --crit-border: #e11d48;
      --warn-bg: #362207;
      --warn-fg: #fcd34d;
      --warn-border: #d97706;
      --info-bg: #11263c;
      --info-fg: #7dd3fc;
      --info-border: #0284c7;
      --ok-fg: #4ade80;
      --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
      --font-mono: "SF Mono", "JetBrains Mono", Menlo, Monaco, Consolas, monospace;
    }

    [data-theme="light"] {
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-elevated: #f1f5f9;
      --border: #cbd5e1;
      --text: #0f172a;
      --text-muted: #475569;
      --accent: #0284c7;
      --accent-fg: #ffffff;
      --crit-bg: #ffe4e6;
      --crit-fg: #9f1239;
      --crit-border: #e11d48;
      --warn-bg: #fef3c7;
      --warn-fg: #92400e;
      --warn-border: #d97706;
      --info-bg: #e0f2fe;
      --info-fg: #075985;
      --info-border: #0284c7;
      --ok-fg: #15803d;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    a[href], button, summary, select, label[for], input[type="checkbox"], [role="button"], [role="tab"] {
      cursor: pointer;
    }

    button:disabled, input:disabled, select:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }

    :focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }

    header.topbar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 12px 20px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .brand-group {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }

    .brand-group h1 {
      font-size: 18px;
      font-weight: 700;
      margin: 0;
      font-family: var(--font-mono);
      letter-spacing: -0.02em;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 4px 10px;
      border-radius: 4px;
      background: var(--surface-elevated);
      border: 1px solid var(--border);
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--ok-fg);
      display: inline-block;
    }

    .top-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .btn {
      min-height: 38px;
      padding: 6px 14px;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: var(--surface-elevated);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 600;
      transition: background 0.12s ease, border-color 0.12s ease, transform 0.05s ease;
    }

    .btn:hover:not(:disabled) {
      border-color: var(--accent);
      background: var(--surface);
    }

    .btn:active:not(:disabled) {
      transform: translateY(1px);
    }

    .btn-primary {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--accent);
    }

    .btn-primary:hover:not(:disabled) {
      background: var(--accent);
      color: var(--accent-fg);
      filter: brightness(1.08);
    }

    nav.tabbar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 20px;
      display: flex;
      gap: 4px;
      overflow-x: auto;
    }

    .tab-btn {
      min-height: 44px;
      padding: 10px 16px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 13px;
      white-space: nowrap;
    }

    .tab-btn:hover {
      color: var(--text);
    }

    .tab-btn[aria-selected="true"] {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }

    main.workspace {
      flex: 1;
      padding: 20px;
      max-width: 1480px;
      width: 100%;
      margin: 0 auto;
    }

    .banner-msg {
      margin-bottom: 16px;
      padding: 10px 14px;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: var(--surface-elevated);
      font-size: 13px;
      display: none;
    }

    .banner-msg.visible {
      display: block;
    }

    .tab-panel {
      display: none;
    }

    .tab-panel.active {
      display: block;
    }

    .toolbar-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
      background: var(--surface);
      border: 1px solid var(--border);
      padding: 12px 16px;
      border-radius: 6px;
    }

    .filter-group {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
    }

    .field-group {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    label.field-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
    }

    input.text-input, textarea.code-input, select.select-input {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 13px;
      font-family: var(--font-sans);
      min-height: 38px;
    }

    textarea.code-input {
      font-family: var(--font-mono);
      width: 100%;
      min-height: 180px;
      resize: vertical;
    }

    .sev-toggle {
      min-height: 36px;
      padding: 4px 12px;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
    }

    .sev-toggle[aria-pressed="true"].sev-crit {
      background: var(--crit-bg);
      color: var(--crit-fg);
      border-color: var(--crit-border);
    }

    .sev-toggle[aria-pressed="true"].sev-warn {
      background: var(--warn-bg);
      color: var(--warn-fg);
      border-color: var(--warn-border);
    }

    .sev-toggle[aria-pressed="true"].sev-info {
      background: var(--info-bg);
      color: var(--info-fg);
      border-color: var(--info-border);
    }

    .split-grid {
      display: grid;
      grid-template-columns: 1fr 440px;
      gap: 16px;
      align-items: start;
    }

    @media (max-width: 1024px) {
      .split-grid {
        grid-template-columns: 1fr;
      }
    }

    .panel-box {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }

    .panel-header {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      background: var(--surface-elevated);
    }

    .panel-header h2 {
      margin: 0;
      font-size: 14px;
      font-weight: 700;
    }

    .table-wrap {
      overflow-x: auto;
      max-height: 600px;
      overflow-y: auto;
    }

    table.data-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }

    table.data-table th,
    table.data-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }

    table.data-table th {
      background: var(--surface-elevated);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      position: sticky;
      top: 0;
      z-index: 1;
    }

    table.data-table tbody tr.clickable-row {
      cursor: pointer;
    }

    table.data-table tbody tr.clickable-row:hover {
      background: var(--surface-elevated);
    }

    table.data-table tbody tr.clickable-row.selected {
      background: var(--surface-elevated);
      outline: 1px solid var(--accent);
    }

    .badge {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 3px;
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      border: 1px solid transparent;
    }

    .badge-CRITICAL {
      background: var(--crit-bg);
      color: var(--crit-fg);
      border-color: var(--crit-border);
    }

    .badge-WARN {
      background: var(--warn-bg);
      color: var(--warn-fg);
      border-color: var(--warn-border);
    }

    .badge-INFO {
      background: var(--info-bg);
      color: var(--info-fg);
      border-color: var(--info-border);
    }

    .mono {
      font-family: var(--font-mono);
      font-size: 12px;
      word-break: break-all;
    }

    .inspector-body {
      padding: 16px;
    }

    .inspector-section {
      margin-bottom: 14px;
    }

    .inspector-section h3 {
      margin: 0 0 4px 0;
      font-size: 12px;
      color: var(--text-muted);
      font-weight: 600;
    }

    .inspector-section p {
      margin: 0;
      font-size: 13px;
    }

    pre.code-block {
      margin: 8px 0 0 0;
      padding: 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
    }

    .state-box {
      padding: 28px 20px;
      text-align: left;
      color: var(--text-muted);
    }

    .state-box h3 {
      margin: 0 0 6px 0;
      color: var(--text);
      font-size: 15px;
    }

    .state-box p {
      margin: 0 0 14px 0;
      font-size: 13px;
    }

    .bottom-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 16px;
    }

    @media (max-width: 900px) {
      .bottom-grid {
        grid-template-columns: 1fr;
      }
    }

    footer.footbar {
      padding: 12px 20px;
      border-top: 1px solid var(--border);
      background: var(--surface);
      color: var(--text-muted);
      font-size: 12px;
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand-group">
      <h1>rcdebug workbench</h1>
      <div class="status-pill" id="bridge-status-pill">
        <span class="status-dot" id="bridge-dot"></span>
        <span id="bridge-addr-text">Connecting to local runtime bridge...</span>
      </div>
      <div class="status-pill" id="brain-status-pill">
        <span id="brain-summary-text">Loading FlawBrain...</span>
      </div>
    </div>
    <div class="top-actions">
      <button type="button" class="btn btn-primary" id="btn-copy-luau">Copy Client Luau Script</button>
      <button type="button" class="btn" id="btn-simulate">Run Sample Playtest</button>
      <button type="button" class="btn" id="btn-export-md">Download Report (.md)</button>
      <button type="button" class="btn" id="btn-clear-session">Clear Findings</button>
      <button type="button" class="btn" id="btn-theme-toggle" aria-label="Toggle color theme">Theme: Dark</button>
    </div>
  </header>

  <nav class="tabbar" role="tablist" aria-label="Workbench Sections">
    <button type="button" class="tab-btn" role="tab" aria-selected="true" aria-controls="panel-live" id="tab-live">Live Audit &amp; Telemetry</button>
    <button type="button" class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-static" id="tab-static">Static Place &amp; Script Scanner</button>
    <button type="button" class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-catalog" id="tab-catalog">120,000 Flaw Catalog</button>
    <button type="button" class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-pack" id="tab-pack">120 Luau Debugger Probes</button>
    <button type="button" class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-brain" id="tab-brain">FlawBrain &amp; Command History</button>
  </nav>

  <main class="workspace">
    <div class="banner-msg" id="toast-banner" role="status" aria-live="polite"></div>

    <!-- PANEL 1: LIVE AUDIT & TELEMETRY -->
    <section class="tab-panel active" id="panel-live" role="tabpanel" aria-labelledby="tab-live">
      <div class="toolbar-row">
        <div class="filter-group" role="group" aria-label="Severity Filters">
          <span class="field-label">Severity:</span>
          <button type="button" class="sev-toggle sev-crit" data-sev="CRITICAL" aria-pressed="true">CRITICAL (<span id="count-crit">0</span>)</button>
          <button type="button" class="sev-toggle sev-warn" data-sev="WARN" aria-pressed="true">WARN (<span id="count-warn">0</span>)</button>
          <button type="button" class="sev-toggle sev-info" data-sev="INFO" aria-pressed="true">INFO (<span id="count-info">0</span>)</button>
        </div>
        <div class="field-group">
          <label class="field-label" for="live-search-input">Filter findings:</label>
          <input type="search" id="live-search-input" class="text-input" placeholder="Remote name, instance path, or RCD code..." />
        </div>
      </div>

      <div class="split-grid">
        <div class="panel-box">
          <div class="panel-header">
            <h2>Ordered Security &amp; Architecture Findings (<span id="live-visible-count">0</span>)</h2>
            <span class="mono" id="session-target-label">Target: Roblox Client Runtime Bridge</span>
          </div>
          <div class="table-wrap" id="findings-table-container">
            <div class="state-box" id="findings-loading-state">
              <h3>Loading active audit session...</h3>
              <p>Fetching findings and telemetry snapshots from the local rcdebug bridge.</p>
            </div>
          </div>
        </div>

        <aside class="panel-box" aria-label="Finding Remediation Inspector">
          <div class="panel-header">
            <h2>Remediation &amp; Luau Payload Inspector</h2>
          </div>
          <div class="inspector-body" id="finding-inspector">
            <div class="inspector-section">
              <h3>Select a finding</h3>
              <p>Click any row in the findings table to view its root cause, client abuse vector, and server-side Luau fix. Or copy the client diagnostic script below to paste into Roblox.</p>
            </div>
            <div class="inspector-section">
              <h3>100% Client-Sided Luau Bridge Payload</h3>
              <pre class="code-block" id="luau-payload-preview">Loading Luau bridge script...</pre>
            </div>
          </div>
        </aside>
      </div>

      <div class="bottom-grid">
        <div class="panel-box">
          <div class="panel-header">
            <h2>Remote Traffic Profiler (calls/sec)</h2>
          </div>
          <div class="table-wrap" id="remotes-table-container"></div>
        </div>

        <div class="panel-box">
          <div class="panel-header">
            <h2>10s Instance &amp; Memory Diff Timeline</h2>
          </div>
          <div class="table-wrap" id="snapshots-table-container"></div>
        </div>
      </div>
    </section>

    <!-- PANEL 2: STATIC PLACE & SCRIPT SCANNER -->
    <section class="tab-panel" id="panel-static" role="tabpanel" aria-labelledby="tab-static">
      <div class="split-grid">
        <div class="panel-box">
          <div class="panel-header">
            <h2>Audit Local Place (.rbxlx) or Scripts Directory</h2>
          </div>
          <div class="inspector-body">
            <form id="form-scan-path">
              <div class="inspector-section">
                <label class="field-label" for="input-scan-path">Local file or folder path (.luau, .lua, .rbxlx, .rbxmx):</label>
                <div class="field-group" style="margin-top:6px;">
                  <input type="text" id="input-scan-path" class="text-input" style="flex:1;" placeholder="/Users/you/MyGame/src or ./place.rbxlx" />
                  <button type="submit" class="btn btn-primary" id="btn-run-path-scan">Scan Path</button>
                </div>
              </div>
            </form>
            <hr style="border:none;border-top:1px solid var(--border);margin:16px 0;" />
            <form id="form-scan-source">
              <div class="inspector-section">
                <label class="field-label" for="input-luau-source">Or paste Luau script source code to audit directly:</label>
                <textarea id="input-luau-source" class="code-input" style="margin-top:6px;" placeholder="ReplicatedStorage.BuyItem.OnServerEvent:Connect(function(player, itemName, price)&#10;    player.leaderstats.Cash.Value -= price&#10;end)"></textarea>
              </div>
              <button type="submit" class="btn btn-primary" id="btn-run-source-scan">Audit Luau Source</button>
            </form>
          </div>
        </div>

        <div class="panel-box">
          <div class="panel-header">
            <h2>Static Scanner Output</h2>
          </div>
          <div class="inspector-body" id="static-scan-status">
            <p>Findings discovered by the static scanner are added directly to the live session and ranked by severity and catalog priority.</p>
          </div>
        </div>
      </div>
    </section>

    <!-- PANEL 3: 120,000 FLAW CATALOG -->
    <section class="tab-panel" id="panel-catalog" role="tabpanel" aria-labelledby="tab-catalog">
      <div class="toolbar-row">
        <form id="form-catalog-search" class="field-group" style="flex:1;">
          <label class="field-label" for="input-catalog-query">Search 120,000 Flaws:</label>
          <input type="search" id="input-catalog-query" class="text-input" style="flex:1;" placeholder="datastore, processreceipt, networkowner, remote,cframe..." />
          <label class="field-label" for="select-catalog-sev">Severity:</label>
          <select id="select-catalog-sev" class="select-input">
            <option value="">ALL</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="WARN">WARN</option>
            <option value="INFO">INFO</option>
          </select>
          <button type="submit" class="btn btn-primary">Search Catalog</button>
        </form>
      </div>
      <div class="panel-box">
        <div class="panel-header">
          <h2>Catalog Matches (<span id="catalog-result-count">0</span>)</h2>
          <span class="mono" id="catalog-latency-label">mmap index ready</span>
        </div>
        <div class="table-wrap" id="catalog-table-container"></div>
      </div>
    </section>

    <!-- PANEL 4: 120 LUAU DEBUGGER PROBES -->
    <section class="tab-panel" id="panel-pack" role="tabpanel" aria-labelledby="tab-pack">
      <div class="toolbar-row">
        <form id="form-pack-search" class="field-group" style="flex:1;">
          <label class="field-label" for="input-pack-query">Search 120 Luau Probes:</label>
          <input type="search" id="input-pack-query" class="text-input" style="flex:1;" placeholder="selene, trove, janitor, heartbeat, wait, strict..." />
          <button type="submit" class="btn btn-primary">Filter Probes</button>
        </form>
      </div>
      <div class="panel-box">
        <div class="panel-header">
          <h2>Compiled Luau Probes (<span id="pack-result-count">0</span>)</h2>
        </div>
        <div class="table-wrap" id="pack-table-container"></div>
      </div>
    </section>

    <!-- PANEL 5: FLAWBRAIN & COMMAND HISTORY -->
    <section class="tab-panel" id="panel-brain" role="tabpanel" aria-labelledby="tab-brain">
      <div class="bottom-grid" style="margin-top:0;">
        <div class="panel-box">
          <div class="panel-header">
            <h2>Learned Game Tokens (~/.rcdebug/learned_flaws.json)</h2>
          </div>
          <div class="table-wrap" id="learned-tokens-container"></div>
        </div>
        <div class="panel-box">
          <div class="panel-header">
            <h2>Terminal &amp; UI Command History (~/.rcdebug/command_history.json)</h2>
          </div>
          <div class="table-wrap" id="history-table-container"></div>
        </div>
      </div>
    </section>
  </main>

  <footer class="footbar">
    <span>rcdebug v__VERSION__ (Zero-Dependency Python Standard Library Workbench)</span>
    <span class="mono" id="footer-log-dir">Log Bridge: ~/Library/Logs/Roblox/</span>
  </footer>

  <script>
    (function() {
      const state = {
        theme: "dark",
        activeSev: { CRITICAL: true, WARN: true, INFO: true },
        searchQuery: "",
        selectedIndex: -1,
        session: null,
        luauScript: "",
        error: null
      };

      function esc(str) {
        return String(str == null ? "" : str)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      }

      function showToast(msg, isError) {
        const el = document.getElementById("toast-banner");
        el.textContent = msg;
        el.style.borderColor = isError ? "var(--crit-border)" : "var(--accent)";
        el.classList.add("visible");
        clearTimeout(el._timer);
        el._timer = setTimeout(function() {
          el.classList.remove("visible");
        }, 4500);
      }

      // Tabs
      const tabs = Array.from(document.querySelectorAll(".tab-btn"));
      const panels = Array.from(document.querySelectorAll(".tab-panel"));
      tabs.forEach(function(tab) {
        tab.addEventListener("click", function() {
          tabs.forEach(function(t) { t.setAttribute("aria-selected", "false"); });
          panels.forEach(function(p) { p.classList.remove("active"); });
          tab.setAttribute("aria-selected", "true");
          const targetId = tab.getAttribute("aria-controls");
          const panel = document.getElementById(targetId);
          if (panel) panel.classList.add("active");
          if (targetId === "panel-catalog" && !panel._loaded) {
            panel._loaded = true;
            loadCatalog("", "");
          } else if (targetId === "panel-pack" && !panel._loaded) {
            panel._loaded = true;
            loadPack("");
          } else if (targetId === "panel-brain") {
            loadBrainHistory();
          }
        });
      });

      // Theme toggle (R-34: both dark and light themes tested and working)
      const themeBtn = document.getElementById("btn-theme-toggle");
      themeBtn.addEventListener("click", function() {
        state.theme = state.theme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", state.theme);
        themeBtn.textContent = "Theme: " + (state.theme === "dark" ? "Dark" : "Light");
      });

      // Severity filter buttons
      document.querySelectorAll(".sev-toggle").forEach(function(btn) {
        btn.addEventListener("click", function() {
          const sev = btn.getAttribute("data-sev");
          state.activeSev[sev] = !state.activeSev[sev];
          btn.setAttribute("aria-pressed", state.activeSev[sev] ? "true" : "false");
          renderLiveSession();
        });
      });

      document.getElementById("live-search-input").addEventListener("input", function(e) {
        state.searchQuery = e.target.value.trim().toLowerCase();
        renderLiveSession();
      });

      function filteredFindings() {
        if (!state.session || !Array.isArray(state.session.findings)) return [];
        return state.session.findings.filter(function(f) {
          if (!state.activeSev[f.severity]) return false;
          if (!state.searchQuery) return true;
          const hay = (f.title + " " + f.path + " " + f.category + " " + f.flaw).toLowerCase();
          return hay.indexOf(state.searchQuery) !== -1;
        });
      }

      function renderInspector(finding) {
        const box = document.getElementById("finding-inspector");
        if (!finding) {
          box.innerHTML =
            '<div class="inspector-section">' +
              '<h3>Select a finding</h3>' +
              '<p>Click any row in the findings table to inspect its flaw details, client abuse vector, and server-side Luau fix.</p>' +
            '</div>' +
            '<div class="inspector-section">' +
              '<h3>100% Client-Sided Luau Bridge Payload</h3>' +
              '<pre class="code-block">' + esc(state.luauScript || "Loading...") + '</pre>' +
            '</div>';
          return;
        }
        const codeBlock = finding.code_example
          ? '<div class="inspector-section"><h3>Recommended Server Luau Fix Pattern</h3><pre class="code-block">' + esc(finding.code_example) + '</pre></div>'
          : '';
        box.innerHTML =
          '<div class="inspector-section">' +
            '<span class="badge badge-' + esc(finding.severity) + '">' + esc(finding.severity) + '</span> ' +
            '<span class="mono">' + esc(finding.category) + '</span>' +
            '<h3 style="margin-top:8px;color:var(--text);font-size:15px;">' + esc(finding.title) + '</h3>' +
          '</div>' +
          '<div class="inspector-section"><h3>Instance / Script Path</h3><p class="mono">' + esc(finding.path) + '</p></div>' +
          '<div class="inspector-section"><h3>Architectural Flaw</h3><p>' + esc(finding.flaw) + '</p></div>' +
          '<div class="inspector-section"><h3>Client Abuse Vector</h3><p>' + esc(finding.abuse) + '</p></div>' +
          '<div class="inspector-section"><h3>Remediation</h3><p>' + esc(finding.fix) + '</p></div>' +
          codeBlock;
      }

      function renderLiveSession() {
        const container = document.getElementById("findings-table-container");
        if (state.error) {
          container.innerHTML =
            '<div class="state-box">' +
              '<h3>Connection to local rcdebug bridge lost</h3>' +
              '<p>' + esc(state.error) + '. Verify that the rcdebug --ui process is still running in your terminal.</p>' +
            '</div>';
          return;
        }
        if (!state.session) return;

        const counts = state.session.severity_counts || { CRITICAL: 0, WARN: 0, INFO: 0 };
        document.getElementById("count-crit").textContent = counts.CRITICAL || 0;
        document.getElementById("count-warn").textContent = counts.WARN || 0;
        document.getElementById("count-info").textContent = counts.INFO || 0;
        document.getElementById("session-target-label").textContent = "Target: " + (state.session.target_name || "");

        const list = filteredFindings();
        document.getElementById("live-visible-count").textContent = list.length;

        if (list.length === 0) {
          const totalAll = (state.session.findings || []).length;
          if (totalAll === 0) {
            container.innerHTML =
              '<div class="state-box">' +
                '<h3>No findings recorded in this session yet</h3>' +
                '<p>Paste (Cmd+V) the copied client Luau script into Roblox Developer Console / Studio Command Bar, or click "Run Sample Playtest" in the top bar to test with simulated telemetry.</p>' +
              '</div>';
          } else {
            container.innerHTML =
              '<div class="state-box">' +
                '<h3>No findings match your active filter</h3>' +
                '<p>' + totalAll + ' finding(s) are hidden by the current severity toggles or search filter. Enable CRITICAL/WARN/INFO or clear the search input.</p>' +
              '</div>';
          }
          renderInspector(null);
        } else {
          let rows = "";
          list.forEach(function(f, idx) {
            const selClass = idx === state.selectedIndex ? " selected" : "";
            rows +=
              '<tr class="clickable-row' + selClass + '" data-idx="' + idx + '" tabindex="0">' +
                '<td><span class="badge badge-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
                '<td class="mono">' + esc(f.category) + '</td>' +
                '<td><strong>' + esc(f.title) + '</strong></td>' +
                '<td class="mono">' + esc(f.path) + '</td>' +
                '<td class="mono">' + esc(f.timestamp) + '</td>' +
              '</tr>';
          });
          container.innerHTML =
            '<table class="data-table">' +
              '<thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Instance Path</th><th>Time</th></tr></thead>' +
              '<tbody>' + rows + '</tbody>' +
            '</table>';

          container.querySelectorAll("tr.clickable-row").forEach(function(row) {
            function selectRow() {
              state.selectedIndex = parseInt(row.getAttribute("data-idx"), 10);
              renderLiveSession();
              renderInspector(list[state.selectedIndex]);
            }
            row.addEventListener("click", selectRow);
            row.addEventListener("keydown", function(e) {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                selectRow();
              }
            });
          });
          if (state.selectedIndex >= 0 && state.selectedIndex < list.length) {
            renderInspector(list[state.selectedIndex]);
          }
        }

        // Remotes table
        const remContainer = document.getElementById("remotes-table-container");
        const remotes = state.session.remote_traffic || [];
        if (remotes.length === 0) {
          remContainer.innerHTML =
            '<div class="state-box">' +
              '<h3>No remote traffic profiled yet</h3>' +
              '<p>Live OnClientEvent call rates (calls/sec) appear here once the Luau bridge sends 10-second telemetry snapshots.</p>' +
            '</div>';
        } else {
          let rRows = "";
          remotes.forEach(function(r) {
            const statusBadge = r.has_cooldown_warning
              ? '<span class="badge badge-CRITICAL">UNTHROTTLED</span>'
              : '<span class="badge badge-INFO">OK</span>';
            rRows +=
              '<tr>' +
                '<td class="mono">' + esc(r.remote_path) + '</td>' +
                '<td class="mono">' + esc(r.remote_type) + '</td>' +
                '<td class="mono">' + esc(r.last_rate_per_sec.toFixed(1)) + '/s</td>' +
                '<td class="mono">' + esc(r.peak_rate_per_sec.toFixed(1)) + '/s</td>' +
                '<td class="mono">' + esc(r.total_calls) + '</td>' +
                '<td>' + statusBadge + '</td>' +
              '</tr>';
          });
          remContainer.innerHTML =
            '<table class="data-table">' +
              '<thead><tr><th>Remote Path</th><th>Class</th><th>Current Rate</th><th>Peak Rate</th><th>Total</th><th>Status</th></tr></thead>' +
              '<tbody>' + rRows + '</tbody>' +
            '</table>';
        }

        // Snapshots table
        const snapContainer = document.getElementById("snapshots-table-container");
        const snaps = state.session.memory_snapshots || [];
        if (snaps.length === 0) {
          snapContainer.innerHTML =
            '<div class="state-box">' +
              '<h3>No 10s memory snapshots recorded yet</h3>' +
              '<p>Workspace instance counts, Player instance counts, and total memory (MB) are sampled every 10 seconds during a playtest.</p>' +
            '</div>';
        } else {
          let sRows = "";
          snaps.forEach(function(s, i) {
            const prev = i > 0 ? snaps[i - 1] : null;
            const wsDelta = prev ? (s.workspace_instances - prev.workspace_instances) : 0;
            const memDelta = prev ? (s.total_memory_mb - prev.total_memory_mb) : 0;
            const deltaText = prev
              ? ((wsDelta >= 0 ? "+" : "") + wsDelta + " inst / " + (memDelta >= 0 ? "+" : "") + memDelta.toFixed(2) + " MB")
              : "baseline";
            sRows +=
              '<tr>' +
                '<td class="mono">' + esc(s.timestamp) + '</td>' +
                '<td class="mono">' + esc(s.elapsed_sec.toFixed(1)) + 's</td>' +
                '<td class="mono">' + esc(s.workspace_instances) + '</td>' +
                '<td class="mono">' + esc(s.player_instances) + '</td>' +
                '<td class="mono">' + esc(s.total_memory_mb.toFixed(2)) + ' MB</td>' +
                '<td class="mono">' + esc(deltaText) + '</td>' +
              '</tr>';
          });
          snapContainer.innerHTML =
            '<table class="data-table">' +
              '<thead><tr><th>Time</th><th>Elapsed</th><th>Workspace</th><th>Players</th><th>Memory</th><th>10s Delta</th></tr></thead>' +
              '<tbody>' + sRows + '</tbody>' +
            '</table>';
        }
      }

      function pollState() {
        fetch("/api/state")
          .then(function(r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(function(data) {
            state.error = null;
            state.session = data.session;
            if (!state.luauScript && data.luau_script) {
              state.luauScript = data.luau_script;
            }
            document.getElementById("bridge-addr-text").textContent =
              "Bridge: " + data.host + ":" + data.port + " (Log Tailer Active)";
            document.getElementById("brain-summary-text").textContent =
              data.catalog_count.toLocaleString() + " Flaws | " +
              data.learned_count.toLocaleString() + " Learned | " +
              data.brain_concepts.toLocaleString() + " Brain Concepts";
            renderLiveSession();
          })
          .catch(function(err) {
            state.error = err.message || "Bridge unreachable";
            renderLiveSession();
          });
      }

      // Top action buttons
      document.getElementById("btn-copy-luau").addEventListener("click", function() {
        fetch("/api/copy-luau", { method: "POST" })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            if (navigator.clipboard && state.luauScript) {
              navigator.clipboard.writeText(state.luauScript).catch(function() {});
            }
            showToast(res.message || "Copied Luau diagnostic script to clipboard.", false);
          })
          .catch(function(e) { showToast("Copy failed: " + e.message, true); });
      });

      document.getElementById("btn-simulate").addEventListener("click", function() {
        showToast("Injecting simulated playtest findings and 10s telemetry snapshots...", false);
        fetch("/api/simulate", { method: "POST" })
          .then(function(r) { return r.json(); })
          .then(function() { setTimeout(pollState, 400); })
          .catch(function(e) { showToast("Simulation error: " + e.message, true); });
      });

      document.getElementById("btn-export-md").addEventListener("click", function() {
        window.location.href = "/api/export.md";
      });

      document.getElementById("btn-clear-session").addEventListener("click", function() {
        fetch("/api/clear", { method: "POST" })
          .then(function() {
            state.selectedIndex = -1;
            pollState();
            showToast("Cleared active session findings and telemetry.", false);
          });
      });

      // Static Scanner forms
      document.getElementById("form-scan-path").addEventListener("submit", function(e) {
        e.preventDefault();
        const pathVal = document.getElementById("input-scan-path").value.trim();
        const statusBox = document.getElementById("static-scan-status");
        if (!pathVal) {
          statusBox.innerHTML = '<p style="color:var(--crit-fg);">Enter a local file or folder path to scan.</p>';
          return;
        }
        statusBox.innerHTML = '<p>Scanning <code>' + esc(pathVal) + '</code>...</p>';
        fetch("/api/scan-path", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: pathVal })
        })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            if (res.error) {
              statusBox.innerHTML = '<p style="color:var(--crit-fg);">' + esc(res.error) + '</p>';
            } else {
              statusBox.innerHTML =
                '<p style="color:var(--ok-fg);"><strong>Scan complete:</strong> Added ' +
                esc(res.added) + ' new finding(s) from <code>' + esc(res.path) + '</code> (' +
                esc(res.total_findings) + ' total in session).</p>';
              pollState();
            }
          })
          .catch(function(err) {
            statusBox.innerHTML = '<p style="color:var(--crit-fg);">Request failed: ' + esc(err.message) + '</p>';
          });
      });

      document.getElementById("form-scan-source").addEventListener("submit", function(e) {
        e.preventDefault();
        const srcVal = document.getElementById("input-luau-source").value;
        const statusBox = document.getElementById("static-scan-status");
        if (!srcVal.trim()) {
          statusBox.innerHTML = '<p style="color:var(--crit-fg);">Paste a Luau script snippet to audit.</p>';
          return;
        }
        statusBox.innerHTML = '<p>Auditing Luau source against 12 static rules and 120 debugger probes...</p>';
        fetch("/api/scan-source", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source: srcVal, script_name: "UI_Snippet.luau" })
        })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            statusBox.innerHTML =
              '<p style="color:var(--ok-fg);"><strong>Source audit complete:</strong> Matched ' +
              esc(res.matched) + ' flaw(s) (' + esc(res.added) + ' added to Live Audit tab).</p>';
            pollState();
          });
      });

      // Catalog search
      function loadCatalog(query, severity) {
        const container = document.getElementById("catalog-table-container");
        container.innerHTML = '<div class="state-box"><h3>Searching 120,000-flaw mmap index...</h3></div>';
        const url = "/api/catalog?q=" + encodeURIComponent(query) + "&severity=" + encodeURIComponent(severity) + "&limit=50";
        fetch(url)
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("catalog-result-count").textContent = res.results.length;
            document.getElementById("catalog-latency-label").textContent =
              "Lookup: " + res.elapsed_ms.toFixed(2) + " ms (120,000 indexed)";
            if (res.results.length === 0) {
              container.innerHTML =
                '<div class="state-box"><h3>No catalog signatures matched "' + esc(query) + '"</h3><p>Try searching for a Roblox service, remote keyword, or RCD code.</p></div>';
              return;
            }
            let rows = "";
            res.results.forEach(function(item) {
              rows +=
                '<tr>' +
                  '<td class="mono"><strong>' + esc(item.code) + '</strong><br/>Rank #' + esc(item.rank) + '</td>' +
                  '<td><span class="badge badge-' + esc(item.severity) + '">' + esc(item.severity) + '</span></td>' +
                  '<td class="mono">' + esc(item.domain) + '<br/>' + esc(item.category) + '</td>' +
                  '<td><strong>' + esc(item.title) + '</strong><br/><span style="color:var(--text-muted)">' + esc(item.flaw) + '</span></td>' +
                  '<td>' + esc(item.fix) + '</td>' +
                '</tr>';
            });
            container.innerHTML =
              '<table class="data-table">' +
                '<thead><tr><th>Code / Rank</th><th>Severity</th><th>Domain</th><th>Signature &amp; Flaw</th><th>Recommended Fix</th></tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
              '</table>';
          });
      }

      document.getElementById("form-catalog-search").addEventListener("submit", function(e) {
        e.preventDefault();
        loadCatalog(
          document.getElementById("input-catalog-query").value.trim(),
          document.getElementById("select-catalog-sev").value
        );
      });

      // Pack search
      function loadPack(query) {
        const container = document.getElementById("pack-table-container");
        container.innerHTML = '<div class="state-box"><h3>Loading Luau debugger probes...</h3></div>';
        fetch("/api/pack?q=" + encodeURIComponent(query) + "&limit=120")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("pack-result-count").textContent = res.results.length;
            if (res.results.length === 0) {
              container.innerHTML =
                '<div class="state-box"><h3>No Luau probes matched "' + esc(query) + '"</h3></div>';
              return;
            }
            let rows = "";
            res.results.forEach(function(p) {
              rows +=
                '<tr>' +
                  '<td class="mono"><strong>' + esc(p.id) + '</strong></td>' +
                  '<td><span class="badge badge-' + esc(p.severity) + '">' + esc(p.severity) + '</span></td>' +
                  '<td class="mono">' + esc(p.source) + '</td>' +
                  '<td><strong>' + esc(p.name) + '</strong><br/><span style="color:var(--text-muted)">' + esc(p.root_cause) + '</span></td>' +
                  '<td>' + esc(p.fix) + '</td>' +
                '</tr>';
            });
            container.innerHTML =
              '<table class="data-table">' +
                '<thead><tr><th>ID</th><th>Severity</th><th>Source</th><th>Probe &amp; Cause</th><th>Fix</th></tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
              '</table>';
          });
      }

      document.getElementById("form-pack-search").addEventListener("submit", function(e) {
        e.preventDefault();
        loadPack(document.getElementById("input-pack-query").value.trim());
      });

      // Brain & History
      function loadBrainHistory() {
        fetch("/api/history")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            const tokBox = document.getElementById("learned-tokens-container");
            if (!res.learned_tokens || res.learned_tokens.length === 0) {
              tokBox.innerHTML = '<div class="state-box"><h3>No custom tokens learned yet</h3></div>';
            } else {
              let tRows = "";
              res.learned_tokens.forEach(function(t) {
                tRows +=
                  '<tr>' +
                    '<td class="mono"><strong>' + esc(t.token) + '</strong></td>' +
                    '<td><span class="badge badge-' + esc(t.severity) + '">' + esc(t.severity) + '</span></td>' +
                    '<td class="mono">' + esc(t.domain) + '</td>' +
                    '<td class="mono">' + esc(t.seen_count) + 'x</td>' +
                  '</tr>';
              });
              tokBox.innerHTML =
                '<table class="data-table">' +
                  '<thead><tr><th>Token</th><th>Severity</th><th>Domain</th><th>Seen</th></tr></thead>' +
                  '<tbody>' + tRows + '</tbody>' +
                '</table>';
            }

            const histBox = document.getElementById("history-table-container");
            if (!res.history || res.history.length === 0) {
              histBox.innerHTML = '<div class="state-box"><h3>No command history recorded yet</h3></div>';
            } else {
              let hRows = "";
              res.history.forEach(function(h) {
                hRows +=
                  '<tr>' +
                    '<td class="mono">' + esc(h.timestamp) + '</td>' +
                    '<td class="mono"><strong>' + esc(h.command) + '</strong></td>' +
                    '<td class="mono">' + esc(h.findings_count) + ' findings</td>' +
                    '<td class="mono">' + esc(h.duration_ms) + ' ms</td>' +
                  '</tr>';
              });
              histBox.innerHTML =
                '<table class="data-table">' +
                  '<thead><tr><th>Timestamp</th><th>Command</th><th>Findings</th><th>Duration</th></tr></thead>' +
                  '<tbody>' + hRows + '</tbody>' +
                '</table>';
            }
          });
      }

      pollState();
      setInterval(pollState, 1200);
    })();
  </script>
</body>
</html>
"""


def build_ui_html() -> str:
    return UI_HTML_DOCUMENT.replace("__VERSION__", __version__)


class UIWorkbenchHandler(DebugReportHandler):
    """
    Extends DebugReportHandler so the same port serves both:
    - The live Roblox Luau runtime bridge (/report, /telemetry, /ws, /status, /shutdown)
    - The graphical rcdebug Workbench UI (/ui, /api/*)
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
        upgrade = self.headers.get("Upgrade", "").lower()
        if upgrade == "websocket":
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
                findings_data = [
                    {
                        **f.to_dict(),
                        "rank": f.rank,
                    }
                    for f in sorted_findings
                ]
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
                    "message": "Luau diagnostic script copied to macOS clipboard (pbcopy)!"
                    if copied
                    else "Clipboard copy returned false; copy the script from the right-hand panel.",
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
            script_name = str(data.get("script_name", "UI_Snippet.luau"))
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
    Binds RuntimeBridgeServer with UIWorkbenchHandler, automatically falling back
    to the next free port if preferred_port (e.g. 8765) is occupied by MacSploit.
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
