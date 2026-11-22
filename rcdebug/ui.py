"""
Interactive Web Workbench for rcdebug (rcdebug --ui).

Follows DESIGN.md (Calm Biometric & Acoustic Telemetry Studio, Dial: ENERGY 3 / RHYTHM 3 / MOTION 3).
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
      --bg: #0b0f14;
      --surface: #111720;
      --surface-alt: #161e2a;
      --surface-hover: #1d2736;
      --border: #263345;
      --border-control: #63768d;
      --text: #edf2f7;
      --text-muted: #98a6b8;
      --accent: #2dd4bf;
      --accent-fg: #071312;
      --accent-soft: rgba(45, 212, 191, 0.14);
      --crit-bg: #38111c;
      --crit-fg: #fda4af;
      --crit-border: #f43f5e;
      --warn-bg: #362107;
      --warn-fg: #fcd34d;
      --warn-border: #f59e0b;
      --info-bg: #12263a;
      --info-fg: #93c5fd;
      --info-border: #38bdf8;
      --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
      --font-mono: "SF Mono", "JetBrains Mono", Menlo, Monaco, Consolas, monospace;
      --ease-spring: cubic-bezier(0.22, 1, 0.36, 1);
      --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
    }

    [data-theme="light"] {
      --bg: #f4f6f8;
      --surface: #ffffff;
      --surface-alt: #e8edf2;
      --surface-hover: #dde5ed;
      --border: #cbd5e1;
      --border-control: #6c7a8e;
      --text: #0f1722;
      --text-muted: #465365;
      --accent: #0f766e;
      --accent-fg: #ffffff;
      --accent-soft: rgba(15, 118, 110, 0.12);
      --crit-bg: #ffe4e6;
      --crit-fg: #9f1239;
      --crit-border: #e11d48;
      --warn-bg: #fef3c7;
      --warn-fg: #92400e;
      --warn-border: #d97706;
      --info-bg: #e0f2fe;
      --info-fg: #075985;
      --info-border: #0284c7;
    }

    *, *::before, *::after {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: clamp(0.85rem, 0.82rem + 0.15vw, 0.94rem);
      line-height: 1.5;
      min-height: 100dvh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      transition: background-color 0.25s ease, color 0.25s ease;
    }

    a[href], button, summary, select, label[for], input[type="checkbox"], [role="button"], [role="tab"], [role="switch"] {
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

    @keyframes rowCascade {
      from {
        opacity: 0;
        transform: translateY(10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes viewMorph {
      from {
        opacity: 0;
        transform: translateY(8px) scale(0.995);
      }
      to {
        opacity: 1;
        transform: translateY(0) scale(1);
      }
    }

    @keyframes splineDraw {
      from {
        stroke-dashoffset: 1200;
      }
      to {
        stroke-dashoffset: 0;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-delay: 0ms !important;
        transition-duration: 0.01ms !important;
      }
    }

    header.deck-header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 12px 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      flex-wrap: wrap;
    }

    .brand-bar {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .brand-title {
      margin: 0;
      font-family: var(--font-mono);
      font-size: clamp(1rem, 0.95rem + 0.3vw, 1.18rem);
      font-weight: 700;
      letter-spacing: -0.03em;
      display: inline-flex;
      align-items: center;
      gap: 10px;
    }

    .brand-mark {
      display: inline-block;
      width: 10px;
      height: 20px;
      background: var(--accent);
      border-radius: 3px;
      transition: transform 0.25s var(--ease-spring);
    }

    .brand-title:hover .brand-mark {
      transform: scaleY(1.18);
    }

    .coord-readout {
      font-family: var(--font-mono);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
      color: var(--text-muted);
      background: var(--surface-alt);
      border: 1px solid var(--border);
      padding: 6px 11px;
      border-radius: 6px;
    }

    .deck-controls {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    /* Uiverse-inspired 3D Tactile Spring Button */
    .uiv-btn {
      position: relative;
      overflow: hidden;
      min-height: 44px;
      padding: 8px 15px;
      border-radius: 6px;
      border: 1px solid var(--border-control);
      background: var(--surface-alt);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: transform 0.2s var(--ease-spring), background-color 0.2s ease, border-color 0.2s ease;
    }

    .uiv-btn::after {
      content: "";
      position: absolute;
      inset: 0;
      background: var(--accent-soft);
      transform: translateX(-102%);
      transition: transform 0.32s var(--ease-out);
      pointer-events: none;
    }

    .uiv-btn:hover:not(:disabled) {
      background: var(--surface-hover);
      border-color: var(--accent);
      transform: translateY(-2px);
    }

    .uiv-btn:hover:not(:disabled)::after {
      transform: translateX(0);
    }

    .uiv-btn:active:not(:disabled) {
      transform: translateY(1px) scale(0.975);
    }

    .uiv-btn > * {
      position: relative;
      z-index: 1;
    }

    .uiv-btn-primary {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--accent);
      font-weight: 700;
    }

    .uiv-btn-primary::after {
      background: rgba(255, 255, 255, 0.16);
    }

    .uiv-btn-primary:hover:not(:disabled) {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--text);
    }

    /* Uiverse-inspired Morphing Pill Switch */
    .uiv-switch {
      min-height: 44px;
      padding: 6px 12px;
      border-radius: 6px;
      border: 1px solid var(--border-control);
      background: var(--surface-alt);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 10px;
      transition: border-color 0.2s ease, background-color 0.2s ease;
    }

    .uiv-switch:hover {
      border-color: var(--accent);
    }

    .uiv-switch-track {
      width: 34px;
      height: 18px;
      border-radius: 999px;
      background: var(--bg);
      border: 1px solid var(--border-control);
      position: relative;
      transition: background-color 0.25s ease, border-color 0.25s ease;
    }

    .uiv-switch-thumb {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: var(--text-muted);
      position: absolute;
      top: 2px;
      left: 2px;
      transition: transform 0.28s var(--ease-spring), background-color 0.25s ease;
    }

    .uiv-switch[aria-checked="true"] .uiv-switch-track {
      background: var(--accent-soft);
      border-color: var(--accent);
    }

    .uiv-switch[aria-checked="true"] .uiv-switch-thumb {
      transform: translateX(16px);
      background: var(--accent);
    }

    .kbd-hint {
      font-family: var(--font-mono);
      font-size: 11px;
      padding: 2px 6px;
      background: var(--bg);
      border: 1px solid var(--border-control);
      border-radius: 4px;
      color: var(--text);
    }

    /* Uiverse-inspired Sliding Pill Glider Navigation */
    nav.mode-nav {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 8px 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .tab-track {
      position: relative;
      display: flex;
      gap: 4px;
      padding: 4px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow-x: auto;
      max-width: 100%;
      scroll-snap-type: x mandatory;
    }

    .mode-tab {
      position: relative;
      z-index: 2;
      min-height: 44px;
      padding: 8px 16px;
      background: transparent;
      border: none;
      border-radius: 6px;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
      scroll-snap-align: start;
      transition: color 0.2s ease, transform 0.16s var(--ease-spring);
    }

    .mode-tab:hover {
      color: var(--text);
    }

    .mode-tab:active {
      transform: scale(0.97);
    }

    .mode-tab[aria-selected="true"] {
      color: var(--text);
    }

    .tab-glider {
      position: absolute;
      top: 4px;
      bottom: 4px;
      left: 0;
      z-index: 1;
      background: var(--surface-alt);
      border: 1px solid var(--accent);
      border-radius: 6px;
      transition: transform 0.34s var(--ease-spring), width 0.34s var(--ease-spring);
      pointer-events: none;
    }

    .sync-cluster {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    main.workbench {
      flex: 1;
      width: 100%;
      max-width: 1580px;
      margin: 0 auto;
      padding: 20px 22px 36px;
    }

    .status-toast {
      display: none;
      margin-bottom: 16px;
      padding: 12px 16px;
      background: var(--surface-alt);
      border: 1px solid var(--accent);
      border-radius: 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      animation: viewMorph 0.24s var(--ease-spring);
    }

    .status-toast.visible {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .view-section {
      display: none;
    }

    .view-section.active {
      display: block;
      animation: viewMorph 0.3s var(--ease-spring);
    }

    .studio-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      transition: border-color 0.22s ease;
    }

    .studio-panel:hover {
      border-color: var(--border-control);
    }

    /* RHYTHM 3 - Zone 2: Asymmetric Telemetry Strip */
    .telemetry-hero-strip {
      display: grid;
      grid-template-columns: 1.45fr 1fr;
      gap: 16px;
      margin-bottom: 18px;
    }

    .waveform-body {
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 12px;
    }

    .waveform-svg-wrap {
      width: 100%;
      height: 124px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      position: relative;
      overflow: hidden;
    }

    .waveform-svg {
      width: 100%;
      height: 100%;
      display: block;
    }

    .spline-line {
      stroke-dasharray: 1200;
      stroke-dashoffset: 0;
      animation: splineDraw 0.9s var(--ease-out);
    }

    .waveform-node {
      transition: r 0.18s var(--ease-spring), stroke-width 0.18s ease;
    }

    .waveform-node:hover,
    .waveform-node:focus {
      r: 8px;
      stroke-width: 3px;
    }

    .waveform-readout {
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      font-variant-numeric: tabular-nums;
    }

    .distribution-body {
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 14px;
    }

    .ratio-track {
      width: 100%;
      height: 14px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      display: flex;
      overflow: hidden;
    }

    .ratio-seg {
      height: 100%;
      transition: width 0.55s var(--ease-spring);
    }

    .ratio-crit { background: var(--crit-border); }
    .ratio-warn { background: var(--warn-border); }
    .ratio-info { background: var(--info-border); }

    .metric-strip {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
    }

    .metric-cell {
      padding: 10px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      transition: transform 0.2s var(--ease-spring), border-color 0.2s ease;
    }

    .metric-cell:hover {
      transform: translateY(-2px);
      border-color: var(--border-control);
    }

    .metric-cell .m-label {
      font-size: 11px;
      color: var(--text-muted);
      display: block;
    }

    .metric-cell .m-val {
      font-size: clamp(1.05rem, 1rem + 0.3vw, 1.3rem);
      font-weight: 700;
      color: var(--text);
    }

    /* RHYTHM 3 - Zone 3: Master-Detail Matrix & Tabbed Drawer */
    .triage-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 16px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px 10px 0 0;
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
      padding: 6px 13px;
      border-radius: 6px;
      border: 1px solid var(--border-control);
      background: var(--bg);
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      transition: transform 0.18s var(--ease-spring), background-color 0.18s ease, border-color 0.18s ease;
    }

    .sev-btn:hover {
      transform: translateY(-2px);
      color: var(--text);
    }

    .sev-btn:active {
      transform: translateY(1px) scale(0.97);
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

    /* Uiverse-inspired Expanding Focus Input */
    .text-field, .select-field, .code-area {
      min-height: 44px;
      padding: 8px 14px;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border-control);
      border-radius: 6px;
      font-family: var(--font-sans);
      font-size: 13px;
      transition: border-color 0.2s ease, transform 0.2s var(--ease-spring), background-color 0.2s ease;
    }

    .text-field:focus, .select-field:focus, .code-area:focus {
      border-color: var(--accent);
      background: var(--surface);
    }

    .code-area {
      font-family: var(--font-mono);
      width: 100%;
      min-height: 190px;
      resize: vertical;
      line-height: 1.5;
    }

    .ledger-split {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) minmax(380px, 1fr);
      border: 1px solid var(--border);
      border-radius: 0 0 10px 10px;
      background: var(--surface);
      overflow: hidden;
    }

    .ledger-pane {
      border-right: 1px solid var(--border);
      min-width: 0;
    }

    .drawer-pane {
      background: var(--surface);
      min-width: 0;
      display: flex;
      flex-direction: column;
    }

    .pane-head {
      padding: 12px 16px;
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
      font-size: clamp(0.84rem, 0.82rem + 0.12vw, 0.92rem);
      font-weight: 700;
      letter-spacing: -0.01em;
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
      padding: 11px 13px;
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
      animation: rowCascade 0.28s var(--ease-spring) both;
      transition: background-color 0.16s ease, transform 0.16s var(--ease-spring);
    }

    table.ledger-table tbody tr.finding-row:hover {
      background: var(--surface-hover);
    }

    table.ledger-table tbody tr.finding-row.active-row {
      background: var(--surface-alt);
      box-shadow: inset 3px 0 0 var(--accent);
    }

    .sev-tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
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

    /* Uiverse-inspired Pointer-Spotlight Interactive Workflow Cards */
    .launch-console {
      padding: 22px;
    }

    .launch-console h3 {
      margin: 0 0 6px 0;
      font-size: clamp(1rem, 0.95rem + 0.25vw, 1.15rem);
      letter-spacing: -0.02em;
    }

    .launch-console p {
      margin: 0 0 18px 0;
      color: var(--text-muted);
      font-size: 13px;
    }

    .launch-steps {
      display: grid;
      grid-template-columns: 1.25fr 1fr 1fr;
      gap: 14px;
    }

    .workflow-card {
      position: relative;
      padding: 16px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 14px;
      overflow: hidden;
      transition: border-color 0.22s ease, transform 0.24s var(--ease-spring);
    }

    .workflow-card::before {
      content: "";
      position: absolute;
      inset: 0;
      background: radial-gradient(
        260px circle at var(--mx, 50%) var(--my, 50%),
        var(--accent-soft),
        transparent 70%
      );
      opacity: 0;
      transition: opacity 0.25s ease;
      pointer-events: none;
    }

    .workflow-card:hover {
      border-color: var(--accent);
      transform: translateY(-3px);
    }

    .workflow-card:hover::before {
      opacity: 1;
    }

    .workflow-card > * {
      position: relative;
      z-index: 1;
    }

    .launch-step-num {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--accent);
      font-weight: 700;
    }

    .workflow-card h4 {
      margin: 6px 0 4px 0;
      font-size: 14px;
    }

    .workflow-card p {
      margin: 0;
      font-size: 12px;
      color: var(--text-muted);
    }

    .drawer-subtabs {
      display: flex;
      gap: 4px;
      padding: 6px;
      border-bottom: 1px solid var(--border);
      background: var(--bg);
    }

    .drawer-subtab {
      flex: 1;
      min-height: 44px;
      padding: 8px 10px;
      background: transparent;
      border: 1px solid transparent;
      border-radius: 6px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 600;
      transition: color 0.18s ease, background-color 0.18s ease, border-color 0.18s ease, transform 0.15s var(--ease-spring);
    }

    .drawer-subtab:hover {
      color: var(--text);
      background: var(--surface-alt);
    }

    .drawer-subtab:active {
      transform: scale(0.97);
    }

    .drawer-subtab[aria-selected="true"] {
      color: var(--text);
      border-color: var(--accent);
      background: var(--surface-alt);
    }

    .drawer-content {
      padding: 16px;
      flex: 1;
    }

    .spec-block {
      margin-bottom: 14px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
      animation: viewMorph 0.22s var(--ease-spring);
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
      margin: 8px 0 0 0;
      padding: 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      max-height: 330px;
      overflow-y: auto;
    }

    /* RHYTHM 3 - Zone 4: Full-Width Remote Traffic Matrix */
    .telemetry-strip {
      margin-top: 20px;
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 16px;
    }

    .rate-bar-wrap {
      width: 110px;
      height: 8px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      display: inline-block;
      vertical-align: middle;
      margin-left: 8px;
      overflow: hidden;
    }

    .rate-bar-fill {
      height: 100%;
      background: var(--accent);
      transition: width 0.45s var(--ease-spring);
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

    .scanner-stack {
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 16px;
    }

    .cmd-modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(11, 15, 20, 0.78);
      display: none;
      align-items: flex-start;
      justify-content: center;
      padding-top: 10vh;
      z-index: 100;
    }

    .cmd-modal-backdrop.open {
      display: flex;
      animation: viewMorph 0.18s var(--ease-spring);
    }

    .cmd-modal {
      width: 100%;
      max-width: 580px;
      background: var(--surface);
      border: 1px solid var(--accent);
      border-radius: 10px;
      margin: 0 16px;
      overflow: hidden;
    }

    .cmd-modal-header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .cmd-list {
      max-height: 340px;
      overflow-y: auto;
      padding: 6px;
    }

    .cmd-item {
      width: 100%;
      min-height: 44px;
      padding: 10px 12px;
      background: transparent;
      border: 1px solid transparent;
      color: var(--text);
      text-align: left;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: var(--font-sans);
      font-size: 13px;
      border-radius: 6px;
      transition: background-color 0.15s ease, transform 0.15s var(--ease-spring);
    }

    .cmd-item:hover,
    .cmd-item:focus {
      background: var(--surface-alt);
      border-color: var(--border-control);
      transform: translateX(3px);
    }

    footer.status-footer {
      background: var(--surface);
      border-top: 1px solid var(--border);
      padding: 12px 22px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }

    /* 3-State Responsive Reflow (antislop-layoutmobile: Desktop > 1120px, Tablet 680px-1120px, Mobile < 680px) */
    @media (max-width: 1120px) {
      .telemetry-hero-strip {
        grid-template-columns: 1fr;
      }
      .ledger-split {
        grid-template-columns: 1fr;
      }
      .ledger-pane {
        border-right: none;
        border-bottom: 1px solid var(--border);
      }
      .launch-steps {
        grid-template-columns: 1fr 1fr;
      }
      .telemetry-strip,
      .scanner-stack {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 680px) {
      header.deck-header,
      nav.mode-nav,
      main.workbench,
      footer.status-footer {
        padding-left: 12px;
        padding-right: 12px;
      }
      main.workbench {
        padding-top: 14px;
        padding-bottom: 24px;
      }
      .launch-steps {
        grid-template-columns: 1fr;
      }
      .metric-strip {
        grid-template-columns: 1fr;
      }
      .tab-glider {
        display: none;
      }
      .mode-tab[aria-selected="true"] {
        background: var(--surface-alt);
        border: 1px solid var(--accent);
      }
    }
  </style>
</head>
<body>
  <header class="deck-header">
    <div class="brand-bar">
      <h1 class="brand-title"><span class="brand-mark" aria-hidden="true"></span>rcdebug [v__VERSION__]</h1>
      <span class="coord-readout" id="bridge-coord-tag">[BRIDGE 127.0.0.1:8765]</span>
      <span class="coord-readout" id="corpus-coord-tag">[120,000 FLAWS | 120 PROBES]</span>
    </div>
    <div class="deck-controls">
      <button type="button" class="uiv-btn uiv-btn-primary" id="btn-copy-luau"><span>Copy Client Luau Payload</span></button>
      <button type="button" class="uiv-btn" id="btn-simulate"><span>Inject Sample Playtest</span></button>
      <button type="button" class="uiv-btn" id="btn-export-md"><span>Export Report (.md)</span></button>
      <button type="button" class="uiv-btn" id="btn-clear-session"><span>Reset Session</span></button>
      <button type="button" class="uiv-btn" id="btn-open-cmd" aria-haspopup="dialog" aria-controls="cmd-palette-modal">
        <span>Command Deck</span><span class="kbd-hint">Cmd+K</span>
      </button>
      <button type="button" class="uiv-switch" id="btn-theme-toggle" role="switch" aria-checked="true" aria-label="Dark theme enabled">
        <span id="theme-label-text">Studio Dark</span>
        <span class="uiv-switch-track" aria-hidden="true"><span class="uiv-switch-thumb"></span></span>
      </button>
    </div>
  </header>

  <nav class="mode-nav" aria-label="Inspector Modes">
    <div class="tab-track" role="tablist" id="main-tablist">
      <button type="button" class="mode-tab" role="tab" aria-selected="true" aria-controls="view-live" id="tab-live">[01] Vulnerability Matrix &amp; Telemetry</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-static" id="tab-static">[02] Static Place &amp; Luau Auditor</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-catalog" id="tab-catalog">[03] 120,000 Flaw Index (mmap)</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-pack" id="tab-pack">[04] 120 Luau Probes</button>
      <button type="button" class="mode-tab" role="tab" aria-selected="false" aria-controls="view-brain" id="tab-brain">[05] FlawBrain &amp; CLI History</button>
      <div class="tab-glider" id="tab-glider" aria-hidden="true"></div>
    </div>
    <div class="sync-cluster">
      <button type="button" class="uiv-switch" id="btn-toggle-sync" role="switch" aria-checked="true" aria-label="Live telemetry sync enabled">
        <span id="sync-status-label">Live Sync (1.5s)</span>
        <span class="uiv-switch-track" aria-hidden="true"><span class="uiv-switch-thumb"></span></span>
      </button>
    </div>
  </nav>

  <main class="workbench">
    <div class="status-toast" id="notice-banner" role="status" aria-live="polite">
      <span id="notice-text"></span>
      <button type="button" class="uiv-btn" id="btn-close-notice" style="min-height:36px;padding:4px 12px;"><span>Dismiss</span></button>
    </div>

    <section class="view-section active" id="view-live" role="tabpanel" aria-labelledby="tab-live">
      <div class="telemetry-hero-strip">
        <div class="studio-panel">
          <div class="pane-head">
            <h2>10s Memory &amp; Workspace Instance Oscilloscope (Interactive Scrub)</h2>
            <span class="mono-cell" id="waveform-hover-readout">[TAP, HOVER, OR FOCUS NODE TO INSPECT SNAPSHOT]</span>
          </div>
          <div class="waveform-body">
            <div class="waveform-svg-wrap" id="waveform-container">
              <svg class="waveform-svg" viewBox="0 0 600 120" preserveAspectRatio="none" id="telemetry-svg" aria-label="Memory and Workspace Instance Spline Curve"></svg>
            </div>
            <div class="waveform-readout">
              <span id="readout-latest-mem">Latest Memory: 0.00 MB</span>
              <span id="readout-latest-ws">Workspace Instances: 0</span>
              <span id="readout-snapshots-cnt">Snapshots Recorded: 0</span>
            </div>
          </div>
        </div>

        <div class="studio-panel">
          <div class="pane-head">
            <h2>Session Severity Distribution &amp; Corpus Telemetry</h2>
            <span class="mono-cell" id="session-target-text">Target: Roblox Client Bridge</span>
          </div>
          <div class="distribution-body">
            <div>
              <div style="display:flex;justify-content:space-between;margin-bottom:6px;" class="mono-cell">
                <span>Severity Ratio</span>
                <span id="total-findings-readout">0 Total Findings</span>
              </div>
              <div class="ratio-track" aria-label="Severity distribution bar">
                <div class="ratio-seg ratio-crit" id="bar-crit" style="width:0%"></div>
                <div class="ratio-seg ratio-warn" id="bar-warn" style="width:0%"></div>
                <div class="ratio-seg ratio-info" id="bar-info" style="width:0%"></div>
              </div>
            </div>
            <div class="metric-strip">
              <div class="metric-cell">
                <span class="m-label">CRITICAL</span>
                <span class="m-val" id="metric-crit" style="color:var(--crit-fg)">0</span>
              </div>
              <div class="metric-cell">
                <span class="m-label">WARNING</span>
                <span class="m-val" id="metric-warn" style="color:var(--warn-fg)">0</span>
              </div>
              <div class="metric-cell">
                <span class="m-label">INFO</span>
                <span class="m-val" id="metric-info" style="color:var(--info-fg)">0</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="triage-bar">
        <div class="sev-group" role="group" aria-label="Severity Filters">
          <span class="field-label">Filter Matrix:</span>
          <button type="button" class="sev-btn sev-CRITICAL" data-sev="CRITICAL" aria-pressed="true">CRITICAL [<span id="cnt-crit">0</span>]</button>
          <button type="button" class="sev-btn sev-WARN" data-sev="WARN" aria-pressed="true">WARN [<span id="cnt-warn">0</span>]</button>
          <button type="button" class="sev-btn sev-INFO" data-sev="INFO" aria-pressed="true">INFO [<span id="cnt-info">0</span>]</button>
        </div>
        <div class="search-cluster">
          <label class="field-label" for="input-live-filter">Search Findings:</label>
          <input type="search" id="input-live-filter" class="text-field" placeholder="Remote name, instance path, or [RCD-XXXXXX]..." />
        </div>
      </div>

      <div class="ledger-split">
        <div class="ledger-pane">
          <div class="pane-head">
            <h2>Ordered Vulnerability Matrix (<span id="visible-findings-cnt">0</span> shown)</h2>
            <span class="mono-cell">[SORT: SEVERITY -> RANK #1..120000]</span>
          </div>
          <div class="scroll-ledger" id="findings-ledger-box">
            <div class="state-panel">
              <h3>Connecting to local rcdebug runtime bridge...</h3>
              <p>Fetching active session findings and telemetry snapshots.</p>
            </div>
          </div>
        </div>

        <aside class="drawer-pane" aria-label="Remediation & Luau Payload Drawer">
          <div class="pane-head">
            <h2>Inspector &amp; Luau Payload Drawer</h2>
            <span class="mono-cell" id="inspector-code-tag">[READY]</span>
          </div>
          <div class="drawer-subtabs" role="tablist" aria-label="Inspector Views">
            <button type="button" class="drawer-subtab" role="tab" aria-selected="true" data-dtab="remediation">01. Flaw &amp; Abuse</button>
            <button type="button" class="drawer-subtab" role="tab" aria-selected="false" data-dtab="serverfix">02. Server Fix</button>
            <button type="button" class="drawer-subtab" role="tab" aria-selected="false" data-dtab="clientpayload">03. Client Bridge</button>
          </div>
          <div class="drawer-content" id="remediation-drawer"></div>
        </aside>
      </div>

      <div class="telemetry-strip">
        <div class="studio-panel">
          <div class="pane-head">
            <h2>Remote Traffic Rate Matrix (OnClientEvent calls/sec)</h2>
          </div>
          <div class="scroll-ledger" id="remotes-ledger-box"></div>
        </div>

        <div class="studio-panel">
          <div class="pane-head">
            <h2>10s Instance &amp; Memory Delta Ledger</h2>
          </div>
          <div class="scroll-ledger" id="snapshots-ledger-box"></div>
        </div>
      </div>
    </section>

    <section class="view-section" id="view-static" role="tabpanel" aria-labelledby="tab-static">
      <div class="scanner-stack">
        <div class="studio-panel">
          <div class="pane-head">
            <h2>Scan Local Place (.rbxlx / .rbxmx) or Luau Directory</h2>
          </div>
          <div class="drawer-content">
            <form id="form-scan-path">
              <div class="spec-block">
                <label class="field-label" for="input-scan-path">Filesystem path to .rbxlx place file or .luau scripts folder:</label>
                <div class="search-cluster" style="margin-top:8px;">
                  <input type="text" id="input-scan-path" class="text-field" style="flex:1;" placeholder="./place.rbxlx or ./src/ServerScriptService" />
                  <button type="submit" class="uiv-btn uiv-btn-primary"><span>Audit Path</span></button>
                </div>
              </div>
            </form>

            <form id="form-scan-source">
              <div class="spec-block">
                <label class="field-label" for="input-luau-source">Paste Luau script source for immediate static analysis:</label>
                <textarea id="input-luau-source" class="code-area" style="margin-top:8px;" placeholder="-- Paste Luau server or client script source here to test against 12 static rules and 120 probes"></textarea>
                <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
                  <button type="submit" class="uiv-btn uiv-btn-primary"><span>Audit Luau Source</span></button>
                  <button type="button" class="uiv-btn" id="btn-load-sample-luau"><span>Load Sample Vulnerable Server Script</span></button>
                </div>
              </div>
            </form>
          </div>
        </div>

        <div class="studio-panel">
          <div class="pane-head">
            <h2>Static Audit Execution Log</h2>
          </div>
          <div class="drawer-content" id="static-audit-log">
            <div class="state-panel" style="padding:8px 0;">
              <h3>Static analyzer ready</h3>
              <p>Submit a local file/directory path, paste a Luau script, or click "Load Sample Vulnerable Server Script" to run all 12 static security rules and 120 Luau debugger probes.</p>
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
          <button type="submit" class="uiv-btn uiv-btn-primary"><span>Query Index</span></button>
        </form>
      </div>
      <div class="studio-panel" style="border-radius:0 0 10px 10px;">
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
          <button type="submit" class="uiv-btn uiv-btn-primary"><span>Filter Probes</span></button>
        </form>
      </div>
      <div class="studio-panel" style="border-radius:0 0 10px 10px;">
        <div class="pane-head">
          <h2>Compiled Luau Debugger Probes (<span id="pack-match-cnt">0</span>)</h2>
        </div>
        <div class="scroll-ledger" id="pack-ledger-box"></div>
      </div>
    </section>

    <section class="view-section" id="view-brain" role="tabpanel" aria-labelledby="tab-brain">
      <div class="telemetry-strip" style="margin-top:0;">
        <div class="studio-panel">
          <div class="pane-head">
            <h2>Learned Game Tokens (~/.rcdebug/learned_flaws.json)</h2>
          </div>
          <div class="scroll-ledger" id="brain-tokens-box"></div>
        </div>
        <div class="studio-panel">
          <div class="pane-head">
            <h2>Logged CLI &amp; UI Invocations (~/.rcdebug/command_history.json)</h2>
          </div>
          <div class="scroll-ledger" id="brain-history-box"></div>
        </div>
      </div>
    </section>
  </main>

  <div class="cmd-modal-backdrop" id="cmd-palette-modal" role="dialog" aria-modal="true" aria-labelledby="cmd-palette-title">
    <div class="cmd-modal">
      <div class="cmd-modal-header">
        <label class="field-label" id="cmd-palette-title" for="cmd-search-input">[CMD]</label>
        <input type="search" id="cmd-search-input" class="text-field" style="flex:1;" placeholder="Type a command or view name (e.g. Simulate, Copy Luau, Catalog, Static)..." />
        <button type="button" class="uiv-btn" id="btn-close-cmd" style="min-height:36px;padding:4px 12px;"><span>Esc</span></button>
      </div>
      <div class="cmd-list" id="cmd-list-box"></div>
    </div>
  </div>

  <footer class="status-footer">
    <span>rcdebug v__VERSION__ | Zero-Dependency Python Standard Library Engine</span>
    <span>Shortcuts: [Cmd+K] Command Deck | Log Source: ~/Library/Logs/Roblox/*_last.log</span>
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
        drawerTab: "remediation",
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
        document.getElementById("notice-text").textContent = msg;
        banner.classList.add("visible");
        clearTimeout(banner._t);
        banner._t = setTimeout(function() {
          banner.classList.remove("visible");
        }, 5000);
      }

      document.getElementById("btn-close-notice").addEventListener("click", function() {
        document.getElementById("notice-banner").classList.remove("visible");
      });

      const tabs = Array.from(document.querySelectorAll(".mode-tab"));
      const sections = Array.from(document.querySelectorAll(".view-section"));
      const glider = document.getElementById("tab-glider");

      function updateGlider(activeTab) {
        if (!activeTab || !glider) return;
        glider.style.width = activeTab.offsetWidth + "px";
        glider.style.transform = "translateX(" + activeTab.offsetLeft + "px)";
      }

      function activateMainTab(tab) {
        tabs.forEach(function(t) { t.setAttribute("aria-selected", "false"); });
        sections.forEach(function(s) { s.classList.remove("active"); });
        tab.setAttribute("aria-selected", "true");
        updateGlider(tab);
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
      }

      tabs.forEach(function(tab) {
        tab.addEventListener("click", function() { activateMainTab(tab); });
      });
      window.addEventListener("resize", function() {
        const current = document.querySelector('.mode-tab[aria-selected="true"]');
        if (current) updateGlider(current);
      });
      setTimeout(function() { updateGlider(tabs[0]); }, 30);

      const drawerSubtabs = Array.from(document.querySelectorAll(".drawer-subtab"));
      drawerSubtabs.forEach(function(dtab) {
        dtab.addEventListener("click", function() {
          drawerSubtabs.forEach(function(t) { t.setAttribute("aria-selected", "false"); });
          dtab.setAttribute("aria-selected", "true");
          uiState.drawerTab = dtab.getAttribute("data-dtab");
          const visible = getFilteredFindings();
          const currentFinding = (uiState.selectedIdx >= 0 && uiState.selectedIdx < visible.length)
            ? visible[uiState.selectedIdx]
            : null;
          renderDrawer(currentFinding);
        });
      });

      const themeBtn = document.getElementById("btn-theme-toggle");
      const themeLabel = document.getElementById("theme-label-text");
      themeBtn.addEventListener("click", function() {
        uiState.theme = uiState.theme === "dark" ? "light" : "dark";
        const isDark = uiState.theme === "dark";
        document.documentElement.setAttribute("data-theme", uiState.theme);
        themeBtn.setAttribute("aria-checked", isDark ? "true" : "false");
        themeLabel.textContent = isDark ? "Studio Dark" : "Studio Day";
      });

      const syncBtn = document.getElementById("btn-toggle-sync");
      const syncLabel = document.getElementById("sync-status-label");
      syncBtn.addEventListener("click", function() {
        uiState.syncEnabled = !uiState.syncEnabled;
        syncBtn.setAttribute("aria-checked", uiState.syncEnabled ? "true" : "false");
        syncLabel.textContent = uiState.syncEnabled ? "Live Sync (1.5s)" : "Sync Paused";
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

      // Smooth Cubic-Bezier Spline Generator for Oscilloscope
      function buildSmoothSplinePath(pts) {
        if (pts.length === 0) return "";
        if (pts.length === 1) return "M " + pts[0].x.toFixed(1) + " " + pts[0].y.toFixed(1);
        let d = "M " + pts[0].x.toFixed(1) + " " + pts[0].y.toFixed(1);
        for (let i = 0; i < pts.length - 1; i++) {
          const p0 = pts[i];
          const p1 = pts[i + 1];
          const midX = ((p0.x + p1.x) / 2).toFixed(1);
          d += " C " + midX + " " + p0.y.toFixed(1) + ", " + midX + " " + p1.y.toFixed(1) + ", " + p1.x.toFixed(1) + " " + p1.y.toFixed(1);
        }
        return d;
      }

      function renderWaveformSVG(snaps) {
        const svg = document.getElementById("telemetry-svg");
        const hoverLabel = document.getElementById("waveform-hover-readout");
        if (!snaps || snaps.length === 0) {
          svg.innerHTML =
            '<line x1="0" y1="60" x2="600" y2="60" stroke="var(--border)" stroke-dasharray="4 4" stroke-width="1"/>' +
            '<text x="300" y="55" text-anchor="middle" fill="var(--text-muted)" font-family="var(--font-mono)" font-size="11">' +
              '[AWAITING 10S PLAYTEST TELEMETRY STREAM: PASTE CLIENT LUAU OR CLICK INJECT SAMPLE PLAYTEST]' +
            '</text>';
          document.getElementById("readout-latest-mem").textContent = "Latest Memory: 0.00 MB";
          document.getElementById("readout-latest-ws").textContent = "Workspace Instances: 0";
          document.getElementById("readout-snapshots-cnt").textContent = "Snapshots Recorded: 0";
          return;
        }

        const latest = snaps[snaps.length - 1];
        document.getElementById("readout-latest-mem").textContent = "Latest Memory: " + latest.total_memory_mb.toFixed(2) + " MB";
        document.getElementById("readout-latest-ws").textContent = "Workspace Instances: " + latest.workspace_instances;
        document.getElementById("readout-snapshots-cnt").textContent = "Snapshots Recorded: " + snaps.length;

        const mems = snaps.map(function(s) { return s.total_memory_mb; });
        const minM = Math.min.apply(null, mems);
        const maxM = Math.max.apply(null, mems);
        const span = Math.max(1, maxM - minM);

        const pts = snaps.map(function(s, i) {
          const x = snaps.length === 1 ? 300 : (32 + (i / (snaps.length - 1)) * 536);
          const y = 94 - ((s.total_memory_mb - minM) / span) * 68;
          return { x: x, y: y, snap: s, idx: i };
        });

        const curvePath = buildSmoothSplinePath(pts);
        const areaPath = curvePath + " L " + pts[pts.length - 1].x.toFixed(1) + " 114 L " + pts[0].x.toFixed(1) + " 114 Z";

        let circles = "";
        pts.forEach(function(p) {
          circles +=
            '<circle class="waveform-node" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="6" fill="var(--accent)" stroke="var(--bg)" stroke-width="2" ' +
            'tabindex="0" role="button" aria-label="Snapshot at ' + esc(p.snap.timestamp) + '" ' +
            'data-info="[' + esc(p.snap.timestamp) + ' | t=' + p.snap.elapsed_sec.toFixed(1) + 's] Workspace=' + p.snap.workspace_instances + ' | Players=' + p.snap.player_instances + ' | Mem=' + p.snap.total_memory_mb.toFixed(2) + ' MB" ' +
            'style="cursor:pointer;"/>';
        });

        svg.innerHTML =
          '<line x1="0" y1="28" x2="600" y2="28" stroke="var(--border)" stroke-width="1"/>' +
          '<line x1="0" y1="60" x2="600" y2="60" stroke="var(--border)" stroke-width="1"/>' +
          '<line x1="0" y1="92" x2="600" y2="92" stroke="var(--border)" stroke-width="1"/>' +
          '<path d="' + areaPath + '" fill="var(--accent)" fill-opacity="0.14"/>' +
          '<path class="spline-line" d="' + curvePath + '" fill="none" stroke="var(--accent)" stroke-width="2.5"/>' +
          circles;

        svg.querySelectorAll("circle").forEach(function(c) {
          function showInfo() {
            hoverLabel.textContent = c.getAttribute("data-info");
          }
          c.addEventListener("mouseenter", showInfo);
          c.addEventListener("focus", showInfo);
          c.addEventListener("click", showInfo);
        });
      }

      function attachSpotlightCards(container) {
        container.querySelectorAll(".workflow-card").forEach(function(card) {
          card.addEventListener("mousemove", function(e) {
            const rect = card.getBoundingClientRect();
            card.style.setProperty("--mx", (e.clientX - rect.left) + "px");
            card.style.setProperty("--my", (e.clientY - rect.top) + "px");
          });
        });
      }

      function renderDrawer(finding) {
        const drawer = document.getElementById("remediation-drawer");
        const tag = document.getElementById("inspector-code-tag");

        if (uiState.drawerTab === "clientpayload" || !finding) {
          if (!finding && uiState.drawerTab !== "clientpayload") {
            tag.textContent = "[CLIENT BRIDGE]";
            drawer.innerHTML =
              '<div class="spec-block">' +
                '<p class="spec-label">[NO FINDING SELECTED: SHOWING CLIENT LUAU PAYLOAD]</p>' +
                '<p class="spec-value">Select any row in the Vulnerability Matrix on the left to inspect its root architectural flaw, client abuse vector, and server-side Luau fix.</p>' +
              '</div>' +
              '<div class="spec-block">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                  '<p class="spec-label" style="margin:0;">[100% CLIENT-SIDED LUAU PAYLOAD]</p>' +
                  '<button type="button" class="uiv-btn" id="btn-inline-copy-payload" style="min-height:38px;padding:4px 12px;"><span>Copy Snippet</span></button>' +
                '</div>' +
                '<pre class="luau-code">' + esc(uiState.luauScript || "Loading...") + '</pre>' +
              '</div>';
          } else {
            tag.textContent = "[CLIENT BRIDGE]";
            drawer.innerHTML =
              '<div class="spec-block">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                  '<p class="spec-label" style="margin:0;">[100% CLIENT-SIDED LUAU BRIDGE PAYLOAD]</p>' +
                  '<button type="button" class="uiv-btn uiv-btn-primary" id="btn-inline-copy-payload" style="min-height:38px;padding:4px 12px;"><span>Copy to Clipboard</span></button>' +
                '</div>' +
                '<p class="spec-value" style="margin-top:6px;">Paste (Cmd+V) into Roblox Developer Console, executor, or Studio Command Bar. Uses zero server-only APIs and falls back to ~/Library/Logs/Roblox/*_last.log automatically.</p>' +
                '<pre class="luau-code">' + esc(uiState.luauScript || "Loading...") + '</pre>' +
              '</div>';
          }
          const copyBtn = document.getElementById("btn-inline-copy-payload");
          if (copyBtn) {
            copyBtn.addEventListener("click", function() {
              document.getElementById("btn-copy-luau").click();
            });
          }
          return;
        }

        const rankStr = finding.rank && finding.rank < 999999 ? ("RANK #" + finding.rank) : finding.category;
        tag.textContent = "[" + rankStr + "]";

        if (uiState.drawerTab === "serverfix") {
          const fixCode = finding.code_example || (
            "-- Server-Authoritative Validation Pattern for " + finding.path + "\n" +
            "-- " + finding.fix + "\n" +
            "local lastCall: {[Player]: number} = {}\n" +
            "Players.PlayerRemoving:Connect(function(plr) lastCall[plr] = nil end)\n"
          );
          drawer.innerHTML =
            '<div class="spec-block">' +
              '<span class="sev-tag sev-tag-' + esc(finding.severity) + '">' + esc(finding.severity) + '</span> ' +
              '<span class="mono-cell">[' + esc(finding.category) + ']</span>' +
              '<h3 style="margin:8px 0 0 0;font-size:15px;">' + esc(finding.title) + '</h3>' +
            '</div>' +
            '<div class="spec-block"><p class="spec-label">[RECOMMENDED REMEDIATION]</p><p class="spec-value">' + esc(finding.fix) + '</p></div>' +
            '<div class="spec-block">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                '<p class="spec-label" style="margin:0;">[SERVER LUAU REMEDIATION PATTERN]</p>' +
                '<button type="button" class="uiv-btn" id="btn-copy-fix-code" style="min-height:38px;padding:4px 12px;"><span>Copy Luau Fix</span></button>' +
              '</div>' +
              '<pre class="luau-code">' + esc(fixCode) + '</pre>' +
            '</div>';
          const copyFix = document.getElementById("btn-copy-fix-code");
          if (copyFix) {
            copyFix.addEventListener("click", function() {
              if (navigator.clipboard) navigator.clipboard.writeText(fixCode).catch(function() {});
              notify("Copied server-side Luau remediation snippet to clipboard.");
            });
          }
          return;
        }

        drawer.innerHTML =
          '<div class="spec-block">' +
            '<span class="sev-tag sev-tag-' + esc(finding.severity) + '">' + esc(finding.severity) + '</span> ' +
            '<span class="mono-cell">[' + esc(finding.category) + ']</span>' +
            '<h3 style="margin:8px 0 0 0;font-size:15px;">' + esc(finding.title) + '</h3>' +
          '</div>' +
          '<div class="spec-block"><p class="spec-label">[INSTANCE / SCRIPT COORDINATE]</p><p class="mono-cell">' + esc(finding.path) + '</p></div>' +
          '<div class="spec-block"><p class="spec-label">[ARCHITECTURAL FLAW]</p><p class="spec-value">' + esc(finding.flaw) + '</p></div>' +
          '<div class="spec-block"><p class="spec-label">[CLIENT ABUSE VECTOR]</p><p class="spec-value">' + esc(finding.abuse) + '</p></div>' +
          '<div class="spec-block"><p class="spec-label">[RECOMMENDED FIX]</p><p class="spec-value">' + esc(finding.fix) + '</p></div>';
      }

      function renderSessionView() {
        const box = document.getElementById("findings-ledger-box");
        if (uiState.bridgeError) {
          box.innerHTML =
            '<div class="state-panel">' +
              '<h3>Runtime bridge connection interrupted</h3>' +
              '<p>Error: ' + esc(uiState.bridgeError) + '. Confirm that rcdebug --ui is running in your terminal or toggle Live Sync back on.</p>' +
            '</div>';
          return;
        }
        if (!uiState.session) return;

        const counts = uiState.session.severity_counts || { CRITICAL: 0, WARN: 0, INFO: 0 };
        const cCrit = counts.CRITICAL || 0;
        const cWarn = counts.WARN || 0;
        const cInfo = counts.INFO || 0;
        const cTotal = cCrit + cWarn + cInfo;

        document.getElementById("cnt-crit").textContent = cCrit;
        document.getElementById("cnt-warn").textContent = cWarn;
        document.getElementById("cnt-info").textContent = cInfo;
        document.getElementById("metric-crit").textContent = cCrit;
        document.getElementById("metric-warn").textContent = cWarn;
        document.getElementById("metric-info").textContent = cInfo;
        document.getElementById("total-findings-readout").textContent = cTotal + " Total Findings";
        document.getElementById("session-target-text").textContent = "Target: " + (uiState.session.target_name || "");

        document.getElementById("bar-crit").style.width = (cTotal > 0 ? (cCrit / cTotal * 100) : 0) + "%";
        document.getElementById("bar-warn").style.width = (cTotal > 0 ? (cWarn / cTotal * 100) : 0) + "%";
        document.getElementById("bar-info").style.width = (cTotal > 0 ? (cInfo / cTotal * 100) : 0) + "%";

        renderWaveformSVG(uiState.session.memory_snapshots || []);

        const visible = getFilteredFindings();
        document.getElementById("visible-findings-cnt").textContent = visible.length;

        if (visible.length === 0) {
          const total = (uiState.session.findings || []).length;
          if (total === 0) {
            box.innerHTML =
              '<div class="launch-console">' +
                '<h3>Workbench Ready: Choose an Audit Source to Begin</h3>' +
                '<p>The local runtime bridge and Roblox log tailer are active. Start streaming telemetry using one of the three workflows below:</p>' +
                '<div class="launch-steps">' +
                  '<div class="workflow-card">' +
                    '<div>' +
                      '<span class="launch-step-num">[WORKFLOW 01: LIVE CLIENT]</span>' +
                      '<h4>Audit Live Roblox Client or Studio</h4>' +
                      '<p>Copy the 100% client-sided Luau payload and paste (Cmd+V) into Roblox Developer Console, executor, or Studio Command Bar.</p>' +
                    '</div>' +
                    '<button type="button" class="uiv-btn uiv-btn-primary" id="btn-empty-copy"><span>Copy Client Luau Payload</span></button>' +
                  '</div>' +
                  '<div class="workflow-card">' +
                    '<div>' +
                      '<span class="launch-step-num">[WORKFLOW 02: SIMULATION]</span>' +
                      '<h4>Inject Sample Playtest Stream</h4>' +
                      '<p>Stream realistic RemoteEvent vulnerabilities, unanchored physics parts, and 10s memory leak snapshots right now.</p>' +
                    '</div>' +
                    '<button type="button" class="uiv-btn" id="btn-empty-sim"><span>Inject Sample Playtest</span></button>' +
                  '</div>' +
                  '<div class="workflow-card">' +
                    '<div>' +
                      '<span class="launch-step-num">[WORKFLOW 03: STATIC PLACE]</span>' +
                      '<h4>Scan Local .rbxlx or Luau Scripts</h4>' +
                      '<p>Audit local .rbxlx/.rbxmx place files or Luau source code against 12 static rules and 120 debugger probes.</p>' +
                    '</div>' +
                    '<button type="button" class="uiv-btn" id="btn-empty-static"><span>Open Static Place Auditor</span></button>' +
                  '</div>' +
                '</div>' +
              '</div>';
            attachSpotlightCards(box);
            document.getElementById("btn-empty-copy").addEventListener("click", function() {
              document.getElementById("btn-copy-luau").click();
            });
            document.getElementById("btn-empty-sim").addEventListener("click", function() {
              document.getElementById("btn-simulate").click();
            });
            document.getElementById("btn-empty-static").addEventListener("click", function() {
              document.getElementById("tab-static").click();
            });
          } else {
            box.innerHTML =
              '<div class="state-panel">' +
                '<h3>0 findings match the current filter</h3>' +
                '<p>' + total + ' finding(s) are hidden by the active severity toggles or search query. Re-enable CRITICAL/WARN/INFO or clear the filter box.</p>' +
              '</div>';
          }
          renderDrawer(null);
        } else {
          if (uiState.selectedIdx < 0) uiState.selectedIdx = 0;
          let rows = "";
          visible.forEach(function(f, idx) {
            const activeCls = idx === uiState.selectedIdx ? " active-row" : "";
            const rankBadge = f.rank && f.rank < 999999 ? ("#" + f.rank) : "-";
            const delayMs = Math.min(idx * 22, 240);
            rows +=
              '<tr class="finding-row' + activeCls + '" data-idx="' + idx + '" tabindex="0" style="animation-delay:' + delayMs + 'ms">' +
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
            const pct = Math.min(100, Math.round((r.peak_rate_per_sec / 40.0) * 100));
            rRows +=
              '<tr>' +
                '<td class="mono-cell">' + esc(r.remote_path) + '</td>' +
                '<td class="mono-cell">' + esc(r.remote_type) + '</td>' +
                '<td class="mono-cell">' + esc(r.last_rate_per_sec.toFixed(1)) + '/s</td>' +
                '<td class="mono-cell">' +
                  esc(r.peak_rate_per_sec.toFixed(1)) + '/s' +
                  '<span class="rate-bar-wrap" aria-hidden="true"><span class="rate-bar-fill" style="width:' + pct + '%"></span></span>' +
                '</td>' +
                '<td class="mono-cell">' + esc(r.total_calls) + '</td>' +
                '<td>' + flagHtml + '</td>' +
              '</tr>';
          });
          remBox.innerHTML =
            '<table class="ledger-table">' +
              '<thead><tr><th>Remote Path</th><th>Class</th><th>Current</th><th>Peak Rate</th><th>Total Calls</th><th>Guard State</th></tr></thead>' +
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
              "[" + data.catalog_count.toLocaleString() + " FLAWS | " +
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
          .then(function() {
            setTimeout(fetchBridgeState, 350);
            setTimeout(fetchBridgeState, 1100);
          })
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

      document.getElementById("btn-load-sample-luau").addEventListener("click", function() {
        document.getElementById("input-luau-source").value =
          'local ReplicatedStorage = game:GetService("ReplicatedStorage")\n' +
          'local DataStoreService = game:GetService("DataStoreService")\n' +
          'local store = DataStoreService:GetDataStore("PlayerGold")\n\n' +
          'ReplicatedStorage.Remotes.BuyItem.OnServerEvent:Connect(function(player, itemId, price)\n' +
          '    player.leaderstats.Gold.Value -= price\n' +
          '    store:SetAsync("user_" .. player.UserId, player.leaderstats.Gold.Value)\n' +
          'end)\n\n' +
          'workspace.VaultPrompt.Triggered:Connect(function(player)\n' +
          '    loadstring("print(1)")()\n' +
          'end)\n';
        notify("Loaded sample vulnerable server script into the editor. Click Audit Luau Source to scan.");
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
                  '<p>Added <strong>' + esc(res.added) + '</strong> finding(s) from <span class="mono-cell">' + esc(res.path) + '</span> (' + esc(res.total_findings) + ' total in session).</p>' +
                  '<div style="margin-top:12px;"><button type="button" class="uiv-btn uiv-btn-primary" id="btn-jump-live-path"><span>View in Vulnerability Matrix</span></button></div>' +
                '</div>';
              document.getElementById("btn-jump-live-path").addEventListener("click", function() {
                activateMainTab(document.getElementById("tab-live"));
              });
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
          logBox.innerHTML = '<div class="state-panel"><h3>Empty Luau source</h3><p>Paste a Luau script into the editor or click Load Sample Vulnerable Server Script.</p></div>';
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
                '<p>Matched <strong>' + esc(res.matched) + '</strong> flaw(s) (' + esc(res.added) + ' new finding(s) added to the Vulnerability Matrix).</p>' +
                '<div style="margin-top:12px;"><button type="button" class="uiv-btn uiv-btn-primary" id="btn-jump-live-src"><span>Inspect Findings in Matrix</span></button></div>' +
              '</div>';
            document.getElementById("btn-jump-live-src").addEventListener("click", function() {
              activateMainTab(document.getElementById("tab-live"));
            });
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
            res.results.forEach(function(item, idx) {
              const delayMs = Math.min(idx * 16, 200);
              rows +=
                '<tr class="finding-row" style="animation-delay:' + delayMs + 'ms">' +
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
            res.results.forEach(function(p, idx) {
              const delayMs = Math.min(idx * 14, 180);
              rows +=
                '<tr class="finding-row" style="animation-delay:' + delayMs + 'ms">' +
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

      const modal = document.getElementById("cmd-palette-modal");
      const cmdInput = document.getElementById("cmd-search-input");
      const cmdListBox = document.getElementById("cmd-list-box");

      const commands = [
        { label: "Copy 100% Client-Sided Luau Diagnostic Payload", tag: "[CLIPBOARD]", run: function() { document.getElementById("btn-copy-luau").click(); } },
        { label: "Inject Sample Studio Playtest Telemetry & Memory Diffs", tag: "[SIMULATE]", run: function() { document.getElementById("btn-simulate").click(); } },
        { label: "Switch to [01] Vulnerability Matrix & Telemetry", tag: "[VIEW 01]", run: function() { activateMainTab(document.getElementById("tab-live")); } },
        { label: "Switch to [02] Static Place & Luau Source Auditor", tag: "[VIEW 02]", run: function() { activateMainTab(document.getElementById("tab-static")); } },
        { label: "Switch to [03] 120,000 Flaw Index (sub-10ms mmap)", tag: "[VIEW 03]", run: function() { activateMainTab(document.getElementById("tab-catalog")); } },
        { label: "Switch to [04] 120 Luau Debugger Probes", tag: "[VIEW 04]", run: function() { activateMainTab(document.getElementById("tab-pack")); } },
        { label: "Switch to [05] FlawBrain & Command History", tag: "[VIEW 05]", run: function() { activateMainTab(document.getElementById("tab-brain")); } },
        { label: "Download Markdown Security Audit Report (.md)", tag: "[EXPORT]", run: function() { document.getElementById("btn-export-md").click(); } },
        { label: "Reset Active Session Findings & Snapshots", tag: "[RESET]", run: function() { document.getElementById("btn-clear-session").click(); } },
        { label: "Toggle Studio Dark / Studio Day Theme", tag: "[THEME]", run: function() { document.getElementById("btn-theme-toggle").click(); } },
        { label: "Pause / Resume 1.5s Live Telemetry Polling", tag: "[SYNC]", run: function() { document.getElementById("btn-toggle-sync").click(); } }
      ];

      function renderCmdList(filterText) {
        const q = (filterText || "").trim().toLowerCase();
        const matches = commands.filter(function(c) {
          return !q || c.label.toLowerCase().indexOf(q) !== -1 || c.tag.toLowerCase().indexOf(q) !== -1;
        });
        cmdListBox.innerHTML = "";
        matches.forEach(function(cmd) {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "cmd-item";
          btn.innerHTML = '<span>' + esc(cmd.label) + '</span><span class="mono-cell" style="color:var(--text-muted)">' + esc(cmd.tag) + '</span>';
          btn.addEventListener("click", function() {
            closeCmdPalette();
            cmd.run();
          });
          cmdListBox.appendChild(btn);
        });
      }

      function openCmdPalette() {
        modal.classList.add("open");
        cmdInput.value = "";
        renderCmdList("");
        setTimeout(function() { cmdInput.focus(); }, 20);
      }

      function closeCmdPalette() {
        modal.classList.remove("open");
      }

      document.getElementById("btn-open-cmd").addEventListener("click", openCmdPalette);
      document.getElementById("btn-close-cmd").addEventListener("click", closeCmdPalette);
      modal.addEventListener("click", function(e) {
        if (e.target === modal) closeCmdPalette();
      });
      cmdInput.addEventListener("input", function(e) {
        renderCmdList(e.target.value);
      });

      document.addEventListener("keydown", function(e) {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
          e.preventDefault();
          if (modal.classList.contains("open")) closeCmdPalette();
          else openCmdPalette();
        } else if (e.key === "Escape" && modal.classList.contains("open")) {
          e.preventDefault();
          closeCmdPalette();
        }
      });

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
