"""
Interactive Web Workbench for rcdebug (rcdebug --ui).

Follows DESIGN.md (Calm Modern Mac App Shell, Dial: ENERGY 2 / RHYTHM 2 / MOTION 3).
Serves both the live Roblox Luau runtime bridge (/report, /telemetry, /ws, /status, /shutdown)
and the browser workbench (/ui, /api/*) on the same local port using only the Python standard library.
"""

from __future__ import annotations

import json
import re
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
from .contract_spec import build_contract_specification, kid_friendly_exploit_summary
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
      --bg: #09090b;
      --surface: #111114;
      --surface-hover: #18181d;
      --surface-active: #1f1f26;
      --divider: rgba(255, 255, 255, 0.08);
      --border-ctrl: rgba(255, 255, 255, 0.14);
      --border-ctrl-hover: rgba(255, 255, 255, 0.28);
      --text: #ededef;
      --text-muted: #94949e;
      --accent: #10b981;
      --accent-fg: #051411;
      --accent-soft: rgba(16, 185, 129, 0.12);
      --crit: #fb7185;
      --crit-soft: rgba(251, 113, 133, 0.12);
      --warn: #fbbf24;
      --warn-soft: rgba(251, 191, 36, 0.12);
      --info: #60a5fa;
      --info-soft: rgba(96, 165, 250, 0.12);
      --shadow-sheet: -24px 0 60px rgba(0, 0, 0, 0.55);
      --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Inter", sans-serif;
      --font-mono: "SF Mono", "JetBrains Mono", Menlo, Monaco, Consolas, monospace;
      --ease-spring: cubic-bezier(0.22, 1, 0.36, 1);
    }

    [data-theme="light"] {
      --bg: #fafafa;
      --surface: #ffffff;
      --surface-hover: #f4f4f5;
      --surface-active: #e4e4e7;
      --divider: rgba(0, 0, 0, 0.08);
      --border-ctrl: rgba(0, 0, 0, 0.14);
      --border-ctrl-hover: rgba(0, 0, 0, 0.28);
      --text: #111113;
      --text-muted: #5a5a66;
      --accent: #047857;
      --accent-fg: #ffffff;
      --accent-soft: rgba(4, 120, 87, 0.10);
      --crit: #be123c;
      --crit-soft: rgba(190, 18, 60, 0.10);
      --warn: #b45309;
      --warn-soft: rgba(180, 83, 9, 0.10);
      --info: #1d4ed8;
      --info-soft: rgba(29, 78, 216, 0.10);
      --shadow-sheet: -16px 0 48px rgba(0, 0, 0, 0.12);
    }

    *, *::before, *::after { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.5;
      min-height: 100dvh;
      display: flex;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.25s ease, color 0.25s ease;
    }

    a[href], button, summary, select, label[for], input[type="checkbox"], [role="button"], [role="tab"], [role="switch"] {
      cursor: pointer;
    }

    button:disabled, input:disabled, select:disabled, textarea:disabled {
      cursor: not-allowed;
      opacity: 0.45;
    }

    :focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }

    @keyframes fadeSlideUp {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes splineDraw {
      from { stroke-dashoffset: 1200; }
      to { stroke-dashoffset: 0; }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-delay: 0ms !important;
        transition-duration: 0.01ms !important;
      }
    }

    /* Left Sidebar Rail */
    aside.sidebar {
      width: 244px;
      flex-shrink: 0;
      background: var(--surface);
      border-right: 1px solid var(--divider);
      display: flex;
      flex-direction: column;
      height: 100dvh;
      position: sticky;
      top: 0;
      z-index: 40;
      transition: transform 0.3s var(--ease-spring), background-color 0.25s ease;
    }

    .sidebar-brand {
      height: 58px;
      padding: 0 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--divider);
    }

    .brand-lockup {
      display: flex;
      align-items: center;
      gap: 9px;
      font-weight: 700;
      font-size: 15px;
      letter-spacing: -0.02em;
    }

    .brand-pip {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent);
    }

    .ver-pill {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-muted);
    }

    .sidebar-nav {
      flex: 1;
      padding: 14px 10px;
      display: flex;
      flex-direction: column;
      gap: 2px;
      overflow-y: auto;
    }

    .nav-section-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      padding: 10px 10px 6px;
      letter-spacing: 0.02em;
    }

    .nav-item {
      width: 100%;
      min-height: 40px;
      padding: 8px 12px;
      border: none;
      border-radius: 8px;
      background: transparent;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 13.5px;
      font-weight: 500;
      display: flex;
      align-items: center;
      justify-content: space-between;
      text-align: left;
      transition: background-color 0.16s ease, color 0.16s ease, transform 0.16s var(--ease-spring);
    }

    .nav-item:hover {
      background: var(--surface-hover);
      color: var(--text);
    }

    .nav-item:active {
      transform: scale(0.98);
    }

    .nav-item[aria-selected="true"] {
      background: var(--surface-active);
      color: var(--text);
      font-weight: 600;
    }

    .nav-count {
      font-family: var(--font-mono);
      font-size: 11px;
      font-variant-numeric: tabular-nums;
      color: var(--text-muted);
      padding: 1px 6px;
      border-radius: 999px;
      background: var(--bg);
    }

    .nav-item[aria-selected="true"] .nav-count {
      color: var(--accent);
      background: var(--accent-soft);
    }

    .sidebar-footer {
      padding: 12px 14px;
      border-top: 1px solid var(--divider);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .rail-status-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-muted);
      padding: 2px 4px;
    }

    .rail-switch {
      width: 100%;
      min-height: 36px;
      padding: 6px 8px;
      border-radius: 8px;
      border: none;
      background: transparent;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 12.5px;
      font-weight: 500;
      display: flex;
      align-items: center;
      justify-content: space-between;
      transition: background-color 0.15s ease, color 0.15s ease;
    }

    .rail-switch:hover {
      background: var(--surface-hover);
      color: var(--text);
    }

    .pill-track {
      width: 30px;
      height: 16px;
      border-radius: 999px;
      background: var(--surface-active);
      border: 1px solid var(--border-ctrl);
      position: relative;
      transition: background-color 0.22s ease, border-color 0.22s ease;
    }

    .pill-thumb {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--text-muted);
      position: absolute;
      top: 2px;
      left: 2px;
      transition: transform 0.26s var(--ease-spring), background-color 0.22s ease;
    }

    .rail-switch[aria-checked="true"] .pill-track {
      background: var(--accent-soft);
      border-color: var(--accent);
    }

    .rail-switch[aria-checked="true"] .pill-thumb {
      transform: translateX(14px);
      background: var(--accent);
    }

    /* Main Workspace Shell */
    .shell-main {
      flex: 1;
      min-width: 0;
      display: flex;
      flex-direction: column;
      min-height: 100dvh;
    }

    header.topbar {
      height: 58px;
      padding: 0 28px;
      border-bottom: 1px solid var(--divider);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      position: sticky;
      top: 0;
      background: var(--bg);
      z-index: 20;
    }

    .topbar-left {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .mobile-menu-btn {
      display: none;
      min-height: 40px;
      min-width: 40px;
      padding: 0 10px;
      border-radius: 8px;
      border: 1px solid var(--border-ctrl);
      background: var(--surface);
      color: var(--text);
      font-size: 13px;
      font-weight: 600;
    }

    .page-title {
      margin: 0;
      font-size: 15px;
      font-weight: 600;
      letter-spacing: -0.015em;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Clean Modern Buttons */
    .btn {
      min-height: 36px;
      padding: 7px 14px;
      border-radius: 8px;
      border: 1px solid var(--border-ctrl);
      background: var(--surface);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: transform 0.18s var(--ease-spring), background-color 0.16s ease, border-color 0.16s ease;
    }

    .btn:hover:not(:disabled) {
      background: var(--surface-hover);
      border-color: var(--border-ctrl-hover);
      transform: translateY(-1px);
    }

    .btn:active:not(:disabled) {
      transform: translateY(0) scale(0.975);
    }

    .btn-primary {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--accent);
      font-weight: 600;
    }

    .btn-primary:hover:not(:disabled) {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--accent);
      filter: brightness(1.06);
    }

    .btn-ghost {
      border-color: transparent;
      background: transparent;
      color: var(--text-muted);
    }

    .btn-ghost:hover:not(:disabled) {
      background: var(--surface-hover);
      border-color: transparent;
      color: var(--text);
    }

    .kbd-chip {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-muted);
      background: var(--bg);
      border: 1px solid var(--border-ctrl);
      padding: 1px 5px;
      border-radius: 4px;
    }

    main.canvas {
      flex: 1;
      width: 100%;
      max-width: 1140px;
      margin: 0 auto;
      padding: 28px 28px 48px;
    }

    .view-panel {
      display: none;
    }

    .view-panel.active {
      display: block;
      animation: fadeSlideUp 0.28s var(--ease-spring);
    }

    /* Floating Bottom Toast */
    .toast-pill {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 120;
      padding: 11px 16px;
      border-radius: 10px;
      background: var(--surface);
      border: 1px solid var(--border-ctrl-hover);
      color: var(--text);
      font-size: 13px;
      font-weight: 500;
      display: none;
      align-items: center;
      gap: 12px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }

    .toast-pill.visible {
      display: flex;
      animation: fadeSlideUp 0.24s var(--ease-spring);
    }

    /* Clean Filter & Search Bar */
    .filter-strip {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 20px;
    }

    .segmented-pills {
      display: inline-flex;
      gap: 4px;
      padding: 3px;
      background: var(--surface);
      border: 1px solid var(--divider);
      border-radius: 9px;
    }

    .seg-btn {
      min-height: 34px;
      padding: 5px 12px;
      border: none;
      border-radius: 6px;
      background: transparent;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 12.5px;
      font-weight: 500;
      font-variant-numeric: tabular-nums;
      transition: background-color 0.16s ease, color 0.16s ease;
    }

    .seg-btn:hover {
      color: var(--text);
    }

    .seg-btn[aria-pressed="true"].sev-CRITICAL { background: var(--crit-soft); color: var(--crit); font-weight: 600; }
    .seg-btn[aria-pressed="true"].sev-WARN { background: var(--warn-soft); color: var(--warn); font-weight: 600; }
    .seg-btn[aria-pressed="true"].sev-INFO { background: var(--info-soft); color: var(--info); font-weight: 600; }

    .surface-subbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 18px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--divider);
    }

    .surface-tabs {
      display: inline-flex;
      gap: 6px;
    }

    .surface-tab {
      min-height: 36px;
      padding: 6px 14px;
      border-radius: 8px;
      border: 1px solid var(--border-ctrl);
      background: transparent;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: background-color 0.16s ease, color 0.16s ease, border-color 0.16s ease;
    }

    .surface-tab:hover {
      background: var(--surface-hover);
      color: var(--text);
    }

    .surface-tab[aria-selected="true"] {
      background: var(--surface-active);
      color: var(--text);
      border-color: var(--border-ctrl-hover);
      font-weight: 600;
    }

    .surface-tab[aria-selected="true"].tab-exploit {
      background: var(--crit-soft);
      color: var(--crit);
      border-color: var(--crit);
    }

    .surface-tag {
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 10.5px;
      font-weight: 600;
      padding: 1px 6px;
      border-radius: 4px;
      margin-left: 8px;
      vertical-align: middle;
    }

    .surface-tag-exploit {
      background: var(--crit-soft);
      color: var(--crit);
    }

    .surface-tag-developer {
      background: var(--surface-active);
      color: var(--text-muted);
    }

    .search-input, .select-input, .code-textarea {
      min-height: 38px;
      padding: 8px 13px;
      border-radius: 8px;
      border: 1px solid var(--border-ctrl);
      background: var(--surface);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 13px;
      transition: border-color 0.18s ease, background-color 0.18s ease;
    }

    .search-input {
      width: 280px;
      max-width: 100%;
    }

    .search-input:focus, .select-input:focus, .code-textarea:focus {
      border-color: var(--accent);
    }

    .code-textarea {
      font-family: var(--font-mono);
      width: 100%;
      min-height: 220px;
      resize: vertical;
      line-height: 1.55;
      padding: 14px;
    }

    /* Ultra-Clean Borderless Row List */
    .clean-list {
      display: flex;
      flex-direction: column;
      border-top: 1px solid var(--divider);
    }

    .list-row {
      display: grid;
      grid-template-columns: 92px minmax(0, 1fr) auto;
      align-items: center;
      gap: 16px;
      padding: 15px 14px;
      border-bottom: 1px solid var(--divider);
      border-radius: 8px;
      transition: background-color 0.15s ease, transform 0.18s var(--ease-spring);
      animation: fadeSlideUp 0.25s var(--ease-spring) both;
    }

    .list-row.clickable {
      cursor: pointer;
    }

    .list-row.clickable:hover {
      background: var(--surface);
      transform: translateX(3px);
    }

    .sev-indicator {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      font-family: var(--font-mono);
      font-size: 11.5px;
      font-weight: 600;
    }

    .sev-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .sev-dot-CRITICAL { background: var(--crit); }
    .sev-dot-WARN { background: var(--warn); }
    .sev-dot-INFO { background: var(--info); }

    .sev-text-CRITICAL { color: var(--crit); }
    .sev-text-WARN { color: var(--warn); }
    .sev-text-INFO { color: var(--info); }

    .row-main {
      min-width: 0;
    }

    .row-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      margin: 0 0 2px 0;
    }

    .row-sub {
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      margin: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .row-meta {
      font-family: var(--font-mono);
      font-size: 11.5px;
      color: var(--text-muted);
      text-align: right;
      white-space: nowrap;
    }

    /* Calm Centered Empty State */
    .calm-empty {
      max-width: 560px;
      margin: 64px auto;
      text-align: center;
    }

    .calm-empty h2 {
      font-size: 20px;
      font-weight: 600;
      letter-spacing: -0.025em;
      margin: 0 0 8px 0;
    }

    .calm-empty p {
      color: var(--text-muted);
      margin: 0 0 24px 0;
      font-size: 14px;
    }

    .calm-actions {
      display: flex;
      justify-content: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    /* Telemetry View */
    .telemetry-metrics {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }

    .clean-stat {
      padding: 18px 20px;
      background: var(--surface);
      border: 1px solid var(--divider);
      border-radius: 12px;
    }

    .clean-stat-label {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 4px;
    }

    .clean-stat-value {
      font-family: var(--font-mono);
      font-size: 22px;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
      letter-spacing: -0.02em;
    }

    .wave-card {
      background: var(--surface);
      border: 1px solid var(--divider);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
    }

    .wave-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 14px;
    }

    .wave-header h2 {
      margin: 0;
      font-size: 14px;
      font-weight: 600;
    }

    .wave-svg {
      width: 100%;
      height: 170px;
      display: block;
    }

    .spline-line {
      stroke-dasharray: 1200;
      stroke-dashoffset: 0;
      animation: splineDraw 0.85s var(--ease-spring);
    }

    .wave-node {
      transition: r 0.16s var(--ease-spring);
    }

    .wave-node:hover, .wave-node:focus {
      r: 7px;
    }

    .rate-bar-bg {
      width: 120px;
      height: 6px;
      border-radius: 999px;
      background: var(--surface-active);
      display: inline-block;
      vertical-align: middle;
      margin-left: 10px;
      overflow: hidden;
    }

    .rate-bar-fill {
      height: 100%;
      background: var(--accent);
      border-radius: 999px;
      transition: width 0.4s var(--ease-spring);
    }

    /* Slide-Over Right Sheet (Finding & Luau Inspector) */
    .sheet-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.45);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s ease;
      z-index: 80;
    }

    .sheet-backdrop.open {
      opacity: 1;
      pointer-events: auto;
    }

    aside.detail-sheet {
      position: fixed;
      top: 0;
      right: 0;
      bottom: 0;
      width: min(560px, 100vw);
      background: var(--surface);
      border-left: 1px solid var(--divider);
      box-shadow: var(--shadow-sheet);
      transform: translateX(100%);
      transition: transform 0.34s var(--ease-spring);
      z-index: 90;
      display: flex;
      flex-direction: column;
    }

    aside.detail-sheet.open {
      transform: translateX(0);
    }

    .sheet-head {
      padding: 18px 22px;
      border-bottom: 1px solid var(--divider);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .sheet-tabs {
      display: flex;
      gap: 4px;
      padding: 10px 22px;
      border-bottom: 1px solid var(--divider);
    }

    .sheet-body {
      flex: 1;
      overflow-y: auto;
      padding: 22px;
    }

    .detail-block {
      margin-bottom: 20px;
    }

    .detail-label {
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
    }

    .detail-text {
      margin: 0;
      font-size: 13.5px;
      line-height: 1.6;
    }

    .risk-strip {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 18px;
    }

    .risk-chip {
      padding: 10px 12px;
      border-radius: 10px;
      background: var(--bg);
      border: 1px solid var(--divider);
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .risk-chip-label {
      font-size: 10.5px;
      font-weight: 600;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      color: var(--text-muted);
    }

    .risk-chip-val {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text);
    }

    .overview-stack {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 18px;
    }

    .overview-card {
      padding: 14px 16px;
      border-radius: 10px;
      background: var(--bg);
      border: 1px solid var(--divider);
      transition: border-color 0.16s ease;
    }

    .overview-card:hover {
      border-color: var(--border-ctrl);
    }

    .overview-card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 6px;
    }

    .overview-card-title {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text);
    }

    .overview-card-badge {
      font-family: var(--font-mono);
      font-size: 10.5px;
      color: var(--accent);
      background: var(--accent-soft);
      padding: 2px 7px;
      border-radius: 999px;
    }

    .overview-card-badge.badge-crit {
      color: var(--crit);
      background: var(--crit-soft);
    }

    .overview-bullets {
      margin: 8px 0 0;
      padding-left: 18px;
      display: flex;
      flex-direction: column;
      gap: 5px;
      font-size: 12.8px;
      line-height: 1.5;
      color: var(--text-muted);
    }

    .overview-bullets li strong {
      color: var(--text);
      font-weight: 600;
    }

    .search-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }

    .search-pill {
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid var(--border-ctrl);
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 11.5px;
      transition: border-color 0.15s ease, background-color 0.15s ease;
    }

    .search-pill:hover {
      border-color: var(--accent);
      background: var(--accent-soft);
    }

    .contract-table-wrap {
      overflow-x: auto;
      border: 1px solid var(--divider);
      border-radius: 10px;
      background: var(--bg);
      margin-top: 8px;
    }

    table.contract-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      line-height: 1.45;
    }

    table.contract-table th,
    table.contract-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--divider);
      vertical-align: top;
    }

    table.contract-table th {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      background: var(--surface);
    }

    table.contract-table tr:last-child td {
      border-bottom: none;
    }

    table.contract-table code {
      font-family: var(--font-mono);
      font-size: 11.5px;
      color: var(--accent);
    }

    pre.code-box {
      margin: 8px 0 0;
      padding: 14px 16px;
      border-radius: 10px;
      background: var(--bg);
      border: 1px solid var(--divider);
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.55;
      overflow-x: auto;
      white-space: pre-wrap;
    }

    /* Command Palette Modal */
    .cmd-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.52);
      display: none;
      align-items: flex-start;
      justify-content: center;
      padding-top: 12vh;
      z-index: 110;
    }

    .cmd-backdrop.open {
      display: flex;
      animation: fadeSlideUp 0.18s var(--ease-spring);
    }

    .cmd-box {
      width: min(540px, calc(100vw - 32px));
      background: var(--surface);
      border: 1px solid var(--border-ctrl-hover);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.5);
    }

    .cmd-top {
      padding: 12px 16px;
      border-bottom: 1px solid var(--divider);
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .cmd-input {
      flex: 1;
      border: none;
      background: transparent;
      color: var(--text);
      font-size: 14px;
      font-family: var(--font-sans);
      min-height: 36px;
    }

    .cmd-input:focus { outline: none; }

    .cmd-items {
      max-height: 320px;
      overflow-y: auto;
      padding: 6px;
    }

    .cmd-row {
      width: 100%;
      min-height: 40px;
      padding: 8px 12px;
      border: none;
      border-radius: 8px;
      background: transparent;
      color: var(--text);
      font-size: 13px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      text-align: left;
      transition: background-color 0.12s ease;
    }

    .cmd-row:hover, .cmd-row:focus {
      background: var(--surface-hover);
    }

    /* Static Scanner Layout */
    .scanner-form-group {
      background: var(--surface);
      border: 1px solid var(--divider);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 18px;
    }

    /* Responsive Mobile & Tablet Reflow */
    @media (max-width: 860px) {
      aside.sidebar {
        position: fixed;
        left: 0;
        top: 0;
        bottom: 0;
        transform: translateX(-100%);
      }
      aside.sidebar.mobile-open {
        transform: translateX(0);
      }
      .mobile-menu-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
      }
      header.topbar {
        padding: 0 16px;
      }
      main.canvas {
        padding: 20px 16px 40px;
      }
      .telemetry-metrics {
        grid-template-columns: 1fr;
      }
      .list-row {
        grid-template-columns: 1fr;
        gap: 6px;
      }
      .row-meta {
        text-align: left;
      }
      .search-input {
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <div class="sheet-backdrop" id="mobile-nav-backdrop"></div>

  <aside class="sidebar" id="sidebar-rail" aria-label="Workspace Navigation">
    <div class="sidebar-brand">
      <div class="brand-lockup">
        <span class="brand-pip" aria-hidden="true"></span>
        <span>rcdebug</span>
      </div>
      <span class="ver-pill">v__VERSION__</span>
    </div>

    <nav class="sidebar-nav" role="tablist" aria-orientation="vertical">
      <div class="nav-section-label">Audit Workspace</div>
      <button type="button" class="nav-item" role="tab" aria-selected="true" aria-controls="view-live" id="nav-live">
        <span>Live Audit</span>
        <span class="nav-count" id="nav-count-findings">0</span>
      </button>
      <button type="button" class="nav-item" role="tab" aria-selected="false" aria-controls="view-telemetry" id="nav-telemetry">
        <span>Telemetry</span>
        <span class="nav-count" id="nav-count-snaps">0</span>
      </button>
      <button type="button" class="nav-item" role="tab" aria-selected="false" aria-controls="view-static" id="nav-static">
        <span>Static Scanner</span>
      </button>

      <div class="nav-section-label">Intelligence</div>
      <button type="button" class="nav-item" role="tab" aria-selected="false" aria-controls="view-catalog" id="nav-catalog">
        <span>Flaw Catalog</span>
        <span class="nav-count">600k</span>
      </button>
      <button type="button" class="nav-item" role="tab" aria-selected="false" aria-controls="view-pack" id="nav-pack">
        <span>Luau Probes</span>
        <span class="nav-count">120</span>
      </button>
      <button type="button" class="nav-item" role="tab" aria-selected="false" aria-controls="view-brain" id="nav-brain">
        <span>Brain &amp; History</span>
        <span class="nav-count" id="nav-count-learned">0</span>
      </button>
    </nav>

    <div class="sidebar-footer">
      <div class="rail-status-row">
        <span id="bridge-addr-label">127.0.0.1:8765</span>
        <span id="brain-concepts-label">0 concepts</span>
      </div>
      <button type="button" class="rail-switch" id="btn-toggle-sync" role="switch" aria-checked="true">
        <span id="sync-label-text">Live Sync</span>
        <span class="pill-track" aria-hidden="true"><span class="pill-thumb"></span></span>
      </button>
      <button type="button" class="rail-switch" id="btn-theme-toggle" role="switch" aria-checked="true">
        <span id="theme-label-text">Dark Mode</span>
        <span class="pill-track" aria-hidden="true"><span class="pill-thumb"></span></span>
      </button>
      <button type="button" class="btn" id="btn-open-cmd" style="width:100%;justify-content:space-between;">
        <span>Command Menu</span>
        <span class="kbd-chip">Cmd+K</span>
      </button>
    </div>
  </aside>

  <div class="shell-main">
    <header class="topbar">
      <div class="topbar-left">
        <button type="button" class="mobile-menu-btn" id="btn-mobile-menu" aria-label="Open Navigation">Menu</button>
        <h1 class="page-title" id="active-view-title">Live Audit</h1>
      </div>
      <div class="topbar-actions">
        <button type="button" class="btn btn-ghost" id="btn-open-payload">Client Script</button>
        <button type="button" class="btn" id="btn-simulate">Run Demo</button>
        <button type="button" class="btn" id="btn-export-md">Export .md</button>
        <button type="button" class="btn btn-primary" id="btn-copy-luau">Copy Luau Script</button>
      </div>
    </header>

    <main class="canvas">
      <!-- VIEW 1: LIVE AUDIT -->
      <section class="view-panel active" id="view-live" role="tabpanel" aria-labelledby="nav-live">
        <div class="filter-strip">
          <div class="segmented-pills" role="group" aria-label="Filter by severity">
            <button type="button" class="seg-btn sev-CRITICAL" data-sev="CRITICAL" aria-pressed="true">Critical (<span id="cnt-crit">0</span>)</button>
            <button type="button" class="seg-btn sev-WARN" data-sev="WARN" aria-pressed="true">Warning (<span id="cnt-warn">0</span>)</button>
            <button type="button" class="seg-btn sev-INFO" data-sev="INFO" aria-pressed="true">Info (<span id="cnt-info">0</span>)</button>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <label for="input-live-filter" class="nav-section-label" style="padding:0;">Search</label>
            <input type="search" id="input-live-filter" class="search-input" placeholder="Filter by remote, instance, or RCD code..." />
            <button type="button" class="btn btn-ghost" id="btn-clear-session">Clear</button>
          </div>
        </div>

        <div class="surface-subbar">
          <div class="surface-tabs" role="tablist" aria-label="Surface Category">
            <button type="button" class="surface-tab" role="tab" aria-selected="true" data-surface="all" id="surf-all">All (<span id="cnt-surf-all">0</span>)</button>
            <button type="button" class="surface-tab" role="tab" aria-selected="false" data-surface="developer" id="surf-dev">Developer (<span id="cnt-surf-dev">0</span>)</button>
            <button type="button" class="surface-tab tab-exploit" role="tab" aria-selected="false" data-surface="exploit" id="surf-exploit">Exploit (<span id="cnt-surf-exp">0</span>)</button>
          </div>
          <span class="ver-pill" id="surface-hint-text">Showing all findings across Developer hygiene and client-exposed Exploit surfaces</span>
        </div>

        <div id="findings-list-root">
          <div class="calm-empty">
            <h2>Connecting to local runtime bridge...</h2>
            <p>Checking for live Roblox telemetry and log events.</p>
          </div>
        </div>
      </section>

      <!-- VIEW 2: TELEMETRY -->
      <section class="view-panel" id="view-telemetry" role="tabpanel" aria-labelledby="nav-telemetry">
        <div class="telemetry-metrics">
          <div class="clean-stat">
            <div class="clean-stat-label">Latest Client Memory</div>
            <div class="clean-stat-value" id="stat-mem">0.00 MB</div>
          </div>
          <div class="clean-stat">
            <div class="clean-stat-label">Workspace Instances</div>
            <div class="clean-stat-value" id="stat-ws">0</div>
          </div>
          <div class="clean-stat">
            <div class="clean-stat-label">Profiled Remotes</div>
            <div class="clean-stat-value" id="stat-remotes">0</div>
          </div>
        </div>

        <div class="wave-card">
          <div class="wave-header">
            <h2>10-Second Memory &amp; Instance Timeline</h2>
            <span class="ver-pill" id="wave-hover-text">Hover or tap any point to inspect snapshot</span>
          </div>
          <svg class="wave-svg" viewBox="0 0 800 170" preserveAspectRatio="none" id="telemetry-svg" aria-label="Memory timeline curve"></svg>
        </div>

        <div style="margin-bottom:10px;font-size:13px;font-weight:600;color:var(--text-muted);">Remote Traffic Profiler (calls/sec)</div>
        <div id="remotes-list-root"></div>
      </section>

      <!-- VIEW 3: STATIC SCANNER -->
      <section class="view-panel" id="view-static" role="tabpanel" aria-labelledby="nav-static">
        <div class="scanner-form-group">
          <form id="form-scan-path">
            <label for="input-scan-path" style="display:block;font-weight:600;margin-bottom:8px;">Audit Local Place (.rbxlx / .rbxmx) or Scripts Folder</label>
            <div style="display:flex;gap:10px;flex-wrap:wrap;">
              <input type="text" id="input-scan-path" class="search-input" style="flex:1;" placeholder="/Users/you/MyGame/src or ./place.rbxlx" />
              <button type="submit" class="btn btn-primary">Scan Path</button>
            </div>
          </form>
        </div>

        <div class="scanner-form-group">
          <form id="form-scan-source">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px;">
              <label for="input-luau-source" style="font-weight:600;">Audit Luau Source Directly</label>
              <button type="button" class="btn btn-ghost" id="btn-load-sample-luau">Insert Sample Script</button>
            </div>
            <textarea id="input-luau-source" class="code-textarea" placeholder="-- Paste a Luau script here to test against 12 static rules and 120 debugger probes"></textarea>
            <div style="margin-top:12px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
              <button type="submit" class="btn btn-primary">Run Static Audit</button>
              <span id="static-result-inline" style="font-size:13px;color:var(--text-muted);"></span>
            </div>
          </form>
        </div>
      </section>

      <!-- VIEW 4: 120,000 FLAW CATALOG -->
      <section class="view-panel" id="view-catalog" role="tabpanel" aria-labelledby="nav-catalog">
        <form id="form-catalog-search" class="filter-strip">
          <div style="display:flex;gap:8px;flex:1;flex-wrap:wrap;">
            <label for="input-catalog-q" class="nav-section-label" style="padding:8px 0;">Query</label>
            <input type="search" id="input-catalog-q" class="search-input" style="flex:1;" placeholder="Search 120,000 flaws (datastore, processreceipt, networkowner, remote)..." />
            <label for="select-catalog-sev" class="nav-section-label" style="padding:8px 0;">Severity</label>
            <select id="select-catalog-sev" class="select-input">
              <option value="">All</option>
              <option value="CRITICAL">Critical</option>
              <option value="WARN">Warning</option>
              <option value="INFO">Info</option>
            </select>
            <button type="submit" class="btn btn-primary">Search</button>
          </div>
          <span class="ver-pill" id="catalog-latency-label">mmap index ready</span>
        </form>
        <div class="surface-subbar">
          <div class="surface-tabs" role="tablist" aria-label="Catalog Surface Filter">
            <button type="button" class="surface-tab" role="tab" aria-selected="true" data-catsurf="all">All</button>
            <button type="button" class="surface-tab" role="tab" aria-selected="false" data-catsurf="developer">Developer</button>
            <button type="button" class="surface-tab tab-exploit" role="tab" aria-selected="false" data-catsurf="exploit">Exploit</button>
          </div>
          <span class="ver-pill">Filter 120,000 signatures by Developer quality vs Client-Abusable Exploit surfaces</span>
        </div>
        <div id="catalog-list-root"></div>
      </section>

      <!-- VIEW 5: 120 LUAU PROBES -->
      <section class="view-panel" id="view-pack" role="tabpanel" aria-labelledby="nav-pack">
        <form id="form-pack-search" class="filter-strip">
          <div style="display:flex;gap:8px;flex:1;flex-wrap:wrap;">
            <label for="input-pack-q" class="nav-section-label" style="padding:8px 0;">Filter</label>
            <input type="search" id="input-pack-q" class="search-input" style="flex:1;" placeholder="Search 120 probes (selene, luau-lsp, trove, janitor, heartbeat, wait)..." />
            <button type="submit" class="btn btn-primary">Filter</button>
          </div>
          <span class="ver-pill" id="pack-count-label">120 probes</span>
        </form>
        <div id="pack-list-root"></div>
      </section>

      <!-- VIEW 6: BRAIN & HISTORY -->
      <section class="view-panel" id="view-brain" role="tabpanel" aria-labelledby="nav-brain">
        <div style="margin-bottom:10px;font-size:13px;font-weight:600;color:var(--text-muted);">Top Learned Game Tokens (~/.rcdebug/learned_flaws.json)</div>
        <div id="brain-tokens-root" style="margin-bottom:32px;"></div>
        <div style="margin-bottom:10px;font-size:13px;font-weight:600;color:var(--text-muted);">Recent Command History (~/.rcdebug/command_history.json)</div>
        <div id="brain-history-root"></div>
      </section>
    </main>
  </div>

  <!-- Slide-Over Detail & Luau Inspector Sheet -->
  <div class="sheet-backdrop" id="sheet-backdrop"></div>
  <aside class="detail-sheet" id="detail-sheet" aria-label="Finding Details" aria-hidden="true">
    <div class="sheet-head">
      <div style="min-width:0;">
        <div class="ver-pill" id="sheet-kicker">Inspector</div>
        <h2 style="margin:2px 0 0;font-size:16px;font-weight:600;" id="sheet-title">Details</h2>
      </div>
      <button type="button" class="btn btn-ghost" id="btn-close-sheet" aria-label="Close inspector">Close</button>
    </div>
    <div class="sheet-tabs" role="tablist">
      <button type="button" class="seg-btn" role="tab" aria-selected="true" data-stab="overview" id="stab-overview">Overview</button>
      <button type="button" class="seg-btn" role="tab" aria-selected="false" data-stab="abuse" id="stab-abuse">Abused Script &amp; Surface</button>
      <button type="button" class="seg-btn" role="tab" aria-selected="false" data-stab="fix" id="stab-fix">Server Fix</button>
      <button type="button" class="seg-btn" role="tab" aria-selected="false" data-stab="payload" id="stab-payload">Client Script</button>
    </div>
    <div class="sheet-body" id="sheet-body"></div>
  </aside>

  <!-- Command Palette Modal (Cmd+K) -->
  <div class="cmd-backdrop" id="cmd-modal" role="dialog" aria-modal="true" aria-labelledby="cmd-title">
    <div class="cmd-box">
      <div class="cmd-top">
        <label for="cmd-input" id="cmd-title" class="ver-pill">Cmd+K</label>
        <input type="search" id="cmd-input" class="cmd-input" placeholder="Jump to view or run action..." />
        <button type="button" class="btn btn-ghost" id="btn-close-cmd" style="min-height:30px;padding:4px 8px;">Esc</button>
      </div>
      <div class="cmd-items" id="cmd-items"></div>
    </div>
  </div>

  <div class="toast-pill" id="toast-pill" role="status" aria-live="polite">
    <span id="toast-text"></span>
  </div>

  <script>
    (function() {
      const state = {
        theme: "dark",
        syncEnabled: true,
        sevFilter: { CRITICAL: true, WARN: true, INFO: true },
        surfaceTab: "all",
        catalogSurfaceTab: "all",
        textFilter: "",
        session: null,
        luauScript: "",
        bridgeError: null,
        activeFinding: null,
        sheetTab: "overview"
      };

      const viewTitles = {
        "view-live": "Live Audit",
        "view-telemetry": "Telemetry",
        "view-static": "Static Scanner",
        "view-catalog": "Flaw Catalog",
        "view-pack": "Luau Probes",
        "view-brain": "Brain & History"
      };

      function esc(v) {
        return String(v == null ? "" : v)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      }

      function toast(msg) {
        const el = document.getElementById("toast-pill");
        document.getElementById("toast-text").textContent = msg;
        el.classList.add("visible");
        clearTimeout(el._t);
        el._t = setTimeout(function() { el.classList.remove("visible"); }, 3600);
      }

      // Navigation
      const navItems = Array.from(document.querySelectorAll(".nav-item"));
      const viewPanels = Array.from(document.querySelectorAll(".view-panel"));
      const sidebar = document.getElementById("sidebar-rail");
      const mobileBackdrop = document.getElementById("mobile-nav-backdrop");

      function closeMobileNav() {
        sidebar.classList.remove("mobile-open");
        mobileBackdrop.classList.remove("open");
      }

      document.getElementById("btn-mobile-menu").addEventListener("click", function() {
        sidebar.classList.add("mobile-open");
        mobileBackdrop.classList.add("open");
      });
      mobileBackdrop.addEventListener("click", closeMobileNav);

      function switchView(navBtn) {
        navItems.forEach(function(n) { n.setAttribute("aria-selected", "false"); });
        viewPanels.forEach(function(p) { p.classList.remove("active"); });
        navBtn.setAttribute("aria-selected", "true");
        const targetId = navBtn.getAttribute("aria-controls");
        document.getElementById("active-view-title").textContent = viewTitles[targetId] || "rcdebug";
        const panel = document.getElementById(targetId);
        if (panel) panel.classList.add("active");
        closeMobileNav();

        if (targetId === "view-catalog" && !panel._loaded) {
          panel._loaded = true;
          loadCatalog("", "");
        } else if (targetId === "view-pack" && !panel._loaded) {
          panel._loaded = true;
          loadPack("");
        } else if (targetId === "view-brain") {
          loadBrainHistory();
        }
      }

      navItems.forEach(function(btn) {
        btn.addEventListener("click", function() { switchView(btn); });
      });

      // Switches
      const themeBtn = document.getElementById("btn-theme-toggle");
      themeBtn.addEventListener("click", function() {
        state.theme = state.theme === "dark" ? "light" : "dark";
        const isDark = state.theme === "dark";
        document.documentElement.setAttribute("data-theme", state.theme);
        themeBtn.setAttribute("aria-checked", isDark ? "true" : "false");
        document.getElementById("theme-label-text").textContent = isDark ? "Dark Mode" : "Light Mode";
      });

      const syncBtn = document.getElementById("btn-toggle-sync");
      syncBtn.addEventListener("click", function() {
        state.syncEnabled = !state.syncEnabled;
        syncBtn.setAttribute("aria-checked", state.syncEnabled ? "true" : "false");
        document.getElementById("sync-label-text").textContent = state.syncEnabled ? "Live Sync" : "Sync Paused";
        if (state.syncEnabled) pollState();
      });

      // Slide-over Inspector Sheet
      const sheet = document.getElementById("detail-sheet");
      const sheetBackdrop = document.getElementById("sheet-backdrop");
      const sheetTabs = Array.from(document.querySelectorAll(".sheet-tabs .seg-btn"));

      function openSheet(finding, tabName) {
        state.activeFinding = finding;
        state.sheetTab = tabName || (finding ? "overview" : "payload");
        sheetTabs.forEach(function(t) {
          const active = t.getAttribute("data-stab") === state.sheetTab;
          t.setAttribute("aria-selected", active ? "true" : "false");
          t.style.background = active ? "var(--surface-active)" : "transparent";
          t.style.color = active ? "var(--text)" : "var(--text-muted)";
        });
        renderSheetBody();
        sheet.classList.add("open");
        sheet.setAttribute("aria-hidden", "false");
        sheetBackdrop.classList.add("open");
      }

      function closeSheet() {
        sheet.classList.remove("open");
        sheet.setAttribute("aria-hidden", "true");
        sheetBackdrop.classList.remove("open");
      }

      document.getElementById("btn-close-sheet").addEventListener("click", closeSheet);
      sheetBackdrop.addEventListener("click", closeSheet);
      document.getElementById("btn-open-payload").addEventListener("click", function() {
        openSheet(state.activeFinding, "payload");
      });

      sheetTabs.forEach(function(t) {
        t.addEventListener("click", function() {
          openSheet(state.activeFinding, t.getAttribute("data-stab"));
        });
      });

      function renderOverviewCards(overviews) {
        if (!overviews || !overviews.length) return "";
        let html = '<div class="overview-stack">';
        overviews.forEach(function(ov, idx) {
          const isVec = ov.id === "vectors";
          const badgeClass = isVec ? "overview-card-badge badge-crit" : "overview-card-badge";
          const badgeText = ov.tag || ("0" + (idx + 1));
          let bulletsHtml = "";
          if (ov.points && ov.points.length) {
            bulletsHtml = '<ul class="overview-bullets">' + ov.points.map(function(pt) {
              return '<li>' + esc(pt) + '</li>';
            }).join("") + '</ul>';
          }
          html +=
            '<div class="overview-card">' +
              '<div class="overview-card-head">' +
                '<div class="overview-card-title">' + esc(ov.title) + '</div>' +
                '<span class="' + badgeClass + '">' + esc(badgeText) + '</span>' +
              '</div>' +
              '<p class="detail-text">' + esc(ov.summary) + '</p>' +
              bulletsHtml +
            '</div>';
        });
        html += '</div>';
        return html;
      }

      function renderRiskStrip(f) {
        const rp = f.risk_profile || {};
        const domain = f.domain_label || f.category || "Runtime Surface";
        const expl = rp.exploitability || (f.surface === "exploit" ? "High (Client Reachable)" : "Low (Internal Hygiene)");
        const blast = rp.blast_radius || "Gameplay Integrity";
        const surfType = rp.surface_type || f.category || "Instance";
        return (
          '<div class="risk-strip">' +
            '<div class="risk-chip"><span class="risk-chip-label">Detected Domain</span><span class="risk-chip-val">' + esc(domain) + '</span></div>' +
            '<div class="risk-chip"><span class="risk-chip-label">Exploitability</span><span class="risk-chip-val">' + esc(expl) + '</span></div>' +
            '<div class="risk-chip"><span class="risk-chip-label">Blast Radius</span><span class="risk-chip-val">' + esc(blast) + '</span></div>' +
            '<div class="risk-chip"><span class="risk-chip-label">Surface Type</span><span class="risk-chip-val">' + esc(surfType) + '</span></div>' +
          '</div>'
        );
      }

      function renderSearchPills(queries) {
        if (!queries || !queries.length) return "";
        return (
          '<div class="detail-block">' +
            '<div class="detail-label">Roblox Studio Ctrl+Shift+F Search Queries (click to copy)</div>' +
            '<div class="search-pills">' +
              queries.map(function(q) {
                return '<button type="button" class="search-pill" data-copy-q="' + esc(q) + '">' + esc(q) + '</button>';
              }).join("") +
            '</div>' +
          '</div>'
        );
      }

      function renderContractMatrix(spec) {
        if (!spec || !Array.isArray(spec.parameter_contract_matrix) || !spec.parameter_contract_matrix.length) return "";
        const tr = spec.trace_locator || {};
        const rowsHtml = spec.parameter_contract_matrix.map(function(row) {
          return (
            '<tr>' +
              '<td><code>' + esc(row.parameter) + '</code></td>' +
              '<td><code>' + esc(row.expected_typeof) + '</code></td>' +
              '<td>' + esc(row.valid_bounds) + '</td>' +
              '<td>' + esc(row.rejected_edge_cases) + '</td>' +
            '</tr>'
          );
        }).join("");
        return (
          '<div class="detail-block">' +
            '<div class="detail-label">1. Vulnerability Trace &amp; Locator</div>' +
            '<p class="row-sub" style="white-space:normal;color:var(--text);">' +
              esc((tr.script_path || "") + " · " + (tr.line_label || "") + " · Remote: " + (tr.remote_name || "") + " (" + (tr.handler_kind || "OnServerEvent") + ")") +
            '</p>' +
          '</div>' +
          '<div class="detail-block">' +
            '<div class="detail-label">3. Parameter Contract &amp; Edge-Case Matrix</div>' +
            '<div class="contract-table-wrap">' +
              '<table class="contract-table">' +
                '<thead><tr><th>Parameter</th><th>Expected typeof()</th><th>Valid Bounds</th><th>Rejected Edge Cases</th></tr></thead>' +
                '<tbody>' + rowsHtml + '</tbody>' +
              '</table>' +
            '</div>' +
          '</div>'
        );
      }

      function wireSearchPills(container) {
        container.querySelectorAll(".search-pill").forEach(function(btn) {
          btn.addEventListener("click", function() {
            const q = btn.getAttribute("data-copy-q") || "";
            if (navigator.clipboard && q) navigator.clipboard.writeText(q).catch(function() {});
            toast("Copied Studio search query: " + q);
          });
        });
      }

      function renderSheetBody() {
        const body = document.getElementById("sheet-body");
        const f = state.activeFinding;
        if (state.sheetTab === "payload" || !f) {
          document.getElementById("sheet-kicker").textContent = "Offline Roblox Studio QA Test Runner";
          document.getElementById("sheet-title").textContent = "Studio QA Test Script (Offline)";
          body.innerHTML =
            '<div class="detail-block">' +
              '<p class="detail-text" style="color:var(--text-muted);margin-bottom:12px;">Offline Studio QA Test Runner: paste into Roblox Studio Command Bar or StarterPlayerScripts during Play Solo / Local Server. Runs 100% locally with zero external HTTP calls and prints [PASS] or [FAIL] directly to the Studio Output window.</p>' +
              '<button type="button" class="btn btn-primary" id="btn-sheet-copy-payload">Copy Studio QA Script</button>' +
              '<pre class="code-box">' + esc(state.luauScript || "Loading script...") + '</pre>' +
            '</div>';
          document.getElementById("btn-sheet-copy-payload").addEventListener("click", function() {
            document.getElementById("btn-copy-luau").click();
          });
          return;
        }

        const rankLabel = f.rank && f.rank < 999999 ? ("Rank #" + f.rank) : f.category;
        const surfLabel = (f.surface === "exploit") ? "EXPLOIT SURFACE" : "DEVELOPER";
        const domainBadge = f.domain_label ? (" · " + f.domain_label) : "";
        document.getElementById("sheet-kicker").textContent = f.severity + " · " + surfLabel + domainBadge + " · " + rankLabel;
        document.getElementById("sheet-title").textContent = f.title;

        const overviews = Array.isArray(f.overviews) ? f.overviews : [];
        const vectorCard = overviews.find(function(o) { return o.id === "vectors"; });
        const impactCard = overviews.find(function(o) { return o.id === "impact"; });
        const checklistCard = overviews.find(function(o) { return o.id === "checklist"; });

        if (state.sheetTab === "abuse") {
          const targetObj = f.responsible_script || f.path || "Unknown";
          const vulnPreview = f.vulnerable_pattern || (
            "-- Responsible script / instance surface:\n" +
            "--   " + targetObj + "\n" +
            "-- Risk Summary:\n" +
            "--   " + (f.abuse || f.flaw)
          );
          const focusedCards = [vectorCard, impactCard].filter(Boolean);
          body.innerHTML =
            renderRiskStrip(f) +
            '<div class="detail-block"><div class="detail-label">Responsible Script / Instance to Fix</div><p class="row-sub" style="white-space:normal;color:var(--text);">' + esc(targetObj) + '</p></div>' +
            renderSearchPills(f.studio_search_queries) +
            (focusedCards.length ? renderOverviewCards(focusedCards) : ('<div class="detail-block"><div class="detail-label">Abuse Vector</div><p class="detail-text">' + esc(f.abuse || f.flaw) + '</p></div>')) +
            '<div class="detail-block">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                '<div class="detail-label" style="margin:0;">Vulnerable Server / Game Pattern to Locate &amp; Patch</div>' +
                '<button type="button" class="btn" id="btn-jump-server-fix">Open Server Fix</button>' +
              '</div>' +
              '<pre class="code-box">' + esc(vulnPreview) + '</pre>' +
            '</div>';
          wireSearchPills(body);
          document.getElementById("btn-jump-server-fix").addEventListener("click", function() {
            openSheet(f, "fix");
          });
          return;
        }

        if (state.sheetTab === "fix") {
          const spec = f.contract_spec || (f.metadata && f.metadata.contract_spec) || null;
          const code = (spec && spec.patched_guard_and_unit_test_code) || f.fix_code || f.code_example || ("-- Recommended server-side fix for " + f.path + "\n-- " + f.fix);
          const vulnSnippet = (spec && spec.vulnerable_handler_code) ? (
            '<div class="detail-block">' +
              '<div class="detail-label">2. Vulnerable Server Handler (Current Code)</div>' +
              '<pre class="code-box">' + esc(spec.vulnerable_handler_code) + '</pre>' +
            '</div>'
          ) : "";
          body.innerHTML =
            '<div class="detail-block"><div class="detail-label">Responsible Script / Target</div><p class="row-sub" style="white-space:normal;color:var(--text);">' + esc(f.responsible_script || f.path) + '</p></div>' +
            renderSearchPills(f.studio_search_queries) +
            renderContractMatrix(spec) +
            vulnSnippet +
            (checklistCard ? renderOverviewCards([checklistCard]) : ('<div class="detail-block"><div class="detail-label">Recommended Fix</div><p class="detail-text">' + esc(f.fix) + '</p></div>')) +
            '<div class="detail-block">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                '<div class="detail-label" style="margin:0;">4. Defensive Guard Module &amp; Studio assert() Unit Test</div>' +
                '<button type="button" class="btn btn-primary" id="btn-copy-fix-snippet">Copy Guard + Unit Test</button>' +
              '</div>' +
              '<pre class="code-box">' + esc(code) + '</pre>' +
            '</div>';
          wireSearchPills(body);
          document.getElementById("btn-copy-fix-snippet").addEventListener("click", function() {
            if (navigator.clipboard) navigator.clipboard.writeText(code).catch(function() {});
            toast("Copied Guard Module & Studio assert() tests for " + (f.path || "finding"));
          });
          return;
        }

        body.innerHTML =
          renderRiskStrip(f) +
          '<div class="detail-block"><div class="detail-label">Instance / Script Path</div><p class="row-sub" style="white-space:normal;color:var(--text);">' + esc(f.path) + '</p></div>' +
          '<div class="detail-block"><div class="detail-label">Responsible Script</div><p class="row-sub" style="white-space:normal;">' + esc(f.responsible_script || f.path) + '</p></div>' +
          renderSearchPills(f.studio_search_queries) +
          (overviews.length
            ? renderOverviewCards(overviews)
            : (
                '<div class="detail-block"><div class="detail-label">Architectural Flaw</div><p class="detail-text">' + esc(f.flaw) + '</p></div>' +
                '<div class="detail-block"><div class="detail-label">Client Abuse Vector</div><p class="detail-text">' + esc(f.abuse) + '</p></div>' +
                '<div class="detail-block"><div class="detail-label">Remediation</div><p class="detail-text">' + esc(f.fix) + '</p></div>'
              ));
        wireSearchPills(body);
      }

      // Severity & Surface filters
      document.querySelectorAll("#view-live .seg-btn").forEach(function(btn) {
        btn.addEventListener("click", function() {
          const sev = btn.getAttribute("data-sev");
          state.sevFilter[sev] = !state.sevFilter[sev];
          btn.setAttribute("aria-pressed", state.sevFilter[sev] ? "true" : "false");
          renderLive();
        });
      });

      document.querySelectorAll("#view-live .surface-tab").forEach(function(btn) {
        btn.addEventListener("click", function() {
          document.querySelectorAll("#view-live .surface-tab").forEach(function(b) {
            b.setAttribute("aria-selected", "false");
          });
          btn.setAttribute("aria-selected", "true");
          state.surfaceTab = btn.getAttribute("data-surface");
          const hintEl = document.getElementById("surface-hint-text");
          if (state.surfaceTab === "exploit") {
            hintEl.textContent = "Exploit tab: client-exposed remotes, physics, and state surfaces that executor scripts can abuse";
          } else if (state.surfaceTab === "developer") {
            hintEl.textContent = "Developer tab: memory leaks, deprecated APIs, lint hygiene, and internal script health";
          } else {
            hintEl.textContent = "Showing all findings across Developer hygiene and client-exposed Exploit surfaces";
          }
          renderLive();
        });
      });

      document.querySelectorAll("#view-catalog .surface-tab").forEach(function(btn) {
        btn.addEventListener("click", function() {
          document.querySelectorAll("#view-catalog .surface-tab").forEach(function(b) {
            b.setAttribute("aria-selected", "false");
          });
          btn.setAttribute("aria-selected", "true");
          state.catalogSurfaceTab = btn.getAttribute("data-catsurf");
          loadCatalog(
            document.getElementById("input-catalog-q").value.trim(),
            document.getElementById("select-catalog-sev").value
          );
        });
      });

      document.getElementById("input-live-filter").addEventListener("input", function(e) {
        state.textFilter = e.target.value.trim().toLowerCase();
        renderLive();
      });

      function buildSpline(pts) {
        if (pts.length === 0) return "";
        if (pts.length === 1) return "M " + pts[0].x.toFixed(1) + " " + pts[0].y.toFixed(1);
        let d = "M " + pts[0].x.toFixed(1) + " " + pts[0].y.toFixed(1);
        for (let i = 0; i < pts.length - 1; i++) {
          const p0 = pts[i], p1 = pts[i + 1];
          const mx = ((p0.x + p1.x) / 2).toFixed(1);
          d += " C " + mx + " " + p0.y.toFixed(1) + ", " + mx + " " + p1.y.toFixed(1) + ", " + p1.x.toFixed(1) + " " + p1.y.toFixed(1);
        }
        return d;
      }

      function renderTelemetry(snaps, remotes) {
        document.getElementById("stat-remotes").textContent = remotes.length;
        const svg = document.getElementById("telemetry-svg");
        const hoverEl = document.getElementById("wave-hover-text");

        if (!snaps || snaps.length === 0) {
          document.getElementById("stat-mem").textContent = "0.00 MB";
          document.getElementById("stat-ws").textContent = "0";
          svg.innerHTML =
            '<line x1="0" y1="85" x2="800" y2="85" stroke="var(--divider)" stroke-dasharray="4 4"/>' +
            '<text x="400" y="78" text-anchor="middle" fill="var(--text-muted)" font-family="var(--font-sans)" font-size="13">' +
              'No 10-second memory snapshots yet. Paste the Luau script or click Run Demo.' +
            '</text>';
        } else {
          const latest = snaps[snaps.length - 1];
          document.getElementById("stat-mem").textContent = latest.total_memory_mb.toFixed(2) + " MB";
          document.getElementById("stat-ws").textContent = latest.workspace_instances.toLocaleString();

          const mems = snaps.map(function(s) { return s.total_memory_mb; });
          const minM = Math.min.apply(null, mems);
          const maxM = Math.max.apply(null, mems);
          const span = Math.max(1, maxM - minM);

          const pts = snaps.map(function(s, i) {
            const x = snaps.length === 1 ? 400 : (36 + (i / (snaps.length - 1)) * 728);
            const y = 136 - ((s.total_memory_mb - minM) / span) * 100;
            return { x: x, y: y, s: s };
          });

          const linePath = buildSpline(pts);
          const areaPath = linePath + " L " + pts[pts.length - 1].x.toFixed(1) + " 160 L " + pts[0].x.toFixed(1) + " 160 Z";
          let nodes = "";
          pts.forEach(function(p) {
            nodes +=
              '<circle class="wave-node" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="5" fill="var(--accent)" stroke="var(--surface)" stroke-width="2" ' +
              'tabindex="0" role="button" aria-label="Snapshot ' + esc(p.s.timestamp) + '" ' +
              'data-tip="' + esc(p.s.timestamp) + ' · Workspace: ' + p.s.workspace_instances + ' · Players: ' + p.s.player_instances + ' · Memory: ' + p.s.total_memory_mb.toFixed(2) + ' MB" style="cursor:pointer;"/>';
          });
          svg.innerHTML =
            '<path d="' + areaPath + '" fill="var(--accent)" fill-opacity="0.10"/>' +
            '<path class="spline-line" d="' + linePath + '" fill="none" stroke="var(--accent)" stroke-width="2.5"/>' +
            nodes;

          svg.querySelectorAll("circle").forEach(function(c) {
            function show() { hoverEl.textContent = c.getAttribute("data-tip"); }
            c.addEventListener("mouseenter", show);
            c.addEventListener("focus", show);
            c.addEventListener("click", show);
          });
        }

        const remRoot = document.getElementById("remotes-list-root");
        if (!remotes || remotes.length === 0) {
          remRoot.innerHTML = '<div style="padding:20px 0;color:var(--text-muted);font-size:13px;">No RemoteEvent traffic recorded yet.</div>';
        } else {
          let html = '<div class="clean-list">';
          remotes.forEach(function(r) {
            const pct = Math.min(100, Math.round((r.peak_rate_per_sec / 40.0) * 100));
            const sev = r.has_cooldown_warning ? "CRITICAL" : "INFO";
            const label = r.has_cooldown_warning ? "Unthrottled" : "Normal";
            html +=
              '<div class="list-row">' +
                '<div class="sev-indicator sev-text-' + sev + '"><span class="sev-dot sev-dot-' + sev + '"></span>' + label + '</div>' +
                '<div class="row-main"><div class="row-title">' + esc(r.remote_path) + '</div><p class="row-sub">' + esc(r.remote_type) + ' · ' + esc(r.total_calls) + ' total calls</p></div>' +
                '<div class="row-meta">' + esc(r.peak_rate_per_sec.toFixed(1)) + '/s<span class="rate-bar-bg"><span class="rate-bar-fill" style="width:' + pct + '%"></span></span></div>' +
              '</div>';
          });
          html += '</div>';
          remRoot.innerHTML = html;
        }
      }

      function renderLive() {
        const root = document.getElementById("findings-list-root");
        if (state.bridgeError) {
          root.innerHTML =
            '<div class="calm-empty">' +
              '<h2>Local bridge disconnected</h2>' +
              '<p>' + esc(state.bridgeError) + '. Make sure rcdebug --ui is running in your terminal.</p>' +
            '</div>';
          return;
        }
        if (!state.session) return;

        const counts = state.session.severity_counts || { CRITICAL: 0, WARN: 0, INFO: 0 };
        document.getElementById("cnt-crit").textContent = counts.CRITICAL || 0;
        document.getElementById("cnt-warn").textContent = counts.WARN || 0;
        document.getElementById("cnt-info").textContent = counts.INFO || 0;

        const allFindings = state.session.findings || [];
        document.getElementById("nav-count-findings").textContent = allFindings.length;
        document.getElementById("nav-count-snaps").textContent = (state.session.memory_snapshots || []).length;

        renderTelemetry(state.session.memory_snapshots || [], state.session.remote_traffic || []);

        const sevMatched = allFindings.filter(function(f) {
          if (!state.sevFilter[f.severity]) return false;
          if (!state.textFilter) return true;
          const hay = (f.title + " " + f.path + " " + f.category + " " + f.flaw + " " + (f.responsible_script || "")).toLowerCase();
          return hay.indexOf(state.textFilter) !== -1;
        });

        const devCount = sevMatched.filter(function(f) { return f.surface !== "exploit"; }).length;
        const expCount = sevMatched.filter(function(f) { return f.surface === "exploit"; }).length;
        document.getElementById("cnt-surf-all").textContent = sevMatched.length;
        document.getElementById("cnt-surf-dev").textContent = devCount;
        document.getElementById("cnt-surf-exp").textContent = expCount;

        const filtered = sevMatched.filter(function(f) {
          if (state.surfaceTab === "exploit") return f.surface === "exploit";
          if (state.surfaceTab === "developer") return f.surface !== "exploit";
          return true;
        });

        if (filtered.length === 0) {
          root._lastSig = "";
          if (allFindings.length === 0) {
            root.innerHTML =
              '<div class="calm-empty">' +
                '<h2>Ready to audit</h2>' +
                '<p>Copy the client-sided Luau script and paste it into Roblox, run a live demo simulation, or open the Static Scanner for local place files.</p>' +
                '<div class="calm-actions">' +
                  '<button type="button" class="btn btn-primary" id="btn-empty-copy">Copy Luau Script</button>' +
                  '<button type="button" class="btn" id="btn-empty-demo">Run Demo Simulation</button>' +
                  '<button type="button" class="btn" id="btn-empty-static">Open Static Scanner</button>' +
                '</div>' +
              '</div>';
            document.getElementById("btn-empty-copy").addEventListener("click", function() { document.getElementById("btn-copy-luau").click(); });
            document.getElementById("btn-empty-demo").addEventListener("click", function() { document.getElementById("btn-simulate").click(); });
            document.getElementById("btn-empty-static").addEventListener("click", function() { switchView(document.getElementById("nav-static")); });
          } else {
            root.innerHTML =
              '<div class="calm-empty">' +
                '<h2>No matching findings</h2>' +
                '<p>' + allFindings.length + ' finding(s) hidden by your current severity or search filter.</p>' +
              '</div>';
          }
          return;
        }

        const listSig = filtered.map(function(f) {
          return f.severity + "|" + f.title + "|" + f.path + "|" + f.timestamp;
        }).join("\n");
        if (root._lastSig === listSig) {
          return;
        }
        root._lastSig = listSig;

        let html = '<div class="clean-list">';
        filtered.forEach(function(f, idx) {
          const delay = Math.min(idx * 20, 220);
          const rankTxt = f.rank && f.rank < 999999 ? ("#" + f.rank + " · ") : "";
          const isExp = f.surface === "exploit";
          const surfTag = isExp
            ? '<span class="surface-tag surface-tag-exploit">EXPLOIT</span>'
            : '<span class="surface-tag surface-tag-developer">DEVELOPER</span>';
          const scriptLoc = f.responsible_script && f.responsible_script !== f.path
            ? (f.path + "  ->  Script: " + f.responsible_script)
            : f.path;
          html +=
            '<div class="list-row clickable" data-fidx="' + idx + '" tabindex="0" role="button" style="animation-delay:' + delay + 'ms">' +
              '<div class="sev-indicator sev-text-' + esc(f.severity) + '"><span class="sev-dot sev-dot-' + esc(f.severity) + '"></span>' + esc(f.severity) + '</div>' +
              '<div class="row-main">' +
                '<div class="row-title">' + esc(f.title) + surfTag + '</div>' +
                '<p class="row-sub">' + esc(scriptLoc) + '</p>' +
              '</div>' +
              '<div class="row-meta">' + esc(rankTxt + f.timestamp) + '</div>' +
            '</div>';
        });
        html += '</div>';
        root.innerHTML = html;

        root.querySelectorAll(".list-row.clickable").forEach(function(row) {
          function select() {
            const idx = parseInt(row.getAttribute("data-fidx"), 10);
            const chosen = filtered[idx];
            openSheet(chosen, state.surfaceTab === "exploit" ? "abuse" : "overview");
          }
          row.addEventListener("click", select);
          row.addEventListener("keydown", function(e) {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              select();
            }
          });
        });
      }

      function pollState() {
        if (!state.syncEnabled) return;
        fetch("/api/state")
          .then(function(r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(function(data) {
            state.bridgeError = null;
            state.session = data.session;
            if (!state.luauScript && data.luau_script) state.luauScript = data.luau_script;
            document.getElementById("bridge-addr-label").textContent = data.host + ":" + data.port;
            document.getElementById("nav-count-learned").textContent = data.learned_count;
            document.getElementById("brain-concepts-label").textContent = data.brain_concepts.toLocaleString() + " concepts";
            renderLive();
          })
          .catch(function(err) {
            state.bridgeError = err.message || "Bridge unreachable";
            renderLive();
          });
      }

      // Primary Actions
      document.getElementById("btn-copy-luau").addEventListener("click", function() {
        fetch("/api/copy-luau", { method: "POST" })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            if (navigator.clipboard && state.luauScript) navigator.clipboard.writeText(state.luauScript).catch(function() {});
            toast(res.message || "Copied Luau script to clipboard");
          })
          .catch(function(e) { toast("Copy failed: " + e.message); });
      });

      document.getElementById("btn-simulate").addEventListener("click", function() {
        toast("Streaming sample playtest telemetry...");
        fetch("/api/simulate", { method: "POST" })
          .then(function() {
            setTimeout(pollState, 350);
            setTimeout(pollState, 1100);
          });
      });

      document.getElementById("btn-export-md").addEventListener("click", function() {
        window.location.href = "/api/export.md";
      });

      document.getElementById("btn-clear-session").addEventListener("click", function() {
        fetch("/api/clear", { method: "POST" }).then(function() {
          state.activeFinding = null;
          closeSheet();
          pollState();
          toast("Session cleared");
        });
      });

      // Static Scanner
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
        toast("Inserted sample server script");
      });

      document.getElementById("form-scan-path").addEventListener("submit", function(e) {
        e.preventDefault();
        const p = document.getElementById("input-scan-path").value.trim();
        if (!p) { toast("Enter a file or folder path first"); return; }
        fetch("/api/scan-path", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: p })
        })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            if (res.error) { toast(res.error); return; }
            toast("Added " + res.added + " finding(s) from " + res.path);
            pollState();
            switchView(document.getElementById("nav-live"));
          });
      });

      document.getElementById("form-scan-source").addEventListener("submit", function(e) {
        e.preventDefault();
        const src = document.getElementById("input-luau-source").value;
        if (!src.trim()) { toast("Paste a Luau script first"); return; }
        fetch("/api/scan-source", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source: src, script_name: "StaticSnippet.luau" })
        })
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("static-result-inline").textContent =
              "Matched " + res.matched + " flaw(s), added " + res.added + " to Live Audit.";
            pollState();
            if (res.added > 0) switchView(document.getElementById("nav-live"));
          });
      });

      // Catalog
      function loadCatalog(q, sev) {
        const root = document.getElementById("catalog-list-root");
        root.innerHTML = '<div style="padding:20px 0;color:var(--text-muted);">Searching 600,000 flaws...</div>';
        const surfParam = state.catalogSurfaceTab && state.catalogSurfaceTab !== "all" ? ("&surface=" + encodeURIComponent(state.catalogSurfaceTab)) : "";
        fetch("/api/catalog?q=" + encodeURIComponent(q) + "&severity=" + encodeURIComponent(sev) + surfParam + "&limit=40")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("catalog-latency-label").textContent = res.elapsed_ms.toFixed(2) + " ms · " + res.results.length + " results";
            if (!res.results.length) {
              root.innerHTML = '<div class="calm-empty"><h2>No catalog matches</h2><p>Try searching by Roblox service, instance class, or RCD code.</p></div>';
              return;
            }
            let html = '<div class="clean-list">';
            res.results.forEach(function(item, idx) {
              const surfTag = item.surface === "exploit"
                ? '<span class="surface-tag surface-tag-exploit">EXPLOIT</span>'
                : '<span class="surface-tag surface-tag-developer">DEVELOPER</span>';
              html +=
                '<div class="list-row clickable" data-cidx="' + idx + '" tabindex="0" role="button">' +
                  '<div class="sev-indicator sev-text-' + esc(item.severity) + '"><span class="sev-dot sev-dot-' + esc(item.severity) + '"></span>' + esc(item.code) + '</div>' +
                  '<div class="row-main"><div class="row-title">' + esc(item.title) + surfTag + '</div><p class="row-sub">' + esc(item.flaw) + '</p></div>' +
                  '<div class="row-meta">#' + esc(item.rank) + ' · ' + esc(item.domain) + '</div>' +
                '</div>';
            });
            html += '</div>';
            root.innerHTML = html;
            root.querySelectorAll(".list-row.clickable").forEach(function(row) {
              function pick() {
                const it = res.results[parseInt(row.getAttribute("data-cidx"), 10)];
                openSheet({
                  severity: it.severity,
                  category: it.category,
                  surface: it.surface,
                  domain_label: it.domain_label,
                  risk_profile: it.risk_profile,
                  overviews: it.overviews,
                  studio_search_queries: it.studio_search_queries,
                  responsible_script: it.responsible_script,
                  vulnerable_pattern: it.vulnerable_pattern,
                  fix_code: it.fix_code,
                  title: "[" + it.code + "] " + it.title,
                  path: it.domain + " (" + it.code + ")",
                  flaw: it.flaw,
                  abuse: it.abuse,
                  fix: it.fix,
                  rank: it.rank,
                  code_example: ""
                }, it.surface === "exploit" ? "abuse" : "overview");
              }
              row.addEventListener("click", pick);
              row.addEventListener("keydown", function(e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
            });
          });
      }

      document.getElementById("form-catalog-search").addEventListener("submit", function(e) {
        e.preventDefault();
        loadCatalog(document.getElementById("input-catalog-q").value.trim(), document.getElementById("select-catalog-sev").value);
      });

      // Luau Pack
      function loadPack(q) {
        const root = document.getElementById("pack-list-root");
        fetch("/api/pack?q=" + encodeURIComponent(q) + "&limit=120")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            document.getElementById("pack-count-label").textContent = res.results.length + " probes";
            if (!res.results.length) {
              root.innerHTML = '<div class="calm-empty"><h2>No probes matched</h2></div>';
              return;
            }
            let html = '<div class="clean-list">';
            res.results.forEach(function(p, idx) {
              html +=
                '<div class="list-row clickable" data-pidx="' + idx + '" tabindex="0" role="button">' +
                  '<div class="sev-indicator sev-text-' + esc(p.severity) + '"><span class="sev-dot sev-dot-' + esc(p.severity) + '"></span>' + esc(p.id) + '</div>' +
                  '<div class="row-main"><div class="row-title">' + esc(p.name) + '</div><p class="row-sub">' + esc(p.root_cause) + '</p></div>' +
                  '<div class="row-meta">' + esc(p.source) + '</div>' +
                '</div>';
            });
            html += '</div>';
            root.innerHTML = html;
            root.querySelectorAll(".list-row.clickable").forEach(function(row) {
              function pick() {
                const p = res.results[parseInt(row.getAttribute("data-pidx"), 10)];
                openSheet({
                  severity: p.severity,
                  category: p.category,
                  title: "[" + p.id + "] " + p.name,
                  path: p.source,
                  flaw: p.root_cause,
                  abuse: "Static Luau probe rule from " + p.source,
                  fix: p.fix,
                  rank: 999999,
                  code_example: ""
                }, "overview");
              }
              row.addEventListener("click", pick);
              row.addEventListener("keydown", function(e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
            });
          });
      }

      document.getElementById("form-pack-search").addEventListener("submit", function(e) {
        e.preventDefault();
        loadPack(document.getElementById("input-pack-q").value.trim());
      });

      // Brain & History
      function loadBrainHistory() {
        fetch("/api/history")
          .then(function(r) { return r.json(); })
          .then(function(res) {
            const tokRoot = document.getElementById("brain-tokens-root");
            if (!res.learned_tokens || !res.learned_tokens.length) {
              tokRoot.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No custom tokens learned yet.</div>';
            } else {
              let h = '<div class="clean-list">';
              res.learned_tokens.slice(0, 20).forEach(function(t) {
                h +=
                  '<div class="list-row">' +
                    '<div class="sev-indicator sev-text-' + esc(t.severity) + '"><span class="sev-dot sev-dot-' + esc(t.severity) + '"></span>' + esc(t.severity) + '</div>' +
                    '<div class="row-main"><div class="row-title">' + esc(t.token) + '</div><p class="row-sub">' + esc(t.domain) + '</p></div>' +
                    '<div class="row-meta">' + esc(t.seen_count) + 'x seen</div>' +
                  '</div>';
              });
              h += '</div>';
              tokRoot.innerHTML = h;
            }

            const histRoot = document.getElementById("brain-history-root");
            if (!res.history || !res.history.length) {
              histRoot.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No command history logged yet.</div>';
            } else {
              let h = '<div class="clean-list">';
              res.history.slice(0, 20).forEach(function(item) {
                h +=
                  '<div class="list-row">' +
                    '<div class="ver-pill">' + esc(item.timestamp) + '</div>' +
                    '<div class="row-main"><div class="row-title" style="font-family:var(--font-mono);font-size:12.5px;">' + esc(item.command) + '</div></div>' +
                    '<div class="row-meta">' + esc(item.findings_count) + ' findings · ' + esc(item.duration_ms) + ' ms</div>' +
                  '</div>';
              });
              h += '</div>';
              histRoot.innerHTML = h;
            }
          });
      }

      // Command Palette
      const cmdModal = document.getElementById("cmd-modal");
      const cmdInput = document.getElementById("cmd-input");
      const cmdItems = document.getElementById("cmd-items");
      const actions = [
        { name: "Copy Client Luau Script", hint: "Clipboard", fn: function() { document.getElementById("btn-copy-luau").click(); } },
        { name: "Run Demo Playtest Simulation", hint: "Simulate", fn: function() { document.getElementById("btn-simulate").click(); } },
        { name: "View Client Diagnostic Script", hint: "Inspector", fn: function() { openSheet(state.activeFinding, "payload"); } },
        { name: "Go to Live Audit", hint: "View", fn: function() { switchView(document.getElementById("nav-live")); } },
        { name: "Go to Telemetry & Memory Waveform", hint: "View", fn: function() { switchView(document.getElementById("nav-telemetry")); } },
        { name: "Go to Static Place & Luau Scanner", hint: "View", fn: function() { switchView(document.getElementById("nav-static")); } },
        { name: "Search 600,000 Flaw Catalog", hint: "View", fn: function() { switchView(document.getElementById("nav-catalog")); } },
        { name: "Browse 120 Luau Debugger Probes", hint: "View", fn: function() { switchView(document.getElementById("nav-pack")); } },
        { name: "Open Brain & Command History", hint: "View", fn: function() { switchView(document.getElementById("nav-brain")); } },
        { name: "Export Markdown Audit Report (.md)", hint: "Download", fn: function() { document.getElementById("btn-export-md").click(); } },
        { name: "Toggle Dark / Light Mode", hint: "Theme", fn: function() { document.getElementById("btn-theme-toggle").click(); } },
        { name: "Pause / Resume Live Sync", hint: "Sync", fn: function() { document.getElementById("btn-toggle-sync").click(); } }
      ];

      function renderCmds(q) {
        const low = (q || "").trim().toLowerCase();
        cmdItems.innerHTML = "";
        actions.filter(function(a) { return !low || a.name.toLowerCase().indexOf(low) !== -1; }).forEach(function(a) {
          const b = document.createElement("button");
          b.type = "button";
          b.className = "cmd-row";
          b.innerHTML = '<span>' + esc(a.name) + '</span><span class="ver-pill">' + esc(a.hint) + '</span>';
          b.addEventListener("click", function() { closeCmd(); a.fn(); });
          cmdItems.appendChild(b);
        });
      }

      function openCmd() {
        cmdModal.classList.add("open");
        cmdInput.value = "";
        renderCmds("");
        setTimeout(function() { cmdInput.focus(); }, 20);
      }
      function closeCmd() { cmdModal.classList.remove("open"); }

      document.getElementById("btn-open-cmd").addEventListener("click", openCmd);
      document.getElementById("btn-close-cmd").addEventListener("click", closeCmd);
      cmdModal.addEventListener("click", function(e) { if (e.target === cmdModal) closeCmd(); });
      cmdInput.addEventListener("input", function(e) { renderCmds(e.target.value); });

      document.addEventListener("keydown", function(e) {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
          e.preventDefault();
          if (cmdModal.classList.contains("open")) closeCmd(); else openCmd();
        } else if (e.key === "Escape") {
          if (cmdModal.classList.contains("open")) closeCmd();
          else if (sheet.classList.contains("open")) closeSheet();
        }
      });

      pollState();
      setInterval(pollState, 1500);
    })();
  </script>
</body>
</html>
"""


_EXPLOIT_SURFACE_TOKENS = (
    "remote",
    "onserverevent",
    "onserverinvoke",
    "fireserver",
    "invokeserver",
    "networkownership",
    "networkowner",
    "unanchored",
    "proximityprompt",
    "touched",
    "statereplication",
    "valuebase",
    "intvalue",
    "numbervalue",
    "boolvalue",
    "attribute",
    "economy",
    "currency",
    "cash",
    "gold",
    "admin",
    "privilege",
    "damage",
    "hitbox",
    "combat",
    "teleport",
    "loadstring",
    "processreceipt",
    "datastore",
    "inventory",
    "trade",
    "exploit",
    "spoof",
    "bypass",
    "client",
)


_GENERIC_CODE_STUBS = (
    'remote.OnServerEvent:Connect(function(plr, amt)\n    if typeof(amt) ~= "number" or amt ~= amt or amt <= 0 then return end\nend)',
    "remote.OnServerEvent:Connect(function(plr, amt)",
)


def _tokenize_identifier(text: str) -> list[str]:
    """Splits camelCase, PascalCase, snake_case, and dotted Roblox paths into lowercase tokens."""
    if not text:
        return []
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [tok.lower() for tok in re.findall(r"[A-Za-z0-9]+", spaced) if len(tok) >= 2]


def _extract_leaf_and_var(path_str: str) -> tuple[str, str]:
    raw_leaf = path_str.split(".")[-1].split("::")[-1].strip()
    leaf = raw_leaf.replace("[Attribute:", "").replace("]", "").strip() or "Endpoint"
    safe_var = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in leaf)
    if not safe_var or safe_var[0].isdigit():
        safe_var = f"obj_{safe_var}"
    return leaf, safe_var


def _detect_finding_domain(category: str, title: str, path: str, flaw: str, abuse: str, fix: str) -> str:
    """Maps a Roblox finding to a concrete gameplay/security domain using camelCase token analysis."""
    cat_low = (category or "").lower()
    leaf, _ = _extract_leaf_and_var(path or title)
    leaf_tokens = set(_tokenize_identifier(leaf))
    all_tokens = set(_tokenize_identifier(f"{category} {title} {path}"))
    blob = f"{category} {title} {path} {flaw} {abuse} {fix}".lower()

    if "loadstring" in blob or "loadstring" in all_tokens:
        return "code_exec"
    if "setasync" in blob or "datastore" in all_tokens or "processreceipt" in blob or (leaf_tokens & {"datastore", "receipt", "save", "savedata", "profile", "gamepass"}):
        return "datastore"
    if "proximityprompt" in blob or "clickdetector" in blob or (leaf_tokens & {"prompt", "click", "interact", "vault", "chest", "door"}) and "remote" not in cat_low:
        return "interaction"
    if "networkownership" in cat_low or "unanchored" in title.lower() or "networkowner" in blob or (leaf_tokens & {"vehicle", "ragdoll", "unanchored"}) and "remote" not in cat_low:
        return "physics"
    if (
        "statereplication" in cat_low
        or "attribute:" in (path or "").lower()
        or any(k in blob for k in ("intvalue", "numbervalue", "boolvalue", "valuebase", "leaderstats"))
    ) and "remote" not in cat_low:
        return "state_rep"

    # Prioritize leaf identifier semantics so remotes like AllDailiesCompletedEvent, BuyItem, FireWeapon, AdminKick get exact domains
    if leaf_tokens & {"daily", "dailies", "quest", "quests", "mission", "missions", "task", "tasks", "achieve", "achievement", "milestone", "streak", "reward", "rewards", "claim", "redeem", "complete", "completed", "bonus", "spin", "wheel", "gift", "code", "battlepass", "pass", "login"}:
        return "daily_quest"
    if leaf_tokens & {"cash", "coin", "coins", "gold", "gem", "gems", "money", "currency", "buy", "purchase", "shop", "store", "sell", "upgrade", "rebirth", "prestige", "bank", "deposit", "withdraw", "pay", "price", "crate", "bundle", "bucks", "tokens"}:
        return "economy"
    if leaf_tokens & {"pet", "pets", "egg", "eggs", "hatch", "gacha", "roll", "equip", "unequip", "inventory", "item", "items", "trade", "craft", "fuse", "drop", "backpack", "skin", "cosmetic", "loot"}:
        return "inventory"
    if leaf_tokens & {"damage", "dmg", "hit", "hitbox", "attack", "fire", "shoot", "weapon", "gun", "sword", "melee", "ability", "skill", "spell", "kill", "heal", "stun", "knockback", "projectile", "bullet", "explode", "pvp", "combat"}:
        return "combat"
    if leaf_tokens & {"admin", "mod", "moderator", "kick", "ban", "unban", "mute", "command", "cmd", "rank", "role", "permission", "owner", "staff", "announce", "broadcast", "shutdown", "god", "noclip"}:
        return "admin"
    if leaf_tokens & {"teleport", "tp", "warp", "zone", "stage", "obby", "checkpoint", "level", "lobby", "match", "round", "queue", "portal", "world", "realm", "map"}:
        return "teleport"

    # Secondary check across full tokens (title + path)
    if all_tokens & {"daily", "dailies", "quest", "reward", "claim", "redeem", "completed", "streak"}:
        return "daily_quest"
    if all_tokens & {"cash", "coin", "gold", "gem", "buy", "purchase", "shop", "currency", "economy", "rebirth"}:
        return "economy"
    if all_tokens & {"pet", "egg", "hatch", "inventory", "trade", "equip", "craft"}:
        return "inventory"
    if all_tokens & {"damage", "hitbox", "combat", "weapon", "attack", "kill"}:
        return "combat"
    if all_tokens & {"admin", "privilege", "kick", "ban", "command"}:
        return "admin"
    if all_tokens & {"teleport", "checkpoint", "stage", "lobby", "match"}:
        return "teleport"
    if "memory" in blob or "debris" in blob or "leak" in blob or cat_low in ("memorydiff", "memoryleak", "performance"):
        return "memory"
    if "remote" in cat_low or "remote" in title.lower() or "onserverevent" in blob or "onserverinvoke" in blob:
        return "remote_generic"
    return "developer_hygiene"


def build_tailored_server_fix(
    category: str,
    title: str,
    path: str,
    flaw: str,
    fix: str,
    existing_code: str = "",
) -> str:
    """
    Returns a finding-specific, copy-pasteable server-side Luau remediation
    tailored to the exact instance path, remote name, domain, or flaw type.
    Ignores generic boilerplate stubs so every remote gets a domain-accurate patch.
    """
    cleaned_existing = (existing_code or "").strip()
    if cleaned_existing and not any(stub in cleaned_existing for stub in _GENERIC_CODE_STUBS):
        return cleaned_existing

    path_str = (path or "Unknown").strip()
    leaf, safe_var = _extract_leaf_and_var(path_str)
    domain = _detect_finding_domain(category, title, path_str, flaw, "", fix)

    if domain == "code_exec":
        return (
            f"-- Patch for {path_str}\n"
            f"-- 1) Set ServerScriptService.LoadStringEnabled = false in Studio Properties\n"
            f"-- 2) Replace loadstring() with an explicit server action allowlist:\n"
            f"local AllowedActions = {{\n"
            f"    Reset = function(player: Player) end,\n"
            f"}}\n"
            f"local function runAction(player: Player, actionName: unknown)\n"
            f"    if typeof(actionName) ~= \"string\" then return end\n"
            f"    local handler = AllowedActions[actionName]\n"
            f"    if handler then handler(player) end\n"
            f"end"
        )

    if domain == "daily_quest":
        return (
            f"-- Server-Authoritative Daily / Quest Completion Patch for '{leaf}' ({path_str})\n"
            f"local Players = game:GetService(\"Players\")\n"
            f"local COOLDOWN_SEC = 1.0\n"
            f"local lastClaim: {{[Player]: number}} = {{}}\n"
            f"-- Track quest progress and claim state strictly on the server (never trust client completion signals)\n"
            f"local PlayerDailyState: {{[number]: {{ completedCount: number, requiredCount: number, claimedDayKey: string }}}} = {{}}\n"
            f"Players.PlayerRemoving:Connect(function(plr) lastClaim[plr] = nil; PlayerDailyState[plr.UserId] = nil end)\n\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player)\n"
            f"    local now = os.clock()\n"
            f"    if now - (lastClaim[player] or 0) < COOLDOWN_SEC then return end\n"
            f"    lastClaim[player] = now\n\n"
            f"    local state = PlayerDailyState[player.UserId]\n"
            f"    if not state then return end\n"
            f"    local utcDayKey = os.date(\"!%Y-%m-%d\")\n"
            f"    if state.claimedDayKey == utcDayKey then return end -- Idempotency: prevent double-claim\n"
            f"    if state.completedCount < state.requiredCount then return end -- Verify actual server progress\n\n"
            f"    -- Lock claim state BEFORE granting reward to prevent concurrent race-condition farming\n"
            f"    state.claimedDayKey = utcDayKey\n"
            f"    -- Grant fixed server-defined reward table here (never accept reward amount from client)\n"
            f"end)"
        )

    if domain == "economy":
        return (
            f"-- Server-Authoritative Economy & Purchase Patch for '{leaf}' ({path_str})\n"
            f"local Players = game:GetService(\"Players\")\n"
            f"local CATALOG = {{\n"
            f"    StarterPack = {{ Price = 250, MaxQty = 1 }},\n"
            f"    HealthPotion = {{ Price = 50, MaxQty = 10 }},\n"
            f"}}\n"
            f"local lastPurchase: {{[Player]: number}} = {{}}\n"
            f"Players.PlayerRemoving:Connect(function(plr) lastPurchase[plr] = nil end)\n\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player, itemId: unknown, rawQty: unknown)\n"
            f"    local now = os.clock()\n"
            f"    if now - (lastPurchase[player] or 0) < 0.4 then return end\n"
            f"    lastPurchase[player] = now\n\n"
            f"    if typeof(itemId) ~= \"string\" then return end\n"
            f"    local item = CATALOG[itemId]\n"
            f"    if not item then return end\n\n"
            f"    local qty = if typeof(rawQty) == \"number\" and rawQty == rawQty then math.floor(rawQty) else 1\n"
            f"    if qty < 1 or qty > item.MaxQty then return end\n"
            f"    local totalCost = item.Price * qty -- Server computes price; client price arg is ignored\n"
            f"    -- Deduct totalCost from server-side balance ledger atomically before granting item\n"
            f"end)"
        )

    if domain == "inventory":
        return (
            f"-- Server-Authoritative Inventory / Pet / Trade Patch for '{leaf}' ({path_str})\n"
            f"local Players = game:GetService(\"Players\")\n"
            f"local inFlight: {{[Player]: boolean}} = {{}}\n"
            f"Players.PlayerRemoving:Connect(function(plr) inFlight[plr] = nil end)\n\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player, itemUid: unknown)\n"
            f"    if inFlight[player] then return end -- Mutex prevents item-duplication race conditions\n"
            f"    if typeof(itemUid) ~= \"string\" or #itemUid > 64 then return end\n"
            f"    inFlight[player] = true\n"
            f"    local ok, err = pcall(function()\n"
            f"        -- 1) Verify player actually owns itemUid in server-side Inventory table\n"
            f"        -- 2) Verify itemUid is not currently locked in an active trade or craft\n"
            f"        -- 3) Mutate ownership / equip state atomically on the server\n"
            f"    end)\n"
            f"    inFlight[player] = nil\n"
            f"    if not ok then warn(\"{leaf} error:\", err) end\n"
            f"end)"
        )

    if domain == "combat":
        return (
            f"-- Server-Authoritative Combat / Hitbox Validation Patch for '{leaf}' ({path_str})\n"
            f"local Players = game:GetService(\"Players\")\n"
            f"local MAX_RANGE_STUDS = 24\n"
            f"local FIRE_COOLDOWN = 0.25\n"
            f"local lastAttack: {{[Player]: number}} = {{}}\n"
            f"Players.PlayerRemoving:Connect(function(plr) lastAttack[plr] = nil end)\n\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player, targetCharacter: unknown)\n"
            f"    local now = os.clock()\n"
            f"    if now - (lastAttack[player] or 0) < FIRE_COOLDOWN then return end\n"
            f"    lastAttack[player] = now\n\n"
            f"    if typeof(targetCharacter) ~= \"Instance\" or not targetCharacter:IsA(\"Model\") then return end\n"
            f"    local attackerRoot = player.Character and player.Character:FindFirstChild(\"HumanoidRootPart\")\n"
            f"    local targetRoot = targetCharacter:FindFirstChild(\"HumanoidRootPart\")\n"
            f"    local targetHum = targetCharacter:FindFirstChildOfClass(\"Humanoid\")\n"
            f"    if not attackerRoot or not targetRoot or not targetHum or targetHum.Health <= 0 then return end\n"
            f"    if (attackerRoot.Position - targetRoot.Position).Magnitude > MAX_RANGE_STUDS then return end\n"
            f"    -- Apply fixed server weapon damage; ignore any client-supplied damage number\n"
            f"    targetHum:TakeDamage(15)\n"
            f"end)"
        )

    if domain == "admin":
        return (
            f"-- Server-Authoritative Privilege & Admin Guard for '{leaf}' ({path_str})\n"
            f"local ADMIN_USER_IDS: {{[number]: boolean}} = {{\n"
            f"    [game.CreatorId] = true,\n"
            f"}}\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player, commandName: unknown, targetUserId: unknown)\n"
            f"    if not ADMIN_USER_IDS[player.UserId] then\n"
            f"        warn(string.format(\"Unauthorized {leaf} call by %s (%d)\", player.Name, player.UserId))\n"
            f"        return\n"
            f"    end\n"
            f"    if typeof(commandName) ~= \"string\" or #commandName > 32 then return end\n"
            f"    if targetUserId ~= nil and typeof(targetUserId) ~= \"number\" then return end\n"
            f"    -- Execute allowlisted admin action with audit logging\n"
            f"end)"
        )

    if domain == "teleport":
        return (
            f"-- Server-Authoritative Zone / Checkpoint Guard for '{leaf}' ({path_str})\n"
            f"local ALLOWED_ZONES: {{[string]: CFrame}} = {{\n"
            f"    Lobby = CFrame.new(0, 10, 0),\n"
            f"}}\n"
            f"local lastTeleport: {{[Player]: number}} = {{}}\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player, zoneId: unknown)\n"
            f"    local now = os.clock()\n"
            f"    if now - (lastTeleport[player] or 0) < 1.5 then return end\n"
            f"    if typeof(zoneId) ~= \"string\" then return end\n"
            f"    local dest = ALLOWED_ZONES[zoneId]\n"
            f"    if not dest then return end -- Never accept raw client Vector3/CFrame destinations\n"
            f"    -- Verify player has unlocked zoneId on the server before teleporting\n"
            f"    lastTeleport[player] = now\n"
            f"    local char = player.Character\n"
            f"    if char then char:PivotTo(dest) end\n"
            f"end)"
        )

    if domain == "datastore":
        return (
            f"-- Atomic DataStore Patch for '{leaf}' ({path_str})\n"
            f"local DataStoreService = game:GetService(\"DataStoreService\")\n"
            f"local Store = DataStoreService:GetDataStore(\"Authoritative_{safe_var}\")\n\n"
            f"local function updatePlayerData(userId: number, delta: number)\n"
            f"    if typeof(delta) ~= \"number\" or delta ~= delta or math.abs(delta) == math.huge then return end\n"
            f"    Store:UpdateAsync(\"p_\" .. tostring(userId), function(old)\n"
            f"        local state = if typeof(old) == \"table\" then old else {{ Balance = 0, Receipts = {{}} }}\n"
            f"        state.Balance = math.max(0, (state.Balance or 0) + delta)\n"
            f"        return state\n"
            f"    end)\n"
            f"end"
        )

    if domain == "interaction":
        return (
            f"-- Server Distance & Cooldown Guard for Interaction '{leaf}' ({path_str})\n"
            f"local lastUse: {{[Player]: number}} = {{}}\n"
            f"prompt.Triggered:Connect(function(player: Player)\n"
            f"    local root = player.Character and player.Character.PrimaryPart\n"
            f"    local hostPart = prompt.Parent\n"
            f"    if not root or not hostPart or not hostPart:IsA(\"BasePart\") then return end\n"
            f"    if (root.Position - hostPart.Position).Magnitude > prompt.MaxActivationDistance + 4 then return end\n"
            f"    local now = os.clock()\n"
            f"    if now - (lastUse[player] or 0) < 0.5 then return end\n"
            f"    lastUse[player] = now\n"
            f"    -- Safe server-side interaction logic for {leaf}\n"
            f"end)"
        )

    if domain == "physics":
        return (
            f"-- Lock Physics Authority for '{leaf}' ({path_str})\n"
            f"local targetPart = {path_str}\n"
            f"if targetPart and targetPart:IsA(\"BasePart\") then\n"
            f"    targetPart.Anchored = true -- Option A: anchor static map/vault geometry\n"
            f"    -- Option B: if '{leaf}' must move physically, assign ownership to the server:\n"
            f"    -- targetPart.Anchored = false\n"
            f"    -- targetPart:SetNetworkOwner(nil)\n"
            f"end"
        )

    if domain == "state_rep":
        return (
            f"-- Authoritative Server State for '{leaf}' (replaces trusting {path_str})\n"
            f"local Players = game:GetService(\"Players\")\n"
            f"local ServerState: {{[number]: number}} = {{}}\n\n"
            f"local function set{safe_var}(player: Player, newValue: number)\n"
            f"    if typeof(newValue) ~= \"number\" or newValue ~= newValue then return end\n"
            f"    ServerState[player.UserId] = math.clamp(newValue, 0, 1e9)\n"
            f"    -- Mirror to client read-only Attribute; never read this back on the server\n"
            f"    player:SetAttribute(\"{leaf}\", ServerState[player.UserId])\n"
            f"end\n"
            f"Players.PlayerRemoving:Connect(function(plr) ServerState[plr.UserId] = nil end)"
        )

    if domain == "memory":
        return (
            f"-- Cleanup Lifecycle Pattern for '{leaf}' ({path_str})\n"
            f"local Debris = game:GetService(\"Debris\")\n"
            f"local instance = template:Clone()\n"
            f"instance.Parent = workspace\n"
            f"Debris:AddItem(instance, 4) -- Guaranteed cleanup after 4s"
        )

    if domain == "remote_generic":
        return (
            f"-- Hardened Server Handler for '{leaf}' ({path_str})\n"
            f"local Players = game:GetService(\"Players\")\n"
            f"local COOLDOWN_SEC = 0.35\n"
            f"local lastCall: {{[Player]: number}} = {{}}\n"
            f"Players.PlayerRemoving:Connect(function(plr) lastCall[plr] = nil end)\n\n"
            f"local remote = {path_str}\n"
            f"remote.OnServerEvent:Connect(function(player: Player, payload: unknown)\n"
            f"    local now = os.clock()\n"
            f"    if now - (lastCall[player] or 0) < COOLDOWN_SEC then return end\n"
            f"    lastCall[player] = now\n\n"
            f"    if typeof(payload) ~= \"string\" or #payload > 64 then return end\n"
            f"    -- Validate player eligibility and compute all outcomes strictly on the server\n"
            f"end)"
        )

    return (
        f"-- Remediation Pattern for {path_str}\n"
        f"-- Flaw: {flaw}\n"
        f"-- Fix:  {fix}\n"
        f"-- Apply server-side validation and cleanup in the owning ServerScriptService module."
    )


def _build_domain_intelligence(
    domain: str,
    leaf: str,
    path_str: str,
    category: str,
    flaw: str,
    abuse: str,
    fix: str,
) -> dict[str, Any]:
    """
    Synthesizes 4 distinct, domain-tailored overview modules, risk profile metrics,
    Studio search queries, and a concrete vulnerable Luau pattern for each finding.
    """
    tokens = _tokenize_identifier(leaf)
    readable_name = " ".join(t.capitalize() for t in tokens) if tokens else leaf
    base_queries = [leaf]
    if "remote" in category.lower() or "replicatedstorage" in path_str.lower():
        base_queries.append(f"{leaf}.OnServerEvent")
    if len(tokens) >= 2:
        longest = max((t for t in tokens if t not in ("event", "remote", "function", "re", "rf")), key=len, default="")
        if longest and longest.lower() != leaf.lower():
            base_queries.append(longest.capitalize())

    if domain == "daily_quest":
        return {
            "domain_label": "Daily Quest & Reward Completion",
            "risk_profile": {
                "exploitability": "High (Direct Client Signal)",
                "blast_radius": "Game Economy & Progression",
                "attack_complexity": "Low (Single Remote Call)",
                "surface_type": "Progression / Reward Remote",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) sits in a client-accessible path ({path_str}) and appears to signal "
                        f"daily task, quest, or milestone completion from client to server. Whenever a client is allowed to notify "
                        f"the server that a quest or daily challenge finished, an executor can invoke '{leaf}' directly without "
                        f"completing any gameplay objectives."
                    ),
                    "points": [
                        f"Target endpoint: {path_str} (callable by any client via FireServer / InvokeServer).",
                        "Client-driven completion events break server authority because the client controls when the event fires.",
                        "If the server handler does not verify server-tracked task counters and per-day claim locks, rewards become infinite.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"If the server script listening to '{leaf}' lacks strict state verification, executors can abuse it in multiple ways:",
                    "points": [
                        f"Direct Completion Bypass: Firing '{leaf}' immediately on join without completing any daily tasks to claim the completion bonus.",
                        f"Replay / Infinite Claim Loop: Invoking '{leaf}' repeatedly in a loop if the server does not mark 'claimedDayKey' before yielding or saving.",
                        "Concurrent Race Condition: Firing multiple rapid requests in the same heartbeat to trigger double-payouts before DataStore or memory state updates.",
                        "Spoofed Payload / Reward ID: Passing arbitrary quest IDs, negative indices, or inflated multiplier tables if the handler accepts client arguments.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Progression Blast Radius",
                    "summary": "Unvalidated daily/quest completion endpoints rapidly destabilize live player retention and leaderboards.",
                    "points": [
                        "Infinite currency, gems, XP, or rare daily streak items minted in seconds.",
                        "Broken leaderboards and player trading economies if daily rewards are tradable or boost power.",
                        "DataStore throttling if every spoofed call triggers an immediate unthrottled save.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Search Roblox Studio (Ctrl+Shift+F) for '{leaf}' and harden the server listener:",
                    "points": [
                        "Move quest/daily progress tracking 100% server-side; increment task counters only inside server gameplay handlers.",
                        "Set a per-player UTC date claim lock (claimedDayKey = os.date('!%Y-%m-%d')) BEFORE granting rewards or yielding.",
                        "Add a per-player rate limit (e.g. 1.0s cooldown) and ignore all client-sent reward amounts or completion flags.",
                        "Even better: have the server fire a client notification when all dailies finish, instead of trusting a client-to-server completion remote.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player)\n"
                f"    -- VULNERABLE: Trusts the client's claim that dailies/quests are complete\n"
                f"    -- without checking server-side task progress or a per-day claim lock.\n"
                f"    giveDailyCompletionReward(player)\n"
                f"end)"
            ),
        }

    if domain == "economy":
        return {
            "domain_label": "Economy & Currency Mutation",
            "risk_profile": {
                "exploitability": "Critical (Direct Currency Surface)",
                "blast_radius": "Full In-Game Economy",
                "attack_complexity": "Low (Parameter Tampering)",
                "surface_type": "Economy / Shop Remote",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) handles currency, shop purchases, upgrades, or balance mutations at {path_str}. "
                        f"Economy remotes are the #1 target for executors because any client-trusted price, quantity, or reward amount "
                        f"translates directly into infinite currency."
                    ),
                    "points": [
                        f"Client-accessible economy endpoint: {path_str}.",
                        "Any client-supplied price, discount, or currency delta can be forged freely.",
                        "Floating-point edge cases (NaN, inf, negative quantities) frequently bypass naive 'balance >= cost' checks.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors probing '{leaf}' test four high-impact economy bypasses:",
                    "points": [
                        "Negative Quantity / Negative Price Injection: Sending qty = -1000 so 'balance -= price * qty' ADDS currency instead of deducting it.",
                        "NaN & Infinity Bypass: Sending 0/0 (NaN) so 'if cost > balance then return end' evaluates to false and grants free items.",
                        "Client Price Spoofing: Passing price = 0 or an unrecognized itemId that falls back to a default 0-cost branch.",
                        "Burst Purchase Race: Spamming '{leaf}' faster than balance deduction or DataStore writes to buy items beyond actual balance.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Economy Blast Radius",
                    "summary": "A single unvalidated shop or currency remote can permanently ruin a game's monetization and trading economy.",
                    "points": [
                        "Instant infinite cash/gems, bypassing Robux developer products and gamepasses.",
                        "Hyperinflation in player-to-player trading markets and leaderboards.",
                        "Corrupted player DataStore profiles if NaN values are saved into persistent currency fields.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Locate '{leaf}' in ServerScriptService and enforce strict server-side pricing:",
                    "points": [
                        "Look up item prices exclusively in a server-side ModuleScript catalog; never accept price or reward amounts from the client.",
                        "Validate typeof(qty) == 'number', qty == qty (blocks NaN), math.floor(qty) == qty, and 1 <= qty <= MAX_QTY.",
                        "Deduct currency atomically in memory BEFORE granting items or calling DataStore UpdateAsync.",
                        "Apply a per-player cooldown (0.3s to 0.5s) and clean up cooldown entries on PlayerRemoving.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player, itemId, price, qty)\n"
                f"    -- VULNERABLE: Trusts client-supplied price/qty; negative or NaN values mint currency\n"
                f"    player.leaderstats.Cash.Value -= (price * qty)\n"
                f"    grantItem(player, itemId)\n"
                f"end)"
            ),
        }

    if domain == "inventory":
        return {
            "domain_label": "Inventory, Pets & Trade Integrity",
            "risk_profile": {
                "exploitability": "High (Ownership / Dupe Surface)",
                "blast_radius": "Item Economy & Trading",
                "attack_complexity": "Medium (Timing / ID Spoof)",
                "surface_type": "Inventory / Gacha Remote",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) manages player items, pets, eggs, crafting, or trades at {path_str}. "
                        f"Inventory remotes are prime targets for item duplication (duping) and unauthorized equip/craft exploits."
                    ),
                    "points": [
                        f"Exposed inventory action endpoint: {path_str}.",
                        "Missing server-side ownership checks allow clients to equip, fuse, or trade items they do not own.",
                        "Lack of per-player transaction locks (mutexes) enables race-condition duplication across trade/craft/hatch flows.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors target '{leaf}' with ownership spoofing and concurrency attacks:",
                    "points": [
                        "Unowned Item / Pet Equip: Passing high-tier item names or GUIDs belonging to other players.",
                        "Trade / Craft Duplication Race: Firing '{leaf}' concurrently while disconnecting or trading the same itemUid twice.",
                        "Egg / Gacha Reroll Abuse: Rapid-firing hatch requests or aborting before currency deduction completes.",
                        "Oversized Table Payload: Passing deeply nested or massive item-list tables to stall server serialization.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Item Market Blast Radius",
                    "summary": "Duplicated rare pets/items collapse trading ecosystems and devalue Robux eggs/crates.",
                    "points": [
                        "Mass duplication of limited or mythical items across alt accounts.",
                        "Server lag spikes from unvalidated table iteration in inventory handlers.",
                        "Permanent inventory desync between client UI and DataStore saves.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Audit the handler for '{leaf}' in ServerScriptService:",
                    "points": [
                        "Assign every item/pet a server-generated unique ID (HttpService:GenerateGUID) and verify ownership in the player's server profile.",
                        "Wrap mutations in a per-player in-flight boolean lock (inFlight[player]) so concurrent calls cannot dupe items.",
                        "Validate argument types and cap array/string lengths before looping.",
                        "Ensure egg/crate RNG rolls happen 100% on the server after deducting cost.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player, itemUid)\n"
                f"    -- VULNERABLE: No per-player transaction lock or server ownership check\n"
                f"    equipOrTransferItem(player, itemUid)\n"
                f"end)"
            ),
        }

    if domain == "combat":
        return {
            "domain_label": "Combat, Weapons & Hitbox Validation",
            "risk_profile": {
                "exploitability": "Critical (Kill-All / Silent Aim)",
                "blast_radius": "Match & PvP Fairness",
                "attack_complexity": "Low (Forged Target / Damage)",
                "surface_type": "Combat / Weapon Remote",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) is a client-callable combat or ability endpoint at {path_str}. "
                        f"When the server trusts client-reported hits, target humanoids, or damage numbers, executors can "
                        f"trigger instant kill-all loops across the entire map."
                    ),
                    "points": [
                        f"Combat remote exposed to all clients: {path_str}.",
                        "Client-side hit detection without server distance, cooldown, and line-of-sight checks can be spoofed at any range.",
                        "Accepting damage values or weapon stats from the client lets any player deal instant lethal damage.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Combat remotes like '{leaf}' are commonly abused via:",
                    "points": [
                        "Map-Wide Kill-All: Iterating over Players:GetPlayers() and firing '{leaf}' with every player's Humanoid regardless of distance.",
                        "Fire-Rate / Cooldown Bypass: Calling '{leaf}' 60 times per second to bypass weapon reload or swing speed.",
                        "Damage / Headshot Spoofing: Passing forged damage multipliers, crit flags, or NaN health deltas.",
                        "Wallbang / Line-of-Sight Bypass: Reporting hits through solid map geometry when the server skips raycast verification.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & PvP Integrity Blast Radius",
                    "summary": "Unprotected combat remotes make public servers unplayable within seconds.",
                    "points": [
                        "Single exploiter wipes entire lobbies repeatedly (kill-all / spawn trapping).",
                        "Instant boss/NPC farming to abuse XP, drops, and round wins.",
                        "High player churn and negative game ratings during live sessions.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Harden the server handler for '{leaf}':",
                    "points": [
                        "Verify attacker owns/equips the weapon and enforce server-side fire-rate cooldowns via os.clock().",
                        "Validate distance between attacker and target HumanoidRootPart against weapon max range (+ latency buffer).",
                        "Perform a server-side Workspace:Raycast line-of-sight check for ranged weapons.",
                        "Compute damage strictly from server weapon config tables; ignore client damage arguments.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player, targetHumanoid, damage)\n"
                f"    -- VULNERABLE: Trusts client target & damage with no distance/cooldown check\n"
                f"    targetHumanoid:TakeDamage(damage)\n"
                f"end)"
            ),
        }

    if domain == "admin":
        return {
            "domain_label": "Admin & Privilege Escalation",
            "risk_profile": {
                "exploitability": "Critical (Server Takeover)",
                "blast_radius": "Entire Live Server",
                "attack_complexity": "Low (Missing Server Auth)",
                "surface_type": "Privileged Admin Remote",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) exposes moderation, rank, or administrative functionality at {path_str}. "
                        f"Hiding an admin GUI on the client does NOT protect the underlying RemoteEvent; any executor can fire it directly."
                    ),
                    "points": [
                        f"Privileged endpoint reachable by every client: {path_str}.",
                        "Client-only UI visibility checks or LocalScript rank checks are trivially bypassed.",
                        "Every single invocation must re-verify player.UserId or GroupRank on the server.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors specifically scan ReplicatedStorage for admin-named remotes like '{leaf}':",
                    "points": [
                        "Unauthorized Kick/Ban/Shutdown: Non-admin clients firing '{leaf}' to kick all players or crash the server.",
                        "Self-Promotion / Rank Spoof: Passing own UserId to grant admin privileges or developer currency.",
                        "Global Announcement Spam: Abusing broadcast commands to display malicious text to all players.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Moderation Blast Radius",
                    "summary": "A single unauthenticated admin remote gives any client full control over the server.",
                    "points": [
                        "Mass kicking/banning of legitimate players and developers.",
                        "Arbitrary server state tampering, economy wipes, and reputation damage.",
                        "Potential Roblox moderation action if inappropriate broadcasts are injected.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Lock down '{leaf}' immediately in ServerScriptService:",
                    "points": [
                        "Check an explicit server-side ADMIN_USER_IDS[player.UserId] table or cached GetRankInGroup() on EVERY call.",
                        "Never trust a client-passed 'isAdmin' boolean or Player Attribute for authorization.",
                        "Log unauthorized calls with player.UserId and rate-limit or kick repeat offenders.",
                        "Allowlist specific command strings rather than executing arbitrary actions.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player, command, targetPlayer)\n"
                f"    -- VULNERABLE: Relies on client Admin GUI visibility instead of server UserId/GroupRank check\n"
                f"    if command == \"kick\" then targetPlayer:Kick() end\n"
                f"end)"
            ),
        }

    if domain == "teleport":
        return {
            "domain_label": "Teleport, Zones & Match Progression",
            "risk_profile": {
                "exploitability": "High (Sequence / Zone Skip)",
                "blast_radius": "Progression & Match Flow",
                "attack_complexity": "Low (Direct Remote Fire)",
                "surface_type": "Zone / Match Remote",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) controls player teleportation, stage checkpoints, or match/zone transitions at {path_str}. "
                        f"If the server accepts arbitrary coordinates or unlocked stage IDs from the client, players can skip entire levels or enter restricted areas."
                    ),
                    "points": [
                        f"Zone/teleport endpoint: {path_str}.",
                        "Trusting client-supplied CFrames, stage numbers, or checkpoint completions lets players finish obbies/dungeons instantly.",
                        "Unthrottled teleport calls can also cause server physics spikes or grief other players if targets are client-controlled.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors abuse teleport and progression remotes like '{leaf}' via:",
                    "points": [
                        "Instant Stage / Finale Skip: Firing '{leaf}' with the final stage/checkpoint ID to farm rebirths or win rewards.",
                        "Restricted VIP / Boss Room Entry: Requesting teleport to paid or level-gated zones without meeting server requirements.",
                        "Arbitrary Coordinate Injection: Passing raw Vector3/CFrame values to clip into locked vaults or out-of-bounds areas.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Progression Blast Radius",
                    "summary": "Zone and checkpoint bypasses trivialize core gameplay loops and paid access passes.",
                    "points": [
                        "Instant win/rebirth farming that breaks time-trial and stage leaderboards.",
                        "Bypassing VIP/Gamepass area gates without paying.",
                        "Match/lobby state corruption if players force-join active rounds.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Secure '{leaf}' in ServerScriptService:",
                    "points": [
                        "Map zoneId strings to a server-side ALLOWED_ZONES CFrame table; never accept raw CFrames from clients.",
                        "Verify the player's server-side level, unlocked zones, or MarketplaceService ownership before teleporting.",
                        "Enforce sequential checkpoint validation (nextStage == currentStage + 1) and a 1.5s cooldown.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player, destinationOrStage)\n"
                f"    -- VULNERABLE: Teleports or advances stage without verifying unlock prerequisites\n"
                f"    player.Character:PivotTo(destinationOrStage)\n"
                f"end)"
            ),
        }

    if domain == "physics":
        return {
            "domain_label": "Physics & NetworkOwnership",
            "risk_profile": {
                "exploitability": "High (Client Physics Control)",
                "blast_radius": "Workspace Stability & Flinging",
                "attack_complexity": "Low (Local CFrame / Velocity)",
                "surface_type": "Unanchored Workspace Part",
            },
            "studio_search_queries": [leaf, "SetNetworkOwner", "Anchored"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' at {path_str} is an unanchored BasePart whose automatic Roblox NetworkOwnership can be claimed "
                        f"by nearby clients. Once a client owns a part's physics, the server replicates whatever position and velocity "
                        f"that client simulates."
                    ),
                    "points": [
                        f"Unanchored Workspace instance: {path_str}.",
                        "Roblox automatically delegates physics ownership of unanchored parts near a player to that player's client.",
                        "Any client holding ownership can apply extreme LinearVelocity/AngularVelocity or teleport the part into other players.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors abuse unanchored client-owned parts like '{leaf}' through:",
                    "points": [
                        "Player Flinging: Spinning '{leaf}' at extreme angular velocity and colliding it with other players to launch them into the void.",
                        "Map / Vault Bypass: Moving '{leaf}' out of the way to bypass physical barriers, doors, or puzzles.",
                        "Bring-Parts Griefing: Pulling all unanchored Workspace parts onto a target player to lag or trap them.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Server Stability Blast Radius",
                    "summary": "Unowned physics parts allow griefers to disrupt every player in the server without touching a single RemoteEvent.",
                    "points": [
                        "Widespread player flinging and map destruction in public lobbies.",
                        "Broken physics puzzles, vehicles, or vault doors.",
                        "Client FPS drops when dozens of unanchored parts are stacked on one coordinate.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Lock down '{leaf}' in Studio Explorer or its spawner ServerScript:",
                    "points": [
                        "If '{leaf}' does not need physics simulation, set Anchored = true in Studio Properties.",
                        "If it must move physically, call targetPart:SetNetworkOwner(nil) on the server so no client can claim it.",
                        "Put decorative/non-gameplay parts in a non-colliding CollisionGroup.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible Workspace Part: {path_str}\n"
                f"-- VULNERABLE: '{leaf}' has Anchored = false with automatic client NetworkOwnership.\n"
                f"-- Nearby executors can teleport or fling '{leaf}' across the server."
            ),
        }

    if domain == "state_rep":
        return {
            "domain_label": "State Replication & ValueBase Trust",
            "risk_profile": {
                "exploitability": "Medium (Local Tampering / Readback)",
                "blast_radius": "Client UI & Server Readback Risk",
                "attack_complexity": "Low (Local Property Edit)",
                "surface_type": "Replicated ValueBase / Attribute",
            },
            "studio_search_queries": [leaf, f'GetAttribute("{leaf}")', f"{leaf}.Value"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) is a client-visible Attribute or ValueBase (IntValue / NumberValue / BoolValue). "
                        f"While FilteringEnabled prevents direct client-to-server property replication, executors can freely edit "
                        f"local values to bypass LocalScript checks or trick any server script that reads client-sent values."
                    ),
                    "points": [
                        f"Exposed state container: {path_str}.",
                        "LocalScripts that check '{leaf}' for cooldowns, walkspeed, VIP status, or prices can be bypassed instantaneously.",
                        "Sensitive economy or progression totals should live in server-only ModuleScript tables, mirrored read-only to clients.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors manipulate client-visible state like '{leaf}' to:",
                    "points": [
                        "Local Gate Bypass: Setting local BoolValue/Attribute '{leaf}' = true to unlock client UI panels, VIP buttons, or abilities.",
                        "Client Stat Spoofing: Inflating local walkspeed, damage, or cooldown attributes read by LocalScripts.",
                        "Reconnaissance: Reading replicated attributes across all players to discover hidden game states or admin flags.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Integrity Blast Radius",
                    "summary": "Relying on client-readable state objects as authoritative truth leads to silent logic bypasses.",
                    "points": [
                        "Clients unlock restricted UI flows and fire hidden remotes normally gated by LocalScript checks.",
                        "Desynchronized client HUD vs server state if players modify local ValueBase objects.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Audit every reference to '{leaf}' across ServerScriptService:",
                    "points": [
                        "Keep the source of truth for '{leaf}' in a server-side Lua table keyed by player.UserId.",
                        "Treat replicated ValueBase/Attributes strictly as one-way display mirrors for UI.",
                        "Re-verify every condition on the server inside RemoteEvent handlers rather than trusting client state.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible State Reference: {path_str}\n"
                f"-- VULNERABLE: Reading client-visible '{leaf}' as authoritative truth or gating remotes only in LocalScripts.\n"
                f"-- Search ServerScriptService for '{leaf}' and back it with a server-only table."
            ),
        }

    if domain == "datastore":
        return {
            "domain_label": "DataStore Persistence & Receipts",
            "risk_profile": {
                "exploitability": "High (Dupe / Save Race)",
                "blast_radius": "Permanent Player Data",
                "attack_complexity": "Medium (Disconnect / Race)",
                "surface_type": "DataStore / Receipt Handler",
            },
            "studio_search_queries": [leaf, "SetAsync", "UpdateAsync", "ProcessReceipt"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) interacts with persistent DataStore saves or Marketplace receipts. "
                        f"Non-atomic SetAsync writes or unguarded ProcessReceipt handlers allow players to overwrite newer "
                        f"server saves or replay purchases across servers."
                    ),
                    "points": [
                        f"Persistence target: {path_str}.",
                        "SetAsync blindly overwrites existing data without reading the latest state, causing data loss and item dupes.",
                        "Missing session locking lets a player join two servers rapidly and duplicate traded items.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Attackers exploit weak DataStore patterns in '{leaf}' via:",
                    "points": [
                        "Server-Hop Item Duplication: Trading an item on Server A and rapidly rejoining Server B before SetAsync flushes.",
                        "DataStore Budget Exhaustion: Triggering rapid save calls via remotes to hit Roblox's DataStore rate limit and prevent saves.",
                        "Receipt Replay: Re-granting Robux products if PurchaseId is not persisted idempotently inside UpdateAsync.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Persistence Blast Radius",
                    "summary": "DataStore bugs cause permanent player data loss, rollbacks, and unpatchable economy dupes.",
                    "points": [
                        "Legitimate players lose progress or Robux purchases during server hops.",
                        "Duplicated items persist permanently in DataStores even after server restarts.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Harden persistence in '{leaf}':",
                    "points": [
                        "Replace SetAsync with atomic UpdateAsync (or adopt ProfileStore / ProfileService session locking).",
                        "Store processed MarketplaceService PurchaseIds inside the player's DataStore record before returning PurchaseGranted.",
                        "Add game:BindToClose() save flushing and debounce saves so clients cannot spam DataStore calls.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible Script: {path_str}\n"
                f"store:SetAsync(\"p_\" .. player.UserId, data)\n"
                f"-- VULNERABLE: Non-atomic write; susceptible to session-hop race conditions and data loss."
            ),
        }

    if domain == "interaction":
        return {
            "domain_label": "World Interactions & ProximityPrompts",
            "risk_profile": {
                "exploitability": "High (Remote Trigger / Range)",
                "blast_radius": "World Objectives & Loot",
                "attack_complexity": "Low (fireproximityprompt)",
                "surface_type": "ProximityPrompt / ClickDetector",
            },
            "studio_search_queries": [leaf, ".Triggered", "MaxActivationDistance"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) uses a ProximityPrompt, ClickDetector, or Touched trigger. "
                        f"Executors include built-in helpers (like fireproximityprompt / firetouchinterest) that can fire "
                        f"world triggers rapidly or from unexpected positions if the server skips distance and cooldown checks."
                    ),
                    "points": [
                        f"World interaction surface: {path_str}.",
                        "Clients can trigger prompts with zero hold duration or spoof character position briefly.",
                        "Without server distance, line-of-sight, and cooldown checks, players auto-farm chests, vaults, and doors.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors automate world interactions on '{leaf}' via:",
                    "points": [
                        "Instant Auto-Farm: Looping fireproximityprompt across every loot/chest prompt in Workspace.",
                        "HoldDuration Bypass: Triggering long-hold heist/vault prompts instantaneously.",
                        "Through-Wall Interaction: Firing prompts from behind locked doors when RequiresLineOfSight is false.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Gameplay Blast Radius",
                    "summary": "Unverified world triggers allow AFK auto-farming of chests, doors, and quest objectives.",
                    "points": [
                        "Instant map-wide loot collection denying fair play to normal players.",
                        "Bypassing locked heist doors, puzzles, or timed capture points.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Harden the Triggered/MouseClick listener for '{leaf}':",
                    "points": [
                        "Check (root.Position - hostPart.Position).Magnitude <= prompt.MaxActivationDistance + 4 on the server.",
                        "Enforce a per-player cooldown and verify the player is alive and not in a restricted state.",
                        "Enable prompt.RequiresLineOfSight = true where walls should block interaction.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible Interaction Handler: search Studio for '{leaf}'\n"
                f"prompt.Triggered:Connect(function(player)\n"
                f"    -- VULNERABLE: Missing server-side distance and cooldown validation\n"
                f"    grantLoot(player)\n"
                f"end)"
            ),
        }

    if domain == "code_exec":
        return {
            "domain_label": "Dynamic Code Execution (RCE)",
            "risk_profile": {
                "exploitability": "Critical (Full Server Compromise)",
                "blast_radius": "Entire Game & DataStores",
                "attack_complexity": "Low (Payload Injection)",
                "surface_type": "Server Script / loadstring",
            },
            "studio_search_queries": ["loadstring", "LoadStringEnabled", leaf],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) invokes dynamic code evaluation (loadstring). If any external or client-influenced "
                        f"input reaches loadstring() on the server, an attacker gains full server-side code execution."
                    ),
                    "points": [
                        f"Detected in: {path_str}.",
                        "loadstring() compiles and runs arbitrary Luau strings with full ServerScriptService permissions.",
                        "Roblox recommends keeping ServerScriptService.LoadStringEnabled = false in all production games.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": "2. Concrete Executor Abuse Vectors",
                    "summary": "Server-side loadstring() is the highest-severity vulnerability class in Roblox:",
                    "points": [
                        "Arbitrary Server Code Execution: Injecting Luau to wipe DataStores, grant admin, or insert backdoor models.",
                        "Silent Persistence: Hiding malicious scripts inside ServerStorage or Chat services.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Game Impact & Security Blast Radius",
                    "summary": "Complete compromise of the game server, player DataStores, and Roblox account reputation.",
                    "points": [
                        "Total loss of server authority and player data integrity.",
                        "Risk of game moderation/takedown if malicious content is injected into live servers.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": "4. Developer Patch & Verification Checklist",
                    "summary": "Eliminate dynamic code execution immediately:",
                    "points": [
                        "Set ServerScriptService.LoadStringEnabled = false in Roblox Studio.",
                        "Replace loadstring() with a static lookup table of allowed server functions.",
                        "Audit all free models and plugins for hidden require(assetId) or getfenv() backdoors.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible Script: {path_str}\n"
                f"loadstring(userPayload)() -- VULNERABLE: Arbitrary server-side code execution"
            ),
        }

    if domain == "memory":
        return {
            "domain_label": "Memory Lifecycle & Performance",
            "risk_profile": {
                "exploitability": "Low (Internal Hygiene)",
                "blast_radius": "Client / Server FPS & Crash Risk",
                "attack_complexity": "N/A (Accumulates Over Time)",
                "surface_type": "Memory / Instance Leak",
            },
            "studio_search_queries": [leaf, "Clone()", "Debris:AddItem"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) exhibits unmanaged instance growth, retained connections, or rising memory usage. "
                        f"Over long play sessions, leaked instances degrade frame rates and trigger mobile memory crashes."
                    ),
                    "points": [
                        f"Observed target: {path_str}.",
                        flaw or "Unbounded instance cloning or undisconnected RBXScriptConnections retain memory.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "DIAGNOSTIC",
                    "title": "2. Failure Modes & Stress Scenarios",
                    "summary": "How this defect manifests in live production servers:",
                    "points": [
                        "Gradual client RAM climb causing iOS/Android crash-to-home after 15-30 minutes.",
                        "Server heartbeat degradation when thousands of orphaned projectiles/effects remain in Workspace.",
                        "PlayerRemoving leaks when per-player tables or connections are never cleared.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Performance & Retention Impact",
                    "summary": "Memory leaks silently hurt mobile retention and server uptime.",
                    "points": [
                        "Higher crash rate on low-RAM mobile devices (majority of Roblox players).",
                        "Increasing physics and replication overhead as instance counts climb.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": "4. Developer Cleanup Checklist",
                    "summary": "Bound instance lifetimes and disconnect listeners:",
                    "points": [
                        "Use Debris:AddItem(instance, lifetime) or explicit :Destroy() for every cloned VFX/projectile.",
                        "Disconnect RBXScriptConnections and clear per-player dictionaries inside Players.PlayerRemoving.",
                        "Verify memory flattens in the rcdebug Telemetry oscilloscope over a 60s playtest.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible Script / Target: {path_str}\n"
                f"-- ISSUE: {flaw}\n"
                f"-- Ensure cloned instances use Debris:AddItem() and connections are cleaned up."
            ),
        }

    if domain == "remote_generic":
        return {
            "domain_label": f"Client-Server Remote ({readable_name})",
            "risk_profile": {
                "exploitability": "High (Client-Callable Remote)",
                "blast_radius": f"Subsystem: {readable_name}",
                "attack_complexity": "Low (Direct FireServer)",
                "surface_type": "RemoteEvent / RemoteFunction",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({readable_name}) is a client-accessible remote at {path_str}. "
                        f"Every RemoteEvent/RemoteFunction in ReplicatedStorage is a public network API that any client "
                        f"can invoke with arbitrary arguments at any frequency."
                    ),
                    "points": [
                        f"Network endpoint: {path_str}.",
                        flaw or f"Server handler for '{leaf}' must treat every client argument as untrusted input.",
                        "Without strict schema validation, rate limiting, and server state checks, executors can abuse this subsystem.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Executor Abuse Vectors for {leaf}",
                    "summary": f"Executors probing '{leaf}' systematically test these attack vectors:",
                    "points": [
                        f"Type & Bounds Fuzzing: Firing '{leaf}' with nil, NaN (0/0), math.huge, negative numbers, or wrong Instance types.",
                        f"Rate-Limit Flooding: Calling '{leaf}' dozens of times per second to exhaust server CPU or trigger race conditions.",
                        f"Out-of-Order State Invocation: Firing '{leaf}' when the player is dead, in lobby, or has not met gameplay prerequisites.",
                        "Oversized Payload DoS: Sending megabyte-sized strings or deeply nested tables to spike server memory.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": f"3. Game Impact for {readable_name}",
                    "summary": f"If '{leaf}' mutates game state or triggers heavy server work, unvalidated calls can disrupt the server.",
                    "points": [
                        "Unhandled Luau type errors spamming server output or breaking shared handler threads.",
                        "State desync or unauthorized gameplay actions inside the '{readable_name}' feature.",
                        "Server lag spikes if unthrottled calls spawn instances or query DataStores.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Search Studio (Ctrl+Shift+F) for '{leaf}' and verify these 4 server guards:",
                    "points": [
                        "Add a per-player os.clock() cooldown table (cleaned up on PlayerRemoving).",
                        "Validate typeof() for every parameter, reject NaN (x ~= x), and cap string/table sizes.",
                        "Verify player gameplay state (alive, cooldown ready, owns prerequisite) on the server.",
                        "Ensure all calculations (rewards, damage, prices, positions) use server-owned tables.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"-- Responsible ServerScript: search Studio (Ctrl+Shift+F) for '{leaf}'\n"
                f"{path_str}.OnServerEvent:Connect(function(player, ...)\n"
                f"    -- VULNERABLE: Missing per-player cooldown, typeof() validation, or server state check\n"
                f"    -- Review all arguments received by '{leaf}' and validate strictly on the server.\n"
                f"end)"
            ),
        }

    # Developer hygiene / general static or runtime finding
    return {
        "domain_label": "Developer Code Hygiene & Architecture",
        "risk_profile": {
            "exploitability": "Low (Internal Code Health)",
            "blast_radius": "Maintainability & Reliability",
            "attack_complexity": "N/A (Developer Quality)",
            "surface_type": category or "Luau Code",
        },
        "studio_search_queries": [leaf] if leaf != "Endpoint" else [category or "Script"],
        "overviews": [
            {
                "id": "mechanic",
                "tag": "ROOT CAUSE",
                "title": f"1. Root Cause Analysis ({leaf})",
                "summary": flaw or f"Code hygiene or architectural finding detected at {path_str}.",
                "points": [
                    f"Target location: {path_str}.",
                    f"Category: {category or 'Developer Hygiene'}.",
                ],
            },
            {
                "id": "vectors",
                "tag": "RISK",
                "title": "2. Operational & Runtime Risks",
                "summary": abuse or "Deprecated APIs, missing strict typing, or unhandled runtime edges increase crash and regression rates.",
                "points": [
                    "Silent runtime failures or unexpected nil dereferences under load.",
                    "Harder maintenance and slower onboarding for team developers.",
                ],
            },
            {
                "id": "impact",
                "tag": "IMPACT",
                "title": "3. Reliability Impact",
                "summary": "Resolving internal developer warnings keeps live servers stable and predictable.",
                "points": [
                    "Prevents cascading errors in shared ServerScriptService modules.",
                    "Improves Luau type-checker coverage and Studio diagnostics.",
                ],
            },
            {
                "id": "checklist",
                "tag": "FIX STEPS",
                "title": "4. Remediation Checklist",
                "summary": fix or "Apply the recommended Luau refactor in the owning script.",
                "points": [
                    f"Open {path_str} in Roblox Studio.",
                    fix or "Replace deprecated calls with modern task.* / Luau strict-typed equivalents.",
                    "Re-run rcdebug static scanner to confirm zero remaining warnings.",
                ],
            },
        ],
        "vulnerable_pattern": (
            f"-- Responsible script / instance: {path_str}\n"
            f"-- Flaw: {flaw}\n"
            f"-- Recommended action: {fix}"
        ),
    }


def classify_finding_surface(
    category: str,
    title: str,
    path: str,
    flaw: str,
    abuse: str,
    fix: str = "",
    code_example: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Classifies a finding into 'exploit' (client-reachable surface that executor
    scripts can abuse) or 'developer' (code quality, memory leaks, deprecated APIs),
    runs semantic domain analysis to generate 4 distinct overview sections, risk profile,
    Studio search queries, vulnerable server pattern, and a tailored server Luau fix.
    """
    cat_low = (category or "").lower()
    blob = f"{category} {title} {path} {flaw} {abuse}".lower()

    is_dev_only = (
        cat_low.startswith("luapack:")
        or cat_low.startswith("luaupack:")
        or cat_low in ("memorydiff", "memoryleak", "performance", "commandhistory", "robloxruntimeerror")
        or any(k in blob for k in ("deprecated", "--!strict", "shadowed global", "redundant getservice", "debris:additem"))
    )
    is_exploit = (not is_dev_only) and any(tok in blob for tok in _EXPLOIT_SURFACE_TOKENS)
    surface = "exploit" if is_exploit else "developer"

    path_str = (path or "Unknown").strip()
    leaf, _ = _extract_leaf_and_var(path_str)
    domain = _detect_finding_domain(category, title, path_str, flaw, abuse, fix)

    if path_str.endswith((".luau", ".lua")) or "::" in path_str or "ServerScriptService" in path_str:
        responsible_script = path_str
    elif "ReplicatedStorage" in path_str or "remote" in cat_low or "remote" in title.lower():
        responsible_script = (
            f"Server Script listening to {path_str}.OnServerEvent / OnServerInvoke "
            f"(search Studio Ctrl+Shift+F for '{leaf}')"
        )
    elif "Workspace" in path_str and ("unanchored" in title.lower() or "networkownership" in cat_low or "physics" in cat_low):
        responsible_script = f"Workspace Instance '{path_str}' (search Studio for '{leaf}' spawner script)"
    elif "Players." in path_str or "Attribute:" in path_str or "value" in title.lower():
        responsible_script = f"Server Player-Data Script setting '{leaf}' ({path_str})"
    else:
        responsible_script = path_str

    intel = _build_domain_intelligence(
        domain=domain,
        leaf=leaf,
        path_str=path_str,
        category=category,
        flaw=flaw,
        abuse=abuse,
        fix=fix,
    )

    fix_code = build_tailored_server_fix(
        category=category,
        title=title,
        path=path_str,
        flaw=flaw,
        fix=fix,
        existing_code=code_example,
    )

    existing_spec = metadata.get("contract_spec") if isinstance(metadata, dict) else None
    if isinstance(existing_spec, dict):
        contract_spec = existing_spec
    else:
        contract_spec = build_contract_specification(
            script_path=path_str,
            title=title,
            category=category,
            flaw=flaw,
            abuse=abuse,
            fix=fix,
            line_number=metadata.get("line_number") if isinstance(metadata, dict) else None,
            remote_name=str(metadata.get("remote_name", "")) if isinstance(metadata, dict) else leaf,
        )

    kid_summary = kid_friendly_exploit_summary(domain)
    raw_vuln_pattern = contract_spec["vulnerable_handler_code"] if isinstance(existing_spec, dict) else intel["vulnerable_pattern"]
    if not raw_vuln_pattern.startswith("-- Simple summary:"):
        raw_vuln_pattern = f"{kid_summary}\n{raw_vuln_pattern}"

    return {
        "surface": surface,
        "domain_key": domain,
        "domain_label": intel["domain_label"],
        "risk_profile": intel["risk_profile"],
        "overviews": intel["overviews"],
        "studio_search_queries": intel["studio_search_queries"],
        "responsible_script": responsible_script,
        "vulnerable_pattern": raw_vuln_pattern,
        "fix_code": fix_code,
        "contract_spec": contract_spec,
    }


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
                findings_data = [
                    {
                        **f.to_dict(),
                        "rank": f.rank,
                        **classify_finding_surface(
                            f.category, f.title, f.path, f.flaw, f.abuse, f.fix, f.code_example, f.metadata
                        ),
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
            surf_filter = (qs.get("surface", [""])[0] or "").strip().lower()
            limit = min(200, max(1, int(qs.get("limit", ["50"])[0] or 50)))
            raw_hits = catalog.search(q, limit=limit * 6 if (sev or surf_filter) else limit)
            if sev in ("CRITICAL", "WARN", "INFO"):
                raw_hits = [s for s in raw_hits if matches_filter(s.severity, sev)]
            enriched_hits = []
            for s in raw_hits:
                meta = classify_finding_surface(s.category, s.title, s.domain, s.flaw, s.abuse, s.fix, s.code_example)
                if surf_filter in ("developer", "exploit") and meta["surface"] != surf_filter:
                    continue
                enriched_hits.append(
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
                        **meta,
                    }
                )
                if len(enriched_hits) >= limit:
                    break
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self._send_json(
                200,
                {
                    "query": q,
                    "elapsed_ms": round(elapsed_ms, 3),
                    "results": enriched_hits,
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
                    else "Clipboard helper unavailable; copy the script from the Client Script drawer.",
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
            script_name = str(data.get("script_name", "StaticSnippet.luau"))
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
