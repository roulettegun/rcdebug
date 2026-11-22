"""
Interactive Web Workbench for rcdebug (rcdebug --ui).

Follows DESIGN.md (Calm Modern Mac App Shell, Dial: ENERGY 2 / RHYTHM 2 / MOTION 3).
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
        <span class="nav-count">120k</span>
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

      function renderSheetBody() {
        const body = document.getElementById("sheet-body");
        const f = state.activeFinding;
        if (state.sheetTab === "payload" || !f) {
          document.getElementById("sheet-kicker").textContent = "100% Client-Sided Luau Bridge";
          document.getElementById("sheet-title").textContent = "Client Diagnostic Script";
          body.innerHTML =
            '<div class="detail-block">' +
              '<p class="detail-text" style="color:var(--text-muted);margin-bottom:12px;">Paste this script into Roblox Developer Console, executor, or Studio Command Bar. Uses zero server-only APIs and falls back to local Roblox logs automatically.</p>' +
              '<button type="button" class="btn btn-primary" id="btn-sheet-copy-payload">Copy Script to Clipboard</button>' +
              '<pre class="code-box">' + esc(state.luauScript || "Loading script...") + '</pre>' +
            '</div>';
          document.getElementById("btn-sheet-copy-payload").addEventListener("click", function() {
            document.getElementById("btn-copy-luau").click();
          });
          return;
        }

        const rankLabel = f.rank && f.rank < 999999 ? ("Rank #" + f.rank) : f.category;
        const surfLabel = (f.surface === "exploit") ? "EXPLOIT SURFACE" : "DEVELOPER";
        document.getElementById("sheet-kicker").textContent = f.severity + " · " + surfLabel + " · " + f.category + " · " + rankLabel;
        document.getElementById("sheet-title").textContent = f.title;

        if (state.sheetTab === "abuse") {
          const targetObj = f.responsible_script || f.path || "Unknown";
          const surfaceNote = f.surface === "exploit"
            ? "Client-reachable surface that an executor can target if server-side checks are missing."
            : "Developer hygiene or server architecture issue (not directly callable from a client executor).";
          const vulnPreview = f.vulnerable_pattern || (
            "-- Responsible script / instance surface:\n" +
            "--   " + targetObj + "\n" +
            "-- Risk Summary:\n" +
            "--   " + (f.abuse || f.flaw) + "\n" +
            "-- Inspect this script in Roblox Studio and apply the Server Fix tab."
          );
          body.innerHTML =
            '<div class="detail-block"><div class="detail-label">Surface Classification</div><p class="detail-text">' + esc(surfaceNote) + '</p></div>' +
            '<div class="detail-block"><div class="detail-label">Responsible Script / Instance to Fix</div><p class="row-sub" style="white-space:normal;color:var(--text);">' + esc(targetObj) + '</p></div>' +
            '<div class="detail-block"><div class="detail-label">How Executor Scripts Abuse This Surface</div><p class="detail-text">' + esc(f.abuse || f.flaw) + '</p></div>' +
            '<div class="detail-block">' +
              '<div class="detail-label">Vulnerable Server/Game Pattern to Locate &amp; Patch</div>' +
              '<pre class="code-box">' + esc(vulnPreview) + '</pre>' +
            '</div>';
          return;
        }

        if (state.sheetTab === "fix") {
          const code = f.code_example || ("-- Recommended server-side fix for " + f.path + "\n-- " + f.fix);
          body.innerHTML =
            '<div class="detail-block"><div class="detail-label">Recommended Fix</div><p class="detail-text">' + esc(f.fix) + '</p></div>' +
            '<div class="detail-block">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                '<div class="detail-label" style="margin:0;">Server Luau Pattern</div>' +
                '<button type="button" class="btn" id="btn-copy-fix-snippet">Copy Luau Fix</button>' +
              '</div>' +
              '<pre class="code-box">' + esc(code) + '</pre>' +
            '</div>';
          document.getElementById("btn-copy-fix-snippet").addEventListener("click", function() {
            if (navigator.clipboard) navigator.clipboard.writeText(code).catch(function() {});
            toast("Copied Luau fix snippet to clipboard");
          });
          return;
        }

        body.innerHTML =
          '<div class="detail-block"><div class="detail-label">Instance / Script Path</div><p class="row-sub" style="white-space:normal;">' + esc(f.path) + '</p></div>' +
          '<div class="detail-block"><div class="detail-label">Architectural Flaw</div><p class="detail-text">' + esc(f.flaw) + '</p></div>' +
          '<div class="detail-block"><div class="detail-label">Client Abuse Vector</div><p class="detail-text">' + esc(f.abuse) + '</p></div>' +
          '<div class="detail-block"><div class="detail-label">Remediation</div><p class="detail-text">' + esc(f.fix) + '</p></div>';
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
        root.innerHTML = '<div style="padding:20px 0;color:var(--text-muted);">Searching 120,000 flaws...</div>';
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
                  responsible_script: it.responsible_script,
                  vulnerable_pattern: it.vulnerable_pattern,
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
        { name: "Search 120,000 Flaw Catalog", hint: "View", fn: function() { switchView(document.getElementById("nav-catalog")); } },
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


def classify_finding_surface(
    category: str,
    title: str,
    path: str,
    flaw: str,
    abuse: str,
) -> dict[str, str]:
    """
    Classifies a finding into 'exploit' (client-reachable surface that executor
    scripts can abuse) or 'developer' (code quality, memory leaks, deprecated APIs),
    and identifies the responsible script/instance surface and vulnerable server
    pattern so the developer can locate and patch it immediately.
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

    path_str = path or "Unknown"
    leaf = path_str.split(".")[-1].split("::")[-1].strip() or "Endpoint"

    if path_str.endswith((".luau", ".lua")) or "::" in path_str or "ServerScriptService" in path_str:
        responsible_script = path_str
    elif "ReplicatedStorage" in path_str or "Remote" in cat_low or "Remote" in title:
        responsible_script = (
            f"Server Script listening to {path_str}.OnServerEvent / OnServerInvoke "
            f"(search Studio for '{leaf}')"
        )
    elif "Workspace" in path_str and ("Unanchored" in title or "NetworkOwnership" in category or "Physics" in category):
        responsible_script = f"Workspace Instance '{path_str}' (or ServerScript spawning '{leaf}')"
    elif "Players." in path_str or "Attribute:" in path_str or "Value" in title:
        responsible_script = f"Server Player-Data Script managing '{leaf}' ({path_str})"
    else:
        responsible_script = path_str

    if "Remote" in category or "Remote" in title or "OnServerEvent" in blob:
        vulnerable_pattern = (
            f"-- Vulnerable server handler pattern to locate in Studio (search for '{leaf}'):\n"
            f"{path_str}.OnServerEvent:Connect(function(player, ...)\n"
            f"    -- FLAW: Accepts client arguments without typeof(), range, or os.clock() cooldown checks\n"
            f"    -- An executor can fire this RemoteEvent directly with arbitrary values or spam it.\n"
            f"end)"
        )
    elif "NetworkOwnership" in category or "Unanchored" in title or "Physics" in category:
        vulnerable_pattern = (
            f"-- Vulnerable physics surface in Workspace:\n"
            f"-- Instance: {path_str}\n"
            f"-- FLAW: Anchored = false with automatic client network ownership.\n"
            f"-- Nearby clients/executors gain physics authority over '{leaf}' and can move/fling it.\n"
            f"-- Fix in server script: part:SetNetworkOwner(nil) or set Anchored = true."
        )
    elif "StateReplication" in category or "Value" in title or "Attribute:" in path_str:
        vulnerable_pattern = (
            f"-- Vulnerable client-visible state surface:\n"
            f"-- Instance: {path_str}\n"
            f"-- FLAW: Server scripts that read '{leaf}' from Character/Player ValueBase instead of\n"
            f"-- an authoritative ServerScriptService table can be desynced or spoofed locally."
        )
    elif "loadstring" in blob:
        vulnerable_pattern = (
            f"-- Vulnerable dynamic code execution in {responsible_script}:\n"
            f"loadstring(untrustedInput)() -- Remove loadstring() and disable ServerScriptService.LoadStringEnabled"
        )
    elif "SetAsync" in blob or "DataStore" in category:
        vulnerable_pattern = (
            f"-- Vulnerable non-atomic persistence in {responsible_script}:\n"
            f"dataStore:SetAsync(key, value) -- Replace with atomic UpdateAsync() + session locking"
        )
    else:
        vulnerable_pattern = (
            f"-- Responsible target: {responsible_script}\n"
            f"-- Flaw: {flaw}\n"
            f"-- Patch: {abuse or 'Inspect and apply the Server Fix tab.'}"
        )

    return {
        "surface": surface,
        "responsible_script": responsible_script,
        "vulnerable_pattern": vulnerable_pattern,
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
                        **classify_finding_surface(f.category, f.title, f.path, f.flaw, f.abuse),
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
                meta = classify_finding_surface(s.category, s.title, s.domain, s.flaw, s.abuse)
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
