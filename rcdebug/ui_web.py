"""
Interactive Website & Web Application Security Workbench for rcdebug (rcdebug --ui-web).

Adapts the full rcdebug --ui experience for websites and web applications:
- 150,000 Website Flaw Catalog (RCW-000001 .. RCW-150000) with sub-10ms mmap index
- 120 Web Debugger Probes (WDP-001 .. WDP-120 across OWASP, React/Next.js, WCAG, Web Vitals)
- Developer vs Exploit surface sub-tabs under Critical, Warning, and Info
- 11-Domain Semantic Multi-Overview Engine (4 distinct overview cards per finding)
- 4-Section Web Handler Unit Test & Contract Specification (JS/TS Guard Module + console.assert())
- Offline Browser DevTools Console QA Test Runner (zero external HTTP calls)
- Parallel static web project directory & code snippet scanner (.html, .js, .jsx, .ts, .tsx, .css, .py)
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
from .client_bridge import DebugReportHandler, RuntimeBridgeServer
from .exporter import export_markdown_report, generate_markdown_report
from .learner import CommandHistory
from .models import AuditSession, SeverityFilter, matches_filter
from .terminal import BOLD, CYAN, DIM, GREEN, RESET, YELLOW, copy_to_clipboard, normalize_filter_label, print_banner
from .ui import UI_HTML_DOCUMENT
from .web_catalog import (
     _detect_web_domain,
    audit_local_web_path,
    audit_web_source,
    build_browser_qa_runner_script,
    build_web_contract_specification,
    get_web_catalog,
    get_web_debugger_pack,
    kid_friendly_web_exploit_summary,
    simulate_web_audit_traffic,
)

_WEB_EXPLOIT_TOKENS = (
    "xss",
    "innerhtml",
    "dangerouslysetinnerhtml",
    "eval",
    "sql",
    "nosql",
    "idor",
    "ownership",
    "checkout",
    "price",
    "coupon",
    "discount",
    "payment",
    "jwt",
    "token",
    "localstorage",
    "cookie",
    "csrf",
    "samesite",
    "cors",
    "csp",
    "redirect",
    "ssrf",
    "secret",
    "apikey",
    "webhook",
    "proto",
    "prototype",
    "auth",
    "apisecurity",
    "domsecurity",
    "datasecurity",
    "secretexposure",
    "codeexecution",
)


def _tokenize_web_ident(text: str) -> list[str]:
    if not text:
        return []
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [tok.lower() for tok in re.findall(r"[A-Za-z0-9]+", spaced) if len(tok) >= 2]


def _build_web_domain_intelligence(
    domain: str,
    leaf: str,
    path_str: str,
    category: str,
    flaw: str,
    abuse: str,
    fix: str,
) -> dict[str, Any]:
    tokens = _tokenize_web_ident(leaf)
    readable = " ".join(t.capitalize() for t in tokens) if tokens else leaf
    base_queries = [leaf]
    if ":" in leaf:
        base_queries = [leaf.split(":")[0]]
    if len(tokens) >= 2:
        longest = max(tokens, key=len, default="")
        if longest and longest not in base_queries:
            base_queries.append(longest)

    if domain == "xss_dom":
        return {
            "domain_label": "DOM XSS & Script Injection",
            "risk_profile": {
                "exploitability": "Critical (Client Script Execution)",
                "blast_radius": "All Active User Sessions",
                "attack_complexity": "Low (Crafted Input / URL)",
                "surface_type": "DOM HTML / JS Sink",
            },
            "studio_search_queries": [*base_queries, "dangerouslySetInnerHTML", "innerHTML"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) renders or evaluates untrusted content directly inside the browser DOM "
                        f"without HTML sanitization or context-aware escaping. When user-controlled strings reach an HTML sink, "
                        f"the browser executes embedded JavaScript under your site's origin."
                    ),
                    "points": [
                        f"Target component/sink: {path_str}.",
                        flaw or "Raw HTML or dynamic script evaluation bypasses framework auto-escaping.",
                        "Any user-editable field (comments, profile names, URL query params) reaching this sink triggers XSS.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Attacker Vectors for {leaf}",
                    "summary": f"Attackers probing '{leaf}' exploit unescaped DOM sinks through:",
                    "points": [
                        "Stored / Reflected Markup Injection: Submitting <img src=x onerror=...> or <svg onload=...> payloads into user fields.",
                        "Session & Storage Theft: Reading localStorage tokens, non-HttpOnly cookies, or CSRF nonces from victim browsers.",
                        "Forced Authenticated Actions: Calling fetch('/api/...') directly from the victim's authenticated session.",
                        "javascript: URI Injection: Passing 'javascript:...' into dynamic href or iframe src attributes.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Application Impact & Session Blast Radius",
                    "summary": "A single DOM XSS sink compromises the confidentiality and integrity of every user who views the affected page.",
                    "points": [
                        "Full account takeover of customers or administrators viewing injected content.",
                        "Unauthorized API mutations, Phishing overlays, or credential harvesting inside your trusted domain.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Search your repo (Cmd+Shift+F) for '{base_queries[0]}' and harden the sink:",
                    "points": [
                        "Replace innerHTML / dangerouslySetInnerHTML with plain textContent or standard JSX {variable} bindings.",
                        "If rich HTML is required, sanitize with DOMPurify.sanitize(html, { USE_PROFILES: { html: true } }).",
                        "Block javascript: and data: URLs in dynamic href/src attributes.",
                        "Deploy a strict nonce-based Content-Security-Policy header to prevent inline script execution.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"// Located in {path_str}\n"
                f"// VULNERABLE: Raw HTML injected into DOM without DOMPurify sanitization\n"
                f"container.innerHTML = userSuppliedContent;"
            ),
        }

    if domain == "economy_checkout":
        return {
            "domain_label": "Checkout, Pricing & Payment Integrity",
            "risk_profile": {
                "exploitability": "Critical (Parameter Tampering)",
                "blast_radius": "Revenue, Orders & Wallet Balances",
                "attack_complexity": "Low (Modified JSON Body)",
                "surface_type": "Checkout / Billing API Route",
            },
            "studio_search_queries": [*base_queries, "req.body", "price", "discount"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) processes checkout, cart, coupon, or balance mutations while trusting "
                        f"client-supplied price, quantity, or discount fields from the request body."
                    ),
                    "points": [
                        f"Billing endpoint: {path_str}.",
                        "Any JSON field sent from the browser can be intercepted and modified in DevTools or an HTTP proxy.",
                        "Floating-point edge cases (NaN, Infinity, negative numbers) bypass naive 'total >= 0' checks.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Attacker Vectors for {leaf}",
                    "summary": f"Clients tampering with '{leaf}' requests test four high-impact billing bypasses:",
                    "points": [
                        "Negative Quantity / Negative Price Injection: Sending quantity: -5 so total = price * quantity credits the user's balance.",
                        "Client Price Override: Modifying unitPrice: 0.01 or discountAmount: 99999 in the POST payload.",
                        "NaN / Float Precision Bypass: Passing NaN or fractional quantities (0.0001) to bypass integer inventory deductions.",
                        "Concurrent Coupon Replay: Sending 20 parallel POST requests to redeem a single-use promo code multiple times.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Business & Financial Blast Radius",
                    "summary": "Unvalidated checkout or wallet endpoints cause direct financial loss and accounting corruption.",
                    "points": [
                        "Paid products, subscriptions, or credits fulfilled for $0.00.",
                        "Infinite wallet balance minting via negative transfer/purchase amounts.",
                        "Corrupted database ledger records when NaN or negative totals are committed.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Audit '{path_str}' and enforce server-authoritative pricing:",
                    "points": [
                        "Look up item prices and coupon rules strictly from the server database by itemId; ignore client price fields.",
                        "Validate Number.isFinite(qty) && Math.floor(qty) === qty && qty >= 1 && qty <= MAX_QTY.",
                        "Execute balance deductions and coupon redemptions inside a single atomic database transaction with row locking.",
                        "Require an Idempotency-Key header and per-user rate limit on all payment/checkout routes.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"// Located in {path_str}\n"
                f"const {{ itemId, quantity, unitPrice, discount }} = req.body;\n"
                f"// VULNERABLE: Trusts client-supplied unitPrice/discount and lacks finite integer bounds on quantity\n"
                f"const total = (unitPrice * quantity) - discount;"
            ),
        }

    if domain == "idor_access":
        return {
            "domain_label": "Broken Access Control & IDOR",
            "risk_profile": {
                "exploitability": "Critical (ID Enumeration)",
                "blast_radius": "Multi-Tenant Customer Data",
                "attack_complexity": "Low (Change ID Parameter)",
                "surface_type": "Authenticated Resource Route",
            },
            "studio_search_queries": [*base_queries, "req.params", "findUnique", "userId"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) fetches or updates a database record using an ID from req.params, req.query, "
                        f"or req.body without verifying that the record belongs to the currently authenticated session.userId."
                    ),
                    "points": [
                        f"Resource endpoint: {path_str}.",
                        "Checking that a user is logged in (authentication) is not the same as checking they own the target record (authorization).",
                        "Sequential or predictable IDs allow trivial horizontal privilege escalation across accounts.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Attacker Vectors for {leaf}",
                    "summary": f"Attackers abuse missing ownership checks on '{leaf}' via:",
                    "points": [
                        "Horizontal IDOR Read: Iterating /api/orders/1001, 1002, 1003 to scrape other users' private records and PII.",
                        "Unauthorized State Mutation: Sending PUT/DELETE with another user's resourceId to modify or delete their data.",
                        "Tenant / Org Switching: Passing another organization's orgId or tenantId in the JSON body.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Privacy & Compliance Blast Radius",
                    "summary": "Broken object-level authorization is the #1 OWASP API vulnerability (API1:2023).",
                    "points": [
                        "Cross-account data breach exposing customer PII, invoices, messages, or private files.",
                        "Unauthorized modification or deletion of other tenants' resources.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Harden object ownership checks in '{path_str}':",
                    "points": [
                        "Always read the caller identity from the verified server session (session.userId), never from req.body.userId.",
                        "Include owner/tenant scoping directly in the query: WHERE id = $1 AND user_id = $2.",
                        "Use random UUIDv4/ULID primary keys alongside strict ownership checks.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"// Located in {path_str}\n"
                f"// VULNERABLE: Queries record by req.params.id without verifying ownerId === session.userId\n"
                f"const record = await db.orders.findUnique({{ where: {{ id: req.params.id }} }});"
            ),
        }

    if domain == "auth_session":
        return {
            "domain_label": "Authentication & Session Token Storage",
            "risk_profile": {
                "exploitability": "High (Token Exfiltration)",
                "blast_radius": "User Account Sessions",
                "attack_complexity": "Low (JS Storage Read)",
                "surface_type": "Auth / Session Storage",
            },
            "studio_search_queries": [*base_queries, "localStorage", "sessionStorage", "cookie"],
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": (
                        f"'{leaf}' ({path_str}) persists or handles authentication tokens in client-accessible browser storage "
                        f"(localStorage / sessionStorage) or cookies missing HttpOnly/Secure flags."
                    ),
                    "points": [
                        f"Auth location: {path_str}.",
                        "Everything in localStorage and sessionStorage is readable by any JavaScript running on the origin.",
                        "HttpOnly cookies isolate session credentials from document.cookie and third-party scripts.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Attacker Vectors for {leaf}",
                    "summary": "Exposed client-side session tokens enable:",
                    "points": [
                        "XSS Token Harvesting: Any XSS or compromised analytics/CDN script reads localStorage.getItem('token').",
                        "Persistent Session Replay: Long-lived refresh tokens copied from browser storage work from any external machine.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Session Integrity Blast Radius",
                    "summary": "Turns any minor script injection or dependency flaw into instant full-account compromise.",
                    "points": [
                        "Silent takeover of active user and admin accounts without needing the user's password.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": f"Move session persistence in '{path_str}' to secure server cookies:",
                    "points": [
                        "Remove localStorage.setItem / sessionStorage.setItem for JWTs, access tokens, and refresh tokens.",
                        "Issue session tokens via Set-Cookie with HttpOnly; Secure; SameSite=Lax; Path=/.",
                        "Rotate session IDs on login and enforce short access-token lifetimes.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"// Located in {path_str}\n"
                f"// VULNERABLE: Session JWT stored in client-readable localStorage\n"
                f"localStorage.setItem('access_token', response.jwt);"
            ),
        }

    if domain in ("cors_headers", "csrf_cookies", "secrets_env", "sql_database", "ssrf_redirect"):
        label_map = {
            "cors_headers": "CORS, CSP & HTTP Security Headers",
            "csrf_cookies": "CSRF & Cookie SameSite Policy",
            "secrets_env": "Secrets, API Keys & Environment Hygiene",
            "sql_database": "SQL / ORM Query Parameterization",
            "ssrf_redirect": "SSRF & Open Redirect Validation",
        }
        return {
            "domain_label": label_map.get(domain, "Web Platform Security"),
            "risk_profile": {
                "exploitability": "High (Boundary Bypass)",
                "blast_radius": "Backend & Browser Origin Trust",
                "attack_complexity": "Low (Crafted Request)",
                "surface_type": category or "Web Security Boundary",
            },
            "studio_search_queries": base_queries,
            "overviews": [
                {
                    "id": "mechanic",
                    "tag": "MECHANIC",
                    "title": f"1. Mechanic & Root Cause ({leaf})",
                    "summary": flaw or f"Security boundary issue detected at {path_str}.",
                    "points": [
                        f"Location: {path_str}.",
                        "Missing strict allowlists or parameterization weakens origin and server isolation.",
                    ],
                },
                {
                    "id": "vectors",
                    "tag": "ABUSE",
                    "title": f"2. Concrete Attacker Vectors for {leaf}",
                    "summary": abuse or "Attackers can craft cross-origin or malformed inputs to bypass boundary assumptions.",
                    "points": [
                        abuse or "Boundary bypass via crafted input or untrusted origin.",
                        "Automated scanners actively probe for wildcard CORS, exposed keys, open redirects, and raw SQL templates.",
                    ],
                },
                {
                    "id": "impact",
                    "tag": "IMPACT",
                    "title": "3. Application Impact & Blast Radius",
                    "summary": "Compromises server data isolation, third-party API quotas, or cross-origin browser protections.",
                    "points": [
                        "Unauthorized data disclosure or forged state-changing requests.",
                    ],
                },
                {
                    "id": "checklist",
                    "tag": "FIX STEPS",
                    "title": f"4. Developer Patch & Verification Checklist for {leaf}",
                    "summary": fix or f"Apply strict server-side validation in {path_str}:",
                    "points": [
                        fix or "Enforce explicit allowlists, parameterized queries, and strict response headers.",
                        "Verify with the generated Guard Module & console.assert() unit test in the Server Fix tab.",
                    ],
                },
            ],
            "vulnerable_pattern": (
                f"// Located in {path_str}\n"
                f"// Flaw: {flaw}\n"
                f"// Abuse: {abuse}"
            ),
        }

    # Memory / WCAG / Frontend Developer Hygiene
    return {
        "domain_label": "Frontend Memory, WCAG & Web Vitals",
        "risk_profile": {
            "exploitability": "Low (Internal Quality & UX)",
            "blast_radius": "Accessibility, CLS & Tab Memory",
            "attack_complexity": "N/A (Developer Quality)",
            "surface_type": category or "Frontend Component",
        },
        "studio_search_queries": base_queries,
        "overviews": [
            {
                "id": "mechanic",
                "tag": "ROOT CAUSE",
                "title": f"1. Root Cause Analysis ({leaf})",
                "summary": flaw or f"Frontend quality, memory lifecycle, or WCAG issue at {path_str}.",
                "points": [
                    f"Component/File: {path_str}.",
                    f"Category: {category}.",
                ],
            },
            {
                "id": "vectors",
                "tag": "FAILURE MODE",
                "title": "2. User Experience & Runtime Failure Modes",
                "summary": abuse or "Uncleaned listeners leak memory across SPA navigation; missing alt/labels block assistive tech.",
                "points": [
                    "Progressive JS heap climb and dropped frames during long user sessions.",
                    "WCAG 2.2 AA audit failures for screen-reader and keyboard-only users.",
                ],
            },
            {
                "id": "impact",
                "tag": "IMPACT",
                "title": "3. Core Web Vitals & Accessibility Impact",
                "summary": "Directly impacts Lighthouse scores, mobile battery/RAM, and accessibility compliance.",
                "points": [
                    "Higher Cumulative Layout Shift (CLS) and Interaction to Next Paint (INP) latency.",
                ],
            },
            {
                "id": "checklist",
                "tag": "FIX STEPS",
                "title": f"4. Developer Remediation Checklist for {leaf}",
                "summary": fix or "Clean up side effects and add explicit accessibility attributes:",
                "points": [
                    fix or "Return cleanup functions from useEffect and add explicit alt/aria-label attributes.",
                    "Run the Offline Browser DevTools QA Script in Console to confirm [PASS].",
                ],
            },
        ],
        "vulnerable_pattern": (
            f"// Located in {path_str}\n"
            f"// Issue: {flaw}\n"
            f"// Fix: {fix}"
        ),
    }


def classify_web_finding_surface(
    category: str,
    title: str,
    path: str,
    flaw: str,
    abuse: str,
    fix: str = "",
    code_example: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cat_low = (category or "").lower()
    blob = f"{category} {title} {path} {flaw} {abuse}".lower()
    is_dev_only = cat_low in ("memoryleak", "accessibilitywcag", "webperformance", "codehygiene") or any(
        k in blob for k in ("wcag", "cls", "layout shift", "addeventlistener", "setinterval", "console.log")
    )
    is_exploit = (not is_dev_only) and any(tok in blob for tok in _WEB_EXPLOIT_TOKENS)
    surface = "exploit" if is_exploit else "developer"

    path_str = (path or "Unknown").strip()
    leaf = path_str.split("/")[-1].split("::")[-1].strip() or "Endpoint"
    domain = _detect_web_domain(category, title, path_str, flaw)

    responsible_script = f"Web Source / Route: {path_str} (search repo Cmd+Shift+F for '{leaf.split(':')[0]}')"
    intel = _build_web_domain_intelligence(domain, leaf, path_str, category, flaw, abuse, fix)

    existing_spec = metadata.get("contract_spec") if isinstance(metadata, dict) else None
    if isinstance(existing_spec, dict):
        contract_spec = existing_spec
    else:
        contract_spec = build_web_contract_specification(
            script_path=path_str,
            title=title,
            category=category,
            flaw=flaw,
            abuse=abuse,
            fix=fix,
            line_number=metadata.get("line_number") if isinstance(metadata, dict) else None,
            endpoint_name=leaf,
        )

    kid_summary = kid_friendly_web_exploit_summary(domain)
    raw_vuln = contract_spec["vulnerable_handler_code"] if isinstance(existing_spec, dict) else intel["vulnerable_pattern"]
    if not raw_vuln.startswith("// Simple summary:"):
        raw_vuln = f"{kid_summary}\n{raw_vuln}"

    return {
        "surface": surface,
        "domain_key": domain,
        "domain_label": intel["domain_label"],
        "risk_profile": intel["risk_profile"],
        "overviews": intel["overviews"],
        "studio_search_queries": intel["studio_search_queries"],
        "responsible_script": responsible_script,
        "vulnerable_pattern": raw_vuln,
        "fix_code": contract_spec["patched_guard_and_unit_test_code"],
        "contract_spec": contract_spec,
    }


def build_ui_web_html() -> str:
    """
    Adapts the calm modern app shell (UI_HTML_DOCUMENT) for Website & Web Application
    auditing (rcdebug --ui-web) with 150,000 web flaws and Browser DevTools QA runner.
    """
    html = UI_HTML_DOCUMENT.replace("__VERSION__", __version__)
    replacements = [
        ("<title>rcdebug Workbench</title>", "<title>rcdebug Web Workbench (--ui-web)</title>"),
        ("<span>rcdebug</span>", "<span>rcdebug web</span>"),
        ('<span class="nav-count">600k</span>', '<span class="nav-count">150k</span>'),
        ("<span>Luau Probes</span>", "<span>Web Probes</span>"),
        (">Client Script</button>", ">Browser QA Script</button>"),
        (">Copy Luau Script</button>", ">Copy Browser QA Script</button>"),
        ("Filter by remote, instance, or RCD code...", "Filter by route, component, file, or RCW code..."),
        ("Latest Client Memory", "Latest JS Heap Memory"),
        ("Workspace Instances", "DOM Nodes"),
        ("Profiled Remotes", "Profiled API Routes"),
        ("Remote Traffic Profiler (calls/sec)", "API Route Traffic Profiler (req/sec)"),
        ("No RemoteEvent traffic recorded yet.", "No API route traffic recorded yet."),
        ("Audit Local Place (.rbxlx / .rbxmx) or Scripts Folder", "Audit Local Website Project Folder or File (.html, .ts, .tsx, .js, .py)"),
        ("/Users/you/MyGame/src or ./place.rbxlx", "/Users/you/my-website/src or ./index.html"),
        ("Audit Luau Source Directly", "Audit Web Source Directly (JS / TS / JSX / HTML / Express)"),
        ("Insert Sample Script", "Insert Sample Web Code"),
        ("-- Paste a Luau script here to test against 12 static rules and 120 debugger probes", "// Paste HTML, React/JSX, Express/Next.js route, or JS/TS code here to audit"),
        ("Roblox Studio Ctrl+Shift+F Search Queries (click to copy)", "VS Code / Project Cmd+Shift+F Search Queries (click to copy)"),
        ("Offline Roblox Studio QA Test Runner", "Offline Browser DevTools QA Test Runner"),
        ("Studio QA Test Script (Offline)", "Browser DevTools QA Test Script (Offline)"),
        ("Offline Studio QA Test Runner: paste into Roblox Studio Command Bar or StarterPlayerScripts during Play Solo / Local Server. Runs 100% locally with zero external HTTP calls and prints [PASS] or [FAIL] directly to the Studio Output window.", "Offline Browser DevTools QA Test Runner: paste into Chrome, Safari, or Firefox DevTools Console on localhost or staging. Runs 100% locally with zero external HTTP calls and prints [PASS] or [FAIL] directly to the Console."),
        ("Copy Studio QA Script", "Copy Browser QA Script"),
        ("4. Defensive Guard Module &amp; Studio assert() Unit Test", "4. Defensive JS/TS Guard Module &amp; console.assert() Unit Test"),
        ("Searching 600,000 flaws...", "Searching 150,000 website flaws..."),
        ("Search 600,000 Flaw Catalog", "Search 150,000 Web Flaw Catalog"),
        ("Browse 120 Luau Debugger Probes", "Browse 120 Web Security & WCAG Probes"),
        ("Copy Client Luau Script", "Copy Browser DevTools QA Script"),
        ("Expected typeof()", "Expected JS/TS typeof"),
        (
            'document.getElementById("input-luau-source").value =\n'
            '          \'local ReplicatedStorage = game:GetService("ReplicatedStorage")\\n\' +\n'
            '          \'local DataStoreService = game:GetService("DataStoreService")\\n\' +\n'
            '          \'local store = DataStoreService:GetDataStore("PlayerGold")\\n\\n\' +\n'
            '          \'ReplicatedStorage.Remotes.BuyItem.OnServerEvent:Connect(function(player, itemId, price)\\n\' +\n'
            '          \'    player.leaderstats.Gold.Value -= price\\n\' +\n'
            '          \'    store:SetAsync("user_" .. player.UserId, player.leaderstats.Gold.Value)\\n\' +\n'
            '          \'end)\\n\\n\' +\n'
            '          \'workspace.VaultPrompt.Triggered:Connect(function(player)\\n\' +\n'
            '          \'    loadstring("print(1)")()\\n\' +\n'
            '          \'end)\\n\';',
            'document.getElementById("input-luau-source").value =\n'
            '          \'app.post("/api/checkout", async (req, res) => {\\n\' +\n'
            '          \'  const price = req.body.price;\\n\' +\n'
            '          \'  const qty = req.body.qty;\\n\' +\n'
            '          \'  await db.$queryRawUnsafe(`UPDATE wallets SET balance = balance - ${price * qty}`);\\n\' +\n'
            '          \'  localStorage.setItem("jwt", req.body.token);\\n\' +\n'
            '          \'  document.getElementById("receipt").innerHTML = req.body.note;\\n\' +\n'
            '          \'});\\n\';',
        ),
    ]
    for old, new in replacements:
        html = html.replace(old, new)
    return html


class UIWebWorkbenchHandler(DebugReportHandler):
    """
    Serves the Website & Web Application Security Workbench (/ui, /api/*)
    and local telemetry endpoints (/report, /telemetry, /status, /shutdown).
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
        parsed = urlparse(self.path)
        route = parsed.path
        qs = parse_qs(parsed.query)

        if route in ("/", "/ui", "/ui-web"):
            accept = self.headers.get("Accept", "")
            if route in ("/ui", "/ui-web") or "text/html" in accept:
                self._send_html(200, build_ui_web_html())
                return

        if route in ("/", "/status", "/health"):
            counts = self.server.session.counts_by_severity()
            self._send_json(
                200,
                {
                    "status": "ok",
                    "tool": "rcdebug-web",
                    "mode": self.server.session.mode,
                    "findings_count": len(self.server.session.findings),
                    "severity_counts": counts,
                },
            )
            return

        if route == "/api/state":
            catalog = get_web_catalog()
            host, port = self.server.server_address[0], int(self.server.server_address[1])
            with self.server.lock:
                sorted_findings = sorted(self.server.session.findings, key=lambda f: f.sort_key())
                findings_data = [
                    {
                        **f.to_dict(),
                        "rank": f.rank,
                        **classify_web_finding_surface(
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
                    "luau_script": build_browser_qa_runner_script(),
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
            catalog = get_web_catalog()
            q = (qs.get("q", [""])[0] or "").strip()
            sev = (qs.get("severity", [""])[0] or "").strip().upper()
            surf_filter = (qs.get("surface", [""])[0] or "").strip().lower()
            limit = min(200, max(1, int(qs.get("limit", ["50"])[0] or 50)))
            raw_hits = catalog.search(q, limit=limit * 6 if (sev or surf_filter) else limit)
            if sev in ("CRITICAL", "WARN", "INFO"):
                raw_hits = [s for s in raw_hits if matches_filter(s.severity, sev)]
            enriched_hits = []
            for s in raw_hits:
                meta = classify_web_finding_surface(s.category, s.title, s.domain, s.flaw, s.abuse, s.fix, s.code_example)
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
            pack = get_web_debugger_pack()
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
            catalog = get_web_catalog()
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
            self._send_markdown("rcdebug_web_audit_report.md", md_text)
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
            script = build_browser_qa_runner_script()
            copied = copy_to_clipboard(script)
            self._send_json(
                200,
                {
                    "status": "ok",
                    "copied": copied,
                    "message": "Copied Offline Browser DevTools QA Script to macOS clipboard (pbcopy)."
                    if copied
                    else "Clipboard helper unavailable; copy the script from the Browser QA Script drawer.",
                },
            )
            return

        if route == "/api/simulate":
            host, port = self.server.server_address[0], int(self.server.server_address[1])
            threading.Thread(
                target=simulate_web_audit_traffic,
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
            added = audit_local_web_path(target, self.server.session, filter_level=self.server.filter_level)
            get_web_catalog().learner.learn_from_session(self.server.session, get_web_catalog())  # type: ignore[arg-type]
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
            script_name = str(data.get("script_name", "WebSnippet.tsx"))
            found = audit_web_source(script_name, source)
            added = 0
            with self.server.lock:
                for f in found:
                    if self.server.session.add_finding(f):
                        added += 1
            if added > 0:
                get_web_catalog().learner.learn_from_session(self.server.session, get_web_catalog())  # type: ignore[arg-type]
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


def bind_ui_web_workbench_server(
    host: str,
    preferred_port: int,
    session: AuditSession,
    filter_level: SeverityFilter = None,
    max_tries: int = 50,
) -> tuple[RuntimeBridgeServer, int, bool]:
    try:
        srv = RuntimeBridgeServer(
            (host, preferred_port),
            UIWebWorkbenchHandler,
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
                UIWebWorkbenchHandler,
                session=session,
                filter_level=filter_level,  # type: ignore[arg-type]
            )
            return srv, int(srv.server_address[1]), True
        except OSError:
            continue

    srv = RuntimeBridgeServer(
        (host, 0),
        UIWebWorkbenchHandler,
        session=session,
        filter_level=filter_level,  # type: ignore[arg-type]
    )
    return srv, int(srv.server_address[1]), True


def run_ui_web_mode(
    host: str = "127.0.0.1",
    port: int = 8765,
    filter_level: SeverityFilter = None,
    export_path: str | None = None,
    auto_clipboard: bool = True,
    simulate: bool = False,
    open_browser: bool = True,
) -> AuditSession:
    catalog = get_web_catalog()
    session = AuditSession(
        mode="ui-web",
        target_name=f"Website Security Workbench ({host}:{port})",
    )
    server, actual_port, used_fallback = bind_ui_web_workbench_server(
        host=host,
        preferred_port=port,
        session=session,
        filter_level=filter_level,
    )
    session.target_name = f"Website Security Workbench ({host}:{actual_port})"
    ui_url = f"http://{host}:{actual_port}/ui"

    print_banner(
        "WEBSITE SECURITY WORKBENCH (--ui-web)",
        subtitle=f"{ui_url} | {catalog.count():,} Website Flaw Signatures | Filter: {normalize_filter_label(filter_level)}",
    )
    if used_fallback:
        print(
            f"\n{YELLOW}{BOLD}⚠ Port {port} is in use by another process; "
            f"Web Workbench bound to {host}:{actual_port}.{RESET}"
        )

    qa_script = build_browser_qa_runner_script()
    if auto_clipboard:
        if copy_to_clipboard(qa_script):
            print(f"\n{GREEN}{BOLD}✔ Offline Browser DevTools QA script copied to macOS clipboard (pbcopy)!{RESET}")

    print(f"\n{BOLD}{GREEN}● Website Security Workbench active at:{RESET} {BOLD}{CYAN}{ui_url}{RESET}")
    print(f"{DIM}  Press Ctrl+C to stop the Web Workbench server.{RESET}\n")

    if open_browser and not simulate:
        threading.Timer(0.25, lambda: webbrowser.open(ui_url)).start()

    if simulate:
        sim_thread = threading.Thread(
            target=simulate_web_audit_traffic,
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
        print(f"\n{YELLOW}[rcdebug] Stopping Website Security Workbench...{RESET}")
    finally:
        server.server_close()

    if session.findings:
        catalog.learner.learn_from_session(session, catalog)  # type: ignore[arg-type]

    if export_path:
        saved = export_markdown_report(session, export_path, filter_level=filter_level)  # type: ignore[arg-type]
        print(f"{GREEN}{BOLD}✔ Exported Website Markdown audit report to:{RESET} {CYAN}{saved}{RESET}\n")

    return session
