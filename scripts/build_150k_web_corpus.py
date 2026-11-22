#!/usr/bin/env python3
"""
Deterministic builder for rcdebug/data/web_flaws_150000.txt.gz (exact 150,000 website flaws).
Strictly ordered:
  Tier 1 (RCW-000001 .. RCW-035000): CRITICAL (35,000)
  Tier 2 (RCW-035001 .. RCW-084000): WARN     (49,000)
  Tier 3 (RCW-084001 .. RCW-150000): INFO     (66,000)
"""

from __future__ import annotations

import gzip
from pathlib import Path

OUT_FILE = Path(__file__).resolve().parent.parent / "rcdebug" / "data" / "web_flaws_150000.txt.gz"

WEB_DOMAINS = [
    ("XSS", "DOMSecurity", [
        "innerhtml", "outerhtml", "dangerouslysetinnerhtml", "documentwrite", "insertadjacenthtml",
        "vhtml", "rawhtml", "markdown", "richtext", "wysiwyg", "comment", "bio", "profile",
        "username", "nickname", "avatar", "searchquery", "tooltip", "modal", "toast", "banner",
        "embed", "iframe", "srcdoc", "svg", "mathml", "href", "javascripturl", "dataurl",
        "onload", "onerror", "onclick", "onmouseover", "template", "handlebars", "ejs", "pug",
        "jinja", "hydration", "ssr", "sanitize", "dompurify",
    ]),
    ("Auth", "AuthSecurity", [
        "login", "signin", "signup", "register", "logout", "password", "passwd", "passcode",
        "pin", "otp", "totp", "mfa", "twofactor", "magiclink", "resetpassword", "forgotpassword",
        "jwt", "accesstoken", "refreshtoken", "idtoken", "session", "sessionid", "cookie",
        "setcookie", "httponly", "samesite", "bearer", "oauth", "oidc", "callback", "pkce",
        "apikey", "clientsecret", "privatekey", "webauthn", "passkey", "rememberme", "impersonate",
        "role", "admin", "superuser", "permission", "acl", "rbac", "scope", "claim",
    ]),
    ("API", "APISecurity", [
        "checkout", "payment", "stripe", "paypal", "invoice", "subscription", "billing", "refund",
        "wallet", "balance", "transfer", "payout", "withdraw", "deposit", "coupon", "discount",
        "promo", "voucher", "cart", "order", "price", "quantity", "amount", "total", "tax",
        "webhook", "graphql", "mutation", "resolver", "rest", "endpoint", "route", "controller",
        "middleware", "payload", "body", "query", "params", "headers", "multipart", "upload",
        "avatarupload", "import", "export", "batch", "bulk", "ratelimit", "throttle",
    ]),
    ("Database", "DataSecurity", [
        "sql", "postgres", "mysql", "sqlite", "prisma", "sequelize", "typeorm", "knex", "drizzle",
        "mongodb", "mongoose", "nosql", "redis", "dynamodb", "RawQuery", "queryraw", "execsql",
        "where", "orderBy", "groupBy", "limit", "offset", "cursor", "pagination", "filter",
        "sort", "join", "transaction", "lock", "optimisticlock", "migration", "seed", "backup",
        "tenant", "orgid", "accountid", "userid", "ownerid", "customerid", "projectid", "record",
    ]),
    ("Platform", "PlatformSecurity", [
        "cors", "csp", "contentsecuritypolicy", "hsts", "xframeoptions", "nosniff", "referrerpolicy",
        "permissionspolicy", "sri", "integrity", "crossorigin", "csrf", "xsrf", "origin", "Host",
        "forwardedfor", "realip", "proxy", "nginx", "cloudflare", "vercel", "netlify", "docker",
        "env", "dotenv", "processenv", "nextpublic", "viteenv", "redirect", "returnurl", "nexturl",
        "callbackurl", "fetch", "axios", "ssrf", "eval", "function", "proto", "prototype",
        "constructor", "merge", "assign", "clone", "deserialize", "jsonparse", "yaml", "xml",
    ]),
]

CRITICAL_PATTERNS = [
    (
        "UnvalidatedSink",
        "Unsanitized Input Reaching Dangerous Sink",
        "Handler or component for '{kw}' passes user-controlled data into an execution, HTML, or query sink without validation.",
        "Untrusted input in '{kw}' can inject arbitrary script markup, mutate query ASTs, or corrupt server state.",
        "Validate '{kw}' against a strict schema (`typeof`, length, allowlist) and use parameterized APIs or context-aware escaping.",
    ),
    (
        "BrokenAccessControl",
        "Missing Object-Level Ownership / Authorization Check (IDOR)",
        "Endpoint handling '{kw}' reads a record ID or tenant key from client input without verifying `session.userId` ownership.",
        "Authenticated callers can substitute another user's ID in '{kw}' requests to read or modify unauthorized records.",
        "Scope every '{kw}' query by the authenticated server session (`WHERE id = $1 AND owner_id = $2`).",
    ),
    (
        "ClientTrustedState",
        "Server Trusts Client-Supplied Price, Role, or Privilege Field",
        "'{kw}' handler accepts price, discount, role, or balance fields directly from `req.body` instead of server storage.",
        "Clients tampering with '{kw}' JSON payloads can set negative amounts, `NaN`, or elevated role flags.",
        "Look up authoritative prices, permissions, and totals for '{kw}' on the server and ignore client-supplied sensitive fields.",
    ),
    (
        "SecretOrTokenExposure",
        "Sensitive Credential or Session Token Exposed to Client JS",
        "'{kw}' stores or transmits credentials in client-readable `localStorage`, public bundle env vars, or inline script state.",
        "Any XSS or third-party script execution can read '{kw}' tokens from browser storage or client bundles.",
        "Keep secrets in server-only environment variables and store session tokens in `HttpOnly; Secure; SameSite=Lax` cookies.",
    ),
    (
        "NonAtomicMutation",
        "Race Condition / Missing Idempotency on State Mutation",
        "'{kw}' performs read-then-write state updates without database transactions, row locking, or idempotency keys.",
        "Concurrent burst requests to '{kw}' bypass balance/quota checks and trigger duplicate grants or double-spends.",
        "Wrap '{kw}' mutations in a serializable database transaction or atomic `UPDATE ... WHERE` with an `Idempotency-Key` guard.",
    ),
]

WARN_PATTERNS = [
    (
        "MissingRateLimit",
        "Missing Per-IP / Per-User Rate Limiting",
        "'{kw}' route processes expensive or state-changing requests without a token-bucket or sliding-window rate limiter.",
        "Automated clients can flood '{kw}' to brute-force tokens, scrape data, or exhaust server CPU and database pools.",
        "Attach rate-limiting middleware (e.g., 20 req/min per user/IP) with `429 Too Many Requests` and `Retry-After` headers.",
    ),
    (
        "WeakSecurityHeaders",
        "Permissive CORS, CSP, or Cookie Security Policy",
        "'{kw}' response omits strict `Content-Security-Policy`, `SameSite`, or uses overly broad `Access-Control-Allow-Origin`.",
        "Missing browser defense-in-depth headers on '{kw}' increase exposure to cross-origin reads, CSRF, and clickjacking.",
        "Enforce a nonce/hash-based CSP, `X-Content-Type-Options: nosniff`, `Frame-Options`, and explicit origin allowlists.",
    ),
    (
        "UnboundedPayload",
        "Missing Input Length, Array Size, or JSON Depth Limit",
        "'{kw}' accepts strings, arrays, or nested JSON objects without enforcing maximum byte length or key-count bounds.",
        "Oversized payloads sent to '{kw}' spike Node/Python event-loop latency and memory usage.",
        "Reject '{kw}' payloads where string length > 256, array length > 100, or JSON body size exceeds the route threshold.",
    ),
    (
        "ListenerMemoryLeak",
        "Uncleaned DOM Event Listener, Timer, or Subscription",
        "'{kw}' registers `addEventListener`, `setInterval`, or WebSocket listeners without cleanup on component unmount.",
        "Repeated route transitions accumulate detached DOM trees and closures in '{kw}', degrading browser tab responsiveness.",
        "Return a deterministic cleanup function (`removeEventListener`, `clearInterval`, `AbortController.abort()`) on unmount.",
    ),
    (
        "UnverifiedExternalCall",
        "Outbound Fetch / Webhook Without Timeout or URL Allowlist",
        "'{kw}' performs outbound `fetch()` or redirect operations without a host allowlist, `AbortSignal.timeout`, or `try/catch`.",
        "Slow upstream services or user-influenced URLs in '{kw}' can hang server workers or reach internal metadata endpoints.",
        "Validate URLs against a strict HTTPS hostname allowlist and pass `AbortSignal.timeout(5000)` to all outbound calls.",
    ),
    (
        "MissingSubresourceIntegrity",
        "External Script or Tab Target Missing Integrity / Isolation",
        "'{kw}' loads third-party assets or opens external links without Subresource Integrity (`integrity`) or `rel='noopener'`.",
        "Compromised CDN assets or `window.opener` references in '{kw}' can tamper with the host origin.",
        "Pin `integrity='sha384-...' crossorigin='anonymous'` on CDN scripts and `rel='noopener noreferrer'` on external links.",
    ),
    (
        "AccessibilityGap",
        "WCAG Contrast, Keyboard Focus, or ARIA Label Deficit",
        "'{kw}' interactive UI element lacks an accessible name, visible `:focus-visible` ring, or keyboard activation handler.",
        "Keyboard and screen-reader users cannot perceive or operate '{kw}' controls reliably.",
        "Use semantic `<button>`/`<a>` elements, explicit `aria-label` or `<label for>`, and high-contrast `:focus-visible` outlines.",
    ),
]

INFO_PATTERNS = [
    (
        "MissingTypeAnnotation",
        "Implicit Any or Missing Runtime Schema Type",
        "'{kw}' module omits explicit TypeScript parameter types or runtime schema inference.",
        "Unhandled `undefined` or type coercion edge cases in '{kw}' surface only at runtime.",
        "Enable `strict: true` in `tsconfig.json` and pair compile-time types with runtime boundary validation.",
    ),
    (
        "LayoutShiftCLS",
        "Image or Async Slot Missing Explicit Dimensions (CLS)",
        "'{kw}' renders `<img>` or async media without explicit `width`/`height` or CSS `aspect-ratio` reservation.",
        "Late-loading media in '{kw}' causes Cumulative Layout Shift (CLS) and jarring visual jumps.",
        "Specify intrinsic `width` and `height` attributes or `aspect-ratio` on '{kw}' media containers.",
    ),
    (
        "RenderLoopAlloc",
        "Unmemoized Object/Callback Allocation in Hot Render Path",
        "'{kw}' recreates inline objects, arrays, or heavy filter pipelines on every render cycle.",
        "Redundant virtual-DOM diffing in '{kw}' increases main-thread scripting time on low-end mobile devices.",
        "Hoist static constants outside the component and memoize expensive derived lists.",
    ),
    (
        "ConsoleDebugLeftover",
        "Unfiltered Console Diagnostic in Production Bundle",
        "'{kw}' leaves raw `console.log` / `console.debug` statements in client-facing code.",
        "Verbose console output in '{kw}' leaks internal state shapes and clutters production telemetry.",
        "Use a structured logger gated by environment level or strip debug logs during build.",
    ),
    (
        "RedundantDOMQuery",
        "Repeated Synchronous DOM Query Inside Loop or Scroll Handler",
        "'{kw}' calls `document.querySelector` or layout-reading properties (`getBoundingClientRect`) inside a tight loop.",
        "Interleaved DOM reads and writes in '{kw}' trigger forced synchronous layout thrashing.",
        "Cache element references once and throttle scroll/resize measurements with `requestAnimationFrame`.",
    ),
    (
        "MissingCacheHeader",
        "Static or Idempotent Resource Missing Cache-Control Directive",
        "'{kw}' asset or read endpoint omits explicit `Cache-Control` or `ETag` headers.",
        "Browsers re-download unchanged '{kw}' payloads on every navigation, increasing TTFB and bandwidth.",
        "Set `Cache-Control: public, max-age=31536000, immutable` for fingerprinted assets and `ETag` for API reads.",
    ),
    (
        "UnoptimizedBundleImport",
        "Barrel Import Pulling Full Library Into Client Bundle",
        "'{kw}' imports an entire icon/utility package instead of a direct submodule path.",
        "Bloated client JS bundles for '{kw}' delay First Contentful Paint (FCP) and Time to Interactive (TTI).",
        "Use direct path imports or verify tree-shaking drops unused exports from '{kw}'.",
    ),
    (
        "FormAutocompleteGap",
        "Form Input Missing Explicit Autocomplete or Type Attribute",
        "'{kw}' form field omits standard `autocomplete`, `inputmode`, or semantic `type` attributes.",
        "Mobile keyboards and password managers struggle to autofill '{kw}' accurately.",
        "Add explicit `autocomplete` tokens (e.g., `email`, `current-password`, `one-time-code`) and `inputmode`.",
    ),
    (
        "MissingReducedMotion",
        "Animation Ignores prefers-reduced-motion Media Query",
        "'{kw}' CSS or JS animation runs continuous motion without respecting `@media (prefers-reduced-motion: reduce)`.",
        "Motion-sensitive users viewing '{kw}' experience visual discomfort or distraction.",
        "Disable or simplify non-essential transitions inside `@media (prefers-reduced-motion: reduce)`.",
    ),
    (
        "UnhandledPromiseRejection",
        "Async Event Handler Missing Error Boundary or Catch Block",
        "'{kw}' triggers an async promise chain from a UI event without handling rejection states.",
        "Network failures in '{kw}' leave loading spinners stuck indefinitely with no user feedback.",
        "Wrap async actions in `try / catch / finally` and surface a clear, actionable error state in the UI.",
    ),
    (
        "HardcodedMagicConstant",
        "Duplicated Magic Timeout, Status Code, or Design Token",
        "'{kw}' embeds raw magic numbers or inline hex colors instead of shared constants or CSS variables.",
        "Inconsistent thresholds and styling across '{kw}' increase maintenance friction.",
        "Extract shared constants and use semantic CSS custom properties (`var(--...)`).",
    ),
]

CONTAINERS = [
    ("NextJSAppRouter", "Next.js App Router Server Action & Route Handler boundary"),
    ("ExpressAPIRoute", "Node.js / Express REST controller & middleware pipeline"),
    ("ReactClientComponent", "Client-side React / SPA interactive component tree"),
    ("GraphQLResolver", "GraphQL query/mutation resolver & schema layer"),
    ("PostgresPrismaORM", "Relational/NoSQL ORM data access & transaction layer"),
    ("AuthMiddleware", "Session, JWT, OAuth & RBAC authorization boundary"),
    ("WebhookHandler", "Inbound/outbound webhook & payment callback processor"),
    ("CloudflareEdgeWorker", "Edge Worker / CDN request router & header policy"),
    ("StaticHTMLTemplate", "HTML document shell, meta tags & asset loader"),
    ("DockerNginxConfig", "Reverse proxy, TLS, CORS & container runtime config"),
]


def _flatten_keywords() -> list[tuple[str, str, str]]:
    seen: set[str] = set()
    items: list[tuple[str, str, str]] = []
    for dom, cat, kws in WEB_DOMAINS:
        for kw in kws:
            low = kw.lower()
            if low not in seen:
                seen.add(low)
                items.append((dom, cat, low))
    return items


def build_web_corpus() -> None:
    base_kws = _flatten_keywords()
    # We need 700 unique web keywords for CRITICAL (700 * 5 * 10 = 35,000) and WARN (700 * 7 * 10 = 49,000),
    # and 600 unique web keywords for INFO (600 * 11 * 10 = 66,000).
    # Total = 35,000 + 49,000 + 66,000 = 150,000 exact records!
    suffixes = ["", "api", "route", "handler", "form", "view", "hook", "store"]
    kw_pool: list[tuple[str, str, str]] = []
    seen_kw: set[str] = set()
    for suf in suffixes:
        for dom, cat, kw in base_kws:
            cand = kw if not suf else f"{kw}_{suf}"
            if cand not in seen_kw:
                seen_kw.add(cand)
                kw_pool.append((dom, cat, cand))
            if len(kw_pool) == 700:
                break
        if len(kw_pool) == 700:
            break

    assert len(kw_pool) == 700, f"Expected 700 web keywords, got {len(kw_pool)}"
    info_kw_pool = kw_pool[:600]

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    rank = 1

    with gzip.open(OUT_FILE, "wt", encoding="utf-8", compresslevel=6) as fh:
        # Tier 1: CRITICAL (1 .. 35,000)
        for dom, cat, kw in kw_pool:
            for dim_key, dim_label, flaw_tpl, abuse_tpl, fix_tpl in CRITICAL_PATTERNS:
                for container, cdesc in CONTAINERS:
                    code = f"RCW-{rank:06d}"
                    title = f"[{dom}] {dim_label}: '{kw}' ({container})"
                    keywords = f"{kw},{dom.lower()},{container.lower()},{dim_key.lower()},{cat.lower()}"
                    flaw = f"{flaw_tpl.format(kw=kw)} [{container}: {cdesc}]"
                    abuse = abuse_tpl.format(kw=kw)
                    fix = fix_tpl.format(kw=kw)
                    fh.write(f"{code}|CRITICAL|{cat}|{dom}|{keywords}|{title}|{flaw}|{abuse}|{fix}|{rank}\n")
                    rank += 1

        assert rank == 35001

        # Tier 2: WARN (35,001 .. 84,000)
        for dom, cat, kw in kw_pool:
            for dim_key, dim_label, flaw_tpl, abuse_tpl, fix_tpl in WARN_PATTERNS:
                for container, cdesc in CONTAINERS:
                    code = f"RCW-{rank:06d}"
                    title = f"[{dom}] {dim_label}: '{kw}' ({container})"
                    keywords = f"{kw},{dom.lower()},{container.lower()},{dim_key.lower()},{cat.lower()}"
                    flaw = f"{flaw_tpl.format(kw=kw)} [{container}: {cdesc}]"
                    abuse = abuse_tpl.format(kw=kw)
                    fix = fix_tpl.format(kw=kw)
                    fh.write(f"{code}|WARN|{cat}|{dom}|{keywords}|{title}|{flaw}|{abuse}|{fix}|{rank}\n")
                    rank += 1

        assert rank == 84001

        # Tier 3: INFO (84,001 .. 150,000)
        for dom, cat, kw in info_kw_pool:
            for dim_key, dim_label, flaw_tpl, abuse_tpl, fix_tpl in INFO_PATTERNS:
                for container, cdesc in CONTAINERS:
                    code = f"RCW-{rank:06d}"
                    title = f"[{dom}] {dim_label}: '{kw}' ({container})"
                    keywords = f"{kw},{dom.lower()},{container.lower()},{dim_key.lower()},{cat.lower()}"
                    flaw = f"{flaw_tpl.format(kw=kw)} [{container}: {cdesc}]"
                    abuse = abuse_tpl.format(kw=kw)
                    fix = fix_tpl.format(kw=kw)
                    fh.write(f"{code}|INFO|{cat}|{dom}|{keywords}|{title}|{flaw}|{abuse}|{fix}|{rank}\n")
                    rank += 1

        assert rank == 150001

    size_mb = OUT_FILE.stat().st_size / (1024 * 1024)
    print(f"Built exact {rank - 1:,} website flaws at {OUT_FILE} ({size_mb:.2f} MB compressed)")


if __name__ == "__main__":
    build_web_corpus()
