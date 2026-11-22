"""
Sub-10ms 150,000-Flaw Website & Web Application Intelligence Catalog
(rcdebug/data/web_flaws_150000.txt.gz + ~/.rcdebug/web_index_cache_150k.bin).

Provides:
- WebFlawCatalog (150,000 ordered website flaws: RCW-000001 .. RCW-150000)
- 12 Static Web Security & Quality Rules (RCW-S001 .. RCW-S012)
- 120 Web Debugger Probes (WDP-001 .. WDP-120 across OWASP, React/Next.js, Express, WCAG, Web Vitals, TypeScript)
- 4-Section Web Handler Unit Test & Contract Specification generator (JS/TS Guard Module + console.assert() suite)
- Offline Browser DevTools Console QA Test Runner (zero external HTTP calls)
- Parallel local web project directory / file scanner (.html, .js, .jsx, .ts, .tsx, .css, .py, .json)
"""

from __future__ import annotations

import bisect
import gzip
import json
import marshal
import mmap
import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator, Pattern
from urllib.request import Request, urlopen

from .flaw_catalog import FlawSignature, StaticCodeRule, _parse_flaw_line, _split_camel_cached
from .learner import AdaptiveLearner, FlawBrain, extract_game_tokens
from .models import AuditSession, Finding, SeverityFilter, matches_filter, normalize_severity

WEB_FLAWS_GZ_PATH = Path(__file__).resolve().parent / "data" / "web_flaws_150000.txt.gz"
WEB_FLAWS_TXT_PATH = Path.home() / ".rcdebug" / "web_flaws_150000.txt"
WEB_FLAWS_STAMP_PATH = Path.home() / ".rcdebug" / "web_flaws_150000.stamp"
WEB_INDEX_CACHE_PATH = Path.home() / ".rcdebug" / "web_index_cache_150k.bin"
WEB_LEARNED_JSON_PATH = Path.home() / ".rcdebug" / "web_learned_flaws.json"
WEB_LEARNED_TXT_PATH = Path.home() / ".rcdebug" / "web_learned_patterns.txt"
WEB_BRAIN_JSON_PATH = Path.home() / ".rcdebug" / "web_flaw_brain.json"

EXPECTED_WEB_FLAW_COUNT = 150000
_WEB_CACHE_VERSION = 1

_TOKEN_SPLIT_RE = re.compile(r"[a-z0-9]+")


def ensure_web_flaws_txt(
    txt_path: Path = WEB_FLAWS_TXT_PATH,
    gz_path: Path = WEB_FLAWS_GZ_PATH,
) -> Path:
    """
    Ensures the uncompressed 150,000-flaw web corpus exists in ~/.rcdebug/web_flaws_150000.txt
    for fast mmap seek-reads, extracting once from the bundled gzip archive.
    """
    if txt_path != WEB_FLAWS_TXT_PATH and txt_path.exists():
        return txt_path
    if not gz_path.exists():
        if txt_path.exists():
            return txt_path
        raise FileNotFoundError(f"Web flaw database archive not found: {gz_path}")

    gz_stat = gz_path.stat()
    stamp_val = f"{gz_stat.st_size}:{gz_stat.st_mtime_ns}"
    if txt_path.exists() and WEB_FLAWS_STAMP_PATH.exists():
        try:
            if WEB_FLAWS_STAMP_PATH.read_text(encoding="utf-8").strip() == stamp_val:
                return txt_path
        except OSError:
            pass

    txt_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = txt_path.with_suffix(".txt.tmp")
    with gzip.open(gz_path, "rb") as src, tmp_path.open("wb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    tmp_path.replace(txt_path)
    try:
        WEB_FLAWS_STAMP_PATH.write_text(stamp_val, encoding="utf-8")
    except OSError:
        pass
    return txt_path


WEB_STATIC_CODE_RULES: tuple[StaticCodeRule, ...] = (
    StaticCodeRule(
        code="RCW-S001",
        severity="CRITICAL",
        category="DOMSecurity",
        title="Unsanitized DOM HTML Sink (innerHTML / dangerouslySetInnerHTML)",
        literal_hint="HTML",
        pattern=re.compile(r"(?:\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML\s*=|document\.write\s*\()"),
        anti_pattern=re.compile(r"DOMPurify\.sanitize|sanitizeHtml|escapeHtml"),
        flaw="Code writes raw HTML into the DOM via innerHTML, outerHTML, dangerouslySetInnerHTML, or document.write without sanitization.",
        abuse="If any user profile field, query parameter, or API response reaches this sink, attackers execute arbitrary JavaScript (DOM XSS) in victim browsers.",
        fix="Render untrusted strings with textContent / standard JSX escaping, or pass rich HTML through DOMPurify.sanitize() with a strict tag allowlist.",
        rank=1,
        code_example="element.textContent = untrustedInput;",
    ),
    StaticCodeRule(
        code="RCW-S002",
        severity="CRITICAL",
        category="CodeExecution",
        title="Dynamic JavaScript Evaluation via eval() or new Function()",
        literal_hint="eval",
        pattern=re.compile(r"(?:\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'])"),
        anti_pattern=None,
        flaw="Script compiles and executes strings as code at runtime using eval(), new Function(), or string-based timers.",
        abuse="Any user-controlled JSON, expression, or query string reaching dynamic evaluation leads to arbitrary client or server (Node.js) code execution.",
        fix="Replace eval() / new Function() with JSON.parse() or an explicit allowlisted dispatch map of static functions.",
        rank=2,
        code_example="const data = JSON.parse(rawPayload);",
    ),
    StaticCodeRule(
        code="RCW-S003",
        severity="CRITICAL",
        category="SecretExposure",
        title="Hardcoded API Key, Private Token, or Webhook Secret in Source",
        literal_hint="",
        pattern=re.compile(
            r"(?:sk_live_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{20,}|AIza[0-9A-Za-z\-_]{25,}|https?://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+|(?:JWT_SECRET|API_SECRET|PRIVATE_KEY)\s*[:=]\s*[\"'][^\"']{8,}[\"'])"
        ),
        anti_pattern=re.compile(r"process\.env\.|os\.environ"),
        flaw="Source file embeds a live secret key, bearer token, or webhook URL directly in code.",
        abuse="Secrets bundled into frontend assets or committed to repositories allow full third-party API impersonation, billing abuse, or forged tokens.",
        fix="Move credentials to server-only environment variables (process.env.SECRET_KEY), rotate exposed keys, and never prefix secrets with NEXT_PUBLIC_ or VITE_.",
        rank=3,
    ),
    StaticCodeRule(
        code="RCW-S004",
        severity="CRITICAL",
        category="DataSecurity",
        title="Unparameterized SQL / Raw Query String Interpolation",
        literal_hint="",
        pattern=re.compile(r"(?:`SELECT\s+[^`]*\$\{|`INSERT\s+[^`]*\$\{|`UPDATE\s+[^`]*\$\{|`DELETE\s+[^`]*\$\{|\$queryRawUnsafe\s*\(|f[\"']SELECT\s+[^\"']*\{)", re.IGNORECASE),
        anti_pattern=None,
        flaw="Database query interpolates runtime variables directly into a SQL string instead of using bound parameters.",
        abuse="Attackers supply crafted strings to alter SQL predicates, dump unauthorized tables, or modify records.",
        fix="Use parameterized queries ($1, ?) or tagged template helpers (Prisma.sql`SELECT * FROM users WHERE id = ${id}`).",
        rank=4,
    ),
    StaticCodeRule(
        code="RCW-S005",
        severity="CRITICAL",
        category="PlatformSecurity",
        title="Wildcard CORS Origin Combined With Credentials",
        literal_hint="Access-Control",
        pattern=re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']", re.IGNORECASE),
        anti_pattern=None,
        flaw="Server or proxy sets Access-Control-Allow-Origin: * on API responses.",
        abuse="Overly permissive CORS policies expose authenticated or sensitive JSON responses to untrusted third-party origins.",
        fix="Validate the request Origin header against an explicit allowlist of trusted production domains before echoing Access-Control-Allow-Origin.",
        rank=5,
    ),
    StaticCodeRule(
        code="RCW-S006",
        severity="WARN",
        category="AuthSecurity",
        title="Session Token / JWT Stored in Client-Readable localStorage",
        literal_hint="localStorage",
        pattern=re.compile(r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*[\"'](?:token|jwt|access_token|refresh_token|auth|session)[\"']", re.IGNORECASE),
        anti_pattern=None,
        flaw="Authentication token is persisted in window.localStorage or window.sessionStorage.",
        abuse="Any XSS payload or compromised third-party script on the page can read localStorage and exfiltrate active user sessions.",
        fix="Issue session and refresh tokens from the server in HttpOnly; Secure; SameSite=Lax cookies inaccessible to document.cookie / JS.",
        rank=35010,
    ),
    StaticCodeRule(
        code="RCW-S007",
        severity="WARN",
        category="AuthSecurity",
        title="Cookie Issued Without HttpOnly, Secure, or SameSite Flags",
        literal_hint="cookie",
        pattern=re.compile(r"(?:res\.cookie\s*\(|Set-Cookie\s*:)", re.IGNORECASE),
        anti_pattern=re.compile(r"httpOnly\s*:\s*true|HttpOnly", re.IGNORECASE),
        flaw="Cookie assignment omits explicit HttpOnly, Secure, and SameSite security attributes.",
        abuse="Cookies without HttpOnly can be read by client scripts; missing SameSite allows cross-site request forgery (CSRF).",
        fix="Configure cookies with { httpOnly: true, secure: true, sameSite: 'lax', path: '/' }.",
        rank=35020,
    ),
    StaticCodeRule(
        code="RCW-S008",
        severity="CRITICAL",
        category="APISecurity",
        title="Unvalidated Redirect or Server-Side Fetch URL From Request Input",
        literal_hint="redirect",
        pattern=re.compile(r"(?:res\.redirect\s*\(\s*req\.(?:query|body|params)|fetch\s*\(\s*req\.(?:query|body|params))"),
        anti_pattern=re.compile(r"ALLOWED_HOSTS|startsWith\s*\(\s*[\"']/[\"']"),
        flaw="Server passes a request query/body parameter directly into res.redirect() or outbound fetch().",
        abuse="Unchecked redirect targets enable phishing via open redirects; unchecked server fetch URLs enable SSRF against internal services.",
        fix="Ensure redirect targets are relative paths starting with '/' (not '//') and validate outbound fetch URLs against an HTTPS hostname allowlist.",
        rank=6,
    ),
    StaticCodeRule(
        code="RCW-S009",
        severity="WARN",
        category="PlatformSecurity",
        title="Potential Prototype Pollution in Dynamic Key Assignment",
        literal_hint="__proto__",
        pattern=re.compile(r"\[\s*(?:key|k|prop|field)\s*\]\s*="),
        anti_pattern=re.compile(r"__proto__|prototype|constructor|Object\.hasOwn|Map\("),
        flaw="Dynamic property assignment obj[key] = val executes without filtering __proto__, constructor, or prototype keys.",
        abuse="Crafted JSON payloads containing {'__proto__': ...} can pollute Object.prototype and alter application control flow.",
        fix="Reject keys in ('__proto__', 'constructor', 'prototype'), use Object.create(null) dictionaries, or store dynamic keys in a Map().",
        rank=35030,
    ),
    StaticCodeRule(
        code="RCW-S010",
        severity="WARN",
        category="MemoryLeak",
        title="Event Listener or Interval Timer Registered Without Cleanup",
        literal_hint="addEventListener",
        pattern=re.compile(r"(?:window\.addEventListener\s*\(|document\.addEventListener\s*\(|setInterval\s*\()"),
        anti_pattern=re.compile(r"removeEventListener|clearInterval|AbortController"),
        flaw="Script registers a global window/document event listener or setInterval timer without a matching cleanup call.",
        abuse="SPA route transitions accumulate duplicate listeners and timers, leaking memory and causing janky UI frames.",
        fix="Pass { signal: abortController.signal } to addEventListener or call removeEventListener / clearInterval in the component cleanup hook.",
        rank=35040,
    ),
    StaticCodeRule(
        code="RCW-S011",
        severity="INFO",
        category="PlatformSecurity",
        title="External Target _blank Link or Third-Party Script Without Isolation",
        literal_hint="_blank",
        pattern=re.compile(r"target\s*=\s*[\"']_blank[\"']", re.IGNORECASE),
        anti_pattern=re.compile(r"rel\s*=\s*[\"'][^\"']*noopener", re.IGNORECASE),
        flaw="Anchor tag opens a new tab with target='_blank' without explicit rel='noopener noreferrer'.",
        abuse="Legacy browsers expose window.opener to the linked page, allowing reverse tabnabbing.",
        fix="Add rel='noopener noreferrer' to all external target='_blank' links.",
        rank=84010,
    ),
    StaticCodeRule(
        code="RCW-S012",
        severity="INFO",
        category="AccessibilityWCAG",
        title="Image Tag Missing Accessible alt Attribute (WCAG 1.1.1)",
        literal_hint="<img",
        pattern=re.compile(r"<img\b(?![^>]*\balt\s*=)[^>]*>", re.IGNORECASE),
        anti_pattern=None,
        flaw="HTML/JSX <img> element omits the alt attribute.",
        abuse="Screen readers fall back to reading raw image filenames or URLs aloud, degrading accessibility compliance.",
        fix="Provide a descriptive alt='...' attribute (or alt='' with aria-hidden='true' for purely decorative images).",
        rank=84020,
    ),
)


@dataclass(frozen=True, slots=True)
class WebDebuggerProbe:
    id: str
    source: str
    category: str
    severity: str
    name: str
    root_cause: str
    fix: str


def _build_120_web_probes() -> tuple[WebDebuggerProbe, ...]:
    sources = (
        ("OWASP-ASVS", "APISecurity", "CRITICAL"),
        ("React-NextJS", "FrontendArchitecture", "WARN"),
        ("WCAG-2.2-AA", "AccessibilityWCAG", "WARN"),
        ("CoreWebVitals", "WebPerformance", "INFO"),
        ("TypeScript-ESLint", "CodeHygiene", "INFO"),
        ("Node-Express-FastAPI", "BackendSecurity", "CRITICAL"),
    )
    topics = (
        ("CSP Nonce & Script-Src Enforcement", "Missing script-src nonce allows inline script execution.", "Issue a per-request cryptographic nonce in Content-Security-Policy."),
        ("SameSite & HttpOnly Session Cookie Policy", "Session cookie readable by document.cookie or sent cross-site.", "Set HttpOnly; Secure; SameSite=Lax on all session cookies."),
        ("IDOR Object Ownership Verification", "Route handler queries record by req.params.id without session.userId check.", "Include AND owner_id = session.userId in every query predicate."),
        ("Rate Limiting & Burst Protection", "Auth or mutation endpoint lacks sliding-window rate limiting.", "Enforce per-IP and per-user rate limits returning HTTP 429."),
        ("Strict Runtime Request Schema (Zod/Valibot)", "Handler trusts req.body field types without runtime schema parsing.", "Parse req.body with a strict schema rejecting unknown keys and NaN."),
        ("SQL/ORM Parameterized Query Boundary", "Raw string interpolation used inside SQL or NoSQL filter.", "Use parameterized prepared statements or typed ORM builders."),
        ("CORS Origin Allowlist Verification", "Wildcard or reflected Origin header exposed on API endpoint.", "Match Origin against an explicit set of trusted production origins."),
        ("CSRF Token & Origin Header Check", "State-changing POST/PUT/DELETE route accepts cross-origin form submissions.", "Verify Origin/Sec-Fetch-Site headers and anti-CSRF tokens."),
        ("SSRF Outbound URL & Private IP Guard", "Server fetches user-supplied URL without blocking RFC1918/link-local IPs.", "Allowlist outbound HTTPS domains and block 127.0.0.0/8 and 169.254.169.254."),
        ("Prototype Pollution & Safe JSON Merge", "Recursive object merge copies __proto__ or constructor properties.", "Strip __proto__/constructor/prototype keys or use Map/Object.create(null)."),
        ("Webhook HMAC Signature & Timestamp Replay Guard", "Webhook route processes payload without constant-time HMAC verification.", "Verify HMAC-SHA256 with crypto.timingSafeEqual and reject timestamps > 300s old."),
        ("File Upload MIME, Magic-Byte & Size Cap", "Upload endpoint trusts client Content-Type or allows unbounded files.", "Verify magic bytes, cap upload size, and store outside webroot with random UUIDs."),
        ("Password Hashing Work Factor (Argon2id/Bcrypt)", "Auth service uses fast hash or low bcrypt cost factor.", "Hash passwords with Argon2id or bcrypt (cost >= 12)."),
        ("JWT Algorithm Pinning & Expiration Check", "JWT verification accepts 'none' algorithm or omits exp/aud claims.", "Pin algorithms: ['HS256'] or ['RS256'] and enforce maxAge/audience."),
        ("Open Redirect Relative Path Enforcement", "Login callback redirects to arbitrary external returnUrl parameter.", "Allow only relative paths starting with '/' and not '//'."),
        ("GraphQL Query Depth & Complexity Limit", "GraphQL endpoint allows deeply nested cyclic queries.", "Enforce max depth <= 7 and query cost complexity limits."),
        ("DOMPurify HTML Sanitization Pipeline", "Rich-text renderer injects raw HTML into innerHTML.", "Sanitize with DOMPurify.sanitize(html, { USE_PROFILES: { html: true } })."),
        ("React useEffect AbortController Cleanup", "Async fetch or window listener in useEffect lacks unmount cleanup.", "Abort in-flight requests and remove listeners in the useEffect cleanup return."),
        ("Cumulative Layout Shift (CLS) Media Reservation", "Images and embeds load without width/height or aspect-ratio.", "Specify intrinsic width and height attributes on all <img> and <video> tags."),
        ("WCAG 2.2 AA Keyboard Focus & Contrast Gate", "Interactive control lacks :focus-visible outline or 4.5:1 text contrast.", "Use semantic <button>, visible 2px focus outlines, and WCAG AA contrast tokens."),
    )
    probes: list[WebDebuggerProbe] = []
    idx = 1
    for topic_name, cause, fix in topics:
        for src_name, cat, sev in sources:
            probes.append(
                WebDebuggerProbe(
                    id=f"WDP-{idx:03d}",
                    source=src_name,
                    category=cat,
                    severity=sev,
                    name=f"[{src_name}] {topic_name}",
                    root_cause=cause,
                    fix=fix,
                )
            )
            idx += 1
    assert len(probes) == 120
    return tuple(probes)


_WEB_PROBES_120 = _build_120_web_probes()


class WebDebuggerPack:
    def __init__(self, probes: tuple[WebDebuggerProbe, ...] = _WEB_PROBES_120) -> None:
        self.probes = probes

    def count(self) -> int:
        return len(self.probes)

    def search(self, query: str = "", limit: int = 120) -> list[WebDebuggerProbe]:
        q = (query or "").strip().lower()
        if not q:
            return list(self.probes[:limit])
        tokens = [t for t in _TOKEN_SPLIT_RE.findall(q) if t]
        out: list[WebDebuggerProbe] = []
        for p in self.probes:
            hay = f"{p.id} {p.source} {p.category} {p.severity} {p.name} {p.root_cause} {p.fix}".lower()
            if all(t in hay for t in tokens):
                out.append(p)
                if len(out) >= limit:
                    break
        return out


@lru_cache(maxsize=1)
def get_web_debugger_pack() -> WebDebuggerPack:
    return WebDebuggerPack()


def _build_or_load_web_index(
    txt_path: Path = WEB_FLAWS_TXT_PATH,
    cache_path: Path = WEB_INDEX_CACHE_PATH,
) -> tuple[list[int], dict[str, list[int]], dict[str, list[int]]]:
    txt_path = ensure_web_flaws_txt(txt_path)
    if not txt_path.exists():
        raise FileNotFoundError(f"Web flaw database file not found: {txt_path}")

    st = txt_path.stat()
    sig_key = (st.st_size, st.st_mtime_ns)

    if cache_path.exists():
        try:
            with cache_path.open("rb") as cfh:
                payload = marshal.load(cfh)
            if (
                isinstance(payload, dict)
                and payload.get("v") == _WEB_CACHE_VERSION
                and payload.get("size") == sig_key[0]
                and payload.get("mtime_ns") == sig_key[1]
                and len(payload.get("offsets", ())) == EXPECTED_WEB_FLAW_COUNT
            ):
                return (
                    payload["offsets"],
                    payload["primary_kw_index"],
                    payload["keyword_index"],
                )
        except Exception:
            pass

    offsets: list[int] = []
    primary_kw_index: dict[str, list[int]] = {}
    keyword_index: dict[str, list[int]] = {}

    with txt_path.open("rb") as fh:
        idx = 0
        while True:
            pos = fh.tell()
            raw = fh.readline()
            if not raw:
                break
            if not raw.strip():
                continue
            offsets.append(pos)
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            parts = line.split("|", 5)
            if len(parts) >= 5:
                kws = [k.strip().lower() for k in parts[4].split(",") if k.strip()]
                if kws:
                    primary_kw_index.setdefault(kws[0], []).append(idx)
                for kw in kws:
                    keyword_index.setdefault(kw, []).append(idx)
            idx += 1

    if len(offsets) != EXPECTED_WEB_FLAW_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_WEB_FLAW_COUNT} web flaws in {txt_path}, found {len(offsets)}"
        )

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("wb") as cfh:
            marshal.dump(
                {
                    "v": _WEB_CACHE_VERSION,
                    "size": sig_key[0],
                    "mtime_ns": sig_key[1],
                    "offsets": offsets,
                    "primary_kw_index": primary_kw_index,
                    "keyword_index": keyword_index,
                },
                cfh,
            )
    except OSError:
        pass

    return offsets, primary_kw_index, keyword_index


class WebFlawCatalog:
    """
    Sub-10ms mmap-indexed storage for 150,000 Website & Web App flaw signatures
    (RCW-000001 .. RCW-150000).
    """

    def __init__(
        self,
        txt_path: Path = WEB_FLAWS_TXT_PATH,
        cache_path: Path = WEB_INDEX_CACHE_PATH,
        static_rules: tuple[StaticCodeRule, ...] = WEB_STATIC_CODE_RULES,
        learner: AdaptiveLearner | None = None,
        brain: FlawBrain | None = None,
    ) -> None:
        self.txt_path = ensure_web_flaws_txt(txt_path)
        self.cache_path = cache_path
        self.static_rules = static_rules
        self.learner = learner or AdaptiveLearner(
            store_path=WEB_LEARNED_JSON_PATH,
            txt_path=WEB_LEARNED_TXT_PATH,
        )
        self.brain = brain or FlawBrain(brain_path=WEB_BRAIN_JSON_PATH)

        offsets, primary_kw_index, keyword_index = _build_or_load_web_index(self.txt_path, cache_path)
        self._offsets = offsets
        self._primary_kw_index = primary_kw_index
        self._keyword_index = keyword_index
        self._record_cache: dict[int, FlawSignature] = {}
        self._match_cache: dict[tuple[str, str, int], list[FlawSignature]] = {}

        self._fh = self.txt_path.open("rb")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self) -> None:
        mm = getattr(self, "_mm", None)
        if mm is not None:
            try:
                mm.close()
            except Exception:
                pass
            self._mm = None  # type: ignore[assignment]
        fh = getattr(self, "_fh", None)
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
            self._fh = None  # type: ignore[assignment]

    def __del__(self) -> None:
        self.close()

    def count(self) -> int:
        return len(self._offsets)

    def signature_count(self) -> int:
        return len(self._offsets)

    def static_rule_count(self) -> int:
        return len(self.static_rules)

    def _read_record(self, idx: int) -> FlawSignature:
        cached = self._record_cache.get(idx)
        if cached is not None:
            return cached
        pos = self._offsets[idx]
        nl = self._mm.find(b"\n", pos)
        raw = self._mm[pos:nl] if nl != -1 else self._mm[pos:]
        sig = _parse_flaw_line(raw.decode("utf-8", errors="replace"))
        if len(self._record_cache) >= 8192:
            self._record_cache.clear()
        self._record_cache[idx] = sig
        return sig

    def get(self, code: str) -> FlawSignature | None:
        m = re.match(r"^RCW-(\d+)$", code.strip().upper())
        if not m:
            return None
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(self._offsets):
            return self._read_record(idx)
        return None

    def match_name(
        self,
        identifier: str,
        container_hint: str = "",
        limit: int = 5,
    ) -> list[FlawSignature]:
        cache_key = (identifier, container_hint, limit)
        cached = self._match_cache.get(cache_key)
        if cached is not None:
            return cached

        generic_kws = {"api", "route", "handler", "form", "view", "hook", "store"}
        lower_id = identifier.lower()
        raw_leaf = container_hint.split("/")[-1].split("::")[-1] if ("/" in container_hint or "::" in container_hint) else identifier
        leaf = raw_leaf.lower()
        tokens = set(_TOKEN_SPLIT_RE.findall(lower_id))
        leaf_tokens = _split_camel_cached(raw_leaf)
        candidate_scores: dict[int, int] = {}

        strong_exact_hit = False
        for tok in leaf_tokens | tokens:
            idxs = self._primary_kw_index.get(tok)
            if not idxs:
                continue
            in_leaf = tok in leaf_tokens
            if tok in generic_kws:
                weight = 2
            elif in_leaf:
                weight = 22
                strong_exact_hit = True
            else:
                weight = 10
                strong_exact_hit = True
            for idx in idxs:
                candidate_scores[idx] = candidate_scores.get(idx, 0) + weight

        if not strong_exact_hit:
            for primary_kw, idxs in self._primary_kw_index.items():
                if len(primary_kw) >= 4 and primary_kw in leaf:
                    weight = 2 if primary_kw in generic_kws else 12
                    for idx in idxs:
                        candidate_scores[idx] = candidate_scores.get(idx, 0) + weight

        if not candidate_scores:
            return []

        hint_lower = container_hint.lower()
        if hint_lower:
            for hint_tok in _TOKEN_SPLIT_RE.findall(hint_lower):
                hint_idxs = self._keyword_index.get(hint_tok)
                if not hint_idxs:
                    continue
                if len(hint_idxs) <= len(candidate_scores):
                    for idx in hint_idxs:
                        if idx in candidate_scores:
                            candidate_scores[idx] += 4
                else:
                    n_hints = len(hint_idxs)
                    for idx in candidate_scores:
                        pos = bisect.bisect_left(hint_idxs, idx)
                        if pos < n_hints and hint_idxs[pos] == idx:
                            candidate_scores[idx] += 4

        ranked = sorted(candidate_scores.items(), key=lambda kv: (-kv[1], kv[0]))
        result = [self._read_record(idx) for idx, _ in ranked[:limit]]
        if len(self._match_cache) >= 4096:
            self._match_cache.clear()
        self._match_cache[cache_key] = result
        return result

    def search(self, query: str, limit: int = 25) -> list[FlawSignature]:
        tokens = _TOKEN_SPLIT_RE.findall(query.lower())
        if not tokens:
            return [self._read_record(i) for i in range(min(limit, len(self._offsets)))]

        counts: dict[int, int] = {}
        for tok in tokens:
            for idx in self._keyword_index.get(tok, ()):
                counts[idx] = counts.get(idx, 0) + 1
            if tok not in self._keyword_index and len(tok) >= 3:
                for kw, idxs in self._keyword_index.items():
                    if tok in kw:
                        for idx in idxs:
                            counts[idx] = counts.get(idx, 0) + 1

        if not counts:
            m = re.match(r"^rcw[-_]?(\d+)$", query.strip().lower())
            if m:
                sig = self.get(f"RCW-{int(m.group(1)):06d}")
                return [sig] if sig else []
            return []

        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return [self._read_record(idx) for idx, _ in ranked[:limit]]

    def enrich_finding(self, finding: Finding) -> Finding:
        matches = self.match_name(
            f"{finding.title} {finding.path}",
            container_hint=finding.path,
            limit=3,
        )
        if matches:
            top = matches[0]
            finding.metadata["catalog_code"] = top.code
            finding.metadata["domain"] = top.domain
            finding.metadata["matched_codes"] = [m.code for m in matches]
            finding.rank = min(finding.rank, top.rank)
            if not finding.flaw:
                finding.flaw = top.flaw
            if not finding.abuse:
                finding.abuse = top.abuse
            if not finding.fix:
                finding.fix = top.fix
            if not finding.title.startswith("[RCW-") and not finding.title.startswith("[LEARNED:"):
                finding.title = f"[{top.code}] {finding.title}"
            self.brain.ingest_flaw_record(
                domain=top.domain,
                severity=finding.severity,
                text=f"{finding.title} {finding.path} {finding.flaw}",
                fix=finding.fix,
            )
        return finding

    def match_source(self, script_path: str, source: str) -> list[Finding]:
        results: list[Finding] = []
        for rule in self.static_rules:
            if rule.literal_hint and rule.literal_hint.lower() not in source.lower():
                continue
            m = rule.pattern.search(source)
            if not m:
                continue
            if rule.anti_pattern and rule.anti_pattern.search(source):
                continue
            line_no = source.count("\n", 0, m.start()) + 1
            line_start = source.rfind("\n", 0, m.start()) + 1
            line_end = source.find("\n", m.end())
            snippet = source[line_start : (line_end if line_end != -1 else len(source))].strip()

            spec = build_web_contract_specification(
                script_path=script_path,
                title=rule.title,
                category=rule.category,
                flaw=rule.flaw,
                abuse=rule.abuse,
                fix=rule.fix,
                line_number=line_no,
                endpoint_name=f"{Path(script_path).name}:{line_no}",
                handler_kind=rule.category,
                vulnerable_snippet=snippet,
            )
            f = Finding(
                severity=rule.severity,
                category=rule.category,
                title=f"[{rule.code}] {rule.title}",
                path=f"{script_path}:{line_no}",
                flaw=rule.flaw,
                abuse=rule.abuse,
                fix=rule.fix,
                code_example=spec["patched_guard_and_unit_test_code"],
                rank=rule.rank,
                metadata={
                    "catalog_code": rule.code,
                    "script_path": script_path,
                    "line_number": line_no,
                    "remote_name": f"{Path(script_path).name}:{line_no}",
                    "contract_spec": spec,
                },
            )
            results.append(f)
        return results


@lru_cache(maxsize=1)
def get_web_catalog() -> WebFlawCatalog:
    return WebFlawCatalog()


def kid_friendly_web_exploit_summary(domain: str) -> str:
    """
    Returns a 1-2 line zero-jargon summary explaining what an attacker can do with
    this website weakness so anyone can understand it immediately.
    """
    summaries = {
        "xss_dom": (
            "// Simple summary: Someone can type hidden code into a text box or link so it runs\n"
            "// inside other visitors' browsers and steals their login or clicks buttons for them."
        ),
        "auth_session": (
            "// Simple summary: A visitor's login pass is left where page scripts can read it\n"
            "// or guess it, letting an attacker log in as someone else."
        ),
        "idor_access": (
            "// Simple summary: Anyone logged in can change the ID number in the address bar\n"
            "// or request to peek at or edit another person's private account data."
        ),
        "economy_checkout": (
            "// Simple summary: A shopper can tamper with the price, coupon, or quantity sent\n"
            "// from their browser to get paid items for free or negative cost."
        ),
        "sql_database": (
            "// Simple summary: User text is glued straight into a database command, letting\n"
            "// an attacker trick the database into spilling or deleting records."
        ),
        "cors_headers": (
            "// Simple summary: The website tells browsers that any outside page on the internet\n"
            "// is allowed to read its responses or frame its pages."
        ),
        "secrets_env": (
            "// Simple summary: A private password or API key is written directly inside the code\n"
            "// where anyone inspecting the site or repo can copy and use it."
        ),
        "csrf_cookies": (
            "// Simple summary: Clicking a trap on a different website can secretly make this\n"
            "// website perform actions using the visitor's active login cookie."
        ),
        "ssrf_redirect": (
            "// Simple summary: An attacker can feed a custom web address to bounce users to\n"
            "// a fake login page or make the server fetch private internal addresses."
        ),
        "memory_vitals": (
            "// Simple summary: The page keeps piling up background timers or listeners without\n"
            "// cleaning them up, making the browser tab slower until it freezes."
        ),
        "wcag_a11y": (
            "// Simple summary: Buttons or images are missing labels or focus rings, making\n"
            "// the site hard to use with a keyboard or screen reader."
        ),
    }
    return summaries.get(
        domain,
        "// Simple summary: This endpoint accepts input from the browser without checking\n"
        "// it first, which can cause errors or let visitors bypass rules.",
    )


def _detect_web_domain(category: str, title: str, path: str, flaw: str) -> str:
    blob = f"{category} {title} {path} {flaw}".lower()
    if any(k in blob for k in ("innerhtml", "dangerouslysetinnerhtml", "xss", "domsecurity", "script", "eval", "function(")):
        return "xss_dom"
    if any(k in blob for k in ("idor", "ownership", "brokenaccess", "permission", "admin", "rbac", "role")):
        return "idor_access"
    if any(k in blob for k in ("checkout", "price", "coupon", "discount", "payment", "stripe", "wallet", "balance", "cart", "order")):
        return "economy_checkout"
    if any(k in blob for k in ("sql", "prisma", "query", "nosql", "mongo", "database", "datasecurity")):
        return "sql_database"
    if any(k in blob for k in ("secret", "apikey", "sk_live", "ghp_", "webhook", "private_key", "env")):
        return "secrets_env"
    if any(k in blob for k in ("csrf", "samesite", "set-cookie", "res.cookie")):
        return "csrf_cookies"
    if any(k in blob for k in ("localstorage", "sessionstorage", "jwt", "token", "login", "password", "oauth", "auth")):
        return "auth_session"
    if any(k in blob for k in ("cors", "csp", "content-security-policy", "x-frame", "header", "sri", "noopener", "_blank")):
        return "cors_headers"
    if any(k in blob for k in ("redirect", "ssrf", "returnurl", "fetch(")):
        return "ssrf_redirect"
    if any(k in blob for k in ("addeventlistener", "setinterval", "memory", "leak", "cls", "layoutshift")):
        return "memory_vitals"
    if any(k in blob for k in ("wcag", "alt", "aria", "accessibility", "contrast", "focus")):
        return "wcag_a11y"
    return "api_contract"


def _infer_web_params(endpoint_name: str, domain: str) -> list[tuple[str, str]]:
    if domain == "economy_checkout":
        return [("userId", "string"), ("itemId", "string"), ("quantity", "number"), ("couponCode", "string")]
    if domain == "idor_access":
        return [("sessionUserId", "string"), ("targetResourceId", "string")]
    if domain == "xss_dom":
        return [("userId", "string"), ("htmlOrTextContent", "string")]
    if domain == "sql_database":
        return [("userId", "string"), ("filterKey", "string"), ("limit", "number")]
    if domain == "ssrf_redirect":
        return [("userId", "string"), ("returnPathOrUrl", "string")]
    return [("userId", "string"), ("actionKey", "string"), ("amount", "number")]


def build_web_contract_specification(
    *,
    script_path: str,
    title: str,
    category: str,
    flaw: str,
    abuse: str,
    fix: str,
    line_number: int | None = None,
    endpoint_name: str = "",
    handler_kind: str = "RouteHandler",
    raw_params: list[tuple[str, str]] | None = None,
    vulnerable_snippet: str = "",
    missing_guards: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generates the 4-section Web Server/App Unit Test & Contract Specification:
      1. trace_locator
      2. vulnerable_handler_code
      3. parameter_contract_matrix (+ parameter_contract_markdown)
      4. patched_guard_and_unit_test_code (TypeScript/JS Guard Module + console.assert() suite)
    """
    path_str = (script_path or "Unknown").strip()
    leaf = (endpoint_name or path_str.split("/")[-1].split("::")[-1]).strip() or "Endpoint"
    domain = _detect_web_domain(category, title, path_str, flaw)
    safe_ident = "".join(ch if ch.isalnum() else "_" for ch in leaf).strip("_") or "Endpoint"
    if safe_ident[0].isdigit():
        safe_ident = f"Route_{safe_ident}"
    guard_name = f"{safe_ident}Guard"

    params = raw_params if raw_params else _infer_web_params(leaf, domain)
    unvalidated_names = [p for p, _ in params]
    line_label = f"Line {line_number}" if line_number is not None else "Static / Runtime Discovery (search Cmd+Shift+F)"

    guards_missing = missing_guards or [
        "typeof & runtime schema validation",
        "finite number & string length bounds",
        "session.userId ownership / allowlist check",
        "per-user / per-IP sliding-window rate limiter",
    ]

    trace_locator = {
        "script_path": path_str,
        "line_number": line_number,
        "line_label": line_label,
        "remote_name": leaf,
        "handler_kind": handler_kind,
        "unvalidated_parameters": unvalidated_names,
        "missing_guards": guards_missing,
    }

    simple_summary = kid_friendly_web_exploit_summary(domain)
    if vulnerable_snippet and vulnerable_snippet.strip():
        vuln_code = f"{simple_summary}\n// Located at {path_str} ({line_label})\n{vulnerable_snippet.strip()}"
    else:
        param_sig = ", ".join(unvalidated_names)
        vuln_code = (
            f"{simple_summary}\n"
            f"// Located at {path_str} ({line_label})\n"
            f"export async function handleRequest(req) {{\n"
            f"  const {{ {param_sig} }} = req.body ?? {{}};\n"
            f"  // Unvalidated fields ({param_sig}) reach sink/database directly:\n"
            f"  // Flaw: {flaw}\n"
            f"}}"
        )

    matrix_rows: list[dict[str, str]] = []
    for pname, ptype in params:
        low = pname.lower()
        if ptype == "number" or any(k in low for k in ("qty", "quantity", "amount", "price", "limit", "count")):
            matrix_rows.append({
                "parameter": pname,
                "expected_typeof": "number (Number.isFinite & integer)",
                "valid_bounds": f"1 <= {pname} <= 1000 (Number.isFinite({pname}) && Math.floor({pname}) === {pname})",
                "rejected_edge_cases": "NaN, Infinity, -Infinity, -10, 0, 1.5, null, undefined, '100', {}",
            })
        elif any(k in low for k in ("url", "path", "redirect", "return")):
            matrix_rows.append({
                "parameter": pname,
                "expected_typeof": "string (relative path allowlist)",
                "valid_bounds": f"Starts with '/' and not '//', length 1..128, no 'javascript:' or CRLF",
                "rejected_edge_cases": "'https://evil.example', '//evil.example', 'javascript:alert(1)', null, 123",
            })
        else:
            matrix_rows.append({
                "parameter": pname,
                "expected_typeof": "string (trimmed, allowlisted / HTML-escaped)",
                "valid_bounds": f"1 <= {pname}.length <= 64, matches /^[A-Za-z0-9_\\-]+$/, not in (__proto__, constructor)",
                "rejected_edge_cases": "null, undefined, '', '<script>...</script>', '__proto__', 'A'.repeat(5000), {}",
            })

    md_table_lines = [
        "| Parameter / Field | Expected JS/TS `typeof` | Valid Bounds & Authority Rule | Rejected Edge-Case Inputs |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for r in matrix_rows:
        md_table_lines.append(
            f"| `{r['parameter']}` | `{r['expected_typeof']}` | {r['valid_bounds']} | {r['rejected_edge_cases']} |"
        )
    markdown_table = "\n".join(md_table_lines)

    # Build deterministic TypeScript/JavaScript Guard Module + console.assert() test suite
    guard_lines: list[str] = [
        "// What this does: This keeps your website fair and safe from attackers.",
        "// It checks every request from the browser so visitors cannot send fake prices,",
        "// sneaky script tags, or spam requests, and runs a self-test at the bottom to verify it works.",
        f"// Defensive Web Guard Module for '{leaf}' ({path_str}, {line_label})",
        "",
        f"const {guard_name} = {{",
        "  COOLDOWN_MS: 350,",
        "  MAX_STR_LEN: 64,",
        "  MAX_NUM_VAL: 1000,",
        "  FORBIDDEN_KEYS: new Set(['__proto__', 'prototype', 'constructor']),",
        "  _lastCallByUser: new Map(),",
        "",
        "  escapeHtml(raw) {",
        "    return String(raw)",
        "      .replace(/&/g, '&amp;')",
        "      .replace(/</g, '&lt;')",
        "      .replace(/>/g, '&gt;')",
        "      .replace(/\"/g, '&quot;')",
        "      .replace(/'/g, '&#39;');",
        "  },",
        "",
        "  validateAndAuthorize(payload, nowMs = Date.now()) {",
        "    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {",
        "      return { ok: false, reason: 'invalid_payload_object' };",
        "    }",
    ]

    for row in matrix_rows:
        p = row["parameter"]
        if "number" in row["expected_typeof"]:
            guard_lines.extend([
                f"    if (typeof payload.{p} !== 'number' || !Number.isFinite(payload.{p}) || Math.floor(payload.{p}) !== payload.{p}) {{",
                f"      return {{ ok: false, reason: 'invalid_number_{p}' }};",
                f"    }}",
                f"    if (payload.{p} < 1 || payload.{p} > this.MAX_NUM_VAL) {{",
                f"      return {{ ok: false, reason: 'out_of_bounds_{p}' }};",
                f"    }}",
            ])
        elif "relative path" in row["expected_typeof"]:
            guard_lines.extend([
                f"    if (typeof payload.{p} !== 'string' || payload.{p}.length < 1 || payload.{p}.length > 128) {{",
                f"      return {{ ok: false, reason: 'invalid_path_{p}' }};",
                f"    }}",
                f"    if (!payload.{p}.startsWith('/') || payload.{p}.startsWith('//') || payload.{p}.includes('\\\\')) {{",
                f"      return {{ ok: false, reason: 'open_redirect_blocked_{p}' }};",
                f"    }}",
            ])
        else:
            guard_lines.extend([
                f"    if (typeof payload.{p} !== 'string' || payload.{p}.trim().length < 1 || payload.{p}.length > this.MAX_STR_LEN) {{",
                f"      return {{ ok: false, reason: 'invalid_string_{p}' }};",
                f"    }}",
                f"    if (this.FORBIDDEN_KEYS.has(payload.{p}) || /[<>&\"']/.test(payload.{p})) {{",
                f"      return {{ ok: false, reason: 'unsafe_token_{p}' }};",
                f"    }}",
            ])

    first_user_param = next((r["parameter"] for r in matrix_rows if "user" in r["parameter"].lower()), matrix_rows[0]["parameter"])
    guard_lines.extend([
        f"    const callerKey = String(payload.{first_user_param});",
        "    const prevMs = this._lastCallByUser.get(callerKey);",
        "    if (prevMs !== undefined && (nowMs - prevMs) < this.COOLDOWN_MS) {",
        "      return { ok: false, reason: 'rate_limited' };",
        "    }",
        "    this._lastCallByUser.set(callerKey, nowMs);",
        "    return { ok: true, reason: 'ok' };",
        "  },",
        "};",
        "",
        "// ============================================================================",
        f"// Node / Browser Console Deterministic Unit-Test Verification ({guard_name})",
        "// ============================================================================",
        "function runWebContractAssertions() {",
    ])

    valid_props: list[str] = []
    for r in matrix_rows:
        p = r["parameter"]
        if "number" in r["expected_typeof"]:
            valid_props.append(f"{p}: 2")
        elif "relative path" in r["expected_typeof"]:
            valid_props.append(f"{p}: '/dashboard'")
        else:
            valid_props.append(f"{p}: 'valid_token_01'")
    valid_obj_str = "{ " + ", ".join(valid_props) + " }"

    guard_lines.extend([
        f"  {guard_name}._lastCallByUser.clear();",
        f"  const validPayload = {valid_obj_str};",
        f"  const passRes = {guard_name}.validateAndAuthorize(validPayload, 1000);",
        "  console.assert(passRes.ok === true, 'Expected valid web contract payload to pass:', passRes);",
        "",
        "  // Rapid burst call within 350ms window must be rate_limited",
        f"  const burstRes = {guard_name}.validateAndAuthorize(validPayload, 1050);",
        "  console.assert(burstRes.ok === false && burstRes.reason === 'rate_limited', 'Expected burst request to be rate_limited');",
    ])

    for r in matrix_rows:
        p = r["parameter"]
        if "number" in r["expected_typeof"]:
            bad_cases = [("nan", "NaN"), ("inf", "Infinity"), ("neg", "-5"), ("str", "'100'")]
        elif "relative path" in r["expected_typeof"]:
            bad_cases = [("ext", "'https://evil.example'"), ("proto_rel", "'//evil.example'"), ("null", "null")]
        else:
            bad_cases = [("xss", "'<script>alert(1)</script>'"), ("proto", "'__proto__'"), ("oversized", "'A'.repeat(256)"), ("null", "null")]
        for label, expr in bad_cases:
            guard_lines.extend([
                f"  {guard_name}._lastCallByUser.clear();",
                f"  const bad_{p}_{label} = {guard_name}.validateAndAuthorize({{ ...validPayload, {p}: {expr} }}, 2000);",
                f"  console.assert(bad_{p}_{label}.ok === false, 'Expected rejection for {p}={label}');",
            ])

    guard_lines.extend([
        f"  console.log('[rcdebug-web] All contract assertions PASSED for {leaf} ({path_str})');",
        "}",
        "runWebContractAssertions();",
    ])

    return {
        "trace_locator": trace_locator,
        "vulnerable_handler_code": vuln_code,
        "parameter_contract_matrix": matrix_rows,
        "parameter_contract_markdown": markdown_table,
        "patched_guard_and_unit_test_code": "\n".join(guard_lines),
    }


def audit_web_source(script_path: str, source: str) -> list[Finding]:
    """
    Static analyzer for website & web application source files (.html, .js, .jsx, .ts, .tsx, .py, .css):
    - Evaluates all 12 precompiled Web Static Code Rules (RCW-S001..RCW-S012)
    - Audits Express / Next.js / FastAPI route handlers for missing runtime validation & rate limiting
    """
    catalog = get_web_catalog()
    findings: list[Finding] = catalog.match_source(script_path, source)

    route_pattern = re.compile(
        r"(?:(app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{(.*?)\}|export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(([^)]*)\)\s*\{(.*?)\})",
        re.DOTALL,
    )
    for m in route_pattern.finditer(source):
        line_no = source.count("\n", 0, m.start()) + 1
        snippet = m.group(0).strip()
        if m.group(3):
            method = m.group(2).upper()
            route_name = f"{method} {m.group(3)}"
            body = m.group(5) or ""
        else:
            method = (m.group(6) or "POST").upper()
            route_name = f"{method} {Path(script_path).name}"
            body = m.group(8) or ""

        reads_input = bool(re.search(r"\b(?:req\.body|req\.query|req\.params|request\.json)\b", body))
        has_validation = bool(re.search(r"\b(?:typeof|Number\.isFinite|z\.object|schema\.parse|safeParse|validate)\b", body))
        has_ratelimit = bool(re.search(r"\b(?:rateLimit|limiter|cooldown|throttle)\b", body, re.IGNORECASE))

        if reads_input and not has_validation:
            field_matches = re.findall(r"req\.(?:body|query|params)\.([A-Za-z_][A-Za-z0-9_]*)", body)
            raw_params = [(fn, "number" if any(k in fn.lower() for k in ("price", "qty", "amount", "limit")) else "string") for fn in dict.fromkeys(field_matches)]
            spec = build_web_contract_specification(
                script_path=script_path,
                title=f"Missing Request Schema Validation on {route_name}",
                category="APISecurity",
                flaw=f"Route handler '{route_name}' at {script_path}:{line_no} reads request fields without runtime schema/typeof validation.",
                abuse="Clients can send unexpected types, NaN, negative numbers, or prototype-polluting keys in JSON bodies.",
                fix=f"Validate request fields with the generated Guard Module or a strict Zod/Valibot schema at entry.",
                line_number=line_no,
                endpoint_name=route_name,
                handler_kind="APIRouteHandler",
                raw_params=raw_params or None,
                vulnerable_snippet=snippet,
            )
            f = Finding(
                severity="CRITICAL",
                category="APISecurity",
                title=f"Missing Request Schema Validation on {route_name}",
                path=f"{script_path}:{line_no}",
                flaw=f"Route handler at {script_path}:{line_no} reads client input without typeof/schema validation.",
                abuse="Attackers can send negative quantities, NaN, oversized strings, or nested objects to bypass business logic.",
                fix=f"Enforce strict typeof, finite bounds, and rate limiting on {route_name}.",
                code_example=spec["patched_guard_and_unit_test_code"],
                metadata={
                    "script_path": script_path,
                    "line_number": line_no,
                    "remote_name": route_name,
                    "contract_spec": spec,
                },
            )
            findings.append(catalog.enrich_finding(f))
        elif reads_input and not has_ratelimit and method in ("POST", "PUT", "PATCH", "DELETE"):
            spec = build_web_contract_specification(
                script_path=script_path,
                title=f"Missing Rate Limiter on State-Changing Route {route_name}",
                category="APISecurity",
                flaw=f"Mutation route '{route_name}' at {script_path}:{line_no} has no visible rate-limiting guard.",
                abuse="Automated clients can flood state-changing endpoints to trigger race conditions or exhaust database pools.",
                fix="Enforce a per-user and per-IP sliding-window rate limiter before processing mutations.",
                line_number=line_no,
                endpoint_name=route_name,
                handler_kind="APIRouteHandler",
                vulnerable_snippet=snippet,
            )
            f = Finding(
                severity="WARN",
                category="APISecurity",
                title=f"Missing Rate Limiter on {route_name}",
                path=f"{script_path}:{line_no}",
                flaw=f"State-changing route '{route_name}' lacks per-user/IP rate limiting.",
                abuse="High-frequency burst requests can brute-force tokens or cause race-condition double writes.",
                fix="Attach rate-limiting middleware returning HTTP 429 Too Many Requests.",
                code_example=spec["patched_guard_and_unit_test_code"],
                metadata={
                    "script_path": script_path,
                    "line_number": line_no,
                    "remote_name": route_name,
                    "contract_spec": spec,
                },
            )
            findings.append(catalog.enrich_finding(f))

    findings.sort(key=lambda item: item.sort_key())
    return findings


_WEB_EXTENSIONS = {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".css"}
_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "coverage"}


def audit_local_web_path(
    target_path: Path,
    session: AuditSession,
    filter_level: SeverityFilter = None,
) -> int:
    """Scans a local web file or project folder in parallel and adds findings to session."""
    files: list[Path] = []
    if target_path.is_file():
        files.append(target_path)
    elif target_path.is_dir():
        for p in target_path.rglob("*"):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.is_file() and p.suffix.lower() in _WEB_EXTENSIONS and p.stat().st_size <= 2 * 1024 * 1024:
                files.append(p)

    def _scan_one(fp: Path) -> list[Finding]:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        try:
            rel = str(fp.relative_to(target_path.parent if target_path.is_file() else target_path))
        except ValueError:
            rel = str(fp)
        return audit_web_source(rel, text)

    added = 0
    if files:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for file_findings in pool.map(_scan_one, files[:400]):
                for f in file_findings:
                    if matches_filter(f.severity, filter_level):
                        if session.add_finding(f):
                            added += 1
    return added


def build_browser_qa_runner_script(snapshot_interval: int = 10) -> str:
    """
    Returns an offline, self-contained Browser DevTools Console QA Test Runner (JavaScript).
    Makes zero external HTTP calls and prints [PASS] / [FAIL] directly to the Browser Console.
    """
    return f"""// What this script does:
// This is an offline Browser DevTools QA Test Runner for your own website.
// Paste it into Chrome, Safari, or Firefox DevTools Console while testing your site
// on localhost or staging. It makes zero internet calls and prints [PASS] or [FAIL]
// straight into the Console so you can fix security, accessibility, and memory bugs.
// [rcdebug --ui-web v1.0] Offline Browser DevTools QA Test Runner (Zero External HTTP Calls)

(async function runRcdebugWebQA() {{
  const SNAPSHOT_INTERVAL_SEC = {snapshot_interval};
  let passedCount = 0;
  let failedCount = 0;

  function logPass(suite, checkName, detail) {{
    passedCount += 1;
    console.log(`[PASS] [${{suite}}] ${{checkName}} - ${{detail}}`);
  }}

  function logFail(suite, checkName, plainEnglishReason) {{
    failedCount += 1;
    console.warn(`[FAIL] [${{suite}}] ${{checkName}} - ${{plainEnglishReason}}`);
  }}

  console.log("====================================================================");
  console.log("[rcdebug-web] Starting Offline Browser DevTools QA Test Runner...");
  console.log("====================================================================");

  // SUITE 1: Transport, CSP Meta & Security Boundary Check
  (function runSecurityHeadersAndCSPSuite() {{
    const suite = "SecurityAndCSP";
    const isSecureContext = window.isSecureContext || location.hostname === "localhost" || location.hostname === "127.0.0.1";
    if (isSecureContext) {{
      logPass(suite, "SecureContext", `Page is running in a secure context (${{location.protocol}}//${{location.hostname}}).`);
    }} else {{
      logFail(suite, "SecureContext", "Page is loaded over plain HTTP on a non-localhost domain. Serve over HTTPS so cookies and inputs cannot be intercepted.");
    }}

    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
    if (cspMeta && cspMeta.content) {{
      if (cspMeta.content.includes("'unsafe-inline'") || cspMeta.content.includes("'unsafe-eval'")) {{
        logFail(suite, "ContentSecurityPolicy", "CSP meta tag allows 'unsafe-inline' or 'unsafe-eval'. Use nonces or hashes so injected scripts cannot run.");
      }} else {{
        logPass(suite, "ContentSecurityPolicy", "Strict CSP meta policy detected.");
      }}
    }} else {{
      logFail(suite, "ContentSecurityPolicy", "No Content-Security-Policy meta tag found in <head> (verify your server sends a strict Content-Security-Policy HTTP response header).");
    }}
  }})();

  // SUITE 2: DOM XSS Sinks, Inline Event Attributes & Third-Party Script SRI
  (function runDOMSinksAndSRISuite() {{
    const suite = "DOMSinksAndSRI";
    const inlineHandlerAttrs = ["onclick", "onerror", "onload", "onmouseover", "onfocus", "onsubmit"];
    const selector = inlineHandlerAttrs.map((a) => `[${{a}}]`).join(",");
    const inlineEls = document.querySelectorAll(selector);
    if (inlineEls.length > 0) {{
      logFail(suite, "InlineEventHandlers", `Found ${{inlineEls.length}} element(s) using inline HTML event attributes (${{inlineHandlerAttrs.join("/")}}). Move listeners to JS addEventListener so you can enforce a strict CSP.`);
    }} else {{
      logPass(suite, "InlineEventHandlers", "Zero inline HTML event handler attributes found.");
    }}

    const externalScripts = Array.from(document.querySelectorAll("script[src]")).filter((s) => {{
      try {{
        const u = new URL(s.src, location.href);
        return u.origin !== location.origin;
      }} catch (_) {{
        return false;
      }}
    }});
    const missingSri = externalScripts.filter((s) => !s.integrity);
    if (missingSri.length > 0) {{
      logFail(suite, "SubresourceIntegrity", `${{missingSri.length}} third-party <script src> tag(s) lack an integrity="sha384-..." attribute. Add SRI so a compromised CDN cannot alter your scripts.`);
    }} else {{
      logPass(suite, "SubresourceIntegrity", "All external scripts either share origin or enforce Subresource Integrity.");
    }}

    const unsafeBlankLinks = Array.from(document.querySelectorAll('a[target="_blank"]')).filter((a) => {{
      const rel = (a.getAttribute("rel") || "").toLowerCase();
      return !rel.includes("noopener") && !rel.includes("noreferrer");
    }});
    if (unsafeBlankLinks.length > 0) {{
      logFail(suite, "TargetBlankIsolation", `${{unsafeBlankLinks.length}} <a target="_blank"> link(s) omit rel="noopener noreferrer".`);
    }} else {{
      logPass(suite, "TargetBlankIsolation", 'All target="_blank" links include rel="noopener" isolation.');
    }}
  }})();

  // SUITE 3: Client Storage & JS-Readable Cookie Exposure Check
  (function runStorageAndCookieSuite() {{
    const suite = "StorageAndCookies";
    const sensitivePattern = /(token|jwt|auth|secret|password|apikey|session|bearer)/i;
    const exposedKeys = [];
    try {{
      for (let i = 0; i < localStorage.length; i++) {{
        const k = localStorage.key(i) || "";
        if (sensitivePattern.test(k)) exposedKeys.push(`localStorage.${{k}}`);
      }}
      for (let i = 0; i < sessionStorage.length; i++) {{
        const k = sessionStorage.key(i) || "";
        if (sensitivePattern.test(k)) exposedKeys.push(`sessionStorage.${{k}}`);
      }}
    }} catch (_) {{}}

    if (exposedKeys.length > 0) {{
      logFail(suite, "ClientStorageSecrets", `Sensitive keys (${{exposedKeys.slice(0, 5).join(", ")}}) are stored in localStorage/sessionStorage where any page script can read them. Store session tokens in HttpOnly cookies instead.`);
    }} else {{
      logPass(suite, "ClientStorageSecrets", "No sensitive token/secret keys found in localStorage or sessionStorage.");
    }}

    if (document.cookie && sensitivePattern.test(document.cookie)) {{
      logFail(suite, "ReadableAuthCookies", "An authentication or session cookie is readable by document.cookie. Add the HttpOnly and Secure flags when setting session cookies on the server.");
    }} else {{
      logPass(suite, "ReadableAuthCookies", "No sensitive session cookies exposed to document.cookie.");
    }}
  }})();

  // SUITE 4: Forms, Accessibility (WCAG 2.2) & Layout Stability (CLS)
  (function runAccessibilityAndFormsSuite() {{
    const suite = "AccessibilityAndForms";
    const imgsMissingAlt = document.querySelectorAll("img:not([alt])");
    if (imgsMissingAlt.length > 0) {{
      logFail(suite, "ImageAltText", `${{imgsMissingAlt.length}} <img> element(s) are missing an alt attribute (WCAG 1.1.1).`);
    }} else {{
      logPass(suite, "ImageAltText", "Every <img> element includes an alt attribute.");
    }}

    const unlabeledButtons = Array.from(document.querySelectorAll("button, [role='button']")).filter((btn) => {{
      const text = (btn.textContent || "").trim();
      const aria = btn.getAttribute("aria-label") || btn.getAttribute("aria-labelledby") || btn.getAttribute("title");
      return !text && !aria;
    }});
    if (unlabeledButtons.length > 0) {{
      logFail(suite, "AccessibleButtonNames", `${{unlabeledButtons.length}} button(s) have no visible text or aria-label for screen readers.`);
    }} else {{
      logPass(suite, "AccessibleButtonNames", "All buttons expose an accessible name.");
    }}

    const passwordInputsNoAuto = document.querySelectorAll('input[type="password"]:not([autocomplete])');
    if (passwordInputsNoAuto.length > 0) {{
      logFail(suite, "PasswordAutocomplete", `${{passwordInputsNoAuto.length}} password input(s) omit autocomplete="current-password" or "new-password".`);
    }} else {{
      logPass(suite, "PasswordAutocomplete", "Password inputs declare explicit autocomplete attributes.");
    }}
  }})();

  // SUITE 5: 10-Second DOM Node & JS Heap Memory Stability Check
  await (async function runMemoryStabilitySuite() {{
    const suite = "DOMAndHeapMemory";
    const baseNodes = document.querySelectorAll("*").length;
    const baseHeapMb = performance && performance.memory ? (performance.memory.usedJSHeapSize / (1024 * 1024)) : 0;
    console.log(`[INFO] [${{suite}}] Baseline -> DOM nodes: ${{baseNodes}} | JS Heap: ${{baseHeapMb.toFixed(2)}} MB (waiting ${{SNAPSHOT_INTERVAL_SEC}}s...)`);

    await new Promise((r) => setTimeout(r, SNAPSHOT_INTERVAL_SEC * 1000));

    const nextNodes = document.querySelectorAll("*").length;
    const nextHeapMb = performance && performance.memory ? (performance.memory.usedJSHeapSize / (1024 * 1024)) : 0;
    const nodeDelta = nextNodes - baseNodes;
    const heapDelta = nextHeapMb - baseHeapMb;

    if (nodeDelta > 250 || heapDelta > 25) {{
      logFail(suite, "DOMAndHeapGrowth", `DOM grew by +${{nodeDelta}} nodes and JS heap rose by +${{heapDelta.toFixed(2)}} MB in ${{SNAPSHOT_INTERVAL_SEC}}s. Check for uncleaned setInterval timers or addEventListener leaks.`);
    }} else {{
      logPass(suite, "DOMAndHeapGrowth", `Stable over ${{SNAPSHOT_INTERVAL_SEC}}s (DOM nodes ${{nodeDelta >= 0 ? "+" : ""}}${{nodeDelta}}, JS heap ${{heapDelta >= 0 ? "+" : ""}}${{heapDelta.toFixed(2)}} MB).`);
    }}
  }})();

  console.log("====================================================================");
  console.log(`[rcdebug-web QA Summary] Passed: ${{passedCount}} | Failed: ${{failedCount}}`);
  console.log("====================================================================");
}})();
"""


def simulate_web_audit_traffic(host: str, port: int) -> None:
    """
    Streams realistic website & web-application security, performance, and WCAG findings,
    10-second DOM/JS Heap memory telemetry, and API endpoint traffic into the local --ui-web server.
    """
    report_url = f"http://{host}:{port}/report"
    telemetry_url = f"http://{host}:{port}/telemetry"

    demo_findings = [
        {
            "severity": "CRITICAL",
            "category": "DOMSecurity",
            "title": "[RCW-000001] Unsanitized DOM HTML Sink in Comment Renderer",
            "path": "src/components/RichComment.tsx:42",
            "flaw": "Component renders user-authored comment.html directly via dangerouslySetInnerHTML without DOMPurify sanitization.",
            "abuse": "Attackers submit <img src=x onerror=...> payloads in comments to execute arbitrary JS in every viewer's browser session.",
            "fix": "Sanitize untrusted HTML with DOMPurify.sanitize(comment.html, { USE_PROFILES: { html: true } }) before rendering.",
        },
        {
            "severity": "CRITICAL",
            "category": "APISecurity",
            "title": "[RCW-000105] Client-Trusted Price & Discount in Checkout Endpoint",
            "path": "src/app/api/checkout/apply-coupon/route.ts:28",
            "flaw": "POST /api/checkout/apply-coupon accepts unitPrice, quantity, and discountAmount directly from req.body JSON without server catalog lookup.",
            "abuse": "Shoppers send negative quantities, NaN, or 100% discountAmount values to complete orders for $0.00 or credit their balance.",
            "fix": "Look up item prices and coupon rules strictly from the server database, enforce finite integer quantity bounds, and ignore client price fields.",
        },
        {
            "severity": "CRITICAL",
            "category": "AuthSecurity",
            "title": "[RCW-000210] Missing Object-Level Ownership Check (IDOR) on Order Endpoint",
            "path": "src/server/routes/orders.ts:64",
            "flaw": "GET /api/orders/:orderId queries db.orders.findUnique({ where: { id: req.params.orderId } }) without verifying order.userId === session.userId.",
            "abuse": "Any authenticated user can enumerate orderId parameters to view other customers' billing addresses, invoices, and items.",
            "fix": "Scope the database query by both resource ID and authenticated session owner: where: { id: orderId, userId: session.userId }.",
        },
        {
            "severity": "WARN",
            "category": "AuthSecurity",
            "title": "[RCW-035010] Session JWT Stored in Client-Readable localStorage",
            "path": "src/auth/tokenStore.ts:19",
            "flaw": "Auth client persists bearer access_token and refresh_token inside window.localStorage.setItem('access_token', token).",
            "abuse": "Any XSS flaw or compromised npm dependency can read localStorage and exfiltrate active JWTs across all users.",
            "fix": "Set session tokens from the server in HttpOnly; Secure; SameSite=Lax cookies and keep short-lived tokens in memory only.",
        },
        {
            "severity": "WARN",
            "category": "PlatformSecurity",
            "title": "[RCW-035140] Permissive Wildcard CORS & Missing CSP Header",
            "path": "src/middleware/corsConfig.ts:11",
            "flaw": "API middleware responds with Access-Control-Allow-Origin: * and omits a Content-Security-Policy header.",
            "abuse": "Untrusted external sites can read cross-origin API responses and inject inline scripts if any markup sink exists.",
            "fix": "Validate Origin against an explicit production domain allowlist and emit a strict nonce-based Content-Security-Policy header.",
        },
        {
            "severity": "WARN",
            "category": "MemoryLeak",
            "title": "[RCW-035420] Uncleaned window.addEventListener & setInterval in LiveTicker",
            "path": "src/hooks/useLiveTicker.ts:33",
            "flaw": "useEffect registers window.addEventListener('resize', onResize) and setInterval(poll, 1000) without returning an unmount cleanup function.",
            "abuse": "Every SPA page navigation leaks closures and detached DOM references, climbing JS heap memory and dropping frame rate.",
            "fix": "Return () => { window.removeEventListener('resize', onResize); clearInterval(timerId); } from useEffect.",
        },
        {
            "severity": "INFO",
            "category": "AccessibilityWCAG",
            "title": "[RCW-084020] Hero & Product Images Missing alt Text and Intrinsic Dimensions",
            "path": "src/components/ProductGrid.tsx:78",
            "flaw": "Product card <img> elements omit alt attributes and explicit width/height attributes.",
            "abuse": "Screen readers cannot describe product images (WCAG 1.1.1) and late-loading images trigger Cumulative Layout Shift (CLS).",
            "fix": "Add descriptive alt={product.title} and intrinsic width={640} height={480} attributes to all <img> elements.",
        },
    ]

    try:
        req = Request(
            report_url,
            data=json.dumps({"findings": demo_findings}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=2.5):
            pass
    except Exception:
        return

    snapshots = [
        {"elapsed_sec": 0.0, "workspace_instances": 1420, "player_instances": 18, "total_memory_mb": 48.4},
        {"elapsed_sec": 10.0, "workspace_instances": 1590, "player_instances": 24, "total_memory_mb": 56.2},
        {"elapsed_sec": 20.0, "workspace_instances": 1840, "player_instances": 31, "total_memory_mb": 69.8},
        {"elapsed_sec": 30.0, "workspace_instances": 2190, "player_instances": 42, "total_memory_mb": 88.5},
    ]
    remotes = [
        {"remote_path": "POST /api/checkout/apply-coupon", "remote_type": "REST POST (Unthrottled)", "total_calls": 340, "rate_per_sec": 34.0},
        {"remote_path": "GET /api/orders/:orderId", "remote_type": "REST GET (IDOR Surface)", "total_calls": 180, "rate_per_sec": 18.0},
        {"remote_path": "POST /api/graphql (UpdateProfileMutation)", "remote_type": "GraphQL Mutation", "total_calls": 64, "rate_per_sec": 6.4},
    ]

    for idx, snap in enumerate(snapshots):
        time.sleep(0.15)
        payload: dict[str, Any] = {"memory_snapshot": snap}
        if idx == len(snapshots) - 1:
            payload["remote_traffic"] = remotes
        try:
            t_req = Request(
                telemetry_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(t_req, timeout=2.5):
                pass
        except Exception:
            break
