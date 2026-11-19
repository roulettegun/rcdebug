"""
Sub-10ms 120,000-Flaw Intelligence Catalog (flaws_120000.txt + ~/.rcdebug/index_cache.bin).

Uses a marshal-backed byte-offset & inverted-posting-list binary cache plus mmap
seek-reads so cold/warm CLI startups bypass parsing 120,000 lines into Python dicts.
"""

from __future__ import annotations

import marshal
import mmap
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator, Pattern

from .debugger_pack import get_debugger_pack
from .learner import AdaptiveLearner, FlawBrain, extract_game_tokens
from .models import Finding, normalize_severity

FLAWS_TXT_PATH = Path(__file__).resolve().parent / "data" / "flaws_120000.txt"
INDEX_CACHE_PATH = Path.home() / ".rcdebug" / "index_cache.bin"
EXPECTED_FLAW_COUNT = 120000
_CACHE_VERSION = 2


@dataclass(frozen=True, slots=True)
class FlawSignature:
    code: str
    severity: str
    category: str
    domain: str
    title: str
    keywords: tuple[str, ...]
    flaw: str
    abuse: str
    fix: str
    rank: int = 999999
    code_example: str = ""


@dataclass(frozen=True, slots=True)
class StaticCodeRule:
    code: str
    severity: str
    category: str
    title: str
    literal_hint: str
    pattern: Pattern[str]
    anti_pattern: Pattern[str] | None
    flaw: str
    abuse: str
    fix: str
    rank: int = 100
    code_example: str = ""


STATIC_CODE_RULES: tuple[StaticCodeRule, ...] = (
    StaticCodeRule(
        code="RCD-S001",
        severity="CRITICAL",
        category="StaticScriptAudit",
        title="Dynamic Code Execution via loadstring()",
        literal_hint="loadstring",
        pattern=re.compile(r"\bloadstring\s*\("),
        anti_pattern=None,
        flaw="Script invokes loadstring() to dynamically compile and execute arbitrary Luau strings.",
        abuse="If any remote argument, DataStore entry, or free-model payload reaches loadstring(), attackers achieve full server RCE.",
        fix="Disable ServerScriptService.LoadStringEnabled and replace dynamic execution with a static function lookup table.",
        rank=1,
        code_example="local Handlers = { Heal = function(plr) ... end }\nlocal fn = Handlers[action]\nif fn then fn(player) end",
    ),
    StaticCodeRule(
        code="RCD-S002",
        severity="CRITICAL",
        category="HttpSecurity",
        title="Hardcoded Discord Webhook URL in Script",
        literal_hint="webhooks/",
        pattern=re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/", re.IGNORECASE),
        anti_pattern=None,
        flaw="Script embeds a raw Discord webhook URL directly in source code.",
        abuse="Attackers can extract exposed shared URLs or trigger remote-backed actions to spam/delete the webhook or forge audit logs.",
        fix="Store credentials in HttpService:GetSecret() and throttle outbound webhook dispatches server-side.",
        rank=2,
        code_example='local secret = HttpService:GetSecret("AUDIT_WEBHOOK")',
    ),
    StaticCodeRule(
        code="RCD-S003",
        severity="WARN",
        category="HttpSecurity",
        title="Unwrapped or Unthrottled Outbound HttpService Call",
        literal_hint="HttpService",
        pattern=re.compile(r"HttpService\s*:\s*(?:PostAsync|GetAsync|RequestAsync)\s*\("),
        anti_pattern=re.compile(r"\bpcall\s*\("),
        flaw="Script calls HttpService network methods without an enclosing pcall() or visible rate-limit guard.",
        abuse="Malicious players triggering HTTP-backed actions can exhaust the 500 req/min HttpService budget or cause unhandled script crashes.",
        fix="Wrap all HttpService calls in pcall(), enforce per-player/server request queues, and never interpolate client input into URLs.",
        rank=25010,
        code_example="local ok, res = pcall(function() return HttpService:RequestAsync(opts) end)",
    ),
    StaticCodeRule(
        code="RCD-S004",
        severity="CRITICAL",
        category="DataStoreSecurity",
        title="Non-Atomic DataStore SetAsync() Without UpdateAsync()",
        literal_hint="SetAsync",
        pattern=re.compile(r":\s*SetAsync\s*\("),
        anti_pattern=re.compile(r":\s*UpdateAsync\s*\("),
        flaw="Script writes player progression using SetAsync() instead of atomic UpdateAsync() transforms.",
        abuse="Concurrent server saves, cross-server teleports, or rapid trade/drop requests cause classic DataStore item duplication or rollback.",
        fix="Use DataStore:UpdateAsync() with session locking (or ProfileStore/ProfileService) for all currency and inventory persistence.",
        rank=3,
        code_example="store:UpdateAsync(key, function(old)\n    old = old or { Cash = 0 }\n    old.Cash += delta\n    return old\nend)",
    ),
    StaticCodeRule(
        code="RCD-S005",
        severity="CRITICAL",
        category="MarketplaceSecurity",
        title="ProcessReceipt Handler Missing PurchaseId Idempotency Check",
        literal_hint="ProcessReceipt",
        pattern=re.compile(r"MarketplaceService\.ProcessReceipt\s*="),
        anti_pattern=re.compile(r"PurchaseId|Enum\.ProductPurchaseDecision\.PurchaseGranted"),
        flaw="MarketplaceService.ProcessReceipt callback lacks visible PurchaseId deduplication or explicit PurchaseGranted handling.",
        abuse="Players can trigger duplicate developer product grants on rejoin or leave receipts unacknowledged across sessions.",
        fix="Record receiptInfo.PurchaseId atomically via UpdateAsync() before returning Enum.ProductPurchaseDecision.PurchaseGranted.",
        rank=4,
        code_example="if table.find(profile.ProcessedReceipts, receipt.PurchaseId) then\n    return Enum.ProductPurchaseDecision.PurchaseGranted\nend",
    ),
    StaticCodeRule(
        code="RCD-S006",
        severity="CRITICAL",
        category="PromptSecurity",
        title="ProximityPrompt.Triggered Without Server Distance Check",
        literal_hint="Triggered",
        pattern=re.compile(r"\.Triggered\s*:\s*Connect\s*\("),
        anti_pattern=re.compile(r"Magnitude|MaxActivationDistance|DistanceFromCharacter"),
        flaw="ProximityPrompt.Triggered handler trusts client prompt activation without verifying character distance on the server.",
        abuse="Exploiters manipulating local character position or replication timing can fire prompts from across the map or through walls.",
        fix="Verify player.Character PrimaryPart distance to the prompt's parent BasePart (<= prompt.MaxActivationDistance + tolerance) on the server.",
        rank=5,
        code_example="local root = player.Character and player.Character.PrimaryPart\nif not root or (root.Position - promptPart.Position).Magnitude > prompt.MaxActivationDistance + 4 then return end",
    ),
    StaticCodeRule(
        code="RCD-S007",
        severity="WARN",
        category="PhysicsSecurity",
        title="BasePart.Touched Handler Missing Player/Cooldown Guard",
        literal_hint="Touched",
        pattern=re.compile(r"\.Touched\s*:\s*Connect\s*\("),
        anti_pattern=re.compile(r"GetPlayerFromCharacter|debounce|cooldown|os\.clock"),
        flaw="Touched connection processes hits without checking GetPlayerFromCharacter or enforcing a per-player debounce.",
        abuse="Clients with network ownership over their character or unanchored parts can spam Touched events 60+ times per second.",
        fix="Validate Players:GetPlayerFromCharacter(hit.Parent) and apply a per-player cooldown before awarding damage, coins, or teleports.",
        rank=25020,
        code_example="local plr = Players:GetPlayerFromCharacter(hit.Parent)\nif not plr or isDebounced(plr) then return end",
    ),
    StaticCodeRule(
        code="RCD-S008",
        severity="CRITICAL",
        category="TeleportSecurity",
        title="TeleportService Call With Unvalidated TeleportData or PlaceId",
        literal_hint="Teleport",
        pattern=re.compile(r"TeleportService\s*:\s*(?:Teleport|TeleportAsync|TeleportToPlaceInstance)\s*\("),
        anti_pattern=re.compile(r"ALLOWED_PLACES|MemoryStoreService|DataStore"),
        flaw="Script invokes TeleportService without validating target PlaceIds or signing cross-server state.",
        abuse="If teleport options or TeleportData come from client-accessible sources, attackers can spoof carried stats/inventory on arrival.",
        fix="Never trust GetLocalPlayerTeleportData() on the server; pass authoritative cross-server state via MemoryStoreService or DataStoreService.",
        rank=6,
    ),
    StaticCodeRule(
        code="RCD-S009",
        severity="WARN",
        category="TextFiltering",
        title="User-Supplied Text Displayed Without TextService Filtering",
        literal_hint=".Text",
        pattern=re.compile(r"\.Text\s*=\s*(?:msg|message|text|input|name|bio|petName|title)\b", re.IGNORECASE),
        anti_pattern=re.compile(r"FilterStringAsync|TextService|TextChatService"),
        flaw="User-supplied string appears to be assigned directly to a UI/SurfaceGui Text property without TextService filtering.",
        abuse="Players can broadcast unfiltered profanity, PII, or moderation-violating text to other players, risking game moderation action.",
        fix="Always pass user-authored text through TextService:FilterStringAsync() on the server before replicating to other clients.",
        rank=25030,
    ),
    StaticCodeRule(
        code="RCD-S010",
        severity="WARN",
        category="MemoryLeak",
        title="Unbounded Connection or Instance Creation Without Cleanup",
        literal_hint="Instance.new",
        pattern=re.compile(r"Instance\.new\s*\(\s*[\"'](?:Part|MeshPart|Model|Sound|ParticleEmitter)[\"']"),
        anti_pattern=re.compile(r"Debris\s*:\s*AddItem|:Destroy\s*\("),
        flaw="Script dynamically instantiates Workspace/FX objects without visible Debris:AddItem() or :Destroy() lifecycle cleanup.",
        abuse="Repeated combat, projectile, or VFX spawns leak instances until server memory saturates and physics degrades.",
        fix="Register temporary instances with Debris:AddItem(obj, lifetime) or reuse objects via an instance pool.",
        rank=25040,
        code_example='game:GetService("Debris"):AddItem(fxInstance, 2.5)',
    ),
    StaticCodeRule(
        code="RCD-S011",
        severity="CRITICAL",
        category="ServerSecurity",
        title="Legacy Require by Numeric Asset ID (Potential Backdoor Surface)",
        literal_hint="require",
        pattern=re.compile(r"\brequire\s*\(\s*\d{6,}\s*\)"),
        anti_pattern=None,
        flaw="Script calls require(<numeric_asset_id>) to load external closed-source ModuleScripts at runtime.",
        abuse="External asset modules can be updated independently by third parties to inject server backdoors, remote shells, or data exfiltration.",
        fix="Replace numeric asset require() calls with audited local ModuleScripts inside ServerScriptService or ReplicatedStorage.",
        rank=7,
    ),
    StaticCodeRule(
        code="RCD-S012",
        severity="CRITICAL",
        category="CombatSecurity",
        title="Server Accepts Client-Supplied Damage or Target Health Value",
        literal_hint="Humanoid",
        pattern=re.compile(r"Humanoid\s*(?::\s*TakeDamage|\.Health\s*[-+]?=)\s*\(?\s*(?:dmg|damage|amount|heal|val)\b", re.IGNORECASE),
        anti_pattern=re.compile(r"WEAPON_STATS|MAX_DAMAGE|math\.clamp"),
        flaw="Server damage/healing calculation applies a variable directly without looking up authoritative weapon stats or clamping.",
        abuse="If the parameter originates from a RemoteEvent, attackers can pass 1e9 to insta-kill any player/boss or negative values to heal/godmode.",
        fix="Look up damage server-side from weapon/ability IDs, validate range/LoS/cooldowns, and reject NaN or negative numbers.",
        rank=8,
    ),
)

_TOKEN_SPLIT_RE = re.compile(r"[a-z0-9]+")
_CAMEL_SUB_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)|\d+")


@lru_cache(maxsize=16384)
def _split_camel_cached(raw_leaf: str) -> frozenset[str]:
    out: set[str] = set(_TOKEN_SPLIT_RE.findall(raw_leaf.lower()))
    for part in re.split(r"[^A-Za-z0-9]+", raw_leaf):
        if not part:
            continue
        for sub in _CAMEL_SUB_RE.findall(part):
            out.add(sub.lower())
    return frozenset(out)


def _parse_flaw_line(raw_line: str) -> FlawSignature:
    line = raw_line.rstrip("\r\n")
    parts = line.split("|", 9)
    if len(parts) < 9:
        raise ValueError(f"Malformed flaw record: {line[:80]}")
    code, sev, cat, domain, kw_csv, title, flaw, abuse, fix = parts[:9]
    rank = int(parts[9]) if len(parts) == 10 and parts[9].isdigit() else 999999
    keywords = tuple(k.strip().lower() for k in kw_csv.split(",") if k.strip())
    return FlawSignature(
        code=code,
        severity=sev,
        category=cat,
        domain=domain,
        title=title,
        keywords=keywords,
        flaw=flaw,
        abuse=abuse,
        fix=fix,
        rank=rank,
    )


def _build_or_load_index(
    txt_path: Path = FLAWS_TXT_PATH,
    cache_path: Path = INDEX_CACHE_PATH,
) -> tuple[list[int], dict[str, list[int]], dict[str, list[int]]]:
    """
    Loads pre-built byte-offset & inverted-posting-list index from `cache_path`
    if `txt_path` (size, mtime_ns) matches; otherwise builds and writes it once.
    """
    if not txt_path.exists():
        raise FileNotFoundError(f"Flaw database file not found: {txt_path}")

    st = txt_path.stat()
    sig_key = (st.st_size, st.st_mtime_ns)

    if cache_path.exists():
        try:
            with cache_path.open("rb") as cfh:
                payload = marshal.load(cfh)
            if (
                isinstance(payload, dict)
                and payload.get("v") == _CACHE_VERSION
                and payload.get("size") == sig_key[0]
                and payload.get("mtime_ns") == sig_key[1]
                and len(payload.get("offsets", ())) == EXPECTED_FLAW_COUNT
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

    if len(offsets) != EXPECTED_FLAW_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_FLAW_COUNT} flaws in {txt_path}, found {len(offsets)}"
        )

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("wb") as cfh:
            marshal.dump(
                {
                    "v": _CACHE_VERSION,
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


class FlawCatalog:
    """
    Sub-10ms indexed storage for 120,000 Roblox flaw signatures.
    Seek-reads only matched records from flaws_120000.txt via mmap/offset table.
    """

    def __init__(
        self,
        txt_path: Path = FLAWS_TXT_PATH,
        cache_path: Path = INDEX_CACHE_PATH,
        static_rules: tuple[StaticCodeRule, ...] = STATIC_CODE_RULES,
        learner: AdaptiveLearner | None = None,
        brain: FlawBrain | None = None,
    ) -> None:
        self.txt_path = txt_path
        self.cache_path = cache_path
        self.static_rules = static_rules
        self.learner = learner or AdaptiveLearner()
        self.brain = brain or FlawBrain()

        offsets, primary_kw_index, keyword_index = _build_or_load_index(txt_path, cache_path)
        self._offsets = offsets
        self._primary_kw_index = primary_kw_index
        self._keyword_index = keyword_index
        self._record_cache: dict[int, FlawSignature] = {}
        self._match_cache: dict[tuple[str, str, int], list[FlawSignature]] = {}

        # Open read-only mmap handle for sub-millisecond seek-reads
        self._fh = txt_path.open("rb")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)

    def _read_record(self, idx: int) -> FlawSignature:
        cached = self._record_cache.get(idx)
        if cached is not None:
            return cached
        offset = self._offsets[idx]
        self._mm.seek(offset)
        raw_line = self._mm.readline().decode("utf-8", errors="replace")
        sig = _parse_flaw_line(raw_line)
        if len(self._record_cache) >= 8192:
            self._record_cache.clear()
        self._record_cache[idx] = sig
        return sig

    def iter_signatures(self) -> Iterator[FlawSignature]:
        """Streams all 120,000 signatures sequentially without holding all in RAM."""
        with self.txt_path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                if raw_line.strip():
                    yield _parse_flaw_line(raw_line)

    def has_primary_keyword(self, token: str) -> bool:
        return token.lower() in self._primary_kw_index

    def count(self) -> int:
        return len(self._offsets)

    def signature_count(self) -> int:
        return len(self._offsets)

    def static_rule_count(self) -> int:
        return len(self.static_rules)

    def get(self, code: str) -> FlawSignature | None:
        m = re.match(r"^RCD-(\d+)$", code.strip().upper())
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
        """
        O(1)-per-token lookup matching an instance name or path against 120,000
        indexed signatures, returning top matches sorted by relevance & rank.
        """
        cache_key = (identifier, container_hint, limit)
        cached = self._match_cache.get(cache_key)
        if cached is not None:
            return cached

        generic_kws = {"remote", "bindable", "tool", "attribute", "valuebase", "replication", "streaming"}
        lower_id = identifier.lower()
        raw_leaf = container_hint.split(".")[-1] if "." in container_hint else identifier
        leaf = raw_leaf.lower()
        tokens = set(_TOKEN_SPLIT_RE.findall(lower_id))
        leaf_tokens = _split_camel_cached(raw_leaf)
        candidate_scores: dict[int, int] = {}

        for primary_kw, idxs in self._primary_kw_index.items():
            in_leaf_exact = primary_kw in leaf_tokens
            in_leaf_sub = (not in_leaf_exact) and len(primary_kw) >= 5 and primary_kw in leaf and primary_kw != "emote"
            in_full = primary_kw in tokens
            if not (in_leaf_exact or in_leaf_sub or in_full):
                continue

            if primary_kw in generic_kws:
                weight = 2
            elif in_leaf_exact:
                weight = 22
            elif in_leaf_sub:
                weight = 12
            else:
                weight = 10

            for idx in idxs:
                candidate_scores[idx] = candidate_scores.get(idx, 0) + weight

        if not candidate_scores:
            return []

        hint_lower = container_hint.lower()
        if hint_lower:
            for hint_tok in _TOKEN_SPLIT_RE.findall(hint_lower):
                for idx in self._keyword_index.get(hint_tok, ()):
                    if idx in candidate_scores:
                        candidate_scores[idx] += 4

        # Boost historically reinforced catalog codes
        hits_map = self.learner.catalog_hits
        if hits_map:
            for idx in list(candidate_scores.keys()):
                code = f"RCD-{idx + 1:06d}"
                hit_count = hits_map.get(code, 0)
                if hit_count > 0:
                    candidate_scores[idx] += min(6, hit_count)

        # Rank by (-score, idx) where idx == rank - 1 (CRITICAL first -> lowest last)
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

        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return [self._read_record(idx) for idx, _ in ranked[:limit]]

    def match_source(self, script_path: str, source: str) -> list[Finding]:
        """Runs all precompiled static Luau rules using a fast literal pre-filter."""
        findings: list[Finding] = []
        for rule in self.static_rules:
            if rule.literal_hint and rule.literal_hint not in source:
                continue
            if not rule.pattern.search(source):
                continue
            if rule.anti_pattern is not None and rule.anti_pattern.search(source):
                continue
            findings.append(
                Finding(
                    severity=rule.severity,
                    category=rule.category,
                    title=f"[{rule.code}] {rule.title}",
                    path=script_path,
                    flaw=rule.flaw,
                    abuse=rule.abuse,
                    fix=rule.fix,
                    code_example=rule.code_example,
                    rank=rule.rank,
                    metadata={"rule_code": rule.code},
                )
            )
        return findings

    def enrich_finding(self, finding: Finding) -> Finding:
        """
        Matches a runtime/client finding against the 120,000 catalog signatures,
        learned custom game tokens, and FlawBrain statistical inference.
        """
        learned_hit = None
        learned_tok_name = None
        for tok in extract_game_tokens(f"{finding.path} {finding.title}"):
            if tok in self.learner.learned_tokens:
                learned_hit = self.learner.learned_tokens[tok]
                learned_tok_name = tok
                break

        matches = self.match_name(
            f"{finding.title} {finding.path}",
            container_hint=finding.path,
            limit=3,
        )
        generic_kws = {"remote", "bindable", "tool", "attribute", "valuebase", "replication", "streaming"}
        strong_catalog_match = bool(
            matches and matches[0].keywords and matches[0].keywords[0] not in generic_kws
        )

        if strong_catalog_match:
            top = matches[0]
            finding.metadata["catalog_code"] = top.code
            finding.metadata["domain"] = top.domain
            finding.metadata["matched_codes"] = [m.code for m in matches]
            finding.rank = top.rank

            if not finding.flaw or finding.flaw.startswith("Detected via Roblox Client Console"):
                finding.flaw = top.flaw
            if not finding.abuse or finding.abuse.startswith("Client-exposed state, remote"):
                finding.abuse = top.abuse
            if not finding.fix or finding.fix.startswith("Enforce server-authoritative validation"):
                finding.fix = top.fix

            if not finding.title.startswith("[RCD-") and not finding.title.startswith("[LEARNED:"):
                finding.title = f"[{top.code}] {finding.title}"

            if finding.severity == "INFO" and normalize_severity(top.severity) == "CRITICAL":
                finding.severity = "WARN"
            return finding

        if learned_hit is not None and learned_tok_name is not None:
            finding.metadata["learned_token"] = learned_tok_name
            finding.metadata["domain"] = learned_hit.get("domain", "Learned")
            if not finding.flaw:
                finding.flaw = str(learned_hit.get("flaw", ""))
            if not finding.abuse:
                finding.abuse = str(learned_hit.get("abuse", ""))
            if not finding.fix:
                finding.fix = str(learned_hit.get("fix", ""))
            sev_rank = {"INFO": 1, "WARN": 2, "CRITICAL": 3}
            learned_sev = normalize_severity(str(learned_hit.get("severity", "INFO")))
            if sev_rank.get(learned_sev, 1) > sev_rank.get(finding.severity, 1):
                finding.severity = learned_sev
            if not finding.title.startswith("[LEARNED:") and not finding.title.startswith("[RCD-"):
                finding.title = f"[LEARNED:{learned_tok_name}] {finding.title}"
            return finding

        if matches:
            top = matches[0]
            finding.metadata["catalog_code"] = top.code
            finding.metadata["domain"] = top.domain
            finding.metadata["matched_codes"] = [m.code for m in matches]
            finding.rank = top.rank
            if not finding.title.startswith("[RCD-"):
                finding.title = f"[{top.code}] {finding.title}"
            self.brain.ingest_flaw_record(
                domain=top.domain,
                severity=finding.severity,
                text=f"{finding.title} {finding.path} {finding.flaw}",
                fix=finding.fix,
            )
            return finding

        pred = self.brain.predict(f"{finding.title} {finding.path} {finding.flaw} {finding.abuse}")
        if pred is not None:
            pred_domain, pred_sev, pred_fix = pred
            finding.metadata["inferred_domain"] = pred_domain
            finding.metadata.setdefault("domain", pred_domain)
            if not finding.fix:
                finding.fix = pred_fix
            if finding.severity == "INFO" and pred_sev in ("WARN", "CRITICAL"):
                finding.severity = "WARN"

        self.brain.ingest_flaw_record(
            domain=str(finding.metadata.get("domain", finding.category)),
            severity=finding.severity,
            text=f"{finding.title} {finding.path} {finding.flaw}",
            fix=finding.fix,
        )
        return finding


@lru_cache(maxsize=1)
def get_catalog() -> FlawCatalog:
    """Returns the cached singleton FlawCatalog instance with trained FlawBrain."""
    cat = FlawCatalog(txt_path=FLAWS_TXT_PATH, cache_path=INDEX_CACHE_PATH, static_rules=STATIC_CODE_RULES)
    cat.brain.train_from_corpus(cat, pack=get_debugger_pack())
    return cat
