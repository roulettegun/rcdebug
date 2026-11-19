"""
Adaptive Place & Flaw Learning Engine for rcdebug.

Automatically learns game-specific naming conventions, remote patterns,
state exposure surfaces, and flaw frequencies from every audited place
or live playtest session, persisting knowledge to ~/.rcdebug/learned_flaws.json
and ~/.rcdebug/learned_patterns.txt so rcdebug becomes smarter across all games.
"""

from __future__ import annotations

import json
import math
import random
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import AuditSession, Finding, normalize_severity

if TYPE_CHECKING:
    from .flaw_catalog import FlawCatalog

LEARNED_DIR = Path.home() / ".rcdebug"
LEARNED_FILE = LEARNED_DIR / "learned_flaws.json"
LEARNED_TXT_FILE = LEARNED_DIR / "learned_patterns.txt"
HISTORY_FILE = LEARNED_DIR / "command_history.json"
SYNC_STATE_FILE = LEARNED_DIR / "brain_sync_state.json"
FLAW_BRAIN_FILE = LEARNED_DIR / "flaw_brain.json"

_CAMEL_SPLIT_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)|\d+")
_STOP_TOKENS = frozenset({
    "workspace", "replicatedstorage", "replicatedfirst", "serverscriptservice",
    "serverstorage", "startergui", "starterpack", "starterplayer", "players",
    "localplayer", "character", "backpack", "playergui", "remotes", "remote",
    "events", "event", "functions", "function", "folder", "model", "part",
    "meshpart", "main", "menu", "script", "localscript", "modulescript",
    "value", "intvalue", "numbervalue", "boolvalue", "stringvalue", "attribute",
    "client", "server", "exposed", "endpoint", "visible", "accessible",
    "readable", "high", "risk", "unanchored", "network", "ownership", "game",
    "ui", "gui", "fx", "vfx", "sfx", "handler", "manager", "controller",
    "system", "service", "core", "shared", "common", "default", "object",
    "data", "info", "warn", "critical", "rcd", "matched", "state", "player",
    "replicated", "local", "right", "left", "body", "storage", "top", "bottom",
})


def extract_game_tokens(text: str) -> list[str]:
    """Extracts meaningful lowercase tokens from camelCase/PascalCase/snake_case paths."""
    tokens: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[^A-Za-z0-9]+", text):
        if not part:
            continue
        # Whole identifier token if >= 4 chars
        whole = part.lower()
        if len(whole) >= 4 and not whole.isdigit() and whole not in _STOP_TOKENS and whole not in seen:
            seen.add(whole)
            tokens.append(whole)
        # Split camelCase sub-tokens
        for sub in _CAMEL_SPLIT_RE.findall(part):
            low = sub.lower()
            if len(low) >= 4 and not low.isdigit() and low not in _STOP_TOKENS and low not in seen:
                seen.add(low)
                tokens.append(low)
    return tokens


class AdaptiveLearner:
    """
    Persistent learning store that records newly discovered game tokens,
    flaw frequencies, and place signatures across audits.
    """

    def __init__(self, store_path: Path = LEARNED_FILE, txt_path: Path = LEARNED_TXT_FILE) -> None:
        self.store_path = store_path
        self.txt_path = txt_path
        self.learned_tokens: dict[str, dict[str, Any]] = {}
        self.catalog_hits: dict[str, int] = {}
        self.places_audited: list[str] = []
        self.load()

    def load(self) -> None:
        if not self.store_path.exists():
            return
        try:
            raw = json.loads(self.store_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                tokens = raw.get("learned_tokens", {})
                if isinstance(tokens, dict):
                    self.learned_tokens = tokens
                hits = raw.get("catalog_hits", {})
                if isinstance(hits, dict):
                    self.catalog_hits = {str(k): int(v) for k, v in hits.items()}
                places = raw.get("places_audited", [])
                if isinstance(places, list):
                    self.places_audited = [str(p) for p in places]
        except Exception:
            pass

    def save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_learned_tokens": len(self.learned_tokens),
            "places_audited": self.places_audited[-50:],
            "catalog_hits": self.catalog_hits,
            "learned_tokens": self.learned_tokens,
        }
        self.store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        # Also export human-readable pipe-delimited learned patterns file
        lines: list[str] = []
        for tok, info in sorted(self.learned_tokens.items()):
            lines.append(
                "|".join([
                    tok,
                    str(info.get("severity", "WARN")),
                    str(info.get("category", "RuntimeAudit")),
                    str(info.get("domain", "Learned")),
                    f"seen={info.get('seen_count', 1)}",
                    str(info.get("flaw", "")).replace("|", "/"),
                    str(info.get("fix", "")).replace("|", "/"),
                ])
            )
        self.txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def learn_from_finding(
        self,
        finding: Finding,
        catalog: FlawCatalog,
        place_name: str = "Unknown",
    ) -> int:
        """
        Learns from a single Finding. Returns the number of newly discovered tokens.
        """
        new_count = 0
        cat_code = finding.metadata.get("catalog_code")
        if cat_code:
            self.catalog_hits[str(cat_code)] = self.catalog_hits.get(str(cat_code), 0) + 1

        tokens = extract_game_tokens(f"{finding.path} {finding.title}")
        domain = str(finding.metadata.get("domain") or finding.category or "Universal")

        for tok in tokens:
            # Skip tokens already natively indexed as primary keywords in flaws_18000.txt
            if catalog.has_primary_keyword(tok):
                continue

            existing = self.learned_tokens.get(tok)
            if existing is None:
                self.learned_tokens[tok] = {
                    "severity": normalize_severity(finding.severity),
                    "category": finding.category,
                    "domain": domain,
                    "seen_count": 1,
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "places": [place_name],
                    "flaw": finding.flaw or f"Learned pattern '{tok}' observed in {finding.category}.",
                    "abuse": finding.abuse or f"Custom endpoint/state '{tok}' may allow client tampering if unvalidated.",
                    "fix": finding.fix or f"Enforce server-side validation, typeof() checks, and cooldowns for '{tok}'.",
                }
                new_count += 1
            else:
                existing["seen_count"] = int(existing.get("seen_count", 1)) + 1
                # Escalate learned severity if observed at higher severity
                sev_rank = {"INFO": 1, "WARN": 2, "CRITICAL": 3}
                old_sev = normalize_severity(str(existing.get("severity", "INFO")))
                new_sev = normalize_severity(finding.severity)
                if sev_rank.get(new_sev, 1) > sev_rank.get(old_sev, 1):
                    existing["severity"] = new_sev
                places = existing.setdefault("places", [])
                if place_name not in places and len(places) < 20:
                    places.append(place_name)

        return new_count

    def learn_from_session(self, session: AuditSession, catalog: FlawCatalog) -> int:
        """
        Automatically learns from all findings in an AuditSession and persists updates.
        Returns the count of newly discovered tokens.
        """
        if session.target_name and session.target_name not in self.places_audited:
            self.places_audited.append(session.target_name)

        total_new = 0
        for finding in session.findings:
            total_new += self.learn_from_finding(finding, catalog, place_name=session.target_name)

        if session.findings:
            self.save()
            if getattr(catalog, "brain", None) is not None:
                for finding in session.findings:
                    catalog.brain.ingest_flaw_record(
                        domain=str(finding.metadata.get("domain", finding.category)),
                        severity=finding.severity,
                        text=f"{finding.title} {finding.path} {finding.flaw}",
                        fix=finding.fix,
                    )
                catalog.brain.save()
        return total_new


class CommandHistory:
    """
    Persistent JSON log of every rcdebug terminal command execution (~/.rcdebug/command_history.json).
    Tracks command invocations, severities, learned tokens, and domain weights
    so rcdebug gets smarter and faster across sessions.
    """

    def __init__(self, history_path: Path = HISTORY_FILE) -> None:
        self.history_path = history_path
        self.entries: list[dict[str, Any]] = []
        self.domain_weights: dict[str, int] = {}
        self.load()

    def load(self) -> None:
        if not self.history_path.exists():
            return
        try:
            raw = json.loads(self.history_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                entries = raw.get("history", [])
                if isinstance(entries, list):
                    self.entries = entries
                weights = raw.get("domain_weights", {})
                if isinstance(weights, dict):
                    self.domain_weights = {str(k): int(v) for k, v in weights.items()}
        except Exception:
            pass

    def save(self) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_commands": len(self.entries),
            "domain_weights": self.domain_weights,
            "history": self.entries[-500:],
        }
        self.history_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def record_run(
        self,
        argv: list[str],
        mode: str,
        target: str = "",
        filters: list[str] | None = None,
        findings_count: int = 0,
        severity_counts: dict[str, int] | None = None,
        domains_seen: list[str] | None = None,
        learned_added: int = 0,
        duration_ms: float = 0.0,
        synthetic: bool = False,
        timestamp_override: str | None = None,
    ) -> dict[str, Any]:
        for dom in domains_seen or []:
            if dom:
                self.domain_weights[dom] = self.domain_weights.get(dom, 0) + 1

        entry = {
            "timestamp": timestamp_override or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command": f"rcdebug {' '.join(argv)}".strip(),
            "argv": argv,
            "mode": mode,
            "target": target,
            "filters": filters or [],
            "findings_count": findings_count,
            "severity_counts": severity_counts or {"CRITICAL": 0, "WARN": 0, "INFO": 0},
            "domains_seen": sorted(set(domains_seen or [])),
            "learned_tokens_added": learned_added,
            "duration_ms": round(duration_ms, 2),
            "synthetic": synthetic,
        }
        self.entries.append(entry)
        self.save()
        return entry


_TRAINING_SCENARIOS: tuple[tuple[str, str, list[str], list[tuple[str, str, str, str]]], ...] = (
    (
        "SimulatorPlace",
        "--client --critical --warning",
        ["Economy", "Inventory", "Progression"],
        [
            ("CRITICAL", "EconomySecurity", "GiveRebirthCoins", "ReplicatedStorage.Remotes.GiveRebirthCoins"),
            ("WARN", "InventorySecurity", "HatchMythicEgg", "ReplicatedStorage.Remotes.HatchMythicEgg"),
            ("CRITICAL", "StateReplication", "PetMultiplier", "Players.LocalPlayer.PetMultiplier"),
        ],
    ),
    (
        "HorrorCoopPlace",
        "--client --replay-log",
        ["Vitals", "NetworkOwnership", "Session"],
        [
            ("WARN", "NetworkOwnership", "WraithPatrolRig", "Workspace.Monsters.WraithPatrolRig"),
            ("CRITICAL", "StateReplication", "FlashlightBattery", "Workspace.Player1.FlashlightBattery"),
            ("INFO", "StateReplication", "SanityMeter", "Players.LocalPlayer [Attribute:SanityMeter]"),
        ],
    ),
    (
        "FPSArenaPlace",
        "--server --critical",
        ["Combat", "Movement", "Admin"],
        [
            ("CRITICAL", "CombatSecurity", "FireBulletDamage", "ReplicatedStorage.Weapons.FireBulletDamage"),
            ("CRITICAL", "PrivilegeEscalation", "ModKickRemote", "ReplicatedStorage.Admin.ModKickRemote"),
            ("WARN", "PhysicsSecurity", "DashImpulse", "ReplicatedStorage.Movement.DashImpulse"),
        ],
    ),
    (
        "TycoonEmpirePlace",
        "--server --place ./TycoonSrc --critical --warning",
        ["Building", "Economy", "Shop"],
        [
            ("CRITICAL", "MarketplaceSecurity", "ClaimVipDropper", "ReplicatedStorage.Tycoon.ClaimVipDropper"),
            ("WARN", "WorldSecurity", "PlotCollector", "Workspace.Tycoons.PlotCollector"),
            ("CRITICAL", "EconomySecurity", "CollectBankPayout", "ReplicatedStorage.Remotes.CollectBankPayout"),
        ],
    ),
    (
        "RPGLobbyPlace",
        "--client --warning",
        ["Trading", "Session", "Vitals"],
        [
            ("CRITICAL", "EconomySecurity", "ConfirmPlayerTrade", "ReplicatedStorage.Trading.ConfirmPlayerTrade"),
            ("WARN", "SessionSecurity", "DungeonTeleport", "ReplicatedStorage.Matchmaking.DungeonTeleport"),
            ("CRITICAL", "StateReplication", "ManaPool", "Workspace.Player1.ManaPool"),
        ],
    ),
    (
        "VehicleDerbyPlace",
        "--client --critical --warning",
        ["Vehicle", "PhysicsSecurity", "Performance"],
        [
            ("WARN", "PhysicsSecurity", "NitroBoostSeat", "Workspace.Vehicles.NitroBoostSeat"),
            ("CRITICAL", "RemoteTraffic", "ChassisSyncRemote", "ReplicatedStorage.Vehicles.ChassisSyncRemote"),
            ("WARN", "Performance", "SkidmarkDebris", "Workspace.VFX.SkidmarkDebris"),
        ],
    ),
)


def seed_training_history(
    catalog: FlawCatalog,
    history: CommandHistory | None = None,
    count: int = 24,
    force: bool = False,
) -> int:
    """
    Seeds randomized multi-genre terminal command history & learned flaw patterns
    so rcdebug's brain (command_history.json + learned_flaws.json) starts warm and smart.
    Returns number of seeded entries added.
    """
    hist = history or CommandHistory()
    if hist.entries and not force:
        return 0

    rng = random.Random(20261117)
    base_time = datetime.now() - timedelta(hours=count)
    added = 0

    for i in range(count):
        place_name, cmd_str, domains, items = rng.choice(_TRAINING_SCENARIOS)
        argv = cmd_str.split()
        mode = "server" if "--server" in argv else "client"
        filters = [f.lstrip("-").upper() for f in argv if f in ("--critical", "--warning", "--info")]
        if "WARNING" in filters:
            filters = ["WARN" if x == "WARNING" else x for x in filters]

        sev_counts = {"CRITICAL": 0, "WARN": 0, "INFO": 0}
        learned_added = 0
        for sev, cat, title_tok, path in items:
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            f = Finding(
                severity=sev,
                category=cat,
                title=f"Discovered {title_tok}",
                path=path,
                flaw=f"Pattern '{title_tok}' observed during {place_name} audit.",
                abuse=f"Unvalidated '{title_tok}' endpoint or state can be spoofed by clients.",
                fix=f"Enforce server-side typeof(), range, and cooldown validation for '{title_tok}'.",
            )
            catalog.enrich_finding(f)
            learned_added += catalog.learner.learn_from_finding(f, catalog, place_name=place_name)

        ts = (base_time + timedelta(minutes=i * rng.randint(12, 45))).strftime("%Y-%m-%d %H:%M:%S")
        hist.record_run(
            argv=argv,
            mode=mode,
            target=place_name,
            filters=filters,
            findings_count=len(items),
            severity_counts=sev_counts,
            domains_seen=domains,
            learned_added=learned_added,
            duration_ms=rng.uniform(42.0, 185.0),
            synthetic=True,
            timestamp_override=ts,
        )
        added += 1

    catalog.learner.save()
    return added


_LOG_WIRE_RE = re.compile(r"\[rcdebug-wire:report\]\s+(\{.*\})\s*$")
_LOG_CONSOLE_RE = re.compile(
    r"\[rcdebug-console\]\s+\[(CRITICAL|WARN|INFO)\]\s+\[([^\]]+)\]\s+(.+?)\s+\|\s+(.+?)\s*$"
)
_ROBLOX_ERR_RE = re.compile(r"\[FLog::(?:Output|CreatorOutput|Error)\]\s+(.+)$")


class AutonomousBrainSync:
    """
    Continuously reads command_history.json and ~/Library/Logs/Roblox/*_last.log
    so rcdebug learns automatically even outside explicit --learn runs.
    """

    def __init__(
        self,
        state_path: Path = SYNC_STATE_FILE,
        log_dir: Path | None = None,
    ) -> None:
        self.state_path = state_path
        self.log_dir = log_dir if log_dir is not None else (Path.home() / "Library" / "Logs" / "Roblox")
        self.synced_history_count = 0
        self.log_offsets: dict[str, int] = {}
        self._load_state()

    def _load_state(self) -> None:
        if not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.synced_history_count = int(data.get("synced_history_count", 0))
                offsets = data.get("log_offsets", {})
                if isinstance(offsets, dict):
                    self.log_offsets = {str(k): int(v) for k, v in offsets.items()}
        except Exception:
            pass

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(
                {
                    "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "synced_history_count": self.synced_history_count,
                    "log_offsets": self.log_offsets,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def sync_once(self, catalog: FlawCatalog, history: CommandHistory) -> int:
        """
        Ingests any unprocessed command_history.json entries and new Roblox log lines.
        Returns total newly learned tokens.
        """
        new_tokens = 0
        dirty = False

        # 1. Always read & learn from command_history.json
        history.load()
        if len(history.entries) > self.synced_history_count:
            for entry in history.entries[self.synced_history_count :]:
                target = str(entry.get("target", ""))
                cmd = str(entry.get("command", ""))
                domains = entry.get("domains_seen", [])
                dom = domains[0] if domains else "History"
                if target or cmd:
                    f = Finding(
                        severity="INFO",
                        category="CommandHistory",
                        title=f"History Pattern: {target or cmd}",
                        path=target or cmd,
                        flaw=f"Observed in command history ({cmd}).",
                        abuse="Recurring targets/domains indicate high-value audit surfaces.",
                        fix=f"Prioritize {dom} server-side validation checks.",
                        metadata={"domain": dom},
                    )
                    new_tokens += catalog.learner.learn_from_finding(f, catalog, place_name=target or "CLI")
            self.synced_history_count = len(history.entries)
            dirty = True

        # 2. Always scan new bytes in Roblox Player/Studio logs
        if self.log_dir.exists():
            candidates = sorted(
                [
                    p
                    for p in self.log_dir.iterdir()
                    if p.is_file()
                    and p.name.endswith("_last.log")
                    and "CrashHandler" not in p.name
                    and ("_Player_" in p.name or "_Studio_" in p.name)
                ],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )[:3]

            for log_path in candidates:
                key = str(log_path)
                try:
                    size = log_path.stat().st_size
                except OSError:
                    continue
                offset = self.log_offsets.get(key, 0)
                if size < offset:
                    offset = 0
                if size <= offset:
                    continue

                try:
                    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(offset)
                        chunk = fh.read()
                        self.log_offsets[key] = fh.tell()
                    dirty = True
                except OSError:
                    continue

                for line in chunk.splitlines():
                    m_wire = _LOG_WIRE_RE.search(line)
                    if m_wire:
                        try:
                            data = json.loads(m_wire.group(1))
                            f = Finding(
                                severity=str(data.get("severity", "INFO")),
                                category=str(data.get("category", "RuntimeAudit")),
                                title=str(data.get("title", "Finding")),
                                path=str(data.get("path", "Roblox")),
                                flaw=str(data.get("flaw", "")),
                                abuse=str(data.get("abuse", "")),
                                fix=str(data.get("fix", "")),
                            )
                            catalog.enrich_finding(f)
                            new_tokens += catalog.learner.learn_from_finding(f, catalog, place_name=log_path.name)
                        except Exception:
                            pass
                        continue

                    m_con = _LOG_CONSOLE_RE.search(line)
                    if m_con:
                        sev, cat, title, path = m_con.groups()
                        f = Finding(
                            severity=sev,
                            category=cat,
                            title=title,
                            path=path,
                            flaw="",
                            abuse="",
                            fix="",
                        )
                        catalog.enrich_finding(f)
                        new_tokens += catalog.learner.learn_from_finding(f, catalog, place_name=log_path.name)
                        continue

                    if "ScriptContext" in line or "Infinite yield possible on" in line:
                        m_err = _ROBLOX_ERR_RE.search(line)
                        if m_err:
                            f = Finding(
                                severity="WARN",
                                category="RobloxRuntimeError",
                                title="Runtime Error / Infinite Yield",
                                path=m_err.group(1)[:140],
                                flaw="Detected runtime error or infinite WaitForChild yield in Roblox log.",
                                abuse="Unhandled script errors or missing timeout on WaitForChild break gameplay loops.",
                                fix="Add WaitForChild(name, 5) timeouts and nil guards.",
                            )
                            new_tokens += catalog.learner.learn_from_finding(f, catalog, place_name=log_path.name)

        if dirty:
            if new_tokens > 0:
                catalog.learner.save()
            self._save_state()

        return new_tokens


_BRAIN_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "into", "when", "without",
    "context", "handler", "endpoint", "client", "server", "clients", "players",
    "player", "roblox", "system", "logic", "state", "values", "value", "before",
    "instead", "directly", "over", "across", "during", "every", "all", "any",
    "can", "may", "are", "is", "not", "or", "on", "in", "to", "of", "by", "as",
})


class FlawBrain:
    """
    Flaw-level statistical learner trained directly on the 18,000-flaw database,
    the 120-probe Luau debugger pack, and every live finding observed at runtime.
    Infers domain, severity, and remediation for previously unseen flaw patterns.
    """

    def __init__(self, brain_path: Path = FLAW_BRAIN_FILE) -> None:
        self.brain_path = brain_path
        self.total_flaws_learned: int = 0
        self.token_domain_weights: dict[str, dict[str, int]] = {}
        self.token_severity_counts: dict[str, dict[str, int]] = {}
        self.domain_fixes: dict[str, str] = {}
        self.load()

    def load(self) -> None:
        if not self.brain_path.exists():
            return
        try:
            raw = json.loads(self.brain_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.total_flaws_learned = int(raw.get("total_flaws_learned", 0))
                self.token_domain_weights = raw.get("token_domain_weights", {})
                self.token_severity_counts = raw.get("token_severity_counts", {})
                self.domain_fixes = raw.get("domain_fixes", {})
        except Exception:
            pass

    def save(self) -> None:
        self.brain_path.parent.mkdir(parents=True, exist_ok=True)
        # Keep top 25,000 most informative flaw concepts
        ranked_tokens = sorted(
            self.token_domain_weights.items(),
            key=lambda kv: (-sum(kv[1].values()), kv[0]),
        )[:25000]
        trimmed_domains = dict(ranked_tokens)
        trimmed_sevs = {
            tok: self.token_severity_counts[tok]
            for tok in trimmed_domains
            if tok in self.token_severity_counts
        }
        payload = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_flaws_learned": self.total_flaws_learned,
            "indexed_flaw_concepts": len(trimmed_domains),
            "domain_fixes": self.domain_fixes,
            "token_domain_weights": trimmed_domains,
            "token_severity_counts": trimmed_sevs,
        }
        self.brain_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _extract_flaw_concepts(self, text: str) -> list[str]:
        concepts: list[str] = []
        seen: set[str] = set()
        for tok in extract_game_tokens(text):
            if tok not in _BRAIN_STOPWORDS and tok not in seen:
                seen.add(tok)
                concepts.append(tok)
        return concepts

    def ingest_flaw_record(
        self,
        domain: str,
        severity: str,
        text: str,
        fix: str = "",
    ) -> None:
        sev = normalize_severity(severity)
        concepts = self._extract_flaw_concepts(text)
        for tok in concepts:
            dom_map = self.token_domain_weights.setdefault(tok, {})
            dom_map[domain] = dom_map.get(domain, 0) + 1
            sev_map = self.token_severity_counts.setdefault(tok, {})
            sev_map[sev] = sev_map.get(sev, 0) + 1
        if fix and domain not in self.domain_fixes:
            self.domain_fixes[domain] = fix
        self.total_flaws_learned += 1

    def train_from_corpus(self, catalog: FlawCatalog, pack: Any | None = None, force: bool = False) -> int:
        """
        Trains directly on all 18,000 flaws in flaws_18000.txt and all 120 probes
        in luau_debugger_pack_120.json.
        """
        target_min = catalog.count() + (pack.count() if pack is not None else 0)
        if not force and self.total_flaws_learned >= target_min and self.token_domain_weights:
            return 0

        self.total_flaws_learned = 0
        self.token_domain_weights.clear()
        self.token_severity_counts.clear()
        self.domain_fixes.clear()

        for sig in catalog.iter_signatures():
            self.ingest_flaw_record(
                domain=sig.domain,
                severity=sig.severity,
                text=f"{sig.title} {sig.flaw} {sig.abuse} {' '.join(sig.keywords)}",
                fix=sig.fix,
            )

        if pack is not None:
            for probe in pack.probes:
                self.ingest_flaw_record(
                    domain=probe.category,
                    severity=probe.severity,
                    text=f"{probe.name} {probe.root_cause} {probe.source}",
                    fix=probe.fix,
                )

        self.save()
        return self.total_flaws_learned

    def predict(self, text: str) -> tuple[str, str, str] | None:
        """
        Infers (domain, severity, fix) for any unseen flaw or endpoint using
        learned co-occurrence weights from the 18,000+ flaw brain.
        """
        concepts = self._extract_flaw_concepts(text)
        if not concepts or not self.token_domain_weights:
            return None

        domain_scores: dict[str, float] = {}
        sev_scores: dict[str, float] = {"CRITICAL": 0.0, "WARN": 0.0, "INFO": 0.0}
        matched_any = False
        total_docs = max(1, self.total_flaws_learned)

        for tok in concepts:
            dom_map = self.token_domain_weights.get(tok)
            if dom_map:
                matched_any = True
                doc_freq = sum(dom_map.values())
                idf = math.log((1.0 + total_docs) / (1.0 + doc_freq))
                for dom, w in dom_map.items():
                    domain_scores[dom] = domain_scores.get(dom, 0.0) + (w * idf)
            sev_map = self.token_severity_counts.get(tok)
            if sev_map:
                doc_freq = sum(sev_map.values())
                idf = math.log((1.0 + total_docs) / (1.0 + doc_freq))
                for sev, w in sev_map.items():
                    sev_scores[sev] = sev_scores.get(sev, 0.0) + (w * idf)

        if not matched_any or not domain_scores:
            return None

        best_domain = max(domain_scores.items(), key=lambda kv: kv[1])[0]
        best_sev = max(sev_scores.items(), key=lambda kv: kv[1])[0]
        best_fix = self.domain_fixes.get(
            best_domain,
            f"Enforce server-authoritative validation and rate limiting for {best_domain} endpoints.",
        )
        return best_domain, best_sev, best_fix



