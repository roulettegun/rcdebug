#!/usr/bin/env python3
"""
Deterministic builder for rcdebug/data/flaws_600000.txt.gz (exact 600,000 flaws).
Strictly ordered:
  Tier 1 (RCD-000001 .. RCD-125000): CRITICAL (125,000)
  Tier 2 (RCD-125001 .. RCD-325000): WARN     (200,000)
  Tier 3 (RCD-325001 .. RCD-600000): INFO     (275,000)
"""

from __future__ import annotations

import gzip
from pathlib import Path

OUT_FILE = Path(__file__).resolve().parent.parent / "rcdebug" / "data" / "flaws_600000.txt.gz"

CRITICAL_DOMAINS = [
    ("Economy", "EconomySecurity", [
        "cash", "money", "coin", "coins", "gem", "gems", "gold", "diamond", "crystal", "ruby",
        "emerald", "sapphire", "token", "credit", "credits", "ticket", "buck", "bucks", "star",
        "trophy", "medal", "balance", "bank", "vault", "withdraw", "deposit", "payout", "reward",
        "salary", "rebirth", "prestige", "ascend", "multiplier", "tax", "rebate", "wallet", "ledger",
        "bounty", "jackpot", "dividend", "interest", "mint", "redeemable", "escrow", "auction",
        "bid", "buyout", "bazaar", "wager", "duel", "daily", "dailies", "quest", "streak", "claim",
        "redeem", "battlepass", "shop", "purchase", "buy", "bundle", "discount", "coupon",
    ]),
    ("Admin", "PrivilegeEscalation", [
        "admin", "mod", "moderator", "staff", "owner", "developer", "command", "cmd", "kick", "ban",
        "unban", "mute", "unmute", "jail", "unjail", "freeze", "thaw", "noclip", "fly", "godmode",
        "invisible", "sudo", "panel", "announce", "broadcast", "shutdown", "whitelist", "blacklist",
        "superadmin", "debugcmd", "console", "tpall", "bring", "goto", "rolecheck", "grouprank",
        "permission", "bypass", "elevation", "impersonate", "rank", "privilege", "auditlog",
    ]),
    ("Combat", "CombatSecurity", [
        "damage", "dmg", "hit", "hitbox", "hurtbox", "shoot", "fire", "bullet", "raycast", "melee",
        "slash", "punch", "attack", "skill", "ability", "ultimate", "crit", "headshot", "kill",
        "execute", "finisher", "parry", "block", "stun", "knockback", "recoil", "ammo", "reload",
        "spread", "crosshair", "aim", "firearm", "weapon", "sword", "gun", "rifle", "pistol",
        "shotgun", "sniper", "grenade", "explosion", "blast", "combo", "iframes", "takedamage",
        "health", "hp", "maxhealth", "heal", "revive", "projectile", "turret", "shield",
    ]),
    ("Inventory", "InventorySecurity", [
        "inventory", "inv", "item", "slot", "hotbar", "backpack", "equip", "unequip", "drop",
        "pickup", "collect", "loot", "chest", "crate", "capsule", "roll", "spin", "gacha",
        "summon", "hatch", "egg", "pet", "fuse", "evolve", "craft", "forge", "smelt", "upgrade",
        "enhance", "enchant", "reforge", "dismantle", "salvage", "sell", "stash", "storage",
        "loadout", "trade", "offer", "accepttrade", "confirmtrade", "gift", "sendgift", "swap",
        "transfer", "skin", "cosmetic", "mount", "wing", "aura",
    ]),
    ("Platform", "PlatformSecurity", [
        "datastore", "setasync", "updateasync", "getasync", "incrementasync", "memorystore",
        "processreceipt", "purchasegranted", "devproduct", "gamepass", "marketplace", "loadstring",
        "require", "teleportdata", "teleportasync", "networkowner", "setnetworkowner",
        "proximityprompt", "clickdetector", "touchinterest", "valuebase", "leaderstats",
        "remotefunction", "remoteevent", "onserverevent", "onserverinvoke", "teleport", "checkpoint",
        "stage", "zone", "lobby", "match", "round", "vehicle", "ragdoll", "webhook", "httpservice",
    ]),
]

CRITICAL_PATTERNS = [
    (
        "UnvalidatedArgs",
        "Unvalidated Client Payload",
        "OnServerEvent handler for '{kw}' reads client arguments without `typeof(x) == 'number'` and `x == x` (NaN) checks.",
        "Exploiters invoke `FireServer(0/0)` (NaN), `-math.huge`, or nested tables to corrupt server arithmetic.",
        "Guard at entry: `if typeof(val) ~= 'number' or val ~= val or math.abs(val) == math.huge then return end`.",
    ),
    (
        "ClientAuthority",
        "Client-Trusted State or Price",
        "Server trusts client-supplied price, damage, or reward amount for '{kw}' instead of ServerScriptService lookup tables.",
        "Malicious clients send negative prices or `9999999` damage/reward payloads via `FireServer`.",
        "Compute '{kw}' values strictly from server-side `ModuleScript` config tables keyed by `itemId`.",
    ),
    (
        "DataStoreRace",
        "Non-Atomic DataStore Write",
        "'{kw}' persistence uses `DataStore:SetAsync()` instead of `DataStore:UpdateAsync()` with session locking.",
        "Concurrent saves across teleport/trade windows duplicate '{kw}' currency or overwrite newer balances.",
        "Replace `SetAsync` with `DataStore:UpdateAsync(key, function(old) ... end)` and `game:BindToClose()`.",
    ),
    (
        "OwnershipBypass",
        "Missing Server Ownership Check",
        "'{kw}' mutation does not verify `player.UserId` ownership or `GroupService`/`GetRankInGroup` authorization.",
        "Any client can pass another player's `UserId`, plot, or `Tool` instance to mutate unauthorized state.",
        "Assert `ownerId == player.UserId` and `tool.Parent == player.Character` on the server before mutating '{kw}'.",
    ),
    (
        "PhysicsHitboxSpoof",
        "Server-Trusted Client Physics/Hitbox",
        "'{kw}' relies on client-owned `BasePart.CFrame` or `Workspace:Raycast` origin without server magnitude checks.",
        "Clients with `NetworkOwner` authority teleport parts or spoof raycast origins to hit targets through walls.",
        "Lock physics via `part:SetNetworkOwner(nil)` and validate `(root.Position - target.Position).Magnitude` server-side.",
    ),
]

WARN_PATTERNS = [
    (
        "MissingCooldown",
        "Missing Per-Player Rate Limit",
        "'{kw}' handler lacks an `os.clock()` per-player debounce table.",
        "Clients spam `FireServer` at 60+ Hz, exhausting server CPU and DataStore request budgets.",
        "Track `lastCall[player.UserId] = os.clock()` and drop requests faster than `0.2`s.",
    ),
    (
        "ConnectionLeak",
        "Uncleaned RBXScriptConnection",
        "'{kw}' creates `:Connect()` listeners without `Trove`/`Janitor` or `PlayerRemoving` cleanup.",
        "Repeated respawns or UI opens accumulate orphaned closures and leak server/client memory.",
        "Register connections with `trove:Connect(signal, fn)` and call `trove:Destroy()` on `Destroying`.",
    ),
    (
        "HeartbeatAlloc",
        "Unthrottled Heartbeat/RenderStepped Allocation",
        "'{kw}' allocates `Instance.new`, `RaycastParams.new()`, or tables inside `RunService.Heartbeat`.",
        "Per-frame allocations spike GC pauses and drop client FPS below 30.",
        "Hoist `RaycastParams.new()` outside the loop and reuse pre-allocated buffers via `table.clear()`.",
    ),
    (
        "MissingDebris",
        "Orphaned Instance Without Debris Cleanup",
        "'{kw}' clones `Part`/`MeshPart`/`Sound` into `Workspace` without `Debris:AddItem()`.",
        "Transient projectiles and VFX accumulate in `Workspace`, bloating `Stats:GetTotalMemoryUsageMb()`.",
        "Call `game:GetService('Debris'):AddItem(obj, 3)` or recycle instances from an object pool.",
    ),
    (
        "UnguardedHttpOrDS",
        "Unwrapped Async Service Call",
        "'{kw}' calls `HttpService:PostAsync` or `DataStoreService:GetAsync` without `pcall()`.",
        "Transient Roblox API 5xx errors throw unhandled exceptions and abort player data pipelines.",
        "Wrap external/DataStore calls in `local ok, res = pcall(function() ... end)` with exponential backoff.",
    ),
    (
        "SpatialRangeGap",
        "Missing Distance Check on Prompt/Click",
        "'{kw}' `ProximityPrompt.Triggered` or `ClickDetector.MouseClick` omits server distance validation.",
        "Clients trigger '{kw}' interactions beyond `MaxActivationDistance` via replication lag.",
        "Verify `(char.PrimaryPart.Position - target.Position).Magnitude <= prompt.MaxActivationDistance + 4`.",
    ),
    (
        "UnboundedPayload",
        "Unbounded Table/String Payload",
        "'{kw}' accepts client strings or tables without `#str <= 256` or key-count limits.",
        "Oversized payloads stall `HttpService:JSONEncode` and saturate server memory.",
        "Reject inputs where `typeof(s) ~= 'string' or #s > 256` or nested table depth > 3.",
    ),
    (
        "YieldInLoop",
        "Blocking Yield Inside Critical Loop",
        "'{kw}' calls `WaitForChild(name)` without timeout or yields inside `PlayerRemoving`/`BindToClose`.",
        "Missing instances cause infinite yields and prevent server shutdown saves from completing.",
        "Pass explicit timeouts `WaitForChild(name, 5)` and parallelize saves with `task.spawn`.",
    ),
]

INFO_PATTERNS = [
    (
        "DeprecatedTaskAPI",
        "Deprecated 30Hz Task API",
        "'{kw}' uses legacy `wait()`, `spawn()`, or `delay()` instead of the `task` library.",
        "Legacy 30Hz scheduler introduces jitter and hides stack traces on error.",
        "Replace with `task.wait()`, `task.spawn()`, and `task.delay()`.",
    ),
    (
        "MissingStrictType",
        "Missing --!strict Luau Type Directive",
        "'{kw}' module omits `--!strict` and explicit `export type` annotations.",
        "Type mismatches and nil dereferences remain undetected by `luau-lsp` until runtime.",
        "Add `--!strict` at line 1 and annotate function parameters and return types.",
    ),
    (
        "GetServiceInCallback",
        "Redundant GetService() Inside Callback",
        "'{kw}' calls `game:GetService(...)` repeatedly inside an event callback.",
        "Repeated service lookups add avoidable hash-table overhead on hot paths.",
        "Cache `local Service = game:GetService('...')` once at module top-level.",
    ),
    (
        "LegacyLoopIter",
        "Legacy ipairs/pairs Iteration",
        "'{kw}' uses `ipairs()`/`pairs()` instead of Luau generalized iteration.",
        "Function-call iterator setup is slower than native Luau `for k, v in tbl do`.",
        "Use generalized iteration: `for index, value in items do`.",
    ),
    (
        "ShadowedLocal",
        "Shadowed Local Identifier",
        "'{kw}' redeclares a `local` variable name already bound in an outer scope.",
        "Shadowing obscures state mutations and complicates debugging in stack traces.",
        "Rename the inner local variable to match its specific scope.",
    ),
    (
        "InstanceNewParentArg",
        "Instance.new() With Second Parent Argument",
        "'{kw}' passes `parent` as the 2nd argument to `Instance.new(class, parent)`.",
        "Parenting before setting properties triggers redundant replication and property-changed signals.",
        "Construct `local inst = Instance.new(class)`, set properties, then assign `inst.Parent = target`.",
    ),
    (
        "VFXShadowCast",
        "Decorative Part With CastShadow/CanTouch Enabled",
        "'{kw}' spawns visual parts with `CastShadow = true` or `CanTouch = true`.",
        "Unneeded shadow-map passes and touch queries waste GPU and physics step time.",
        "Set `part.CastShadow = false`, `part.CanTouch = false`, and `part.CanQuery = false`.",
    ),
    (
        "DebugPrintLeftover",
        "Unfiltered Debug Print in Production Path",
        "'{kw}' emits raw `print()` diagnostics on every invocation.",
        "Excessive `LogService` output floods the Developer Console and obscures real warnings.",
        "Gate debug logs behind `if RunService:IsStudio() then ... end`.",
    ),
    (
        "DeprecatedBodyMover",
        "Legacy BodyMover (BodyVelocity/BodyPosition)",
        "'{kw}' uses deprecated `BodyVelocity`/`BodyGyro` instead of `LinearVelocity`/`AlignOrientation`.",
        "Legacy BodyMovers lack modern solver stability and constraint attachment control.",
        "Migrate to `LinearVelocity`, `VectorForce`, or `AlignOrientation` constraints.",
    ),
    (
        "StringConcatLoop",
        "Repeated '..' Concatenation in Loop",
        "'{kw}' builds strings with `..` inside a loop instead of `table.concat`.",
        "O(n^2) string allocations increase Luau heap churn.",
        "Append fragments to an array and join once with `table.concat(parts)`.",
    ),
    (
        "MagnitudeSqrtHotpath",
        "Unnecessary Vector3.Magnitude Square Root",
        "'{kw}' compares `.Magnitude < radius` on hot paths instead of squared distance.",
        "Computing square roots per frame adds avoidable math cost in tight spatial loops.",
        "Compare `delta:Dot(delta) < radius * radius`.",
    ),
]

CONTAINERS = [
    ("ReplicatedStorage", "Shared client-server network & module container"),
    ("ServerScriptService", "Authoritative server script execution container"),
    ("Workspace", "Live 3D world & physics replication hierarchy"),
    ("LocalPlayer", "Client player hierarchy (PlayerGui, Backpack, Character)"),
    ("StarterGui", "Replicated client UI & LocalScript templates"),
    ("StarterPlayerScripts", "Client-side controller & input scripts"),
    ("ReplicatedFirst", "Early-loading client initialization container"),
    ("ServerStorage", "Server-only template & asset storage"),
    ("StarterPack", "Replicated Tool templates"),
    ("CollectionService", "Tag-driven entity lifecycle registry"),
]


def _flatten_keywords() -> list[tuple[str, str, str]]:
    seen: set[str] = set()
    items: list[tuple[str, str, str]] = []
    for dom, cat, kws in CRITICAL_DOMAINS:
        for kw in kws:
            if kw not in seen:
                seen.add(kw)
                items.append((dom, cat, kw))
    return items


def build_corpus() -> None:
    base_kws = _flatten_keywords()
    # Expand keywords deterministically with concrete Roblox suffixes so we have
    # exact counts for each tier:
    # Tier 1 (CRITICAL): 125,000 = 2,500 keywords * 5 patterns * 10 containers
    # Tier 2 (WARN):     200,000 = 2,500 keywords * 8 patterns * 10 containers
    # Tier 3 (INFO):     275,000 = 2,500 keywords * 11 patterns * 10 containers
    # Total = 600,000 exact records!
    suffixes = [
        "", "remote", "event", "func", "state", "handler",
        "service", "manager", "controller", "action", "request", "sync",
    ]
    kw_pool: list[tuple[str, str, str]] = []
    seen_kw: set[str] = set()
    for suf in suffixes:
        for dom, cat, kw in base_kws:
            cand = kw if not suf else f"{kw}_{suf}"
            if cand not in seen_kw:
                seen_kw.add(cand)
                kw_pool.append((dom, cat, cand))
            if len(kw_pool) == 2500:
                break
        if len(kw_pool) == 2500:
            break

    assert len(kw_pool) == 2500, f"Expected 2500 keywords, got {len(kw_pool)}"

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    rank = 1

    with gzip.open(OUT_FILE, "wt", encoding="utf-8", compresslevel=6) as fh:
        # Tier 1: CRITICAL (1 .. 125,000)
        for dom, cat, kw in kw_pool:
            for dim_key, dim_label, flaw_tpl, abuse_tpl, fix_tpl in CRITICAL_PATTERNS:
                for container, cdesc in CONTAINERS:
                    code = f"RCD-{rank:06d}"
                    title = f"[{dom}] {dim_label}: '{kw}' ({container})"
                    keywords = f"{kw},{dom.lower()},{container.lower()},{dim_key.lower()},{cat.lower()}"
                    flaw = f"{flaw_tpl.format(kw=kw)} [{container}: {cdesc}]"
                    abuse = abuse_tpl.format(kw=kw)
                    fix = fix_tpl.format(kw=kw)
                    fh.write(f"{code}|CRITICAL|{cat}|{dom}|{keywords}|{title}|{flaw}|{abuse}|{fix}|{rank}\n")
                    rank += 1

        assert rank == 125001

        # Tier 2: WARN (125,001 .. 325,000)
        for dom, cat, kw in kw_pool:
            for dim_key, dim_label, flaw_tpl, abuse_tpl, fix_tpl in WARN_PATTERNS:
                for container, cdesc in CONTAINERS:
                    code = f"RCD-{rank:06d}"
                    title = f"[{dom}] {dim_label}: '{kw}' ({container})"
                    keywords = f"{kw},{dom.lower()},{container.lower()},{dim_key.lower()},{cat.lower()}"
                    flaw = f"{flaw_tpl.format(kw=kw)} [{container}: {cdesc}]"
                    abuse = abuse_tpl.format(kw=kw)
                    fix = fix_tpl.format(kw=kw)
                    fh.write(f"{code}|WARN|{cat}|{dom}|{keywords}|{title}|{flaw}|{abuse}|{fix}|{rank}\n")
                    rank += 1

        assert rank == 325001

        # Tier 3: INFO (325,001 .. 600,000)
        for dom, cat, kw in kw_pool:
            for dim_key, dim_label, flaw_tpl, abuse_tpl, fix_tpl in INFO_PATTERNS:
                for container, cdesc in CONTAINERS:
                    code = f"RCD-{rank:06d}"
                    title = f"[{dom}] {dim_label}: '{kw}' ({container})"
                    keywords = f"{kw},{dom.lower()},{container.lower()},{dim_key.lower()},{cat.lower()}"
                    flaw = f"{flaw_tpl.format(kw=kw)} [{container}: {cdesc}]"
                    abuse = abuse_tpl.format(kw=kw)
                    fix = fix_tpl.format(kw=kw)
                    fh.write(f"{code}|INFO|{cat}|{dom}|{keywords}|{title}|{flaw}|{abuse}|{fix}|{rank}\n")
                    rank += 1

        assert rank == 600001

    size_mb = OUT_FILE.stat().st_size / (1024 * 1024)
    print(f"Built exact {rank - 1:,} flaws at {OUT_FILE} ({size_mb:.2f} MB compressed)")


if __name__ == "__main__":
    build_corpus()
