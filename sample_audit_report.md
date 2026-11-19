# rcdebug — Roblox Security & Performance Audit Report

## 1. Executive Summary

| Field | Value |
| :--- | :--- |
| **Audit Mode** | `CLIENT` |
| **Target** | `Roblox Studio Live Playtest (127.0.0.1:8769)` |
| **Session Timestamp** | `2026-11-17 16:16:02` |
| **Severity Filter** | `ALL` |
| **Total Findings** | **6** (`3` Critical, `2` Warn, `1` Info) |

## 2. Findings Overview

| # | Severity | Category | Title | Instance Path |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **CRITICAL** | `StateReplication` | Sensitive IntValue in Character: Cash | `Workspace.Player1.Cash` |
| 2 | **CRITICAL** | `MemoryDiff` | Instance / Memory Growth Spike (+245 Workspace instances, +35.7 MB) | `Workspace / Memory` |
| 3 | **CRITICAL** | `RemoteTraffic` | Unthrottled Remote Traffic (34.0 calls/sec): ReplicatedStorage.Remotes.GiveCashRemote | `ReplicatedStorage.Remotes.GiveCashRemote` |
| 4 | **WARN** | `RemoteSecurity` | High-Value Network Endpoint: GiveCashRemote (matched 'cash') | `ReplicatedStorage.Remotes.GiveCashRemote` |
| 5 | **WARN** | `NetworkOwnership` | Unanchored Part with Client/Auto NetworkOwnership: VaultDoor | `Workspace.BankLevel.VaultDoor` |
| 6 | **INFO** | `RemoteSecurity` | Exposed Network Endpoint: SprintToggle | `ReplicatedStorage.Remotes.SprintToggle` |

## 3. Detailed Security & Architectural Findings

### 3.1 [CRITICAL] Sensitive IntValue in Character: Cash

- **Instance Path:** `Workspace.Player1.Cash`
- **Category:** `StateReplication`
- **Detected At:** `16:16:02`
- **Architectural Flaw:** Gameplay state ('cash') is stored in an IntValue parented inside the player's Character model.
- **Malicious Client Abuse Vector:** Because the Character model is subject to client physics/replication quirks and often read by poorly written scripts, storing currency in Character allows tampering or state desync on respawn.
- **Recommended Server-Side Fix:** Move authoritative currency state into a ServerScriptService module table and expose read-only Attributes on Player.

```luau
local Balances: {[number]: number} = {}
function AddCash(player: Player, delta: number)
    Balances[player.UserId] = (Balances[player.UserId] or 0) + delta
    player:SetAttribute("Cash", Balances[player.UserId])
end
```

### 3.2 [CRITICAL] Instance / Memory Growth Spike (+245 Workspace instances, +35.7 MB)

- **Instance Path:** `Workspace / Memory`
- **Category:** `MemoryDiff`
- **Detected At:** `16:16:03`
- **Architectural Flaw:** Between 10s snapshots (16:16:03 -> 16:16:03), Workspace grew by +245 instances (Players +7) and total memory changed by +35.70 MB.
- **Malicious Client Abuse Vector:** Uncleaned projectiles, VFX parts, or disconnected event connections cause progressive server lag, replication choke, and eventual server crash.
- **Recommended Server-Side Fix:** Schedule transient instances for cleanup with Debris:AddItem(instance, lifetime), pool high-frequency projectiles, and disconnect RBXScriptConnections on destroy.

```luau
local Debris = game:GetService("Debris")
local fxPart = projectileTemplate:Clone()
fxPart.Parent = workspace.Effects
Debris:AddItem(fxPart, 3) -- Guaranteed cleanup after 3 seconds
```

### 3.3 [CRITICAL] Unthrottled Remote Traffic (34.0 calls/sec): ReplicatedStorage.Remotes.GiveCashRemote

- **Instance Path:** `ReplicatedStorage.Remotes.GiveCashRemote`
- **Category:** `RemoteTraffic`
- **Detected At:** `16:16:03`
- **Architectural Flaw:** Remote 'ReplicatedStorage.Remotes.GiveCashRemote' is firing at 34.0 calls/sec (total 340 calls) without effective server-side rate limiting.
- **Malicious Client Abuse Vector:** Exploiters can fire this remote hundreds of times per frame to exhaust server CPU, flood replication queues, or exploit non-atomic datastore/currency operations.
- **Recommended Server-Side Fix:** Add a per-player rate limiter (os.clock() cooldown map or token bucket) at the very start of OnServerEvent before performing any workspace, table, or datastore work.

```luau
local COOLDOWN = 0.25
local lastCall: {[Player]: number} = {}
Players.PlayerRemoving:Connect(function(plr) lastCall[plr] = nil end)

remote.OnServerEvent:Connect(function(plr, ...)
    local now = os.clock()
    if now - (lastCall[plr] or 0) < COOLDOWN then return end
    lastCall[plr] = now
    -- Safe to process request
end)
```

### 3.4 [WARN] High-Value Network Endpoint: GiveCashRemote (matched 'cash')

- **Instance Path:** `ReplicatedStorage.Remotes.GiveCashRemote`
- **Category:** `RemoteSecurity`
- **Detected At:** `16:16:03`
- **Architectural Flaw:** RemoteEvent name suggests privileged currency mutation accessible to all clients.
- **Malicious Client Abuse Vector:** Malicious clients can fire GiveCashRemote:FireServer(999999999) or pass negative values to drain/mint currency.
- **Recommended Server-Side Fix:** Remove direct reward remotes; calculate rewards strictly inside server-side objective/combat completion handlers.

```luau
-- Do NOT let clients request arbitrary currency.
-- Award currency on the server only when a verified server event completes.
```

### 3.5 [WARN] Unanchored Part with Client/Auto NetworkOwnership: VaultDoor

- **Instance Path:** `Workspace.BankLevel.VaultDoor`
- **Category:** `NetworkOwnership`
- **Detected At:** `16:16:03`
- **Architectural Flaw:** Unanchored interactive BasePart allows automatic client physics ownership (Current Owner: Auto).
- **Malicious Client Abuse Vector:** Exploiters standing near VaultDoor gain physics authority and can set its CFrame to bypass locked barriers.
- **Recommended Server-Side Fix:** Anchor the door and animate via server TweenService, or lock physics authority to the server via part:SetNetworkOwner(nil).

```luau
workspace.BankLevel.VaultDoor:SetNetworkOwner(nil)
```

### 3.6 [INFO] Exposed Network Endpoint: SprintToggle

- **Instance Path:** `ReplicatedStorage.Remotes.SprintToggle`
- **Category:** `RemoteSecurity`
- **Detected At:** `16:16:03`
- **Architectural Flaw:** Client-accessible RemoteEvent found in ReplicatedStorage.
- **Malicious Client Abuse Vector:** Clients can fire SprintToggle with non-boolean payloads or spam it every frame.
- **Recommended Server-Side Fix:** Validate typeof(isSprinting) == 'boolean' and enforce a 0.15s per-player debounce on the server.

## 4. Remote Traffic Profiler Summary

| Remote Path | Class | Total Calls | Peak Rate (calls/s) | Last Rate (calls/s) | Cooldown Flag |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ReplicatedStorage.Remotes.GiveCashRemote` | `RemoteEvent` | 340 | 34.0/s | 34.0/s | **NEEDS DEBOUNCE** |
| `ReplicatedStorage.Remotes.SprintToggle` | `RemoteEvent` | 4 | 0.4/s | 0.4/s | **OK** |

## 5. Instance & Memory Diffing Timeline

| Snapshot Time | Elapsed (s) | Workspace Instances | Player Instances | Total Memory (MB) |
| :--- | :--- | :--- | :--- | :--- |
| `16:16:03` | 0.0s | 1420 | 85 | 412.50 MB |
| `16:16:03` | 10.0s | 1665 | 92 | 448.20 MB |

---
_Generated by **rcdebug (Revan Cool Debugger)** v1.0.0_
