"""
Generates the 100% client-sided, universal-game Luau diagnostic & runtime telemetry
snippet for Roblox Client, Studio Client Command Bar, LocalScript, or Developer Console.

Supports all Roblox game genres (Simulators, Tycoons, FPS/Combat, RPG, Horror, Obby,
Roleplay, Racing/Vehicle, Gacha/Trading) with chunked scanning to prevent client freezes
on large 30k-100k+ instance maps.
"""

from __future__ import annotations


def build_luau_bridge_script(host: str = "127.0.0.1", port: int = 8765, snapshot_interval: int = 10) -> str:
    report_url = f"http://{host}:{port}/report"
    telemetry_url = f"http://{host}:{port}/telemetry"

    return f"""-- [rcdebug v1.0] 100% Client-Sided Universal Roblox Game Auditor & Telemetry Bridge
-- What this does: This checks your Roblox game for weak spots and lag,
-- then sends a simple list to your computer so you can fix them and keep the game fair.
-- Compatible with all Roblox game genres; zero server-only APIs; chunked for large maps.
local HttpService = game:GetService("HttpService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ReplicatedFirst = game:GetService("ReplicatedFirst")
local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")
local Lighting = game:GetService("Lighting")
local SoundService = game:GetService("SoundService")
local Teams = game:GetService("Teams")
local StarterGui = game:GetService("StarterGui")
local StarterPack = game:GetService("StarterPack")
local Stats = game:GetService("Stats")
local RunService = game:GetService("RunService")

local LocalPlayer = Players.LocalPlayer or Players.PlayerAdded:Wait()

local REPORT_ENDPOINT = "{report_url}"
local TELEMETRY_ENDPOINT = "{telemetry_url}"
local SNAPSHOT_INTERVAL = {snapshot_interval}
local SCAN_CHUNK_SIZE = 1500

local httpAllowed = true
local bridgeNoticed = false

local function emitWire(wireKind, encoded)
    print("[rcdebug-wire:" .. wireKind .. "] " .. encoded)
end

local function postJSON(url, wireKind, payload)
    local encoded = HttpService:JSONEncode(payload)
    if not httpAllowed then
        emitWire(wireKind, encoded)
        return
    end
    task.spawn(function()
        local ok = pcall(function()
            HttpService:PostAsync(url, encoded, Enum.HttpContentType.ApplicationJson)
        end)
        if not ok then
            httpAllowed = false
            if not bridgeNoticed then
                bridgeNoticed = true
                print("[rcdebug] Client HttpService restricted; streaming full JSON telemetry via Roblox Log Bridge -> rcdebug terminal.")
            end
            emitWire(wireKind, encoded)
        end
    end)
end

local function sendFinding(severity, category, title, path, flaw, abuse, fix, codeExample)
    postJSON(REPORT_ENDPOINT, "report", {{
        severity = severity,
        category = category,
        title = title,
        path = path,
        flaw = flaw,
        abuse = abuse,
        fix = fix,
        code_example = codeExample or ""
    }})
end

-- ============================================================================
-- 1. Universal Keyword Tables (All Game Genres)
-- ============================================================================
local CRITICAL_REMOTE_KEYWORDS = {{
    "cash", "money", "coin", "gem", "gold", "diamond", "buck", "credit", "token", "currency",
    "give", "award", "reward", "payout", "rebirth", "prestige", "admin", "mod", "staff",
    "ban", "kick", "unban", "rank", "sudo", "damage", "dmg", "kill", "execute", "heal",
    "revive", "buy", "purchase", "sell", "trade", "gift", "duel", "hatch", "roll", "spin",
    "gacha", "craft", "upgrade", "enchant", "equip", "drop", "redeem", "promocode"
}}

local WARN_REMOTE_KEYWORDS = {{
    "stamina", "mana", "energy", "hunger", "xp", "exp", "level", "quest", "mission",
    "claim", "collect", "pickup", "loot", "chest", "crate", "build", "place", "delete",
    "destroy", "tycoon", "dropper", "teleport", "tp", "warp", "dash", "speed", "vehicle",
    "spawn", "team", "vote", "ready", "hit", "hitbox", "shoot", "fire", "parry"
}}

local SENSITIVE_VALUE_KEYWORDS = {{
    "stamina", "cash", "money", "coin", "gem", "gold", "currency", "credit", "token",
    "health", "hp", "mana", "energy", "hunger", "thirst", "oxygen", "sanity",
    "xp", "exp", "level", "admin", "rank", "vip", "damage", "dmg", "speed",
    "walkspeed", "jumppower", "ammo", "cooldown", "shield", "armor", "rebirth", "multiplier"
}}

local function matchKeywordList(name, keywords)
    local lower = name:lower()
    for _, kw in ipairs(keywords) do
        if lower:find(kw, 1, true) then
            return true, kw
        end
    end
    return false, nil
end

-- ============================================================================
-- 2. Universal Remote Audit & OnClientEvent Replication Profiler
-- ============================================================================
local remoteCounts = {{}}
local remoteTypes = {{}}
local trackedRemotes = {{}}

local function inspectClientRemote(obj, containerName)
    if not (obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") or obj:IsA("UnreliableRemoteEvent")) then
        return
    end
    local fullPath = obj:GetFullName()
    if trackedRemotes[fullPath] then
        return
    end
    trackedRemotes[fullPath] = true

    local isCrit, critKw = matchKeywordList(obj.Name, CRITICAL_REMOTE_KEYWORDS)
    local isWarn, warnKw = matchKeywordList(obj.Name, WARN_REMOTE_KEYWORDS)
    local inWorkspace = (containerName == "Workspace")

    local sev = "INFO"
    local title = "Client-Visible Remote: " .. obj.Name
    local flaw = "Client-accessible " .. obj.ClassName .. " replicated inside " .. containerName .. "."

    if isCrit then
        sev = "WARN"
        title = "High-Risk Client-Visible Remote: " .. obj.Name .. " ('" .. tostring(critKw) .. "')"
        flaw = "Remote endpoint name matches critical gameplay/economy keyword '" .. tostring(critKw) .. "' accessible to all clients."
    elseif isWarn then
        sev = "WARN"
        title = "Gameplay State Remote: " .. obj.Name .. " ('" .. tostring(warnKw) .. "')"
        flaw = "Remote endpoint name matches gameplay state keyword '" .. tostring(warnKw) .. "' in " .. containerName .. "."
    elseif inWorkspace then
        sev = "WARN"
        title = "Workspace-Parented Remote: " .. obj.Name
        flaw = "Remote endpoint is parented inside Workspace rather than a centralized ReplicatedStorage network folder."
    end

    sendFinding(
        sev,
        "RemoteSecurity",
        title,
        fullPath,
        flaw,
        "Clients can fire or invoke this endpoint with spoofed types, negative numbers, NaN, nil, or oversized tables at high frequency.",
        "Validate typeof() and finite bounds on the server, enforce per-player cooldowns, and keep rewards/prices server-authoritative.",
        "remote.OnServerEvent:Connect(function(plr, amt)\\n    if typeof(amt) ~= \\"number\\" or amt ~= amt or amt <= 0 then return end\\nend)"
    )

    if obj:IsA("RemoteEvent") or obj:IsA("UnreliableRemoteEvent") then
        remoteCounts[fullPath] = 0
        remoteTypes[fullPath] = obj.ClassName
        obj.OnClientEvent:Connect(function(...)
            remoteCounts[fullPath] = (remoteCounts[fullPath] or 0) + 1
        end)
    end
end

local function scanRemotesInContainer(container, label)
    if not container then return end
    local ok, descendants = pcall(function() return container:GetDescendants() end)
    if not ok then return end
    for i, obj in ipairs(descendants) do
        inspectClientRemote(obj, label)
        if i % SCAN_CHUNK_SIZE == 0 then
            task.wait()
        end
    end
    container.DescendantAdded:Connect(function(obj)
        inspectClientRemote(obj, label)
    end)
end

-- ============================================================================
-- 3. Client-Side ValueBase & Attribute Audit (LocalPlayer, Character, Shared)
-- ============================================================================
local reportedValues = {{}}

local function scanContainerForValues(rootInstance, label)
    if not rootInstance then return end
    local ok, descendants = pcall(function() return rootInstance:GetDescendants() end)
    if not ok then return end
    for i, desc in ipairs(descendants) do
        if desc:IsA("ValueBase") then
            local fullPath = desc:GetFullName()
            if not reportedValues[fullPath] then
                local sensitive, kw = matchKeywordList(desc.Name, SENSITIVE_VALUE_KEYWORDS)
                if sensitive then
                    reportedValues[fullPath] = true
                    local inChar = (label == "Character")
                    local sev = inChar and "CRITICAL" or "WARN"
                    sendFinding(
                        sev,
                        "StateReplication",
                        "Client-Accessible " .. desc.ClassName .. " in " .. label .. ": " .. desc.Name,
                        fullPath,
                        "Gameplay state ('" .. tostring(kw) .. "') is stored in a " .. desc.ClassName .. " inside " .. label .. ".",
                        "Client-accessible ValueBase objects can be modified locally; any script trusting them without server authority causes state desync or spoofing.",
                        "Store authoritative state in ServerScriptService tables and replicate read-only Attributes to clients.",
                        "player:SetAttribute(\\"Cash\\", authoritativeCash)"
                    )
                end
            end
        end
        if i % SCAN_CHUNK_SIZE == 0 then
            task.wait()
        end
    end
end

local function scanAttributesOn(instance, label)
    if not instance then return end
    for attrName, _ in pairs(instance:GetAttributes()) do
        local sensitive, kw = matchKeywordList(attrName, SENSITIVE_VALUE_KEYWORDS)
        if sensitive then
            sendFinding(
                "INFO",
                "StateReplication",
                "Client-Readable " .. label .. " Attribute: " .. attrName,
                instance:GetFullName() .. " [Attribute:" .. attrName .. "]",
                "Attribute '" .. attrName .. "' ('" .. tostring(kw) .. "') is replicated to the client on " .. label .. ".",
                "Verify no LocalScript trusts client-mutated local attributes to gate remote arguments or gameplay checks.",
                "Keep Attributes strictly for read-only UI display and enforce all gameplay validation server-side."
            )
        end
    end
end

-- ============================================================================
-- 4. Tool & Humanoid Exposure Audit (Combat / Obby / RPG / Simulator)
-- ============================================================================
local function auditTool(tool)
    if not tool:IsA("Tool") then return end
    local hasTouch = tool:FindFirstChildWhichIsA("TouchTransmitter", true) ~= nil
    local hasRemote = tool:FindFirstChildWhichIsA("RemoteEvent", true) ~= nil or tool:FindFirstChildWhichIsA("RemoteFunction", true) ~= nil
    if hasTouch or hasRemote then
        sendFinding(
            "INFO",
            "InventorySecurity",
            "Tool Replication Surface: " .. tool.Name,
            tool:GetFullName(),
            "Tool contains client-accessible " .. (hasTouch and "TouchTransmitter " or "") .. (hasRemote and "RemoteEndpoint" or "") .. ".",
            "Client-owned character Tools with TouchTransmitters or unvalidated remotes are common targets for hitbox reach or remote-damage spoofing.",
            "Validate tool ownership, equip state, cooldowns, and raycast/magnitude distance on the server before applying tool effects."
        )
    end
end

local function auditCharacter(char)
    if not char then return end
    scanContainerForValues(char, "Character")
    scanAttributesOn(char, "Character")
    for _, child in ipairs(char:GetChildren()) do
        if child:IsA("Tool") then
            auditTool(child)
        elseif child:IsA("Humanoid") then
            if child.WalkSpeed > 24 or child.JumpPower > 65 then
                sendFinding(
                    "INFO",
                    "PhysicsSecurity",
                    "Elevated Humanoid Movement Baseline (" .. child.Name .. ")",
                    child:GetFullName(),
                    string.format("Character Humanoid baseline WalkSpeed=%.1f, JumpPower=%.1f.", child.WalkSpeed, child.JumpPower),
                    "Because clients own their character physics, server anti-cheat thresholds must match game-specific speed/jump abilities.",
                    "Track authoritative movement speed boosts server-side and enforce server displacement/velocity sanity checks."
                )
            end
        end
    end
end

-- ============================================================================
-- 5. Chunked Universal Workspace Scan (Physics, Prompts, ClickDetectors, Seats)
-- ============================================================================
local unanchoredCount = 0
local reportedPhysicsModels = {{}}
local physicsReportedCount = 0
local promptReportedCount = 0
local clickReportedCount = 0

local function isPlayerCharacterPart(part)
    local model = part:FindFirstAncestorOfClass("Model")
    return model ~= nil and Players:GetPlayerFromCharacter(model) ~= nil
end

task.spawn(function()
    -- Scan all client-visible services for Remotes
    local remoteContainers = {{
        {{ ReplicatedStorage, "ReplicatedStorage" }},
        {{ ReplicatedFirst, "ReplicatedFirst" }},
        {{ Workspace, "Workspace" }},
        {{ LocalPlayer, "LocalPlayer" }},
        {{ StarterGui, "StarterGui" }},
        {{ StarterPack, "StarterPack" }},
        {{ Lighting, "Lighting" }},
        {{ SoundService, "SoundService" }},
        {{ Teams, "Teams" }},
    }}
    for _, pair in ipairs(remoteContainers) do
        scanRemotesInContainer(pair[1], pair[2])
    end

    -- Scan LocalPlayer, Backpack, Character, and Shared ValueBases
    scanContainerForValues(LocalPlayer, "LocalPlayer")
    scanAttributesOn(LocalPlayer, "LocalPlayer")
    scanContainerForValues(ReplicatedStorage, "ReplicatedStorage")
    if LocalPlayer.Character then
        auditCharacter(LocalPlayer.Character)
    end
    LocalPlayer.CharacterAdded:Connect(function(char)
        task.wait(0.25)
        auditCharacter(char)
    end)

    local backpack = LocalPlayer:FindFirstChildOfClass("Backpack")
    if backpack then
        for _, item in ipairs(backpack:GetChildren()) do
            auditTool(item)
        end
        backpack.ChildAdded:Connect(auditTool)
    end

    -- Chunked scan of Workspace for physics, ProximityPrompts, ClickDetectors, and VehicleSeats
    local wsDescendants = Workspace:GetDescendants()
    for i, obj in ipairs(wsDescendants) do
        if obj:IsA("BasePart") and not obj.Anchored and not obj:IsDescendantOf(Workspace.CurrentCamera) then
            if not isPlayerCharacterPart(obj) then
                unanchoredCount += 1
                local hasTouch = obj:FindFirstChildOfClass("TouchTransmitter") ~= nil
                local clientSimulated = false
                pcall(function()
                    clientSimulated = (obj.ReceiveAge == 0)
                end)

                if (clientSimulated or hasTouch) and physicsReportedCount < 12 then
                    local ownerModel = obj:FindFirstAncestorOfClass("Model")
                    local groupKey = ownerModel and ownerModel:GetFullName() or obj:GetFullName()
                    if not reportedPhysicsModels[groupKey] then
                        reportedPhysicsModels[groupKey] = true
                        physicsReportedCount += 1
                        local detail = clientSimulated and "simulated by this client (ReceiveAge == 0)" or "contains TouchTransmitter while unanchored"
                        sendFinding(
                            "WARN",
                            "NetworkOwnership",
                            "Client-Exposed Unanchored Part/Model: " .. (ownerModel and ownerModel.Name or obj.Name),
                            groupKey,
                            "Unanchored non-character BasePart (" .. obj.Name .. ") is " .. detail .. ".",
                            "Clients with physics ownership over unanchored parts control their CFrame/velocity and can trigger TouchInterests remotely.",
                            "Anchor static/menu models in Studio, or call part:SetNetworkOwner(nil) server-side and validate Touched events.",
                            "part:SetNetworkOwner(nil)"
                        )
                    end
                end
            end
        elseif obj:IsA("ProximityPrompt") and promptReportedCount < 6 then
            promptReportedCount += 1
            if obj.MaxActivationDistance > 20 or not obj.RequiresLineOfSight then
                sendFinding(
                    "INFO",
                    "PromptSecurity",
                    "Permissive ProximityPrompt Configuration: " .. obj.Name,
                    obj:GetFullName(),
                    string.format("ProximityPrompt has MaxActivationDistance=%.1f, RequiresLineOfSight=%s.", obj.MaxActivationDistance, tostring(obj.RequiresLineOfSight)),
                    "Server Triggered handlers without explicit magnitude checks allow clients to interact from extended range or through walls.",
                    "Validate (player.Character.PrimaryPart.Position - promptPart.Position).Magnitude <= MaxActivationDistance + 4 on the server."
                )
            end
        elseif obj:IsA("ClickDetector") and clickReportedCount < 4 then
            clickReportedCount += 1
            if obj.MaxActivationDistance > 40 then
                sendFinding(
                    "INFO",
                    "PromptSecurity",
                    "Long-Range ClickDetector: " .. obj.Name,
                    obj:GetFullName(),
                    string.format("ClickDetector allows activation up to %.1f studs.", obj.MaxActivationDistance),
                    "Ensure MouseClick server listeners verify player character proximity and ownership before mutating state.",
                    "Check character distance and per-player cooldown inside ClickDetector.MouseClick on the server."
                )
            end
        elseif obj:IsA("VehicleSeat") then
            sendFinding(
                "INFO",
                "PhysicsSecurity",
                "VehicleSeat Network Surface: " .. obj.Name,
                obj:GetFullName(),
                "VehicleSeat grants network ownership to the seated occupant during driving.",
                "Without server velocity/bounds checks, seated clients can manipulate vehicle speed or teleport vehicle assemblies.",
                "Validate seat occupancy server-side and clamp abnormal vehicle velocity/teleport deltas on the server."
            )
        end

        if i % SCAN_CHUNK_SIZE == 0 then
            task.wait()
        end
    end

    if unanchoredCount > 100 then
        sendFinding(
            "WARN",
            "Performance",
            "Excessive Unanchored Parts Visible to Client (" .. tostring(unanchoredCount) .. " parts)",
            "Workspace",
            "Client observes " .. tostring(unanchoredCount) .. " unanchored non-character BaseParts in Workspace.",
            "Large numbers of unanchored parts increase physics simulation overhead, replication bandwidth, and network ownership surface.",
            "Anchor decorative geometry in Studio and disable CanCollide/CanTouch on non-interactive detail parts."
        )
    end

    print("[rcdebug] Universal 100% client-sided scan complete across all containers & live telemetry active (10s interval).")
end)

-- ============================================================================
-- 6. Continuous Client Telemetry Loop (OnClientEvent Rates, FPS & 10s Memory Diffs)
-- ============================================================================
local RUN_TOKEN = HttpService:GenerateGUID(false)
LocalPlayer:SetAttribute("__rcdebug_run_token", RUN_TOKEN)

local frameCount = 0
local heartbeatConn
heartbeatConn = RunService.Heartbeat:Connect(function()
    if LocalPlayer:GetAttribute("__rcdebug_run_token") ~= RUN_TOKEN then
        if heartbeatConn then heartbeatConn:Disconnect() end
        return
    end
    frameCount += 1
end)

task.spawn(function()
    local startTime = os.clock()
    local lastCheck = os.clock()
    local lastRemoteTotals = {{}}

    while LocalPlayer:GetAttribute("__rcdebug_run_token") == RUN_TOKEN do
        task.wait(SNAPSHOT_INTERVAL)
        if LocalPlayer:GetAttribute("__rcdebug_run_token") ~= RUN_TOKEN then
            break
        end

        local now = os.clock()
        local dt = math.max(0.1, now - lastCheck)
        lastCheck = now
        local fps = math.floor((frameCount / dt) * 10) / 10
        frameCount = 0

        local remoteRates = {{}}
        for path, total in pairs(remoteCounts) do
            local prev = lastRemoteTotals[path] or 0
            local delta = total - prev
            lastRemoteTotals[path] = total
            local rate = delta / dt
            if total > 0 then
                table.insert(remoteRates, {{
                    remote_path = path,
                    remote_type = remoteTypes[path] or "RemoteEvent",
                    total_calls = total,
                    rate_per_sec = math.floor(rate * 10) / 10
                }})
            end
            if rate >= 20 then
                sendFinding(
                    "CRITICAL",
                    "RemoteTraffic",
                    "High-Frequency Server->Client Remote Replication: " .. path,
                    path,
                    string.format("OnClientEvent received %.1f calls/sec over the last %.0fs window (Client FPS: %.1f).", rate, dt, fps),
                    "Excessive FireClient/FireAllClients replication saturates client bandwidth, increases ping, and causes frame drops.",
                    "Batch updates into snapshots (10-20 Hz) or use UnreliableRemoteEvent for high-frequency visual updates."
                )
            end
        end

        local wsCount = #Workspace:GetDescendants()
        local plrCount = #LocalPlayer:GetDescendants()
        local memMb = 0
        pcall(function()
            memMb = Stats:GetTotalMemoryUsageMb()
        end)

        postJSON(TELEMETRY_ENDPOINT, "telemetry", {{
            elapsed_sec = math.floor((now - startTime) * 10) / 10,
            workspace_instances = wsCount,
            player_instances = plrCount,
            total_memory_mb = math.floor(memMb * 100) / 100,
            client_fps = fps,
            remotes = remoteRates
        }})
    end
end)
"""
