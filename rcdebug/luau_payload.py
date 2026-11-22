"""
Generates an offline, self-contained Roblox Studio QA Test Runner (Luau).

Runs locally inside Roblox Studio Play Solo / Local Server (StarterPlayerScripts
or Command Bar) with zero external HTTP calls. Outputs clear [PASS] and [FAIL]
results directly to the Roblox Studio Output window.
"""

from __future__ import annotations


def build_studio_qa_runner_script(snapshot_interval: int = 10) -> str:
    """
    Returns a pure, zero-dependency Luau Studio QA test runner that validates
    ReplicatedStorage remotes, local player state, Workspace physics ownership,
    interaction prompts, and memory stability entirely offline in Studio Output.
    """
    return f"""-- What this script does:
-- This is an offline Roblox Studio QA Test Runner for your own game.
-- Paste it into the Studio Command Bar or StarterPlayerScripts during Play Solo
-- to test your game locally. It makes zero internet calls and prints [PASS] or [FAIL]
-- straight into the Roblox Studio Output window so you can verify your game logic safely.
-- [rcdebug v1.0] Offline Studio QA Test Runner (Zero External HTTP Calls)

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")
local Stats = game:GetService("Stats")
local RunService = game:GetService("RunService")

local LocalPlayer = Players.LocalPlayer or Players.PlayerAdded:Wait()

local SNAPSHOT_INTERVAL = {snapshot_interval}
local SCAN_CHUNK_SIZE = 1500
local ENABLE_ACTIVE_REMOTE_PROBES = false -- Set to true in Play Solo to test RemoteFunction rejection of invalid inputs

local passedCount = 0
local failedCount = 0

local function logPass(suiteName, testName, detail)
    passedCount += 1
    print(string.format("[PASS] [%s] %s - %s", suiteName, testName, detail))
end

local function logFail(suiteName, testName, plainEnglishReason)
    failedCount += 1
    warn(string.format("[FAIL] [%s] %s - %s", suiteName, testName, plainEnglishReason))
end

local function isCharacterPart(inst)
    for _, plr in ipairs(Players:GetPlayers()) do
        if plr.Character and inst:IsDescendantOf(plr.Character) then
            return true
        end
    end
    return false
end

local function snapshotLeaderstats()
    local snap = {{}}
    local ls = LocalPlayer:FindFirstChild("leaderstats")
    if not ls then
        return snap
    end
    for _, child in ipairs(ls:GetChildren()) do
        if child:IsA("IntValue") or child:IsA("NumberValue") then
            snap[child.Name] = child.Value
        end
    end
    return snap
end

local function leaderstatsIncreased(beforeSnap, afterSnap)
    for statName, beforeVal in pairs(beforeSnap) do
        local afterVal = afterSnap[statName]
        if typeof(afterVal) == "number" and afterVal > beforeVal then
            return true, statName, beforeVal, afterVal
        end
    end
    return false, nil, nil, nil
end

-- ============================================================================
-- SUITE 1: ReplicatedStorage Remote Discovery & Boundary Rejection Tests
-- ============================================================================
local function runRemoteContractSuite()
    local suite = "RemoteContracts"
    local remotes = {{}}
    local descendants = ReplicatedStorage:GetDescendants()

    for i, obj in ipairs(descendants) do
        if obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") or obj:IsA("UnreliableRemoteEvent") then
            table.insert(remotes, obj)
        end
        if i % SCAN_CHUNK_SIZE == 0 then
            task.wait()
        end
    end

    if #remotes == 0 then
        logPass(suite, "RemoteDiscovery", "No client-visible remotes found under ReplicatedStorage.")
        return
    end

    local highRiskWords = {{ "admin", "kick", "ban", "cash", "coin", "gold", "gem", "money", "reward", "daily", "claim", "buy", "damage", "kill", "give" }}
    local flaggedNames = 0

    for _, remote in ipairs(remotes) do
        local lowName = string.lower(remote.Name)
        local isSensitive = false
        for _, kw in ipairs(highRiskWords) do
            if string.find(lowName, kw, 1, true) then
                isSensitive = true
                break
            end
        end

        if isSensitive then
            flaggedNames += 1
            logFail(
                suite,
                remote:GetFullName(),
                "Sensitive remote is visible to every player. Verify its server script checks player permission, valid numbers, and cooldowns."
            )
        else
            logPass(suite, remote.Name, "Discovered " .. remote.ClassName .. " in ReplicatedStorage.")
        end

        -- Optional active boundary checks on RemoteFunctions during Studio Play Solo
        if ENABLE_ACTIVE_REMOTE_PROBES and RunService:IsStudio() and remote:IsA("RemoteFunction") then
            local invalidCases = {{
                {{ label = "nil_input", args = {{ nil }} }},
                {{ label = "nan_number", args = {{ 0 / 0 }} }},
                {{ label = "negative_number", args = {{ -100 }} }},
                {{ label = "oversized_string", args = {{ string.rep("A", 512) }} }},
            }}

            for _, tc in ipairs(invalidCases) do
                local beforeStats = snapshotLeaderstats()
                local callOk, result = pcall(function()
                    return remote:InvokeServer(table.unpack(tc.args))
                end)
                task.wait(0.05)
                local afterStats = snapshotLeaderstats()
                local gained, statName = leaderstatsIncreased(beforeStats, afterStats)

                if gained then
                    logFail(
                        suite,
                        remote.Name .. ":" .. tc.label,
                        "Server increased leaderstats." .. tostring(statName) .. " after receiving an invalid input (" .. tc.label .. "). Reject invalid inputs before changing player stats."
                    )
                elseif callOk and result == true then
                    logFail(
                        suite,
                        remote.Name .. ":" .. tc.label,
                        "Server returned true for invalid input (" .. tc.label .. "). Add strict typeof() and range validation on the server handler."
                    )
                else
                    logPass(
                        suite,
                        remote.Name .. ":" .. tc.label,
                        "Server safely rejected or ignored invalid input (" .. tc.label .. ")."
                    )
                end
            end
        end
    end

    if flaggedNames == 0 then
        logPass(suite, "SensitiveRemoteNaming", "No high-risk economy/admin remote names exposed.")
    end
end

-- ============================================================================
-- SUITE 2: Local Player State & Replicated Attributes Check
-- ============================================================================
local function runPlayerStateSuite()
    local suite = "PlayerState"
    local sensitiveWords = {{ "cash", "coin", "gold", "gem", "money", "admin", "rank", "vip", "damage", "speed" }}
    local sensitiveFound = 0

    for attrName, attrVal in pairs(LocalPlayer:GetAttributes()) do
        local low = string.lower(attrName)
        for _, kw in ipairs(sensitiveWords) do
            if string.find(low, kw, 1, true) then
                sensitiveFound += 1
                logFail(
                    suite,
                    "PlayerAttribute:" .. attrName,
                    "Sensitive attribute '" .. attrName .. "' (" .. typeof(attrVal) .. ") is visible on the player. Make sure the server never reads this value back as trusted truth."
                )
                break
            end
        end
    end

    for _, desc in ipairs(LocalPlayer:GetDescendants()) do
        if desc:IsA("ValueBase") then
            local low = string.lower(desc.Name)
            for _, kw in ipairs(sensitiveWords) do
                if string.find(low, kw, 1, true) then
                    sensitiveFound += 1
                    logFail(
                        suite,
                        "ValueBase:" .. desc:GetFullName(),
                        "Replicated " .. desc.ClassName .. " '" .. desc.Name .. "' is readable locally. Keep the real balance in a server-only table and use this only for UI display."
                    )
                    break
                end
            end
        end
    end

    if sensitiveFound == 0 then
        logPass(suite, "LocalPlayerState", "No sensitive economy or admin attributes/values exposed on LocalPlayer.")
    end
end

-- ============================================================================
-- SUITE 3: Workspace Unanchored Physics & Ownership Sanity Check
-- ============================================================================
local function runPhysicsOwnershipSuite()
    local suite = "PhysicsOwnership"
    local unanchoredOwned = 0
    local sampleLimit = 5
    local descendants = Workspace:GetDescendants()

    for i, obj in ipairs(descendants) do
        if obj:IsA("BasePart") and not obj.Anchored and not isCharacterPart(obj) then
            if obj.ReceiveAge == 0 then
                unanchoredOwned += 1
                if unanchoredOwned <= sampleLimit then
                    logFail(
                        suite,
                        obj:GetFullName(),
                        "Unanchored part is currently owned by the local player's physics. Set Anchored = true or call part:SetNetworkOwner(nil) on the server so players cannot fling it."
                    )
                end
            end
        end
        if i % SCAN_CHUNK_SIZE == 0 then
            task.wait()
        end
    end

    if unanchoredOwned == 0 then
        logPass(suite, "WorkspacePhysics", "No client-owned unanchored BaseParts detected in Workspace.")
    elseif unanchoredOwned > sampleLimit then
        warn(string.format("[INFO] [%s] Found %d total client-owned unanchored parts (showing first %d).", suite, unanchoredOwned, sampleLimit))
    end
end

-- ============================================================================
-- SUITE 4: World Interaction Prompts & Touch Surfaces Check
-- ============================================================================
local function runInteractionSuite()
    local suite = "WorldInteractions"
    local widePrompts = 0
    local descendants = Workspace:GetDescendants()

    for i, obj in ipairs(descendants) do
        if obj:IsA("ProximityPrompt") then
            if obj.MaxActivationDistance > 20 or not obj.RequiresLineOfSight then
                widePrompts += 1
                if widePrompts <= 5 then
                    logFail(
                        suite,
                        obj:GetFullName(),
                        string.format(
                            "Prompt has MaxActivationDistance=%.1f and RequiresLineOfSight=%s. Keep distance tight and verify player distance on the server.",
                            obj.MaxActivationDistance,
                            tostring(obj.RequiresLineOfSight)
                        )
                    )
                end
            end
        end
        if i % SCAN_CHUNK_SIZE == 0 then
            task.wait()
        end
    end

    if widePrompts == 0 then
        logPass(suite, "ProximityPrompts", "All ProximityPrompts use reasonable activation distances and line-of-sight settings.")
    end
end

-- ============================================================================
-- SUITE 5: Local Memory & Instance Growth Stability Check
-- ============================================================================
local function runMemoryStabilitySuite()
    local suite = "MemoryStability"
    local baseInstances = #Workspace:GetDescendants()
    local baseMemMb = Stats:GetTotalMemoryUsageMb()
    print(string.format("[INFO] [%s] Baseline -> Workspace instances: %d | Memory: %.2f MB (waiting %ds...)", suite, baseInstances, baseMemMb, SNAPSHOT_INTERVAL))

    task.wait(SNAPSHOT_INTERVAL)

    local nextInstances = #Workspace:GetDescendants()
    local nextMemMb = Stats:GetTotalMemoryUsageMb()
    local instDelta = nextInstances - baseInstances
    local memDelta = nextMemMb - baseMemMb

    if instDelta > 200 or memDelta > 35 then
        logFail(
            suite,
            "InstanceAndMemoryGrowth",
            string.format(
                "Workspace grew by +%d instances and memory rose by +%.2f MB in %ds. Check for cloned parts or effects missing Debris:AddItem() cleanup.",
                instDelta,
                memDelta,
                SNAPSHOT_INTERVAL
            )
        )
    else
        logPass(
            suite,
            "InstanceAndMemoryGrowth",
            string.format("Stable over %ds (instances %+d, memory %+.2f MB).", SNAPSHOT_INTERVAL, instDelta, memDelta)
        )
    end
end

print("====================================================================")
print("[rcdebug] Starting Offline Roblox Studio QA Test Runner...")
print("====================================================================")

runRemoteContractSuite()
runPlayerStateSuite()
runPhysicsOwnershipSuite()
runInteractionSuite()
runMemoryStabilitySuite()

print("====================================================================")
print(string.format("[rcdebug QA Summary] Passed: %d | Failed: %d", passedCount, failedCount))
print("====================================================================")
"""


def build_luau_bridge_script(host: str = "127.0.0.1", port: int = 8765, snapshot_interval: int = 10) -> str:
    """
    Backwards-compatible entrypoint returning the offline, self-contained
    Roblox Studio QA Test Runner (zero external HTTP calls).
    """
    _ = (host, port)
    return build_studio_qa_runner_script(snapshot_interval=snapshot_interval)
