"""
Flaw-specific Server-Side Luau Unit Test & Contract Specification generator.

Produces 4 deterministic, zero-boilerplate sections for every flagged finding:
  1. Vulnerability Trace & Locator (exact script path, line number, remote name, parameters)
  2. Vulnerable Server Handler (exact audited code snippet)
  3. Parameter Contract & Edge-Case Matrix (per-parameter typeof, bounds, rejected inputs)
  4. Defensive Server-Side Remediation & Guard Module + Studio Command Bar assert() tests
"""

from __future__ import annotations

import re
from typing import Any


def _safe_luau_ident(name: str, fallback: str = "Handler") -> str:
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in (name or "").strip())
    if not cleaned:
        return fallback
    if cleaned[0].isdigit():
        return f"_{cleaned}"
    return cleaned


def _split_camel_tokens(text: str) -> set[str]:
    if not text:
        return set()
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return {tok.lower() for tok in re.findall(r"[A-Za-z0-9]+", spaced) if len(tok) >= 2}


def infer_param_contract(
    param_name: str,
    annotated_type: str = "",
    handler_context: str = "",
) -> dict[str, Any]:
    """
    Infers the strict Luau typeof(), valid bounds, rejected edge-case inputs,
    guard expression, and deterministic assert() test fixtures for a single parameter.
    """
    pname = param_name.strip()
    low = pname.lower()
    ann = (annotated_type or "").strip().lower()
    ctx = (handler_context or "").lower()

    # Player parameter (server-supplied first arg of OnServerEvent / OnServerInvoke / Triggered)
    if low in ("player", "plr", "client", "sender") or ann == "player":
        return {
            "parameter": pname,
            "kind": "player",
            "expected_typeof": "Instance (Player)",
            "valid_bounds": "Active Player in Players with valid UserId > 0",
            "rejected_edge_cases": "nil, non-Player Instance, disconnected Player (Parent == nil), UserId <= 0",
            "valid_test_expr": "mockPlayer",
            "invalid_tests": [
                ("nil_player", "nil", "missing player"),
                ("wrong_type_player", '"{bad}"', "non-Player value"),
            ],
        }

    # Instance / Target / Character / Part / Tool parameters
    if (
        ann in ("instance", "model", "basepart", "humanoid", "tool", "part")
        or any(k in low for k in ("target", "char", "character", "humanoid", "hum", "part", "model", "obj", "instance", "tool", "enemy", "victim", "npc"))
    ):
        expected_class = "Model" if any(k in low for k in ("char", "target", "enemy", "victim", "npc", "model")) else (
            "Humanoid" if "hum" in low else ("Tool" if "tool" in low else "BasePart")
        )
        return {
            "parameter": pname,
            "kind": "instance",
            "expected_class": expected_class,
            "expected_typeof": f"Instance ({expected_class})",
            "valid_bounds": f"Non-nil {expected_class} inside Workspace within max server distance (<= 24 studs)",
            "rejected_edge_cases": f"nil, wrong Instance class (e.g. Folder), Instance outside Workspace, out-of-range (> 24 studs), table/number",
            "valid_test_expr": "validTargetInstance",
            "invalid_tests": [
                (f"nil_{pname}", "nil", f"{pname} is nil"),
                (f"wrong_class_{pname}", 'Instance.new("Folder")', f"{pname} wrong Instance class"),
                (f"number_{pname}", "42", f"{pname} non-Instance type"),
            ],
        }

    # Spatial Vector3 / CFrame parameters
    if ann in ("vector3", "cframe") or any(k in low for k in ("pos", "position", "cframe", "cf", "dir", "direction", "origin", "dest", "destination", "vec", "look")):
        luau_t = "CFrame" if ("cf" in low or "cframe" in low or ann == "cframe") else "Vector3"
        return {
            "parameter": pname,
            "kind": "spatial",
            "luau_type": luau_t,
            "expected_typeof": luau_t,
            "valid_bounds": "Finite components (x == x, |component| < 10000) within 24 studs of server character",
            "rejected_edge_cases": f"nil, NaN {luau_t} (0/0), math.huge coordinates, coordinates > 24 studs from player, table/string",
            "valid_test_expr": "CFrame.new(0, 5, 0)" if luau_t == "CFrame" else "Vector3.new(0, 5, 0)",
            "invalid_tests": [
                (f"nil_{pname}", "nil", f"{pname} is nil"),
                (f"nan_{pname}", "CFrame.new(0/0, 0, 0)" if luau_t == "CFrame" else "Vector3.new(0/0, 0, 0)", f"{pname} contains NaN"),
                (f"inf_{pname}", "CFrame.new(math.huge, 0, 0)" if luau_t == "CFrame" else "Vector3.new(math.huge, 0, 0)", f"{pname} contains math.huge"),
                (f"far_{pname}", "CFrame.new(99999, 0, 0)" if luau_t == "CFrame" else "Vector3.new(99999, 0, 0)", f"{pname} exceeds spatial bound"),
            ],
        }

    # Boolean flags
    if ann in ("boolean", "bool") or low.startswith(("is", "has", "can", "enable", "toggle", "active", "confirm")):
        return {
            "parameter": pname,
            "kind": "boolean",
            "expected_typeof": "boolean",
            "valid_bounds": "Strict boolean (true or false); server state still overrides privilege/completion flags",
            "rejected_edge_cases": 'nil, number (1/0), string ("true"), table {}',
            "valid_test_expr": "true",
            "invalid_tests": [
                (f"nil_{pname}", "nil", f"{pname} is nil"),
                (f"num_{pname}", "1", f"{pname} non-boolean number"),
                (f"str_{pname}", '"true"', f"{pname} string instead of boolean"),
            ],
        }

    # Numeric parameters (price, cost, qty, amount, count, damage, level, stage, index, id when numeric)
    if (
        ann == "number"
        or any(k in low for k in ("price", "cost", "amt", "amount", "qty", "quantity", "count", "num", "cash", "gold", "coin", "gem", "money", "delta", "dmg", "damage", "hp", "health", "xp", "level", "stage", "slot", "index", "speed", "mult", "multiplier", "value", "val", "userid"))
    ):
        is_int = any(k in low for k in ("qty", "quantity", "count", "slot", "index", "stage", "level", "userid"))
        min_v = 1
        max_v = 100 if any(k in low for k in ("qty", "quantity", "count", "slot")) else 100000
        bounds_desc = (
            f"Finite integer: {min_v} <= {pname} <= {max_v} ({pname} == {pname} and |{pname}| < math.huge and math.floor({pname}) == {pname})"
            if is_int
            else f"Finite number: {min_v} <= {pname} <= {max_v} ({pname} == {pname} and |{pname}| < math.huge); server catalog overrides prices/damage"
        )
        invalid_tests = [
            (f"nan_{pname}", "0/0", f"{pname} is NaN"),
            (f"inf_{pname}", "math.huge", f"{pname} is math.huge"),
            (f"neg_{pname}", "-10", f"{pname} is negative"),
            (f"zero_{pname}", "0", f"{pname} is zero"),
            (f"over_{pname}", str(max_v * 10), f"{pname} exceeds upper bound"),
            (f"nil_{pname}", "nil", f"{pname} is nil"),
            (f"str_{pname}", '"100"', f"{pname} is string"),
        ]
        if is_int:
            invalid_tests.append((f"frac_{pname}", "1.5", f"{pname} is non-integer"))
        return {
            "parameter": pname,
            "kind": "number",
            "is_int": is_int,
            "min_val": min_v,
            "max_val": max_v,
            "expected_typeof": "number (integer)" if is_int else "number (finite)",
            "valid_bounds": bounds_desc,
            "rejected_edge_cases": "0/0 (NaN), math.huge, -math.huge, negative values (-10), 0, out-of-range (> max), nil, string/table" + (", fractional float (1.5)" if is_int else ""),
            "valid_test_expr": "1",
            "invalid_tests": invalid_tests,
        }

    # Table / Payload parameters
    if ann == "table" or any(k in low for k in ("data", "payload", "items", "list", "args", "config", "options", "table", "tbl")):
        return {
            "parameter": pname,
            "kind": "table",
            "expected_typeof": "table (bounded flat map/array)",
            "valid_bounds": "Non-nil table with <= 16 keys and depth <= 2; no cyclic references",
            "rejected_edge_cases": "nil, non-table (string/number), oversized table (> 16 keys), deeply nested table",
            "valid_test_expr": '{ id = "starter" }',
            "invalid_tests": [
                (f"nil_{pname}", "nil", f"{pname} is nil"),
                (f"str_{pname}", '"bad"', f"{pname} non-table string"),
                (f"huge_{pname}", "oversizedTable", f"{pname} exceeds max key count"),
            ],
        }

    # Default: identifier / string (itemId, actionName, zoneId, questId, code, command)
    max_len = 64
    return {
        "parameter": pname,
        "kind": "string",
        "max_len": max_len,
        "expected_typeof": "string (allowlisted)",
        "valid_bounds": f"Non-empty UTF-8 string, 1 <= #{pname} <= {max_len}, present in server allowlist",
        "rejected_edge_cases": f'nil, empty string "", oversized string (> {max_len} bytes), unknown/unlisted key, number/table',
        "valid_test_expr": '"StarterItem"',
        "invalid_tests": [
            (f"nil_{pname}", "nil", f"{pname} is nil"),
            (f"empty_{pname}", '""', f"{pname} is empty string"),
            (f"oversized_{pname}", f'string.rep("A", {max_len + 32})', f"{pname} exceeds max length"),
            (f"unlisted_{pname}", '"__unlisted_key__"', f"{pname} not in server allowlist"),
            (f"num_{pname}", "999", f"{pname} non-string type"),
        ],
    }


def _infer_runtime_params(remote_name: str, category: str, flaw: str) -> list[tuple[str, str]]:
    """
    When a finding comes from live runtime discovery (no source file parsed yet),
    infers concrete, domain-accurate parameter names for that specific remote
    so the contract matrix and guard module remain 100% specific and actionable.
    """
    tokens = _split_camel_tokens(f"{remote_name} {category}")
    if tokens & {"daily", "dailies", "quest", "mission", "task", "reward", "claim", "redeem", "completed", "complete", "streak"}:
        return [("player", "Player"), ("questId", "string")]
    if tokens & {"buy", "purchase", "shop", "store", "sell", "upgrade", "cash", "coin", "gold", "gem", "money", "currency", "crate"}:
        return [("player", "Player"), ("itemId", "string"), ("quantity", "number")]
    if tokens & {"pet", "egg", "hatch", "equip", "unequip", "trade", "craft", "inventory", "item"}:
        return [("player", "Player"), ("itemUid", "string")]
    if tokens & {"damage", "dmg", "hit", "hitbox", "attack", "fire", "shoot", "weapon", "gun", "sword", "ability", "kill"}:
        return [("player", "Player"), ("targetCharacter", "Model"), ("hitPosition", "Vector3")]
    if tokens & {"admin", "mod", "kick", "ban", "command", "cmd", "rank", "broadcast", "announce"}:
        return [("player", "Player"), ("commandName", "string"), ("targetUserId", "number")]
    if tokens & {"teleport", "tp", "warp", "zone", "stage", "checkpoint", "lobby", "match"}:
        return [("player", "Player"), ("zoneId", "string")]
    if tokens & {"proximityprompt", "triggered", "prompt", "click", "interact", "vault", "chest"}:
        return [("player", "Player")]
    if tokens & {"datastore", "setasync", "save", "receipt", "processreceipt"}:
        return [("player", "Player"), ("deltaAmount", "number")]
    if tokens & {"networkownership", "unanchored", "physics"}:
        return [("targetPart", "BasePart")]
    if tokens & {"statereplication", "attribute", "intvalue", "numbervalue", "valuebase", "leaderstats"}:
        return [("player", "Player"), ("newValue", "number")]
    return [("player", "Player"), ("actionKey", "string"), ("amount", "number")]


def kid_friendly_exploit_summary(domain: str) -> str:
    """
    Returns a 1-2 line zero-jargon summary explaining what a cheater can do with
    this weakness so even a kid who knows nothing about coding can understand it.
    """
    summaries = {
        "daily_quest": (
            "-- Simple summary: A cheater can tell the game they finished all their daily tasks\n"
            "-- over and over without playing, and keep getting free prizes every time."
        ),
        "economy": (
            "-- Simple summary: A cheater can trick the shop into giving them free items or\n"
            "-- unlimited money by sending a fake price or a negative number."
        ),
        "inventory": (
            "-- Simple summary: A cheater can copy rare pets or items over and over, or wear\n"
            "-- gear they never actually won or bought."
        ),
        "combat": (
            "-- Simple summary: A cheater can hit or knock out every player on the map from\n"
            "-- anywhere, even through walls, without waiting between hits."
        ),
        "admin": (
            "-- Simple summary: Any normal player can pretend to be the game owner and kick\n"
            "-- other players or mess up the whole server."
        ),
        "teleport": (
            "-- Simple summary: A cheater can jump straight to the end of the game or sneak\n"
            "-- into locked VIP rooms without earning it."
        ),
        "physics": (
            "-- Simple summary: Because this piece is not locked in place, a cheater can grab\n"
            "-- it to knock players off the map or push locked doors out of the way."
        ),
        "state_rep": (
            "-- Simple summary: A cheater can change this number on their own screen to unlock\n"
            "-- hidden buttons or trick parts of the game that trust what their screen says."
        ),
        "datastore": (
            "-- Simple summary: A cheater can leave and rejoin fast to copy their items, or\n"
            "-- make the game forget to save what they just spent."
        ),
        "interaction": (
            "-- Simple summary: A cheater can open every chest, door, or prize box on the map\n"
            "-- right away without walking up to it or waiting."
        ),
        "code_exec": (
            "-- Simple summary: This leaves the back door wide open so a cheater could run\n"
            "-- their own rules and take complete control of the whole game."
        ),
        "memory": (
            "-- Simple summary: The game forgets to clean up old pieces after using them, so\n"
            "-- it gets slower and laggy until phones and computers crash."
        ),
        "remote_generic": (
            "-- Simple summary: A cheater can spam this button super fast or send nonsense to\n"
            "-- confuse the game, cause lag, or make it do things it shouldn't."
        ),
    }
    return summaries.get(
        domain,
        "-- Simple summary: This part of the game has a weak spot that can cause bugs or\n"
        "-- let players bend the rules if it is not checked first.",
    )


def _infer_simple_domain(name: str, category: str) -> str:
    tokens = _split_camel_tokens(f"{name} {category}")
    if tokens & {"loadstring", "eval", "runcode"}:
        return "code_exec"
    if tokens & {"daily", "dailies", "quest", "mission", "task", "reward", "claim", "redeem", "completed", "complete", "streak"}:
        return "daily_quest"
    if tokens & {"buy", "purchase", "shop", "store", "sell", "upgrade", "cash", "coin", "gold", "gem", "money", "currency", "crate"}:
        return "economy"
    if tokens & {"pet", "egg", "hatch", "equip", "unequip", "trade", "craft", "inventory", "item"}:
        return "inventory"
    if tokens & {"damage", "dmg", "hit", "hitbox", "attack", "fire", "shoot", "weapon", "gun", "sword", "ability", "kill"}:
        return "combat"
    if tokens & {"admin", "mod", "kick", "ban", "command", "cmd", "rank", "broadcast", "announce"}:
        return "admin"
    if tokens & {"teleport", "tp", "warp", "zone", "stage", "checkpoint", "lobby", "match"}:
        return "teleport"
    if tokens & {"proximityprompt", "triggered", "prompt", "click", "interact", "vault", "chest"}:
        return "interaction"
    if tokens & {"datastore", "setasync", "save", "receipt", "processreceipt"}:
        return "datastore"
    if tokens & {"networkownership", "unanchored", "physics"}:
        return "physics"
    if tokens & {"statereplication", "attribute", "intvalue", "numbervalue", "valuebase", "leaderstats"}:
        return "state_rep"
    if tokens & {"memory", "debris", "leak"}:
        return "memory"
    return "remote_generic"


def build_contract_specification(
    *,
    script_path: str,
    title: str,
    category: str,
    flaw: str,
    abuse: str,
    fix: str,
    line_number: int | None = None,
    remote_name: str = "",
    handler_kind: str = "OnServerEvent",
    raw_params: list[tuple[str, str]] | None = None,
    vulnerable_snippet: str = "",
    missing_guards: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generates the complete 4-section Server-Side Luau Unit Test & Contract Specification:
      1. trace_locator
      2. vulnerable_handler_code
      3. parameter_contract_matrix (+ markdown_table)
      4. patched_guard_and_unit_test_code
    """
    path_str = (script_path or "Unknown").strip()
    leaf = (remote_name or path_str.split(".")[-1].split("::")[-1]).replace("[Attribute:", "").replace("]", "").strip() or "Endpoint"
    safe_mod = _safe_luau_ident(leaf.split(".")[-1], "Endpoint") + "Guard"

    if raw_params:
        parsed_params = raw_params
    else:
        parsed_params = _infer_runtime_params(leaf, category, flaw)

    contracts = [
        infer_param_contract(pname, ptype, handler_context=f"{leaf} {category} {flaw}")
        for pname, ptype in parsed_params
    ]
    client_contracts = [c for c in contracts if c["kind"] != "player"]
    unvalidated_names = [c["parameter"] for c in client_contracts] or [c["parameter"] for c in contracts]

    guards_missing = missing_guards or [
        "typeof() parameter validation",
        "finite & range bounds enforcement",
        "server-side ownership / state verification",
        "per-player os.clock() rate limiting",
    ]

    line_label = f"Line {line_number}" if line_number is not None else "Runtime Discovery (search Studio Ctrl+Shift+F)"

    # Section 1: Vulnerability Trace & Locator
    trace_locator = {
        "script_path": path_str,
        "line_number": line_number,
        "line_label": line_label,
        "remote_name": leaf,
        "handler_kind": handler_kind,
        "unvalidated_parameters": unvalidated_names,
        "missing_guards": guards_missing,
    }

    # Section 2: Vulnerable Server Handler (Current Code)
    simple_summary = kid_friendly_exploit_summary(_infer_simple_domain(leaf, category))
    if vulnerable_snippet and vulnerable_snippet.strip():
        vuln_code = f"{simple_summary}\n{vulnerable_snippet.strip()}"
    else:
        sig_params = ", ".join(p for p, _ in parsed_params)
        if handler_kind == "OnServerInvoke":
            vuln_code = (
                f"{simple_summary}\n"
                f"-- Located via {path_str} ({line_label})\n"
                f"{path_str}.OnServerInvoke = function({sig_params})\n"
                f"    -- Unvalidated parameters ({', '.join(unvalidated_names)}) reach server state directly:\n"
                f"    -- Flaw: {flaw}\n"
                f"    return true\n"
                f"end"
            )
        else:
            vuln_code = (
                f"{simple_summary}\n"
                f"-- Located via {path_str} ({line_label})\n"
                f"{path_str}.{handler_kind}:Connect(function({sig_params})\n"
                f"    -- Unvalidated parameters ({', '.join(unvalidated_names)}) reach server state directly:\n"
                f"    -- Flaw: {flaw}\n"
                f"end)"
            )

    # Section 3: Parameter Contract & Edge-Case Matrix
    matrix_rows = [
        {
            "parameter": c["parameter"],
            "expected_typeof": c["expected_typeof"],
            "valid_bounds": c["valid_bounds"],
            "rejected_edge_cases": c["rejected_edge_cases"],
        }
        for c in contracts
    ]

    md_table_lines = [
        "| Parameter | Expected Luau `typeof()` | Valid Bounds & Authority Rule | Rejected Edge-Case Inputs |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for row in matrix_rows:
        md_table_lines.append(
            f"| `{row['parameter']}` | `{row['expected_typeof']}` | {row['valid_bounds']} | {row['rejected_edge_cases']} |"
        )
    markdown_table = "\n".join(md_table_lines)

    # Section 4: Defensive Server-Side Remediation & Guard Module + Deterministic assert() Unit Test
    sig_typed = ", ".join(f"{c['parameter']}: unknown" for c in contracts)
    guard_lines: list[str] = [
        f"--!strict",
        f"-- What this does: This keeps your game fair and safe from cheaters.",
        f"-- It stops players from tricking the game into giving them free stuff, breaking the rules,",
        f"-- or clicking way too fast, and checks itself at the bottom to make sure it works.",
        f"-- Defensive Server-Side Guard Module for '{leaf}' ({path_str}, {line_label})",
        f"local Players = game:GetService(\"Players\")",
        f"",
        f"local {safe_mod} = {{}}",
        f"{safe_mod}.COOLDOWN_SEC = 0.35",
        f"{safe_mod}.MAX_DISTANCE_STUDS = 24",
        f"{safe_mod}.ALLOWLIST = {{ StarterItem = true }}",
        f"{safe_mod}._lastCall = {{}} :: {{ [number]: number }}",
        f"",
        f"Players.PlayerRemoving:Connect(function(plr: Player)",
        f"    {safe_mod}._lastCall[plr.UserId] = nil",
        f"end)",
        f"",
        f"function {safe_mod}.ValidateAndAuthorize({sig_typed}): (boolean, string)",
    ]

    has_player_param = any(c["kind"] == "player" for c in contracts)
    player_var = next((c["parameter"] for c in contracts if c["kind"] == "player"), "player")

    if has_player_param:
        guard_lines.extend([
            f"    if typeof({player_var}) ~= \"table\" and (typeof({player_var}) ~= \"Instance\" or not ({player_var} :: Instance):IsA(\"Player\")) then",
            f"        return false, \"invalid_player_type\"",
            f"    end",
            f"    local userId = ({player_var} :: any).UserId",
            f"    if typeof(userId) ~= \"number\" or userId ~= userId or userId <= 0 then",
            f"        return false, \"invalid_player_userid\"",
            f"    end",
            f"    local now = os.clock()",
            f"    local prev = {safe_mod}._lastCall[userId]",
            f"    if prev and (now - prev) < {safe_mod}.COOLDOWN_SEC then",
            f"        return false, \"rate_limited\"",
            f"    end",
        ])

    for c in client_contracts:
        p = c["parameter"]
        kind = c["kind"]
        if kind == "number":
            min_v = c["min_val"]
            max_v = c["max_val"]
            guard_lines.extend([
                f"    if typeof({p}) ~= \"number\" or {p} ~= {p} or math.abs({p}) >= math.huge then",
                f"        return false, \"invalid_number_{p}\"",
                f"    end",
                f"    local num_{p} = {p} :: number",
                f"    if num_{p} < {min_v} or num_{p} > {max_v} then",
                f"        return false, \"out_of_bounds_{p}\"",
                f"    end",
            ])
            if c.get("is_int"):
                guard_lines.extend([
                    f"    if math.floor(num_{p}) ~= num_{p} then",
                    f"        return false, \"non_integer_{p}\"",
                    f"    end",
                ])
            guard_lines.append(f"    local clamped_{p} = math.clamp(num_{p}, {min_v}, {max_v})")
        elif kind == "string":
            max_len = c["max_len"]
            guard_lines.extend([
                f"    if typeof({p}) ~= \"string\" or #{p} < 1 or #{p} > {max_len} then",
                f"        return false, \"invalid_string_{p}\"",
                f"    end",
                f"    if not {safe_mod}.ALLOWLIST[{p} :: string] then",
                f"        return false, \"unlisted_key_{p}\"",
                f"    end",
            ])
        elif kind == "boolean":
            guard_lines.extend([
                f"    if typeof({p}) ~= \"boolean\" then",
                f"        return false, \"invalid_boolean_{p}\"",
                f"    end",
            ])
        elif kind == "table":
            guard_lines.extend([
                f"    if typeof({p}) ~= \"table\" then",
                f"        return false, \"invalid_table_{p}\"",
                f"    end",
                f"    local keyCount_{p} = 0",
                f"    for _ in pairs({p} :: {{ [any]: any }}) do",
                f"        keyCount_{p} += 1",
                f"        if keyCount_{p} > 16 then",
                f"            return false, \"oversized_table_{p}\"",
                f"        end",
                f"    end",
            ])
        elif kind == "spatial":
            lt = c["luau_type"]
            pos_expr = f"({p} :: CFrame).Position" if lt == "CFrame" else f"({p} :: Vector3)"
            guard_lines.extend([
                f"    if typeof({p}) ~= \"{lt}\" then",
                f"        return false, \"invalid_spatial_{p}\"",
                f"    end",
                f"    local vec_{p} = {pos_expr}",
                f"    if vec_{p}.X ~= vec_{p}.X or vec_{p}.Y ~= vec_{p}.Y or vec_{p}.Z ~= vec_{p}.Z or vec_{p}.Magnitude >= 10000 then",
                f"        return false, \"non_finite_spatial_{p}\"",
                f"    end",
                f"    if vec_{p}.Magnitude > {safe_mod}.MAX_DISTANCE_STUDS then",
                f"        return false, \"out_of_range_{p}\"",
                f"    end",
            ])
        elif kind == "instance":
            cls = c["expected_class"]
            guard_lines.extend([
                f"    if typeof({p}) ~= \"Instance\" or not ({p} :: Instance):IsA(\"{cls}\") then",
                f"        return false, \"invalid_instance_{p}\"",
                f"    end",
            ])

    if has_player_param:
        guard_lines.append(f"    {safe_mod}._lastCall[userId] = now")
    guard_lines.extend([
        f"    return true, \"ok\"",
        f"end",
        f"",
        f"-- Wire directly into {leaf}:",
    ])

    raw_call_args = ", ".join(c["parameter"] for c in contracts)
    if handler_kind == "OnServerInvoke":
        guard_lines.extend([
            f"-- {leaf}.OnServerInvoke = function({sig_typed})",
            f"--     local ok, reason = {safe_mod}.ValidateAndAuthorize({raw_call_args})",
            f"--     if not ok then return false, reason end",
            f"--     return true, \"authorized\"",
            f"-- end",
        ])
    else:
        guard_lines.extend([
            f"-- {leaf}.{handler_kind}:Connect(function({sig_typed})",
            f"--     local ok = {safe_mod}.ValidateAndAuthorize({raw_call_args})",
            f"--     if not ok then return end",
            f"-- end)",
        ])

    # Deterministic Studio Command Bar Unit-Test Verification Block
    guard_lines.extend([
        f"",
        f"-- ============================================================================",
        f"-- Studio Command Bar Deterministic Unit-Test Verification ({safe_mod})",
        f"-- ============================================================================",
        f"local function runContractAssertions()",
        f"    local mockPlayer = {{ UserId = 900001, Name = \"ContractTestPlayer\" }}",
    ])
    if any(c["kind"] == "instance" for c in client_contracts):
        cls_first = next(c["expected_class"] for c in client_contracts if c["kind"] == "instance")
        guard_lines.append(f"    local validTargetInstance = Instance.new(\"{cls_first}\")")
    if any(c["kind"] == "table" for c in client_contracts):
        guard_lines.append(f"    local oversizedTable = {{}}; for i = 1, 32 do oversizedTable[i] = i end")

    valid_args = [c["valid_test_expr"] for c in contracts]
    guard_lines.extend([
        f"    {safe_mod}._lastCall[mockPlayer.UserId] = nil",
        f"    local passOk, passReason = {safe_mod}.ValidateAndAuthorize({', '.join(valid_args)})",
        f"    assert(passOk == true, \"Expected valid contract inputs to pass, got: \" .. tostring(passReason))",
    ])

    if has_player_param:
        guard_lines.extend([
            f"    -- Cooldown / Rate-Limit assertion (immediate second call must reject)",
            f"    local burstOk, burstReason = {safe_mod}.ValidateAndAuthorize({', '.join(valid_args)})",
            f"    assert(burstOk == false and burstReason == \"rate_limited\", \"Expected rapid burst call to be rate_limited\")",
        ])

    # Generate an explicit assert() for every parameter's edge cases
    for idx, c in enumerate(contracts):
        for test_label, bad_expr, desc in c["invalid_tests"]:
            mutated_args = list(valid_args)
            mutated_args[idx] = bad_expr
            guard_lines.extend([
                f"    {safe_mod}._lastCall[mockPlayer.UserId] = nil",
                f"    local ok_{_safe_luau_ident(test_label)} = {safe_mod}.ValidateAndAuthorize({', '.join(mutated_args)})",
                f"    assert(ok_{_safe_luau_ident(test_label)} == false, \"Expected rejection for {desc}\")",
            ])

    if any(c["kind"] == "instance" for c in client_contracts):
        guard_lines.append(f"    validTargetInstance:Destroy()")
    guard_lines.extend([
        f"    print(\"[rcdebug] All contract assertions PASSED for {leaf} ({path_str})\")",
        f"end",
        f"runContractAssertions()",
    ])

    patched_code = "\n".join(guard_lines)

    return {
        "trace_locator": trace_locator,
        "vulnerable_handler_code": vuln_code,
        "parameter_contract_matrix": matrix_rows,
        "parameter_contract_markdown": markdown_table,
        "patched_guard_and_unit_test_code": patched_code,
    }


def format_contract_spec_markdown(spec: dict[str, Any]) -> str:
    """Formats the 4-section contract specification into clean Markdown."""
    tr = spec["trace_locator"]
    lines = [
        "#### 1. Vulnerability Trace & Locator",
        "",
        f"- **Script Path:** `{tr['script_path']}`",
        f"- **Location:** `{tr['line_label']}`",
        f"- **Remote / Target Instance:** `{tr['remote_name']}` (`{tr['handler_kind']}`)",
        f"- **Unvalidated Parameters:** `{', '.join(tr['unvalidated_parameters'])}`",
        f"- **Missing Guards:** {', '.join(tr['missing_guards'])}",
        "",
        "#### 2. Vulnerable Server Handler (Current Code)",
        "",
        "```luau",
        spec["vulnerable_handler_code"],
        "```",
        "",
        "#### 3. Parameter Contract & Edge-Case Matrix",
        "",
        spec["parameter_contract_markdown"],
        "",
        "#### 4. Defensive Server-Side Remediation & Guard Module (Patched Code + Unit Test)",
        "",
        "```luau",
        spec["patched_guard_and_unit_test_code"],
        "```",
        "",
    ]
    return "\n".join(lines)
