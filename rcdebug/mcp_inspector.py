"""
Roblox Studio MCP Inspector (rcdebug --server):
- Automatically discovers Roblox Studio MCP configuration on macOS
- Prompts & persists to ~/.rcdebug/config.json if none is found
- Connects to Studio MCP over JSON-RPC (stdio or HTTP) to perform static scene & script audits
- Also supports offline static auditing of .rbxlx/.rbxmx place files and .luau/.lua script directories
"""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from .debugger_pack import get_debugger_pack
from .exporter import export_markdown_report
from .flaw_catalog import get_catalog
from .models import AuditSession, Finding
from .terminal import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    MAGENTA,
    RED,
    RESET,
    WHITE,
    YELLOW,
    normalize_filter_label,
    print_banner,
    print_finding,
    print_session_summary,
)

CONFIG_DIR = Path.home() / ".rcdebug"
CONFIG_FILE = CONFIG_DIR / "config.json"


def candidate_mcp_config_paths() -> list[Path]:
    home = Path.home()
    return [
        CONFIG_FILE,
        home / ".gemini" / "config" / "mcp_config.json",
        home / ".gemini" / "antigravity" / "mcp_config.json",
        home / ".cursor" / "mcp.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "mcp.json",
        home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "mcp.json",
    ]


def find_studio_mcp(custom_paths: list[Path] | None = None) -> dict[str, Any] | None:
    """
    Searches common macOS configuration paths for an active Roblox Studio MCP server configuration.
    """
    paths = custom_paths if custom_paths is not None else candidate_mcp_config_paths()

    for path in paths:
        if not path.exists():
            continue
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(content, dict):
                continue

            if "roblox_studio_mcp" in content and isinstance(content["roblox_studio_mcp"], dict):
                return {
                    "source": str(path),
                    "name": content["roblox_studio_mcp"].get("name", "roblox_studio_mcp"),
                    "config": content["roblox_studio_mcp"],
                }

            servers = content.get("mcpServers", {})
            if isinstance(servers, dict):
                for name, cfg in servers.items():
                    if not isinstance(cfg, dict):
                        continue
                    cmd_str = str(cfg.get("command", ""))
                    if (
                        "roblox" in name.lower()
                        or "studio" in name.lower()
                        or "studiomcp" in cmd_str.lower()
                    ):
                        return {
                            "source": str(path),
                            "name": name,
                            "config": cfg,
                        }
        except Exception:
            continue

    return None


def prompt_and_save_mcp_config(config_file: Path = CONFIG_FILE) -> dict[str, Any]:
    """
    Interactively prompts the user for the MCP endpoint URL or stdio command
    and saves it to ~/.rcdebug/config.json for future runs.
    """
    print(f"{YELLOW}✖ No Roblox Studio MCP configuration found in standard macOS paths.{RESET}")
    default_bin = "/Applications/RobloxStudio.app/Contents/MacOS/StudioMCP"
    hint = f" (e.g. {default_bin} or http://127.0.0.1:3000/mcp)"
    try:
        mcp_target = input(
            f"{BOLD}Enter your Roblox Studio MCP URL or stdio command path{hint}:{RESET} "
        ).strip()
    except EOFError:
        mcp_target = ""

    if not mcp_target:
        print(f"{RED}No MCP input provided. Exiting.{RESET}")
        sys.exit(1)

    config_file.parent.mkdir(parents=True, exist_ok=True)
    if mcp_target.startswith("http://") or mcp_target.startswith("https://"):
        cfg_obj: dict[str, Any] = {"url": mcp_target, "endpoint_or_command": mcp_target}
    else:
        parts = mcp_target.split()
        cfg_obj = {
            "command": parts[0],
            "args": parts[1:],
            "endpoint_or_command": mcp_target,
        }

    saved_data = {"roblox_studio_mcp": cfg_obj}
    config_file.write_text(json.dumps(saved_data, indent=2), encoding="utf-8")
    print(f"{GREEN}✔ Saved MCP configuration to {config_file}{RESET}")
    return {"source": str(config_file), "name": "roblox_studio_mcp", "config": cfg_obj}


class StdioMCPClient:
    """
    Lightweight JSON-RPC 2.0 client over stdio for communicating with StudioMCP.
    """

    def __init__(self, command: str, args: list[str] | None = None, env: dict[str, str] | None = None) -> None:
        self.command = command
        self.args = args or []
        self.env = {**os.environ, **(env or {})}
        self.proc: subprocess.Popen[bytes] | None = None
        self._msg_id = 0

    def __enter__(self) -> StdioMCPClient:
        self.proc = subprocess.Popen(
            [self.command, *self.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
        )
        self.initialize()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def send_request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 4.0) -> dict[str, Any]:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("MCP process not running")

        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }
        line = (json.dumps(payload) + "\n").encode("utf-8")
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.05, deadline - time.time())
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                continue
            raw_line = self.proc.stdout.readline()
            if not raw_line:
                break
            text = raw_line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and msg.get("id") == req_id:
                return msg
        raise TimeoutError(f"Timed out waiting for MCP response to {method}")

    def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        if not self.proc or not self.proc.stdin:
            return
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        self.proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def initialize(self) -> dict[str, Any]:
        resp = self.send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "rcdebug", "version": "1.0.0"},
            },
            timeout=3.5,
        )
        self.send_notification("notifications/initialized", {})
        return resp

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None, timeout: float = 6.0) -> Any:
        resp = self.send_request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            timeout=timeout,
        )
        if "error" in resp:
            raise RuntimeError(str(resp["error"]))
        result = resp.get("result", {})
        content = result.get("content", [])
        if isinstance(content, list) and content:
            texts = [c.get("text", "") for c in content if isinstance(c, dict) and "text" in c]
            joined = "\n".join(texts).strip()
            try:
                return json.loads(joined)
            except Exception:
                return joined
        return result


STATIC_AUDIT_LUAU = r"""
local findings = {}
local HttpService = game:GetService("HttpService")
local ServerScriptService = game:GetService("ServerScriptService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Workspace = game:GetService("Workspace")
local StarterPlayer = game:GetService("StarterPlayer")
local StarterGui = game:GetService("StarterGui")

local function add(sev, cat, title, path, flaw, abuse, fix, code)
    table.insert(findings, {
        severity = sev,
        category = cat,
        title = title,
        path = path,
        flaw = flaw,
        abuse = abuse,
        fix = fix,
        code_example = code or ""
    })
end

pcall(function()
    if ServerScriptService.LoadStringEnabled then
        add(
            "CRITICAL",
            "StaticSceneAudit",
            "ServerScriptService.LoadStringEnabled is Enabled",
            "ServerScriptService.LoadStringEnabled",
            "ServerScriptService allows runtime compilation of arbitrary Luau strings via loadstring().",
            "Any script injection flaw or infected free-model script can execute arbitrary server code.",
            "Set ServerScriptService.LoadStringEnabled = false in Studio Properties.",
            "ServerScriptService.LoadStringEnabled = false"
        )
    end
end)

pcall(function()
    if HttpService.HttpEnabled then
        add(
            "INFO",
            "HttpSecurity",
            "HttpService.HttpEnabled is Active",
            "HttpService.HttpEnabled",
            "Outbound HTTP requests are enabled for this place.",
            "If scripts pass unsanitized player data to external webhooks or third-party scripts exfiltrate place assets, external network calls will succeed.",
            "Keep HttpEnabled = false unless external APIs are required, and route all webhook calls through a rate-limited server proxy."
        )
    end
end)

local unanchored = 0
for _, desc in ipairs(Workspace:GetDescendants()) do
    if desc:IsA("BasePart") and not desc.Anchored and not desc:IsDescendantOf(Workspace.CurrentCamera) then
        unanchored += 1
        if unanchored <= 3 then
            add(
                "WARN",
                "PhysicsAudit",
                "Unanchored Workspace Part: " .. desc.Name,
                desc:GetFullName(),
                "BasePart in Workspace is unanchored at edit time.",
                "Unanchored parts default to automatic client network ownership, allowing nearby exploiters to teleport or fling them.",
                "Set Anchored = true on static geometry or call part:SetNetworkOwner(nil) in a server script."
            )
        end
    elseif desc:IsA("RemoteEvent") or desc:IsA("RemoteFunction") then
        add(
            "WARN",
            "RemoteArchitecture",
            "Remote Endpoint Inside Workspace: " .. desc.Name,
            desc:GetFullName(),
            desc.ClassName .. " is parented under Workspace instead of ReplicatedStorage.",
            "Scattering remotes inside Workspace models complicates access auditing and often pairs with unvalidated tool/vehicle scripts.",
            "Centralize network endpoints inside ReplicatedStorage.Remotes with unified server middleware validation."
        )
    end
end

for _, desc in ipairs(ReplicatedStorage:GetDescendants()) do
    if desc:IsA("RemoteEvent") or desc:IsA("RemoteFunction") then
        add(
            "INFO",
            "RemoteInventory",
            "ReplicatedStorage Remote Endpoint: " .. desc.Name,
            desc:GetFullName(),
            "Client-callable " .. desc.ClassName .. " discovered during static place inspection.",
            "Any client can invoke this endpoint with crafted arguments at any time.",
            "Verify that the corresponding OnServerEvent/OnServerInvoke handler enforces typeof() checks and rate limiting."
        )
    end
end

return HttpService:JSONEncode(findings)
"""


def audit_luau_script_source(script_path: str, source: str) -> list[Finding]:
    """
    Static analyzer for a Luau script's source code:
    - Evaluates all precompiled rules in FlawCatalog (loadstring, webhooks, HttpService,
      DataStore races, Marketplace ProcessReceipt, ProximityPrompt, Touched, Teleport, etc.)
    - Audits OnServerEvent / OnServerInvoke handlers for typeof() validation & cooldowns
    """
    catalog = get_catalog()
    pack = get_debugger_pack()
    findings: list[Finding] = catalog.match_source(script_path, source)
    findings.extend(pack.scan_source(script_path, source))

    # Check OnServerEvent / OnServerInvoke handlers for missing typeof/type checks & cooldowns
    remote_handler_pattern = re.compile(
        r"([\w\.\:\[\]\"']+)\.(OnServerEvent\s*:\s*Connect|OnServerInvoke\s*=)\s*\(?\s*function\s*\(([^)]*)\)(.*?)(?=\bend\s*\))",
        re.DOTALL,
    )
    for match in remote_handler_pattern.finditer(source):
        remote_expr = match.group(1).strip()
        params_raw = match.group(3).strip()
        body = match.group(4)

        params = [p.strip().split(":")[0].strip() for p in params_raw.split(",") if p.strip()]
        # First parameter is always the firing Player
        client_params = params[1:] if len(params) > 1 else []

        has_type_check = bool(re.search(r"\b(typeof|type|tonumber)\s*\(", body))
        has_cooldown = bool(re.search(r"\b(os\.clock|tick|time|debounce|cooldown|lastFired|rateLimit)\b", body, re.IGNORECASE))

        if client_params and not has_type_check:
            f = Finding(
                severity="CRITICAL",
                category="RemoteValidation",
                title=f"Missing Parameter Type Validation on {remote_expr}",
                path=script_path,
                flaw=(
                    f"Server remote handler accepts client arguments ({', '.join(client_params)}) "
                    f"without validating parameter types via typeof() or type()."
                ),
                abuse=(
                    "A malicious client can pass nil, tables, Instances, negative numbers, or NaN for "
                    f"({', '.join(client_params)}), causing server script errors or bypassing price/quantity logic."
                ),
                fix=f"Validate typeof() for every client parameter ({', '.join(client_params)}) at the first line of the handler.",
                code_example=(
                    f"{remote_expr}.OnServerEvent:Connect(function({params_raw})\n"
                    + "\n".join(
                        f'    if typeof({p}) ~= "number" or {p} ~= {p} then return end'
                        for p in client_params[:2]
                    )
                    + "\n    -- Proceed with verified server state\nend)"
                ),
            )
            findings.append(catalog.enrich_finding(f))
        elif not has_cooldown:
            f = Finding(
                severity="WARN",
                category="RemoteValidation",
                title=f"Missing Server-Side Cooldown/Debounce on {remote_expr}",
                path=script_path,
                flaw=f"Remote handler for '{remote_expr}' has no visible per-player rate limit or cooldown check.",
                abuse="Clients can fire this remote dozens of times per frame to trigger race conditions or lag the server.",
                fix="Track last invocation time per Player using os.clock() and drop requests that arrive faster than the cooldown threshold.",
            )
            findings.append(catalog.enrich_finding(f))

    findings.sort(key=lambda f: f.sort_key())
    return findings


def _scan_single_luau_file(file_path: Path) -> list[Finding]:
    try:
        src = file_path.read_text(encoding="utf-8", errors="replace")
        return audit_luau_script_source(str(file_path), src)
    except Exception:
        return []


def audit_local_path(target_path: Path, session: AuditSession, filter_level: str | None = None) -> None:
    """
    Audits a local .luau/.lua file, directory of scripts, or .rbxlx/.rbxmx XML place file
    using parallel worker threads for multi-file directories.
    """
    if target_path.is_file():
        files = [target_path]
    else:
        files = sorted(
            [
                p
                for p in target_path.rglob("*")
                if p.is_file() and p.suffix.lower() in (".luau", ".lua", ".rbxlx", ".rbxmx")
            ]
        )

    luau_files = [f for f in files if f.suffix.lower() in (".luau", ".lua")]
    xml_files = [f for f in files if f.suffix.lower() in (".rbxlx", ".rbxmx")]

    if len(luau_files) > 1:
        with ThreadPoolExecutor(max_workers=min(8, len(luau_files))) as pool:
            for file_findings in pool.map(_scan_single_luau_file, luau_files):
                for finding in file_findings:
                    if session.add_finding(finding):
                        print_finding(finding, filter_level=filter_level)
    else:
        for fpath in luau_files:
            for finding in _scan_single_luau_file(fpath):
                if session.add_finding(finding):
                    print_finding(finding, filter_level=filter_level)

    for file_path in xml_files:
        _audit_rbxlx_file(file_path, session, filter_level=filter_level)


def _audit_rbxlx_file(xml_path: Path, session: AuditSession, filter_level: str | None = None) -> None:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return

    for item in root.iter("Item"):
        cls = item.attrib.get("class", "")
        props = item.find("Properties")
        name = cls
        if props is not None:
            for s in props.findall("string"):
                if s.attrib.get("name") == "Name" and s.text:
                    name = s.text
                    break

        if cls == "ServerScriptService" and props is not None:
            for b in props.findall("bool"):
                if b.attrib.get("name") == "LoadStringEnabled" and (b.text or "").lower() == "true":
                    f = Finding(
                        severity="CRITICAL",
                        category="StaticPlaceAudit",
                        title="ServerScriptService.LoadStringEnabled is TRUE in Place File",
                        path=f"{xml_path.name}::ServerScriptService",
                        flaw="Place file enables server-side loadstring() execution.",
                        abuse="Allows arbitrary server code execution if any script evaluates dynamic strings.",
                        fix="Set LoadStringEnabled to false in ServerScriptService.",
                    )
                    if session.add_finding(f):
                        print_finding(f, filter_level=filter_level)

        if cls in ("Part", "MeshPart", "UnionOperation") and props is not None:
            for b in props.findall("bool"):
                if b.attrib.get("name") == "Anchored" and (b.text or "").lower() == "false":
                    f = Finding(
                        severity="WARN",
                        category="PhysicsAudit",
                        title=f"Unanchored {cls} in Place File: {name}",
                        path=f"{xml_path.name}::{name}",
                        flaw=f"{cls} '{name}' has Anchored = false.",
                        abuse="Clients near unanchored parts automatically acquire network ownership and can manipulate part CFrame/velocity.",
                        fix="Anchor static parts or lock network ownership to the server via part:SetNetworkOwner(nil).",
                    )
                    if session.add_finding(f):
                        print_finding(f, filter_level=filter_level)

        if cls in ("Script", "LocalScript", "ModuleScript") and props is not None:
            for pstr in list(props.findall("ProtectedString")) + list(props.findall("string")):
                if pstr.attrib.get("name") == "Source" and pstr.text:
                    for finding in audit_luau_script_source(f"{xml_path.name}::{name}", pstr.text):
                        if session.add_finding(finding):
                            print_finding(finding, filter_level=filter_level)


def run_live_mcp_audit(
    mcp_cfg: dict[str, Any],
    session: AuditSession,
    filter_level: str | None = None,
) -> bool:
    """
    Attempts to connect to the configured Roblox Studio MCP server via stdio or HTTP
    and perform a live static scene & script audit.
    Returns True if a live Studio instance was audited.
    """
    command = mcp_cfg.get("command")
    args = mcp_cfg.get("args", [])
    env = mcp_cfg.get("env", {})
    url = mcp_cfg.get("url") or mcp_cfg.get("endpoint_or_command", "")

    if command and Path(command).exists():
        print(f"{CYAN}→ Launching MCP stdio handshake with:{RESET} {BOLD}{command}{RESET}")
        try:
            with StdioMCPClient(command, args=args, env=env) as client:
                studios_res = client.call_tool("list_roblox_studios", {})
                studios = (
                    studios_res.get("studios", studios_res)
                    if isinstance(studios_res, dict)
                    else studios_res
                )
                if not isinstance(studios, list) or not studios:
                    print(
                        f"{YELLOW}⚠ StudioMCP binary responded, but 0 active Roblox Studio instances are currently open.{RESET}"
                    )
                    return False

                studio = studios[0]
                studio_id = studio.get("id") or studio.get("studio_id")
                studio_name = studio.get("name", studio_id)
                session.target_name = f"Roblox Studio MCP ({studio_name})"
                print(f"{GREEN}✔ Connected to Studio Instance:{RESET} {BOLD}{studio_name}{RESET} ({studio_id})")

                state = client.call_tool("get_studio_state", {"studio_id": studio_id})
                dm_type = "Edit"
                if isinstance(state, dict):
                    avail = state.get("available_datamodel_types") or state.get("datamodel_types") or []
                    if "Server" in avail:
                        dm_type = "Server"
                    elif "Edit" in avail:
                        dm_type = "Edit"

                # 1. Execute static scene audit Luau snippet
                luau_res = client.call_tool(
                    "execute_luau",
                    {"studio_id": studio_id, "datamodel_type": dm_type, "code": STATIC_AUDIT_LUAU},
                )
                parsed_findings = []
                if isinstance(luau_res, str):
                    try:
                        parsed_findings = json.loads(luau_res)
                    except Exception:
                        pass
                elif isinstance(luau_res, dict) and "result" in luau_res:
                    try:
                        parsed_findings = json.loads(str(luau_res["result"]))
                    except Exception:
                        pass
                elif isinstance(luau_res, list):
                    parsed_findings = luau_res

                for item in parsed_findings:
                    if isinstance(item, dict):
                        f = Finding(
                            severity=str(item.get("severity", "INFO")),
                            category=str(item.get("category", "MCPStaticAudit")),
                            title=str(item.get("title", "MCP Finding")),
                            path=str(item.get("path", "Studio")),
                            flaw=str(item.get("flaw", "")),
                            abuse=str(item.get("abuse", "")),
                            fix=str(item.get("fix", "")),
                            code_example=str(item.get("code_example", "")),
                        )
                        if session.add_finding(f):
                            print_finding(f, filter_level=filter_level)

                # 2. Grep scripts for dangerous patterns via MCP script_grep
                for pattern, sev, title, flaw, abuse, fix in [
                    (
                        "loadstring",
                        "CRITICAL",
                        "Script Uses loadstring()",
                        "Server or shared script references loadstring().",
                        "Enables arbitrary code execution if untrusted input reaches loadstring().",
                        "Remove loadstring() and use static module functions.",
                    ),
                    (
                        "HttpService",
                        "WARN",
                        "Script Uses HttpService",
                        "Script references HttpService for external network calls.",
                        "Unthrottled outbound HTTP calls can hit the 500 req/min limit or leak secrets.",
                        "Ensure HttpService calls use HttpService:GetSecret() and strict server throttling.",
                    ),
                ]:
                    try:
                        grep_res = client.call_tool(
                            "script_grep", {"studio_id": studio_id, "query": pattern}
                        )
                        matches = grep_res if isinstance(grep_res, list) else (
                            grep_res.get("matches", []) if isinstance(grep_res, dict) else []
                        )
                        for m in matches[:10]:
                            spath = m.get("path", m.get("script", "Script")) if isinstance(m, dict) else str(m)
                            f = Finding(
                                severity=sev,
                                category="MCPScriptGrep",
                                title=f"{title}: {spath}",
                                path=spath,
                                flaw=flaw,
                                abuse=abuse,
                                fix=fix,
                            )
                            if session.add_finding(f):
                                print_finding(f, filter_level=filter_level)
                    except Exception:
                        pass

                return True
        except Exception as exc:
            print(f"{YELLOW}⚠ MCP stdio session note: {exc}{RESET}")
            return False

    if isinstance(url, str) and (url.startswith("http://") or url.startswith("https://")):
        print(f"{CYAN}→ Probing HTTP MCP endpoint:{RESET} {BOLD}{url}{RESET}")
        try:
            req = Request(
                url,
                data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=3.0) as resp:
                resp.read()
            print(f"{GREEN}✔ HTTP MCP endpoint reachable.{RESET}")
            return True
        except Exception as exc:
            print(f"{YELLOW}⚠ HTTP MCP endpoint unreachable ({exc}).{RESET}")
            return False

    return False


def inject_simulated_mcp_findings(session: AuditSession, filter_level: str | None = None) -> None:
    """
    Populates realistic static MCP scene/script audit findings when --simulate is used.
    """
    sample_sources = {
        "ServerScriptService.EconomyHandler": (
            'local ReplicatedStorage = game:GetService("ReplicatedStorage")\n'
            'local HttpService = game:GetService("HttpService")\n'
            'local WEBHOOK = "https://discord.com/api/webhooks/123456789/abcdef"\n\n'
            "ReplicatedStorage.Remotes.PurchaseItem.OnServerEvent:Connect(function(player, itemName, price)\n"
            "    player.leaderstats.Cash.Value -= price\n"
            "    HttpService:PostAsync(WEBHOOK, HttpService:JSONEncode({user = player.Name, item = itemName}))\n"
            "end)\n"
        ),
        "ServerScriptService.LegacyAdminLoader": (
            'local Remote = game:GetService("ReplicatedStorage").AdminCommand\n'
            "Remote.OnServerEvent:Connect(function(player, codeString)\n"
            '    if typeof(codeString) == "string" then\n'
            "        loadstring(codeString)()\n"
            "    end\n"
            "end)\n"
        ),
    }

    static_scene_findings = [
        Finding(
            severity="CRITICAL",
            category="StaticSceneAudit",
            title="ServerScriptService.LoadStringEnabled is Enabled",
            path="ServerScriptService.LoadStringEnabled",
            flaw="ServerScriptService.LoadStringEnabled is set to true in the place configuration.",
            abuse="Combined with any remote handler or free-model backdoor calling loadstring(), attackers gain full server RCE.",
            fix="Disable ServerScriptService.LoadStringEnabled in Studio Properties.",
            code_example="ServerScriptService.LoadStringEnabled = false",
        ),
        Finding(
            severity="WARN",
            category="PhysicsAudit",
            title="Unanchored Workspace Parts Detected (48 parts in Workspace.MapProps)",
            path="Workspace.MapProps",
            flaw="48 decorative BaseParts in Workspace.MapProps have Anchored = false.",
            abuse="Clients walking near unanchored props automatically take network ownership and can fling or teleport them across the map.",
            fix="Set Anchored = true on all static map props, or lock physics ownership to the server via part:SetNetworkOwner(nil).",
            code_example=(
                "for _, desc in ipairs(workspace.MapProps:GetDescendants()) do\n"
                '    if desc:IsA("BasePart") then desc.Anchored = true end\n'
                "end"
            ),
        ),
    ]

    for f in static_scene_findings:
        if session.add_finding(f):
            print_finding(f, filter_level=filter_level)

    for script_path, code in sample_sources.items():
        for f in audit_luau_script_source(script_path, code):
            if session.add_finding(f):
                print_finding(f, filter_level=filter_level)


def run_server_mode(
    filter_level: str | None = None,
    export_path: str | None = None,
    place_path: str | None = None,
    simulate: bool = False,
) -> AuditSession:
    catalog = get_catalog()
    print_banner(
        "SERVER / ROBLOX STUDIO MCP INSPECTOR",
        subtitle=f"Static Scene & Script Auditor | {catalog.count():,} Flaw Signatures | Filter: {normalize_filter_label(filter_level)}",
    )
    print(f"\n{BOLD}Scanning macOS configuration files for Roblox Studio MCP...{RESET}")

    mcp_info = find_studio_mcp()
    if mcp_info:
        print(f"{GREEN}{BOLD}✔ Found Roblox Studio MCP config in:{RESET} {CYAN}{mcp_info['source']}{RESET}")
        print(f"  {BOLD}Server Key:{RESET} {WHITE}{mcp_info.get('name', 'Roblox_Studio')}{RESET}")
        print(f"{DIM}{json.dumps(mcp_info['config'], indent=2)}{RESET}")
    else:
        mcp_info = prompt_and_save_mcp_config()

    session = AuditSession(
        mode="server",
        target_name=f"Roblox Studio MCP ({mcp_info.get('name', 'Roblox_Studio')})",
    )

    print(f"\n{BOLD}{CYAN}─── Running Static Scene & Script Security Audit ───{RESET}")

    if place_path:
        target = Path(place_path).expanduser().resolve()
        if target.exists():
            session.target_name = f"Static Audit ({target.name})"
            print(f"{CYAN}→ Auditing local place/script path:{RESET} {BOLD}{target}{RESET}")
            audit_local_path(target, session, filter_level=filter_level)
        else:
            print(f"{RED}✖ Specified --place path does not exist: {target}{RESET}")

    if simulate:
        print(f"{MAGENTA}{BOLD}[SIMULATION MODE]{RESET} Running static MCP scene & script analyzer on sample place...")
        inject_simulated_mcp_findings(session, filter_level=filter_level)
    elif not place_path:
        audited_live = run_live_mcp_audit(mcp_info["config"], session, filter_level=filter_level)
        if not audited_live:
            print(
                f"\n{YELLOW}Tip:{RESET} Open a place in Roblox Studio with the Studio MCP plugin active, "
                f"or pass {BOLD}--place <dir_or_rbxlx>{RESET} / {BOLD}--simulate{RESET} to run static script & place checks offline."
            )

    print_session_summary(session, filter_level=filter_level)

    if session.findings:
        learned_new = catalog.learner.learn_from_session(session, catalog)
        print(
            f"{GREEN}{BOLD}✔ Adaptive Learner:{RESET} +{learned_new} new pattern(s) learned "
            f"({len(catalog.learner.learned_tokens)} total) -> {CYAN}{catalog.learner.store_path}{RESET}"
        )

    if export_path:
        saved_file = export_markdown_report(session, export_path, filter_level=filter_level)
        print(f"{GREEN}{BOLD}✔ Exported Markdown audit report to:{RESET} {CYAN}{saved_file}{RESET}\n")

    return session
