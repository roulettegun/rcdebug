"""
Client Runtime Bridge (rcdebug --client):
- Local HTTP & WebSocket listener on 127.0.0.1:8765
- Auto-copies Luau diagnostic & telemetry snippet to macOS clipboard via pbcopy
- Processes runtime security findings, Remote Traffic Profiler data, and 10s Instance/Memory Diffs
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from .exporter import export_markdown_report
from .flaw_catalog import get_catalog
from .luau_payload import build_luau_bridge_script
from .models import AuditSession, Finding, MemorySnapshot, RemoteTrafficStat
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
    clipboard_label,
    copy_to_clipboard,
    normalize_filter_label,
    print_banner,
    print_finding,
    print_memory_diff,
    print_remote_traffic_update,
    print_session_summary,
)

WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class RuntimeBridgeServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        session: AuditSession,
        filter_level: str | None = None,
    ) -> None:
        self.session = session
        self.filter_level = filter_level
        self.lock = threading.Lock()
        try:
            super().__init__(server_address, handler_class)
        except Exception:
            try:
                self.server_close()
            except Exception:
                pass
            raise


def process_report_payload(
    server: RuntimeBridgeServer,
    payload: dict | list,
) -> int:
    items = payload if isinstance(payload, list) else [payload]
    catalog = get_catalog()
    added_count = 0
    with server.lock:
        for item in items:
            if not isinstance(item, dict):
                continue
            finding = Finding(
                severity=str(item.get("severity", "INFO")),
                title=str(item.get("title", "Security Finding")),
                path=str(item.get("path", "Unknown")),
                flaw=str(item.get("flaw", "")),
                abuse=str(item.get("abuse", "")),
                fix=str(item.get("fix", "")),
                category=str(item.get("category", "RuntimeAudit")),
                code_example=str(item.get("code_example", "")),
            )
            catalog.enrich_finding(finding)
            if server.session.add_finding(finding):
                added_count += 1
                print_finding(finding, filter_level=server.filter_level)
    return added_count


def process_telemetry_payload(
    server: RuntimeBridgeServer,
    payload: dict,
) -> None:
    with server.lock:
        now_str = datetime.now().strftime("%H:%M:%S")
        elapsed = float(payload.get("elapsed_sec", 0.0))
        ws_inst = int(payload.get("workspace_instances", 0))
        pl_inst = int(payload.get("player_instances", 0))
        mem_mb = float(payload.get("total_memory_mb", 0.0))

        prev_snap = (
            server.session.memory_snapshots[-1]
            if server.session.memory_snapshots
            else None
        )
        curr_snap = MemorySnapshot(
            timestamp=now_str,
            elapsed_sec=elapsed,
            workspace_instances=ws_inst,
            player_instances=pl_inst,
            total_memory_mb=mem_mb,
        )
        server.session.memory_snapshots.append(curr_snap)
        print_memory_diff(prev_snap, curr_snap)

        # Detect instance leak or memory spike between 10s snapshots
        if prev_snap is not None:
            ws_delta = curr_snap.workspace_instances - prev_snap.workspace_instances
            pl_delta = curr_snap.player_instances - prev_snap.player_instances
            mem_delta = curr_snap.total_memory_mb - prev_snap.total_memory_mb

            if ws_delta >= 75 or mem_delta >= 20.0:
                sev = "CRITICAL" if (ws_delta >= 200 or mem_delta >= 50.0) else "WARN"
                leak_finding = Finding(
                    severity=sev,
                    category="MemoryDiff",
                    title=f"Instance / Memory Growth Spike (+{ws_delta} Workspace instances, {mem_delta:+.1f} MB)",
                    path="Workspace / Memory",
                    flaw=(
                        f"Between 10s snapshots ({prev_snap.timestamp} -> {curr_snap.timestamp}), "
                        f"Workspace grew by {ws_delta:+d} instances (Players {pl_delta:+d}) and "
                        f"total memory changed by {mem_delta:+.2f} MB."
                    ),
                    abuse=(
                        "Uncleaned projectiles, VFX parts, or disconnected event connections cause progressive "
                        "server lag, replication choke, and eventual server crash."
                    ),
                    fix=(
                        "Schedule transient instances for cleanup with Debris:AddItem(instance, lifetime), "
                        "pool high-frequency projectiles, and disconnect RBXScriptConnections on destroy."
                    ),
                    code_example=(
                        'local Debris = game:GetService("Debris")\n'
                        "local fxPart = projectileTemplate:Clone()\n"
                        "fxPart.Parent = workspace.Effects\n"
                        "Debris:AddItem(fxPart, 3) -- Guaranteed cleanup after 3 seconds"
                    ),
                )
                server.session.add_finding(leak_finding)
                print_finding(leak_finding, filter_level=server.filter_level)

        # Process Remote Traffic Profiler samples
        remotes = payload.get("remotes", [])
        if isinstance(remotes, list):
            for rem in remotes:
                if not isinstance(rem, dict):
                    continue
                rpath = str(rem.get("remote_path", "UnknownRemote"))
                rtype = str(rem.get("remote_type", "RemoteEvent"))
                total_calls = int(rem.get("total_calls", 0))
                rate = float(rem.get("rate_per_sec", 0.0))

                stat = server.session.remote_traffic.get(rpath)
                if stat is None:
                    stat = RemoteTrafficStat(remote_path=rpath, remote_type=rtype)
                    server.session.remote_traffic[rpath] = stat

                stat.total_calls = total_calls
                stat.last_rate_per_sec = rate
                if rate > stat.peak_rate_per_sec:
                    stat.peak_rate_per_sec = rate

                if rate > 0:
                    print_remote_traffic_update(rpath, rate, total_calls)

                if rate >= 12.0 and not stat.has_cooldown_warning:
                    stat.has_cooldown_warning = True
                    sev = "CRITICAL" if rate >= 25.0 else "WARN"
                    spam_finding = Finding(
                        severity=sev,
                        category="RemoteTraffic",
                        title=f"Unthrottled Remote Traffic ({rate:.1f} calls/sec): {rpath}",
                        path=rpath,
                        flaw=(
                            f"Remote '{rpath}' is firing at {rate:.1f} calls/sec "
                            f"(total {total_calls} calls) without effective server-side rate limiting."
                        ),
                        abuse=(
                            "Exploiters can fire this remote hundreds of times per frame to exhaust server CPU, "
                            "flood replication queues, or exploit non-atomic datastore/currency operations."
                        ),
                        fix=(
                            "Add a per-player rate limiter (os.clock() cooldown map or token bucket) at the very "
                            "start of OnServerEvent before performing any workspace, table, or datastore work."
                        ),
                        code_example=(
                            "local COOLDOWN = 0.25\n"
                            "local lastCall: {[Player]: number} = {}\n"
                            "Players.PlayerRemoving:Connect(function(plr) lastCall[plr] = nil end)\n\n"
                            "remote.OnServerEvent:Connect(function(plr, ...)\n"
                            "    local now = os.clock()\n"
                            "    if now - (lastCall[plr] or 0) < COOLDOWN then return end\n"
                            "    lastCall[plr] = now\n"
                            "    -- Safe to process request\n"
                            "end)"
                        ),
                    )
                    server.session.add_finding(spam_finding)
                    print_finding(spam_finding, filter_level=server.filter_level)


class DebugReportHandler(BaseHTTPRequestHandler):
    server: RuntimeBridgeServer  # type annotation for IDE/typechecker

    def log_message(self, format: str, *args: object) -> None:
        # Suppress default HTTP access logs for clean terminal dashboard output
        pass

    def _send_json(self, status_code: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        # Check if client requested a WebSocket upgrade
        upgrade = self.headers.get("Upgrade", "").lower()
        if upgrade == "websocket":
            self._handle_websocket()
            return

        if self.path in ("/", "/status", "/health"):
            counts = self.server.session.counts_by_severity()
            self._send_json(
                200,
                {
                    "status": "ok",
                    "tool": "rcdebug",
                    "mode": self.server.session.mode,
                    "findings_count": len(self.server.session.findings),
                    "severity_counts": counts,
                    "snapshots_count": len(self.server.session.memory_snapshots),
                    "remotes_profiled": len(self.server.session.remote_traffic),
                },
            )
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        try:
            data = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return

        if self.path == "/report":
            added = process_report_payload(self.server, data)
            self._send_json(200, {"status": "ok", "added": added})
        elif self.path == "/telemetry":
            if isinstance(data, dict):
                process_telemetry_payload(self.server, data)
                self._send_json(200, {"status": "ok"})
            else:
                self._send_json(400, {"error": "expected_object"})
        elif self.path == "/shutdown":
            self._send_json(200, {"status": "shutting_down"})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._send_json(404, {"error": "not_found"})

    def _handle_websocket(self) -> None:
        """Minimal RFC 6455 WebSocket handler for Studio WebSocket streams."""
        ws_key = self.headers.get("Sec-WebSocket-Key", "")
        if not ws_key:
            self.send_response(400)
            self.end_headers()
            return

        accept_raw = hashlib.sha1((ws_key + WS_MAGIC_GUID).encode("utf-8")).digest()
        accept_key = base64.b64encode(accept_raw).decode("utf-8")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        self.end_headers()

        while True:
            try:
                header = self.rfile.read(2)
                if not header or len(header) < 2:
                    break
                b1, b2 = header[0], header[1]
                opcode = b1 & 0x0F
                if opcode == 0x8:  # Close frame
                    break
                masked = bool(b2 & 0x80)
                payload_len = b2 & 0x7F
                if payload_len == 126:
                    ext = self.rfile.read(2)
                    payload_len = struct.unpack(">H", ext)[0]
                elif payload_len == 127:
                    ext = self.rfile.read(8)
                    payload_len = struct.unpack(">Q", ext)[0]

                mask_key = self.rfile.read(4) if masked else b""
                payload_bytes = bytearray(self.rfile.read(payload_len))
                if masked and mask_key:
                    for i in range(len(payload_bytes)):
                        payload_bytes[i] ^= mask_key[i % 4]

                text = payload_bytes.decode("utf-8", errors="replace")
                msg = json.loads(text)
                if isinstance(msg, dict) and "workspace_instances" in msg:
                    process_telemetry_payload(self.server, msg)
                else:
                    process_report_payload(self.server, msg)
            except Exception:
                break


def default_roblox_logs_dir() -> Path:
    """
    Returns the default Roblox Player & Studio log directory for the current OS:
    - Windows: %LOCALAPPDATA%\\Roblox\\logs
    - macOS:   ~/Library/Logs/Roblox
    - Linux:   ~/.local/share/Roblox/logs
    """
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
        base = Path(local_app_data) if local_app_data else (Path.home() / "AppData" / "Local")
        return base / "Roblox" / "logs"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "Roblox"
    return Path.home() / ".local" / "share" / "Roblox" / "logs"


ROBLOX_LOGS_DIR = default_roblox_logs_dir()

_WIRE_REPORT_RE = re.compile(r"\[rcdebug-wire:report\]\s+(\{.*\})\s*$")
_WIRE_TELEMETRY_RE = re.compile(r"\[rcdebug-wire:telemetry\]\s+(\{.*\})\s*$")
_CONSOLE_FINDING_RE = re.compile(
    r"\[rcdebug-console\]\s+\[(CRITICAL|WARN|INFO)\]\s+\[([^\]]+)\]\s+(.+?)\s+\|\s+(.+?)\s*$"
)
_CONSOLE_TELEMETRY_RE = re.compile(
    r"\[rcdebug-console\]\s+t=([\d.]+)s\s+\|\s+Workspace=(\d+)\s+\|\s+(?:LocalPlayer|Players)=(\d+)\s+\|\s+Mem=([\d.]+)\s+MB"
)


def ingest_log_line(server: RuntimeBridgeServer, line: str) -> bool:
    """
    Parses a single Roblox log line for rcdebug wire JSON or console fallback messages
    and dispatches them to the active RuntimeBridgeServer session.
    Returns True if the line was handled.
    """
    if "[rcdebug" not in line:
        return False

    m_rep = _WIRE_REPORT_RE.search(line)
    if m_rep:
        try:
            data = json.loads(m_rep.group(1))
            process_report_payload(server, data)
            return True
        except json.JSONDecodeError:
            pass

    m_tel = _WIRE_TELEMETRY_RE.search(line)
    if m_tel:
        try:
            data = json.loads(m_tel.group(1))
            if isinstance(data, dict):
                process_telemetry_payload(server, data)
                return True
        except json.JSONDecodeError:
            pass

    m_cf = _CONSOLE_FINDING_RE.search(line)
    if m_cf:
        sev, cat, title, path = m_cf.groups()
        process_report_payload(
            server,
            {
                "severity": sev,
                "category": cat,
                "title": title,
                "path": path,
                "flaw": f"Detected via Roblox Client Console ({cat}) on {path}.",
                "abuse": "Client-exposed state, remote, or unanchored physics surface can be manipulated locally.",
                "fix": "Enforce server-authoritative validation, cooldowns, and ServerScriptService state.",
            },
        )
        return True

    m_ct = _CONSOLE_TELEMETRY_RE.search(line)
    if m_ct:
        elapsed, ws_inst, pl_inst, mem_mb = m_ct.groups()
        process_telemetry_payload(
            server,
            {
                "elapsed_sec": float(elapsed),
                "workspace_instances": int(ws_inst),
                "player_instances": int(pl_inst),
                "total_memory_mb": float(mem_mb),
                "remotes": [],
            },
        )
        return True

    return False


class RobloxLogTailer:
    """
    Tails active Roblox Player & Studio log files on macOS (~/Library/Logs/Roblox/)
    so 100% client-sided scripts stream seamlessly to the terminal even when
    Roblox restricts HttpService.PostAsync inside live Client contexts.
    """

    def __init__(
        self,
        server: RuntimeBridgeServer,
        log_dir: Path = ROBLOX_LOGS_DIR,
        replay_latest: bool = False,
        poll_interval: float = 0.2,
    ) -> None:
        self.server = server
        self.log_dir = log_dir
        self.replay_latest = replay_latest
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._offsets: dict[Path, int] = {}
        self._thread: threading.Thread | None = None

    def _candidate_logs(self) -> list[Path]:
        if not self.log_dir.exists():
            return []
        files = []
        for p in self.log_dir.iterdir():
            if not p.is_file() or not p.name.endswith("_last.log"):
                continue
            if "CrashHandler" in p.name:
                continue
            if "_Player_" in p.name or "_Studio_" in p.name:
                files.append(p)
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return files

    def _init_offsets(self) -> None:
        candidates = self._candidate_logs()
        for idx, path in enumerate(candidates):
            try:
                if self.replay_latest and idx == 0:
                    self._offsets[path] = 0
                else:
                    self._offsets[path] = path.stat().st_size
            except OSError:
                continue

    def poll_once(self) -> int:
        processed = 0
        for path in self._candidate_logs():
            try:
                size = path.stat().st_size
            except OSError:
                continue

            if path not in self._offsets:
                # Newly created log file after rcdebug started -> read from byte 0
                self._offsets[path] = 0
            elif size < self._offsets[path]:
                # File rotated/truncated
                self._offsets[path] = 0

            offset = self._offsets[path]
            if size <= offset:
                continue

            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    self._offsets[path] = fh.tell()
            except OSError:
                continue

            for line in chunk.splitlines():
                if ingest_log_line(self.server, line):
                    processed += 1
        return processed

    def start(self) -> None:
        self._init_offsets()
        if self.replay_latest:
            self.poll_once()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self.poll_once()
            self._stop_event.wait(self.poll_interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)


def simulate_studio_playtest_traffic(host: str, port: int) -> None:
    """
    Sends realistic synthetic Roblox Studio playtest findings and telemetry snapshots
    to the local rcdebug listener (used when --simulate is passed).
    """
    time.sleep(0.35)
    report_url = f"http://{host}:{port}/report"
    telemetry_url = f"http://{host}:{port}/telemetry"

    def post(url: str, data: dict | list) -> None:
        req = Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=3) as resp:
            resp.read()

    sample_findings = [
        {
            "severity": "CRITICAL",
            "category": "StateReplication",
            "title": "Sensitive IntValue in Character: Cash",
            "path": "Workspace.Player1.Cash",
            "flaw": "Gameplay state ('cash') is stored in an IntValue parented inside the player's Character model.",
            "abuse": (
                "Because the Character model is subject to client physics/replication quirks and often read by poorly "
                "written scripts, storing currency in Character allows tampering or state desync on respawn."
            ),
            "fix": "Move authoritative currency state into a ServerScriptService module table and expose read-only Attributes on Player.",
            "code_example": (
                "local Balances: {[number]: number} = {}\n"
                "function AddCash(player: Player, delta: number)\n"
                "    Balances[player.UserId] = (Balances[player.UserId] or 0) + delta\n"
                '    player:SetAttribute("Cash", Balances[player.UserId])\n'
                "end"
            ),
        },
        {
            "severity": "WARN",
            "category": "RemoteSecurity",
            "title": "High-Value Network Endpoint: GiveCashRemote (matched 'cash')",
            "path": "ReplicatedStorage.Remotes.GiveCashRemote",
            "flaw": "RemoteEvent name suggests privileged currency mutation accessible to all clients.",
            "abuse": "Malicious clients can fire GiveCashRemote:FireServer(999999999) or pass negative values to drain/mint currency.",
            "fix": "Remove direct reward remotes; calculate rewards strictly inside server-side objective/combat completion handlers.",
            "code_example": (
                "-- Do NOT let clients request arbitrary currency.\n"
                "-- Award currency on the server only when a verified server event completes."
            ),
        },
        {
            "severity": "WARN",
            "category": "NetworkOwnership",
            "title": "Unanchored Part with Client/Auto NetworkOwnership: VaultDoor",
            "path": "Workspace.BankLevel.VaultDoor",
            "flaw": "Unanchored interactive BasePart allows automatic client physics ownership (Current Owner: Auto).",
            "abuse": "Exploiters standing near VaultDoor gain physics authority and can set its CFrame to bypass locked barriers.",
            "fix": "Anchor the door and animate via server TweenService, or lock physics authority to the server via part:SetNetworkOwner(nil).",
            "code_example": "workspace.BankLevel.VaultDoor:SetNetworkOwner(nil)",
        },
        {
            "severity": "INFO",
            "category": "RemoteSecurity",
            "title": "Exposed Network Endpoint: SprintToggle",
            "path": "ReplicatedStorage.Remotes.SprintToggle",
            "flaw": "Client-accessible RemoteEvent found in ReplicatedStorage.",
            "abuse": "Clients can fire SprintToggle with non-boolean payloads or spam it every frame.",
            "fix": "Validate typeof(isSprinting) == 'boolean' and enforce a 0.15s per-player debounce on the server.",
        },
    ]

    for f in sample_findings:
        post(report_url, f)
        time.sleep(0.1)

    # Send baseline telemetry snapshot
    post(
        telemetry_url,
        {
            "elapsed_sec": 0.0,
            "workspace_instances": 1420,
            "player_instances": 85,
            "total_memory_mb": 412.5,
            "remotes": [
                {
                    "remote_path": "ReplicatedStorage.Remotes.SprintToggle",
                    "remote_type": "RemoteEvent",
                    "total_calls": 4,
                    "rate_per_sec": 0.4,
                }
            ],
        },
    )
    time.sleep(0.15)

    # Send 10s snapshot with simulated remote spam & uncleaned debris spike
    post(
        telemetry_url,
        {
            "elapsed_sec": 10.0,
            "workspace_instances": 1665,
            "player_instances": 92,
            "total_memory_mb": 448.2,
            "remotes": [
                {
                    "remote_path": "ReplicatedStorage.Remotes.GiveCashRemote",
                    "remote_type": "RemoteEvent",
                    "total_calls": 340,
                    "rate_per_sec": 34.0,
                }
            ],
        },
    )


def _try_reclaim_rcdebug_port(host: str, port: int) -> bool:
    """If an older rcdebug listener is holding `host:port`, request a clean shutdown."""
    try:
        with urlopen(f"http://{host}:{port}/status", timeout=0.4) as resp:
            info = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(info, dict) and info.get("tool") == "rcdebug":
            req = Request(f"http://{host}:{port}/shutdown", data=b"{}", method="POST")
            with urlopen(req, timeout=0.5) as sresp:
                sresp.read()
            time.sleep(0.15)
            return True
    except Exception:
        pass
    return False


def bind_runtime_bridge_server(
    host: str,
    preferred_port: int,
    session: AuditSession,
    filter_level: str | None = None,
    max_tries: int = 50,
) -> tuple[RuntimeBridgeServer, int, bool]:
    """
    Binds RuntimeBridgeServer to `preferred_port`. If another process (such as
    MacSploit or another service) is already holding `preferred_port`, automatically
    selects the next available port so `--client` never crashes with Errno 48.
    """
    try:
        srv = RuntimeBridgeServer((host, preferred_port), DebugReportHandler, session=session, filter_level=filter_level)
        return srv, int(srv.server_address[1]), False
    except OSError:
        if _try_reclaim_rcdebug_port(host, preferred_port):
            try:
                srv = RuntimeBridgeServer((host, preferred_port), DebugReportHandler, session=session, filter_level=filter_level)
                return srv, int(srv.server_address[1]), False
            except OSError:
                pass

    for offset in range(1, max_tries + 1):
        candidate = preferred_port + offset
        if candidate > 65535:
            break
        try:
            srv = RuntimeBridgeServer((host, candidate), DebugReportHandler, session=session, filter_level=filter_level)
            return srv, int(srv.server_address[1]), True
        except OSError:
            continue

    srv = RuntimeBridgeServer((host, 0), DebugReportHandler, session=session, filter_level=filter_level)
    return srv, int(srv.server_address[1]), True


def run_client_mode(
    host: str = "127.0.0.1",
    port: int = 8765,
    filter_level: str | None = None,
    export_path: str | None = None,
    auto_clipboard: bool = True,
    simulate: bool = False,
    enable_log_tail: bool = True,
    replay_latest_log: bool = False,
) -> AuditSession:
    catalog = get_catalog()
    session = AuditSession(
        mode="client",
        target_name=f"Roblox Client Runtime Bridge ({host}:{port})",
    )
    server, actual_port, used_fallback = bind_runtime_bridge_server(
        host=host,
        preferred_port=port,
        session=session,
        filter_level=filter_level,
    )
    session.target_name = f"Roblox Client Runtime Bridge ({host}:{actual_port})"

    print_banner(
        "CLIENT RUNTIME BRIDGE",
        subtitle=f"HTTP/WS ({host}:{actual_port}) + Log Bridge | {catalog.count():,} Flaw Signatures | Filter: {normalize_filter_label(filter_level)}",
    )
    if used_fallback:
        print(
            f"\n{YELLOW}{BOLD}⚠ Port {port} is in use by another process; "
            f"automatically bound to {host}:{actual_port}.{RESET}"
        )

    luau_script = build_luau_bridge_script(host=host, port=actual_port)

    if auto_clipboard:
        copied = copy_to_clipboard(luau_script)
        if copied:
            paste_key = "Ctrl+V" if sys.platform == "win32" else "Cmd+V"
            print(f"\n{GREEN}{BOLD}✔ Studio QA Luau script automatically copied to {clipboard_label()}!{RESET}")
            print(f"  {WHITE}Paste ({BOLD}{paste_key}{RESET}{WHITE}) into Roblox Studio Command Bar or StarterPlayerScripts.{RESET}")
        else:
            print(f"\n{YELLOW}⚠ Could not copy to clipboard automatically; copy the snippet below.{RESET}")

    print(f"\n{YELLOW}{BOLD}─── Luau Diagnostic & Telemetry Bridge Snippet ───{RESET}")
    print(f"{DIM}{luau_script.strip()}{RESET}")
    print(f"{YELLOW}{BOLD}──────────────────────────────────────────────────{RESET}\n")

    print(
        f"{BOLD}{GREEN}● Listening for telemetry on{RESET} "
        f"{BOLD}{CYAN}http://{host}:{actual_port}/report{RESET} & {BOLD}{CYAN}ws://{host}:{actual_port}/ws{RESET}"
    )

    log_tailer: RobloxLogTailer | None = None
    if enable_log_tail and not simulate:
        log_tailer = RobloxLogTailer(server, replay_latest=replay_latest_log)
        log_tailer.start()
        print(
            f"{BOLD}{GREEN}● Roblox Log Bridge active — tailing{RESET} "
            f"{BOLD}{CYAN}{ROBLOX_LOGS_DIR}{RESET}"
        )

    print(f"{DIM}  Press Ctrl+C to stop listener and finalize session report.{RESET}")

    if simulate:
        print(f"\n{MAGENTA}{BOLD}[SIMULATION MODE]{RESET} Injecting sample playtest findings & 10s telemetry snapshots...")
        sim_thread = threading.Thread(target=simulate_studio_playtest_traffic, args=(host, actual_port), daemon=True)
        sim_thread.start()

        def auto_stop() -> None:
            sim_thread.join(timeout=5.0)
            time.sleep(0.25)
            server.shutdown()

        threading.Thread(target=auto_stop, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[rcdebug] Stopping Client Runtime Bridge listener...{RESET}")
    finally:
        if log_tailer is not None:
            log_tailer.stop()
        server.server_close()

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
