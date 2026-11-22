"""
Unit and integration test suite for rcdebug (Revan Cool Debugger).
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from rcdebug.cli import build_parser, resolve_filter_levels
from rcdebug.client_bridge import (
    DebugReportHandler,
    RobloxLogTailer,
    RuntimeBridgeServer,
    ingest_log_line,
)
from rcdebug.debugger_pack import PACK_JSON_PATH, get_debugger_pack
from rcdebug.exporter import export_markdown_report, generate_markdown_report
from rcdebug.flaw_catalog import FLAWS_TXT_PATH, FlawCatalog, get_catalog
from rcdebug.learner import (
    AdaptiveLearner,
    AutonomousBrainSync,
    CommandHistory,
    FlawBrain,
    seed_training_history,
)
from rcdebug.luau_payload import build_luau_bridge_script
from rcdebug.mcp_inspector import (
    audit_local_path,
    audit_luau_script_source,
    find_studio_mcp,
)
from rcdebug.models import AuditSession, Finding, format_filter_label, matches_filter


class TestRcdebugSuite(unittest.TestCase):
    def test_luau_payload_contains_all_required_checks(self) -> None:
        script = build_luau_bridge_script(host="127.0.0.1", port=8765, snapshot_interval=10)
        # Must be 100% offline with zero external HTTP / localhost bridge calls
        self.assertNotIn("HttpService", script)
        self.assertNotIn("PostAsync", script)
        self.assertNotIn("RequestAsync", script)
        self.assertNotIn("http://", script)
        self.assertNotIn("https://", script)
        # Must include offline Studio QA Test Runner suites & [PASS]/[FAIL] reporting
        self.assertIn("[PASS]", script)
        self.assertIn("[FAIL]", script)
        self.assertIn("[rcdebug QA Summary]", script)
        self.assertIn("Players.LocalPlayer", script)
        self.assertIn("SCAN_CHUNK_SIZE", script)
        self.assertIn("ReplicatedStorage:GetDescendants()", script)
        self.assertIn("Workspace:GetDescendants()", script)
        self.assertIn("obj.ReceiveAge == 0", script)
        self.assertIn('obj:IsA("ProximityPrompt")', script)
        self.assertIn('desc:IsA("ValueBase")', script)
        self.assertIn("LocalPlayer:GetAttributes()", script)
        self.assertIn("Stats:GetTotalMemoryUsageMb()", script)
        # Ensure no server-only runtime APIs or placeholder boilerplate
        self.assertNotIn('game:GetService("ServerScriptService")', script)
        self.assertNotIn("RunService:IsServer()", script)
        self.assertNotIn("GetNetworkOwnershipAuto", script)
        self.assertNotIn("obj.OnServerEvent:Connect", script)
        self.assertNotIn("-- TODO", script)

    def test_severity_filter_matching(self) -> None:
        self.assertTrue(matches_filter("CRITICAL", None))
        self.assertTrue(matches_filter("CRITICAL", "CRITICAL"))
        self.assertFalse(matches_filter("WARN", "CRITICAL"))
        self.assertTrue(matches_filter("WARN", "warn"))
        self.assertTrue(matches_filter("INFO", "INFO"))

        # Multi-flag CLI severity filters (--critical, --warning, --critical --warning)
        parser = build_parser()
        f_crit = resolve_filter_levels(parser.parse_args(["--client", "--critical"]))
        self.assertEqual(f_crit, frozenset({"CRITICAL"}))
        self.assertTrue(matches_filter("CRITICAL", f_crit))
        self.assertFalse(matches_filter("WARN", f_crit))

        f_warn = resolve_filter_levels(parser.parse_args(["--client", "--warning"]))
        self.assertEqual(f_warn, frozenset({"WARN"}))
        self.assertTrue(matches_filter("WARN", f_warn))
        self.assertFalse(matches_filter("CRITICAL", f_warn))

        f_both = resolve_filter_levels(parser.parse_args(["--client", "--critical", "--warning"]))
        self.assertEqual(f_both, frozenset({"CRITICAL", "WARN"}))
        self.assertTrue(matches_filter("CRITICAL", f_both))
        self.assertTrue(matches_filter("WARN", f_both))
        self.assertFalse(matches_filter("INFO", f_both))
        self.assertEqual(format_filter_label(f_both), "CRITICAL, WARN")

    def test_static_luau_script_auditor(self) -> None:
        vulnerable_code = """
        local ReplicatedStorage = game:GetService("ReplicatedStorage")
        local HttpService = game:GetService("HttpService")
        local WEBHOOK = "https://discord.com/api/webhooks/999/secret"

        ReplicatedStorage.BuyItem.OnServerEvent:Connect(function(player, itemId, cost)
            player.leaderstats.Cash.Value -= cost
            loadstring("print('bought')")()
            HttpService:PostAsync(WEBHOOK, "{}")
        end)
        """
        findings = audit_luau_script_source("ServerScriptService.ShopScript", vulnerable_code)
        titles = [f.title for f in findings]
        categories = {f.category for f in findings}

        self.assertIn("StaticScriptAudit", categories)  # loadstring
        self.assertIn("HttpSecurity", categories)       # Discord webhook
        self.assertIn("RemoteValidation", categories)   # Missing typeof() on itemId, cost
        self.assertTrue(any("loadstring()" in t for t in titles))
        self.assertTrue(any("Missing Parameter Type Validation" in t for t in titles))

    def test_mcp_config_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "mcp_config.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "Roblox_Studio": {
                                "command": "/Applications/RobloxStudio.app/Contents/MacOS/StudioMCP"
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            found = find_studio_mcp(custom_paths=[cfg_path])
            self.assertIsNotNone(found)
            assert found is not None
            self.assertEqual(found["name"], "Roblox_Studio")
            self.assertIn("StudioMCP", found["config"]["command"])

    def test_runtime_bridge_http_report_and_telemetry(self) -> None:
        session = AuditSession(mode="client", target_name="UnitTest")
        server = RuntimeBridgeServer(("127.0.0.1", 0), DebugReportHandler, session=session, filter_level="CRITICAL")
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # 1. Post a finding
            req1 = Request(
                f"http://127.0.0.1:{port}/report",
                data=json.dumps(
                    {
                        "severity": "WARN",
                        "title": "Exposed Remote: TestRemote",
                        "path": "ReplicatedStorage.TestRemote",
                        "flaw": "Test flaw",
                        "abuse": "Test abuse",
                        "fix": "Test fix",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req1, timeout=2) as resp:
                self.assertEqual(resp.status, 200)

            # 2. Post baseline telemetry snapshot
            req2 = Request(
                f"http://127.0.0.1:{port}/telemetry",
                data=json.dumps(
                    {
                        "elapsed_sec": 0.0,
                        "workspace_instances": 500,
                        "player_instances": 20,
                        "total_memory_mb": 200.0,
                        "remotes": [],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req2, timeout=2) as resp:
                self.assertEqual(resp.status, 200)

            # 3. Post 10s snapshot with memory leak + remote spam
            req3 = Request(
                f"http://127.0.0.1:{port}/telemetry",
                data=json.dumps(
                    {
                        "elapsed_sec": 10.0,
                        "workspace_instances": 760,
                        "player_instances": 25,
                        "total_memory_mb": 260.0,
                        "remotes": [
                            {
                                "remote_path": "ReplicatedStorage.SpamRemote",
                                "remote_type": "RemoteEvent",
                                "total_calls": 400,
                                "rate_per_sec": 40.0,
                            }
                        ],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req3, timeout=2) as resp:
                self.assertEqual(resp.status, 200)

            # Verify findings & telemetry were recorded
            self.assertEqual(len(session.memory_snapshots), 2)
            self.assertIn("ReplicatedStorage.SpamRemote", session.remote_traffic)
            categories = {f.category for f in session.findings}
            self.assertIn("MemoryDiff", categories)
            self.assertIn("RemoteTraffic", categories)
        finally:
            server.shutdown()
            server.server_close()

    def test_markdown_report_export_and_rbxlx_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            rbxlx_file = tmp_path / "place.rbxlx"
            rbxlx_file.write_text(
                """<roblox version="4">
                    <Item class="ServerScriptService">
                        <Properties>
                            <string name="Name">ServerScriptService</string>
                            <bool name="LoadStringEnabled">true</bool>
                        </Properties>
                    </Item>
                    <Item class="Part">
                        <Properties>
                            <string name="Name">FloatingCrate</string>
                            <bool name="Anchored">false</bool>
                        </Properties>
                    </Item>
                </roblox>""",
                encoding="utf-8",
            )

            session = AuditSession(mode="server", target_name="PlaceTest")
            audit_local_path(rbxlx_file, session)
            self.assertGreaterEqual(len(session.findings), 2)

            report_path = tmp_path / "audit_report.md"
            saved = export_markdown_report(session, report_path)
            self.assertTrue(saved.exists())
            content = saved.read_text(encoding="utf-8")
            self.assertIn("# rcdebug — Roblox Security & Performance Audit Report", content)
            self.assertIn("LoadStringEnabled", content)
            self.assertIn("FloatingCrate", content)

    def test_roblox_log_bridge_tailer(self) -> None:
        session = AuditSession(mode="client", target_name="LogBridgeTest")
        server = RuntimeBridgeServer(("127.0.0.1", 0), DebugReportHandler, session=session)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                log_dir = Path(tmpdir)
                log_file = log_dir / "0.745.0_Player_abc123_last.log"
                log_file.write_text("2026-11-17T10:38:40Z,1.0,aa,6,Info [FLog::Output] boot\n", encoding="utf-8")

                tailer = RobloxLogTailer(server, log_dir=log_dir, replay_latest=False, poll_interval=0.05)
                tailer.start()
                try:
                    # Append wire report, wire telemetry, and legacy console fallback lines
                    with log_file.open("a", encoding="utf-8") as fh:
                        fh.write(
                            '2026-11-17T10:38:42Z,2.0,aa,6,Info [FLog::CreatorOutput] [rcdebug-wire:report] '
                            + json.dumps(
                                {
                                    "severity": "WARN",
                                    "category": "RemoteSecurity",
                                    "title": "High-Value Client-Visible Remote: ForceAdmin",
                                    "path": "ReplicatedStorage.Remotes.ForceAdmin",
                                    "flaw": "Exposed admin remote.",
                                    "abuse": "Clients can fire ForceAdmin.",
                                    "fix": "Validate admin rank on server.",
                                }
                            )
                            + "\n"
                        )
                        fh.write(
                            '2026-11-17T10:38:42Z,2.1,aa,6,Info [FLog::CreatorOutput] [rcdebug-wire:telemetry] '
                            + json.dumps(
                                {
                                    "elapsed_sec": 0.0,
                                    "workspace_instances": 33499,
                                    "player_instances": 10800,
                                    "total_memory_mb": 3240.25,
                                    "remotes": [],
                                }
                            )
                            + "\n"
                        )
                        fh.write(
                            "2026-11-17T10:38:52Z,12.1,aa,6,Info [FLog::CreatorOutput] [rcdebug-console] "
                            "t=10.0s | Workspace=33502 | LocalPlayer=10802 | Mem=3219.31 MB\n"
                        )
                        fh.write(
                            "2026-11-17T10:38:52Z,12.2,aa,6,Info [FLog::CreatorOutput] [rcdebug-console] "
                            "[INFO] [StateReplication] Client-Readable Player Attribute: Money | Players.hachiquew [Attribute:Money]\n"
                        )

                    # Allow tailer to poll
                    import time
                    for _ in range(20):
                        if len(session.findings) >= 2 and len(session.memory_snapshots) >= 2:
                            break
                        time.sleep(0.05)

                    self.assertEqual(len(session.findings), 2)
                    self.assertEqual(len(session.memory_snapshots), 2)
                    self.assertEqual(session.findings[0].path, "ReplicatedStorage.Remotes.ForceAdmin")
                    self.assertEqual(session.memory_snapshots[1].workspace_instances, 33502)
                finally:
                    tailer.stop()
        finally:
            server.server_close()

    def test_flaw_catalog_exact_120000_and_enrichment(self) -> None:
        from rcdebug.flaw_catalog import FLAWS_GZ_PATH, ensure_flaws_txt

        self.assertTrue(FLAWS_GZ_PATH.exists())
        txt_path = ensure_flaws_txt()
        self.assertTrue(txt_path.exists())
        with txt_path.open("rb") as fh:
            line_count = sum(1 for ln in fh if ln.strip())
        self.assertEqual(line_count, 600000)

        catalog = get_catalog()
        self.assertEqual(catalog.count(), 600000)
        self.assertEqual(catalog.signature_count(), 600000)

        # Verify strict monotonic ordering: RCD-000001 (CRITICAL, rank 1) -> RCD-600000 (INFO, rank 600000)
        first_sig = catalog.get("RCD-000001")
        last_sig = catalog.get("RCD-600000")
        self.assertIsNotNone(first_sig)
        self.assertIsNotNone(last_sig)
        assert first_sig is not None and last_sig is not None
        self.assertEqual(first_sig.severity, "CRITICAL")
        self.assertEqual(first_sig.rank, 1)
        self.assertEqual(last_sig.severity, "INFO")
        self.assertEqual(last_sig.rank, 600000)

        # Sub-15ms warm lookup latency check
        import time
        t0 = time.perf_counter()
        hits = catalog.match_name("GiveMoneyRemote", container_hint="ReplicatedStorage")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.assertLess(elapsed_ms, 15.0)
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0].domain, "Economy")

        # Enrichment adds catalog code & domain
        finding = Finding(
            severity="INFO",
            category="RemoteSecurity",
            title="Client-Visible Remote: ForceAdmin",
            path="ReplicatedStorage.Remotes.ForceAdmin",
            flaw="",
            abuse="",
            fix="",
        )
        enriched = catalog.enrich_finding(finding)
        self.assertIn("catalog_code", enriched.metadata)
        self.assertEqual(enriched.metadata["domain"], "Admin")
        self.assertEqual(enriched.severity, "WARN")

        # Static rules catch DataStore SetAsync & ProximityPrompt.Triggered
        static_hits = audit_luau_script_source(
            "ServerScriptService.StoreAndPrompt",
            """
            local ds = game:GetService("DataStoreService"):GetDataStore("Main")
            ds:SetAsync("p_1", { Cash = 500 })
            workspace.VaultPrompt.Triggered:Connect(function(player)
                player.leaderstats.Cash.Value += 100
            end)
            """,
        )
        cats = {f.category for f in static_hits}
        self.assertIn("DataStoreSecurity", cats)
        self.assertIn("PromptSecurity", cats)

    def test_adaptive_learner_learns_and_persists(self) -> None:
        base_catalog = get_catalog()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            store_json = tmp_path / "learned_flaws.json"
            store_txt = tmp_path / "learned_patterns.txt"

            learner = AdaptiveLearner(store_path=store_json, txt_path=store_txt)
            session = AuditSession(mode="client", target_name="CustomHorrorPlace")
            session.add_finding(
                Finding(
                    severity="WARN",
                    category="RemoteSecurity",
                    title="Client-Visible Remote: TenantTransform",
                    path="ReplicatedStorage.Remotes.TenantTransform",
                    flaw="Custom transformation remote exposed.",
                    abuse="Clients can spoof TenantTransform state.",
                    fix="Validate TenantTransform state on server.",
                )
            )
            added = learner.learn_from_session(session, base_catalog)
            self.assertGreaterEqual(added, 1)
            self.assertTrue(store_json.exists())
            self.assertTrue(store_txt.exists())
            self.assertIn("tenanttransform", learner.learned_tokens)

            # Reload in a fresh learner + catalog and verify automatic recognition
            reloaded = AdaptiveLearner(store_path=store_json, txt_path=store_txt)
            fresh_cat = FlawCatalog(
                txt_path=FLAWS_TXT_PATH,
                cache_path=base_catalog.cache_path,
                static_rules=base_catalog.static_rules,
                learner=reloaded,
            )
            new_finding = Finding(
                severity="INFO",
                category="RemoteSecurity",
                title="Client-Visible Remote: TenantTransform",
                path="Workspace.TenantTransform",
                flaw="",
                abuse="",
                fix="",
            )
            enriched = fresh_cat.enrich_finding(new_finding)
            self.assertEqual(enriched.severity, "WARN")
            self.assertEqual(enriched.metadata.get("learned_token"), "tenanttransform")
            self.assertIn("TenantTransform", enriched.fix)

    def test_command_history_json_and_brain_seeding(self) -> None:
        base_catalog = get_catalog()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            hist_path = tmp_path / "command_history.json"
            store_json = tmp_path / "learned_flaws.json"
            store_txt = tmp_path / "learned_patterns.txt"

            learner = AdaptiveLearner(store_path=store_json, txt_path=store_txt)
            cat = FlawCatalog(
                txt_path=FLAWS_TXT_PATH,
                cache_path=base_catalog.cache_path,
                static_rules=base_catalog.static_rules,
                learner=learner,
            )
            hist = CommandHistory(history_path=hist_path)
            seeded = seed_training_history(cat, history=hist, count=15)
            self.assertEqual(seeded, 15)
            self.assertTrue(hist_path.exists())

            raw = json.loads(hist_path.read_text(encoding="utf-8"))
            self.assertEqual(raw["total_commands"], 15)
            self.assertEqual(len(raw["history"]), 15)
            self.assertGreater(len(learner.learned_tokens), 0)
            self.assertGreater(len(raw["domain_weights"]), 0)

            # Fast cached lookup check
            first = cat.match_name("GiveCashRemote", "ReplicatedStorage.Remotes.GiveCashRemote")
            second = cat.match_name("GiveCashRemote", "ReplicatedStorage.Remotes.GiveCashRemote")
            self.assertEqual(first, second)

    def test_luau_debugger_pack_exact_120(self) -> None:
        self.assertTrue(PACK_JSON_PATH.exists())
        pack = get_debugger_pack()
        self.assertEqual(pack.count(), 120)
        sources = {p.source for p in pack.probes}
        self.assertIn("Kampfkarren/selene", sources)
        self.assertIn("JohnnyMorganz/luau-lsp", sources)
        self.assertIn("Sleitnick/RbxUtil (Trove)", sources)

        # Verify pack probes run during static script auditing
        hits = audit_luau_script_source(
            "ReplicatedStorage.SampleModule",
            "wait(1)\nlocal x = Color3.new(255, 0, 0)\n",
        )
        cats = {f.category for f in hits}
        self.assertTrue(any(c.startswith("LuauPack:") for c in cats))

    def test_autonomous_brain_sync_from_history_and_logs(self) -> None:
        base_catalog = get_catalog()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            hist_path = tmp_path / "command_history.json"
            store_json = tmp_path / "learned_flaws.json"
            store_txt = tmp_path / "learned_patterns.txt"
            sync_state = tmp_path / "brain_sync_state.json"
            log_dir = tmp_path / "logs"
            log_dir.mkdir()

            learner = AdaptiveLearner(store_path=store_json, txt_path=store_txt)
            cat = FlawCatalog(
                txt_path=FLAWS_TXT_PATH,
                cache_path=base_catalog.cache_path,
                static_rules=base_catalog.static_rules,
                learner=learner,
            )
            hist = CommandHistory(history_path=hist_path)
            hist.record_run(
                argv=["--client"],
                mode="client",
                target="NebulaCitadelPlace",
                domains_seen=["Combat"],
            )

            log_file = log_dir / "0.745_Player_xyz_last.log"
            log_file.write_text(
                "2026-11-17T10:00:00Z,1.0,aa,6,Info [FLog::CreatorOutput] "
                "[rcdebug-console] [WARN] [RemoteSecurity] Client-Visible Remote: AstralPulse | ReplicatedStorage.Remotes.AstralPulse\n",
                encoding="utf-8",
            )

            sync = AutonomousBrainSync(state_path=sync_state, log_dir=log_dir)
            added = sync.sync_once(cat, hist)
            self.assertGreaterEqual(added, 2)
            self.assertIn("nebulacitadelplace", learner.learned_tokens)
            self.assertIn("astralpulse", learner.learned_tokens)

    def test_flaw_brain_learns_from_120000_flaws_and_infers_unseen(self) -> None:
        base_catalog = get_catalog()
        pack = get_debugger_pack()
        with tempfile.TemporaryDirectory() as tmpdir:
            brain_path = Path(tmpdir) / "flaw_brain.json"
            brain = FlawBrain(brain_path=brain_path)
            learned_count = brain.train_from_corpus(base_catalog, pack=pack)
            self.assertEqual(learned_count, 600120)
            self.assertTrue(brain_path.exists())

            pred = brain.predict("Endpoint lacks os.clock() cooldown and accepts NaN math.huge")
            self.assertIsNotNone(pred)
            assert pred is not None
            dom, sev, fix = pred
            self.assertTrue(len(dom) > 0)
            self.assertIn(sev, ("CRITICAL", "WARN", "INFO"))
            self.assertTrue(len(fix) > 0)

    def test_guard_aware_remote_suppression_and_github_harvester_offline(self) -> None:
        from unittest.mock import patch
        from urllib.error import URLError
        from rcdebug.github_harvester import distill_luau_source, harvest_github_luau

        # Guarded OnServerEvent should NOT trigger RemoteValidation
        guarded = """
        local lastCall = {}
        ReplicatedStorage.BuyItem.OnServerEvent:Connect(function(player, itemId, qty)
            if typeof(itemId) ~= "string" or typeof(qty) ~= "number" or qty ~= qty then return end
            if os.clock() - (lastCall[player] or 0) < 0.25 then return end
            lastCall[player] = os.clock()
        end)
        """
        hits = audit_luau_script_source("ServerScriptService.SafeShop", guarded)
        self.assertFalse(any(f.category == "RemoteValidation" for f in hits))

        # Offline-safe GitHub harvester fallback
        with tempfile.TemporaryDirectory() as tmpdir:
            brain = FlawBrain(brain_path=Path(tmpdir) / "brain.json")
            with patch("rcdebug.github_harvester._github_get_json", side_effect=URLError("offline")):
                res = harvest_github_luau("roblox luau", brain=brain)
                self.assertTrue(res.offline_fallback)
                self.assertEqual(res.repos_scanned, 0)

            distilled = distill_luau_source(guarded, "owner/repo", "SafeShop.luau", brain)
            self.assertGreaterEqual(distilled, 1)

    def test_port_collision_auto_fallback_and_bare_cli_default(self) -> None:
        import socket
        from rcdebug.client_bridge import bind_runtime_bridge_server

        # Bare `rcdebug` without flags defaults to --client cleanly
        args = build_parser().parse_args([])
        self.assertFalse(args.client)

        # Simulate a third-party process (e.g. MacSploit) occupying a local TCP port
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        occupied_port = blocker.getsockname()[1]

        session = AuditSession(mode="client", target_name="PortCollisionTest")
        try:
            server, actual_port, used_fallback = bind_runtime_bridge_server(
                "127.0.0.1",
                occupied_port,
                session,
                max_tries=10,
            )
            try:
                self.assertTrue(used_fallback)
                self.assertNotEqual(actual_port, occupied_port)
                self.assertGreater(actual_port, occupied_port)

                # Generated Studio QA Luau script remains offline with zero HTTP calls
                script = build_luau_bridge_script(host="127.0.0.1", port=actual_port)
                self.assertIn("Offline Studio QA Test Runner", script)
                self.assertNotIn("http://", script)
            finally:
                server.server_close()
        finally:
            blocker.close()

    def test_ui_workbench_server_and_endpoints(self) -> None:
        from rcdebug.ui import bind_ui_workbench_server

        args = build_parser().parse_args(["--ui", "--no-browser"])
        self.assertTrue(args.ui)
        self.assertTrue(args.no_browser)

        session = AuditSession(mode="ui", target_name="UITest")
        server, port, _ = bind_ui_workbench_server("127.0.0.1", 0, session)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # 1. GET /ui returns the HTML workbench
            with urlopen(f"http://127.0.0.1:{port}/ui", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                html = resp.read().decode("utf-8")
                self.assertIn("<title>rcdebug Workbench</title>", html)
                self.assertIn("Live Audit", html)

            # 2. GET /api/state returns live session state and offline Studio QA Luau script
            with urlopen(f"http://127.0.0.1:{port}/api/state", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                state = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(state["catalog_count"], 600000)
                self.assertIn("Offline Studio QA Test Runner", state["luau_script"])
                self.assertNotIn("HttpService", state["luau_script"])

            # 3. GET /api/catalog searches the 120,000-flaw mmap index
            with urlopen(f"http://127.0.0.1:{port}/api/catalog?q=datastore&severity=CRITICAL&limit=5", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                cat_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(len(cat_res["results"]), 5)
                self.assertEqual(cat_res["results"][0]["severity"], "CRITICAL")

            # 4. GET /api/pack searches the 120 Luau probes
            with urlopen(f"http://127.0.0.1:{port}/api/pack?q=wait&limit=10", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                pack_res = json.loads(resp.read().decode("utf-8"))
                self.assertGreaterEqual(len(pack_res["results"]), 1)

            # 5. POST /api/scan-source audits Luau source and adds findings to session
            scan_req = Request(
                f"http://127.0.0.1:{port}/api/scan-source",
                data=json.dumps({
                    "script_name": "VulnerableLoader.luau",
                    "source": "loadstring('print(1)')()\n",
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(scan_req, timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                scan_res = json.loads(resp.read().decode("utf-8"))
                self.assertGreaterEqual(scan_res["added"], 1)

            # 6. GET /api/export.md downloads Markdown report containing the new finding
            with urlopen(f"http://127.0.0.1:{port}/api/export.md", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                md = resp.read().decode("utf-8")
                self.assertIn("VulnerableLoader.luau", md)

            # 7. Verify Developer vs Exploit surface classification in /api/state and /api/catalog
            with urlopen(f"http://127.0.0.1:{port}/api/state", timeout=3) as resp:
                st = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(any(f.get("surface") == "exploit" for f in st["session"]["findings"]))
                self.assertTrue(all("responsible_script" in f and "vulnerable_pattern" in f for f in st["session"]["findings"]))

            with urlopen(f"http://127.0.0.1:{port}/api/catalog?q=remote&surface=exploit&limit=5", timeout=3) as resp:
                exp_cat = json.loads(resp.read().decode("utf-8"))
                self.assertGreaterEqual(len(exp_cat["results"]), 1)
                self.assertTrue(all(r["surface"] == "exploit" for r in exp_cat["results"]))
        finally:
            server.shutdown()
            server.server_close()

    def test_multi_overview_domain_specificity_and_boilerplate_override(self) -> None:
        from rcdebug.ui import build_ui_html, classify_finding_surface

        # 1. Zero em dashes in UI HTML (antislop rule)
        self.assertNotIn("—", build_ui_html())

        # 2. Generic luau_payload.py boilerplate must NOT produce identical overviews or identical 3-line stub fixes
        generic_abuse = "Clients can fire or invoke this endpoint with spoofed types, negative numbers, NaN, nil, or oversized tables at high frequency."
        generic_fix = "Validate typeof() and finite bounds on the server, enforce per-player cooldowns, and keep rewards/prices server-authoritative."
        generic_stub = 'remote.OnServerEvent:Connect(function(plr, amt)\n    if typeof(amt) ~= "number" or amt ~= amt or amt <= 0 then return end\nend)'

        samples = [
            ("RemoteSecurity", "Client-Visible Remote: AllDailiesCompletedEvent", "ReplicatedStorage.Remotes.AllDailiesCompletedEvent"),
            ("RemoteSecurity", "Client-Visible Remote: GiveCashRemote", "ReplicatedStorage.Remotes.GiveCashRemote"),
            ("RemoteSecurity", "Client-Visible Remote: FireSniperHit", "ReplicatedStorage.Remotes.FireSniperHit"),
            ("RemoteSecurity", "Client-Visible Remote: AdminKick", "ReplicatedStorage.Remotes.AdminKick"),
            ("RemoteSecurity", "Client-Visible Remote: HatchLegendaryEgg", "ReplicatedStorage.Remotes.HatchLegendaryEgg"),
            ("NetworkOwnership", "Unanchored Part: VaultDoor", "Workspace.VaultDoor"),
        ]

        results = [
            classify_finding_surface(cat, title, path, "Client-accessible RemoteEvent", generic_abuse, generic_fix, generic_stub)
            for cat, title, path in samples
        ]

        # Every single sample must have a unique domain_label, >= 4 overviews, unique vulnerable_pattern, and unique tailored fix_code
        domain_labels = {r["domain_label"] for r in results}
        vuln_patterns = {r["vulnerable_pattern"] for r in results}
        fix_codes = {r["fix_code"] for r in results}
        overview_summaries = {r["overviews"][0]["summary"] for r in results}

        self.assertEqual(len(domain_labels), len(samples))
        self.assertEqual(len(vuln_patterns), len(samples))
        self.assertEqual(len(fix_codes), len(samples))
        self.assertEqual(len(overview_summaries), len(samples))

        for r in results:
            self.assertGreaterEqual(len(r["overviews"]), 4)
            self.assertIn("exploitability", r["risk_profile"])
            self.assertGreaterEqual(len(r["studio_search_queries"]), 1)
            self.assertNotIn("remote.OnServerEvent:Connect(function(plr, amt)", r["fix_code"])

        # Specifically verify AllDailiesCompletedEvent gets Daily Quest & Reward Completion domain & idempotency fix
        dailies = results[0]
        self.assertEqual(dailies["domain_label"], "Daily Quest & Reward Completion")
        self.assertIn("claimedDayKey", dailies["fix_code"])
        self.assertIn("AllDailiesCompletedEvent", dailies["studio_search_queries"])

        # 3. FlawCatalog.enrich_finding() overrides generic luau_payload.py boilerplate
        catalog = get_catalog()
        f = Finding(
            severity="WARN",
            category="RemoteSecurity",
            title="Client-Visible Remote: GiveCashRemote",
            path="ReplicatedStorage.Remotes.GiveCashRemote",
            flaw="Client-accessible RemoteEvent detected.",
            abuse=generic_abuse,
            fix=generic_fix,
        )
        enriched = catalog.enrich_finding(f)
        self.assertNotEqual(enriched.abuse, generic_abuse)
        self.assertNotEqual(enriched.fix, generic_fix)

    def test_contract_specification_and_luau_unit_test_generation(self) -> None:
        sample_source = (
            'local ReplicatedStorage = game:GetService("ReplicatedStorage")\n'
            'local Remotes = ReplicatedStorage:WaitForChild("Remotes")\n'
            '\n'
            'Remotes.BuyShopItem.OnServerEvent:Connect(function(player, itemId, quantity, price)\n'
            '    player.leaderstats.Gold.Value -= (price * quantity)\n'
            'end)\n'
        )
        findings = audit_luau_script_source("ServerScriptService/ShopHandler.luau", sample_source)
        remote_findings = [f for f in findings if f.category == "RemoteValidation"]
        self.assertGreaterEqual(len(remote_findings), 1)

        f = remote_findings[0]
        spec = f.metadata.get("contract_spec")
        self.assertIsInstance(spec, dict)
        assert isinstance(spec, dict)

        # 1. Vulnerability Trace & Locator
        tr = spec["trace_locator"]
        self.assertEqual(tr["script_path"], "ServerScriptService/ShopHandler.luau")
        self.assertEqual(tr["line_number"], 4)
        self.assertEqual(tr["remote_name"], "Remotes.BuyShopItem")
        self.assertEqual(tr["unvalidated_parameters"], ["itemId", "quantity", "price"])

        # 2. Vulnerable Server Handler (exact audited snippet)
        self.assertIn("Remotes.BuyShopItem.OnServerEvent:Connect(function(player, itemId, quantity, price)", spec["vulnerable_handler_code"])
        self.assertIn("player.leaderstats.Gold.Value -= (price * quantity)", spec["vulnerable_handler_code"])

        # 3. Parameter Contract & Edge-Case Matrix
        matrix_params = [row["parameter"] for row in spec["parameter_contract_matrix"]]
        self.assertEqual(matrix_params, ["player", "itemId", "quantity", "price"])
        self.assertIn("| Parameter | Expected Luau `typeof()` |", spec["parameter_contract_markdown"])
        self.assertIn("0/0 (NaN)", spec["parameter_contract_markdown"])
        self.assertIn("math.huge", spec["parameter_contract_markdown"])

        # 4. Defensive Server-Side Guard Module + Studio Command Bar assert() Unit Test (zero boilerplate)
        patched = spec["patched_guard_and_unit_test_code"]
        self.assertIn("local BuyShopItemGuard = {}", patched)
        self.assertIn("typeof(quantity)", patched)
        self.assertIn("math.clamp(", patched)
        self.assertIn("os.clock()", patched)
        self.assertIn("assert(passOk == true", patched)
        self.assertIn("assert(burstOk == false", patched)
        self.assertIn("runContractAssertions()", patched)
        self.assertNotIn("-- TODO", patched)
        self.assertNotIn("-- add checks here", patched.lower())

        # 5. Markdown exporter renders all 4 sections
        session = AuditSession(mode="server", target_name="ShopHandler.luau")
        session.add_finding(f)
        md = generate_markdown_report(session)
        self.assertIn("#### 1. Vulnerability Trace & Locator", md)
        self.assertIn("#### 2. Vulnerable Server Handler (Current Code)", md)
        self.assertIn("#### 3. Parameter Contract & Edge-Case Matrix", md)
        self.assertIn("#### 4. Defensive Server-Side Remediation & Guard Module (Patched Code + Unit Test)", md)

    def test_web_catalog_exact_150000_and_ui_web_workbench(self) -> None:
        import time
        from urllib.request import Request, urlopen
        from rcdebug.ui_web import bind_ui_web_workbench_server, build_ui_web_html, classify_web_finding_surface
        from rcdebug.web_catalog import (
            WEB_FLAWS_GZ_PATH,
            audit_web_source,
            build_browser_qa_runner_script,
            ensure_web_flaws_txt,
            get_web_catalog,
            get_web_debugger_pack,
        )

        # 1. Exact 150,000 website flaws (RCW-000001 .. RCW-150000)
        self.assertTrue(WEB_FLAWS_GZ_PATH.exists())
        web_txt = ensure_web_flaws_txt()
        with web_txt.open("rb") as fh:
            self.assertEqual(sum(1 for ln in fh if ln.strip()), 150000)

        wcat = get_web_catalog()
        self.assertEqual(wcat.count(), 150000)
        first_sig = wcat.get("RCW-000001")
        last_sig = wcat.get("RCW-150000")
        self.assertIsNotNone(first_sig)
        self.assertIsNotNone(last_sig)
        assert first_sig is not None and last_sig is not None
        self.assertEqual(first_sig.severity, "CRITICAL")
        self.assertEqual(first_sig.rank, 1)
        self.assertEqual(last_sig.severity, "INFO")
        self.assertEqual(last_sig.rank, 150000)

        # Sub-15ms lookup across 150,000 web flaws
        t0 = time.perf_counter()
        hits = wcat.match_name("innerhtml_comment", container_hint="ReactClientComponent")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.assertLess(elapsed_ms, 15.0)
        self.assertGreaterEqual(len(hits), 1)

        # 2. 120 Web Debugger Probes & Offline Browser DevTools QA Script
        wpack = get_web_debugger_pack()
        self.assertEqual(wpack.count(), 120)
        qa_js = build_browser_qa_runner_script()
        self.assertIn("[PASS]", qa_js)
        self.assertIn("[FAIL]", qa_js)
        self.assertIn("[rcdebug-web QA Summary]", qa_js)
        self.assertNotIn("fetch(", qa_js)

        # 3. Static web source auditing & 4-section JS/TS Contract Specification
        web_src = (
            'app.post("/api/checkout", async (req, res) => {\n'
            '  const price = req.body.price;\n'
            '  const qty = req.body.qty;\n'
            '  await db.$queryRawUnsafe(`UPDATE wallets SET balance = balance - ${price * qty}`);\n'
            '  localStorage.setItem("jwt", req.body.token);\n'
            '  document.getElementById("receipt").innerHTML = req.body.note;\n'
            '});\n'
        )
        w_findings = audit_web_source("src/routes/checkout.ts", web_src)
        self.assertGreaterEqual(len(w_findings), 4)
        route_f = next(f for f in w_findings if "POST /api/checkout" in f.title)
        w_spec = route_f.metadata["contract_spec"]
        self.assertEqual(w_spec["trace_locator"]["line_number"], 1)
        self.assertIn("price", w_spec["trace_locator"]["unvalidated_parameters"])
        self.assertIn("// Simple summary:", w_spec["vulnerable_handler_code"])
        self.assertIn("// What this does:", w_spec["patched_guard_and_unit_test_code"])
        self.assertIn("console.assert(", w_spec["patched_guard_and_unit_test_code"])

        # 4. CLI flag --ui-web & live HTTP endpoints
        args = build_parser().parse_args(["--ui-web", "--no-browser"])
        self.assertTrue(args.ui_web)
        self.assertNotIn("—", build_ui_web_html())

        session = AuditSession(mode="ui-web", target_name="WebWorkbenchTest")
        server, port, _ = bind_ui_web_workbench_server("127.0.0.1", 0, session)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{port}/ui", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("rcdebug Web Workbench (--ui-web)", resp.read().decode("utf-8"))

            with urlopen(f"http://127.0.0.1:{port}/api/state", timeout=3) as resp:
                st = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(st["catalog_count"], 150000)
                self.assertIn("Offline Browser DevTools QA Test Runner", st["luau_script"])

            with urlopen(f"http://127.0.0.1:{port}/api/catalog?q=xss&surface=exploit&limit=5", timeout=3) as resp:
                cat_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(len(cat_res["results"]), 5)
                self.assertTrue(all(r["surface"] == "exploit" for r in cat_res["results"]))
                self.assertTrue(all(len(r["overviews"]) >= 4 for r in cat_res["results"]))
        finally:
            server.shutdown()
            server.server_close()

    def test_windows_cross_platform_support(self) -> None:
        from unittest.mock import patch
        import rcdebug
        from rcdebug.client_bridge import default_roblox_logs_dir
        from rcdebug.mcp_inspector import candidate_mcp_config_paths
        from rcdebug.terminal import clipboard_label, copy_to_clipboard

        self.assertEqual(rcdebug.__version__, "2.0.0")
        win_bat = Path(__file__).resolve().parent.parent / "bin" / "rcdebug.bat"
        self.assertTrue(win_bat.exists())

        with patch("sys.platform", "win32"), patch.dict(
            "os.environ",
            {"LOCALAPPDATA": "/tmp/win_local", "APPDATA": "/tmp/win_roaming"},
            clear=False,
        ):
            self.assertEqual(default_roblox_logs_dir(), Path("/tmp/win_local") / "Roblox" / "logs")
            self.assertEqual(clipboard_label(), "Windows clipboard")
            mcp_paths = [str(p) for p in candidate_mcp_config_paths()]
            self.assertTrue(any("Claude" in p and "win_roaming" in p for p in mcp_paths))
            self.assertTrue(any("Cursor" in p and "win_roaming" in p for p in mcp_paths))
            with patch("shutil.which", side_effect=lambda cmd: "C:\\Windows\\System32\\clip.exe" if cmd == "clip" else None), patch(
                "subprocess.run"
            ) as mock_run:
                self.assertTrue(copy_to_clipboard("hello windows"))
                mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
