import asyncio
import os
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("PROXY_SCANNER_DATA_DIR", tempfile.mkdtemp(prefix="proxyip-v12-tests-"))
os.environ.setdefault("ADMIN_PASSWORD_HASH", "x")
os.environ.setdefault("SESSION_SECRET", "x")

import app  # noqa: E402
import candidate_pool  # noqa: E402


class FakeRequest:
    headers = {}


class V12LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="proxyip-v12-guard-")
        self.data_dir = Path(self.tmp.name)
        self.previous_pool_dir = candidate_pool._DATA_DIR
        candidate_pool._DATA_DIR = self.data_dir

    def tearDown(self) -> None:
        candidate_pool._DATA_DIR = self.previous_pool_dir
        self.tmp.cleanup()

    def save_verified_fixture(self) -> None:
        candidate_pool._save_json(
            "candidate_verified.json",
            {
                "updated_at": 1789815311.102502,
                "regions": {
                    "HK": {
                        "updated_at": 1789815311.102502,
                        "final_available": 1,
                        "results": [{
                            "target": "156.244.57.227:443",
                            "quality_score": 95,
                            "avg_mbps": 120,
                            "tcp_ms": 38,
                            "tls_ms": 50,
                            "purity": {"network_type": "机房IP", "is_idc": True},
                            "success_count": 10,
                            "failure_count": 0,
                            "check_count": 10,
                            "last_verified_at": 1789815311.102502,
                        }],
                    }
                },
            },
        )

    def test_full_scan_runs_in_batches_and_persists_progress(self) -> None:
        async def scenario() -> None:
            job = {
                "id": "batch-v12",
                "candidate_region": None,
                "scan_mode": "full",
                "batch_size": 2,
                "batch_count": 3,
                "current_batch": 0,
                "completed_batches": 0,
                "created_at": app.now(),
                "started_at": None,
                "finished_at": None,
                "state": "queued",
                "cancel_requested": False,
                "pause_requested": False,
                "resume_available": False,
                "interrupted_stage": None,
                "targets": [f"8.8.8.{i}:443" for i in range(1, 6)],
                "total": 5,
                "completed": 0,
                "available": 0,
                "final_available": 0,
                "generic_available": 0,
                "same_exit": 0,
                "runtime_total": 0,
                "runtime_completed": 0,
                "runtime_available": 0,
                "speed_total": 0,
                "speed_completed": 0,
                "purity_total": 0,
                "purity_completed": 0,
                "settings": {
                    "probe_sni": "example.com",
                    "probe_path": "/cdn-cgi/trace",
                    "expect_cloudflare": True,
                    "generic_sni": "",
                    "timeout": 2,
                    "check_concurrency": 2,
                    "edt_runtime": {"enabled": False},
                    "speed": {"enabled": False},
                },
                "results": [
                    {"candidate": f"8.8.8.{i}:443", "state": "pending"}
                    for i in range(1, 6)
                ],
            }
            original_probe = app.test_one
            original_release = app.release_job_memory

            async def fake_probe(raw, *args, **kwargs):
                return {"candidate": raw, "available": False, "final_available": False, "state": "checked"}

            app.test_one = fake_probe
            app.release_job_memory = lambda current: None
            try:
                await app._run_job_impl(job)
            finally:
                app.test_one = original_probe
                app.release_job_memory = original_release

            self.assertEqual(job["state"], "completed")
            self.assertEqual(job["completed"], 5)
            self.assertEqual(job["completed_batches"], 3)
            self.assertEqual(job["current_batch"], 3)
            self.assertEqual(job["batch_count"], 3)
            self.assertEqual(app.read_job_stub(app.job_path(job["id"]))["completed_batches"], 3)

            for row in job["results"]:
                row.clear()
                row.update({"candidate": "8.8.8.1:443", "state": "pending"})
            job["state"] = "queued"
            job["completed"] = 0
            job["completed_batches"] = 0
            job["current_batch"] = 0
            job["finished_at"] = None
            async def failing_probe(raw, *args, **kwargs):
                raise RuntimeError("probe failed")
            app.test_one = failing_probe
            app.release_job_memory = lambda current: None
            try:
                with self.assertRaises(RuntimeError):
                    await app.run_job(job)
            finally:
                app.test_one = original_probe
                app.release_job_memory = original_release
            self.assertEqual(job["state"], "interrupted")
            self.assertTrue(job["resume_available"])
            self.assertEqual(job["interrupted_stage"], "checking")

        asyncio.run(scenario())

    def test_verified_source_and_asn_feedback_are_updated(self) -> None:
        async def scenario() -> None:
            now = candidate_pool._now()
            candidate_pool._save_json(
                candidate_pool._region_pool_name("HK"),
                {
                    "updated_at": now,
                    "count": 1,
                    "source_stats": [],
                    "candidates": [{
                        "target": "1.1.1.1:443",
                        "source": "source-a",
                        "sources": ["source-a"],
                        "region_hints": ["HK"],
                        "first_seen_at": now,
                        "last_seen_at": now,
                    }],
                },
            )
            candidate_pool._save_json("candidate_pool_meta.json", {"region_counts": {"HK": {"count": 1}}})
            result = await candidate_pool.record_scan_results("HK", [{
                "candidate": "1.1.1.1:443",
                "available": True,
                "final_available": True,
                "entry_asn": "AS13335",
                "tcp_ms": 20,
            }])
            self.assertEqual(result["verified"], 1)
            self.assertEqual(candidate_pool._verified_data()["regions"]["HK"]["final_available"], 1)
            source = candidate_pool._load_json("source_quality.json", {})["sources"]["source-a"]
            self.assertEqual(source["contributed"], 1)
            self.assertEqual(source["verified"], 1)
            self.assertEqual(source["success_rate"], 1.0)
            asn = candidate_pool._load_json("asn_quality.json", {})["asns"]["13335"]
            self.assertEqual(asn["sample_count"], 1)
            self.assertEqual(asn["success_rate"], 1.0)

        asyncio.run(scenario())

    def test_quality_history_prioritizes_sources_and_asns(self) -> None:
        source_quality = {"source-a": {"success_rate": 0.2, "avg_score": 40}, "source-b": {"success_rate": 0.9, "avg_score": 70}}
        self.assertGreater(
            candidate_pool._source_quality_sort_key({"name": "source-b"}, source_quality),
            candidate_pool._source_quality_sort_key({"name": "source-a"}, source_quality),
        )

        async def scenario() -> None:
            candidate_pool._save_json("candidate_verified.json", {
                "regions": {"HK": {"results": [
                    {"candidate": "1.1.1.1:443", "entry_asn": "100", "quality_score": 10},
                    {"candidate": "2.2.2.2:443", "entry_asn": "200", "quality_score": 9},
                ]}}
            })
            candidate_pool._save_json("asn_quality.json", {
                "asns": {
                    "100": {"success_rate": 0.1, "avg_score": 20, "sample_count": 2},
                    "200": {"success_rate": 0.9, "avg_score": 80, "sample_count": 2},
                }
            })
            calls = []
            original_fetch = candidate_pool._fetch_ripe_asn_prefixes

            async def fake_fetch(asn):
                calls.append(str(asn))
                return ["1.1.1.0/24"]

            candidate_pool._fetch_ripe_asn_prefixes = fake_fetch
            try:
                await candidate_pool._discover_asn_candidates("HK")
            finally:
                candidate_pool._fetch_ripe_asn_prefixes = original_fetch
            self.assertEqual(calls[:2], ["200", "100"])

        asyncio.run(scenario())

    def test_legacy_verified_pool_migrates_to_v12_store(self) -> None:
        now = candidate_pool._now()
        candidate_pool._save_json(
            candidate_pool._region_pool_name("HK"),
            {
                "updated_at": now,
                "count": 1,
                "candidates": [
                    {
                        "target": "1.1.1.1:443",
                        "final_available": True,
                        "source": "legacy-source",
                    }
                ],
            },
        )
        candidate_pool._save_json("candidate_pool_meta.json", {"region_counts": {"HK": {"count": 1}}})

        verified = candidate_pool._verified_data()

        self.assertEqual(verified["regions"]["HK"]["final_available"], 1)
        self.assertEqual(verified["regions"]["HK"]["results"][0]["target"], "1.1.1.1:443")
        self.assertTrue((candidate_pool._DATA_DIR / "candidate_verified.json").exists())

    def test_verified_api_returns_flat_results_matching_total(self) -> None:
        self.save_verified_fixture()
        original_require = candidate_pool._REQUIRE_WEB_SESSION
        candidate_pool._REQUIRE_WEB_SESSION = lambda request: {}
        try:
            payload = asyncio.run(candidate_pool.api_verified_pool(FakeRequest()))
        finally:
            candidate_pool._REQUIRE_WEB_SESSION = original_require

        self.assertIn("results", payload)
        self.assertNotIn("regions", payload)
        self.assertEqual(payload["total"], len(payload["results"]))
        self.assertEqual(payload["results"], [{
            "target": "156.244.57.227:443",
            "region": "HK",
            "quality_score": 95,
            "avg_mbps": 120,
            "tcp_ms": 38,
            "tls_ms": 50,
            "purity": "IDC",
            "success_count": 10,
            "failure_count": 0,
            "check_count": 10,
            "last_verified_at": 1789815311.102502,
        }])

    def test_verified_exports_use_flat_columns_and_txt_targets_only(self) -> None:
        self.save_verified_fixture()
        original_require = app.require_web_session
        app.require_web_session = lambda request: {}
        try:
            txt = asyncio.run(app.export_verified_txt(FakeRequest()))
            csv = asyncio.run(app.export_verified_csv(FakeRequest()))
        finally:
            app.require_web_session = original_require

        txt_rows = txt.body.decode("utf-8").splitlines()
        self.assertEqual(txt_rows, ["156.244.57.227:443"])
        self.assertTrue(all(re.fullmatch(r"[^:\s]+:\d+", row) for row in txt_rows))
        self.assertIn("text/plain", txt.media_type)

        csv_text = csv.body.decode("utf-8-sig")
        self.assertEqual(
            csv_text.splitlines()[0],
            "节点,地区,质量分,速度(Mbps),延迟(ms),纯净度,成功率,更新时间",
        )
        self.assertNotIn("1789815311", csv_text)
        self.assertIn("156.244.57.227:443,HK,95,120,38,IDC,100%", csv_text)
        self.assertRegex(csv_text, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

    def test_verified_frontend_uses_results_and_requested_layout(self) -> None:
        html = (Path(__file__).parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        verified_script = html[html.index("function renderVerifiedPool"):html.index("$('poolRegion').onchange")]
        self.assertNotIn("verifiedPreview", html)
        self.assertNotRegex(verified_script, r"(?:data|verifiedAll)\?*\.regions")
        self.assertIn("data?.results", verified_script)

        candidate_at = html.index('<div class="c6"><label>候选预览</label>')
        source_at = html.index('<div class="c6"><label>来源统计</label>')
        verified_at = html.index('<div class="c12"><div class="section-head"', candidate_at)
        self.assertLess(candidate_at, source_at)
        self.assertLess(source_at, verified_at)


if __name__ == "__main__":
    unittest.main()
