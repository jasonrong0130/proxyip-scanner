import asyncio
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("PROXY_SCANNER_DATA_DIR", tempfile.mkdtemp(prefix="proxyip-v12-tests-"))
os.environ.setdefault("ADMIN_PASSWORD_HASH", "x")
os.environ.setdefault("SESSION_SECRET", "x")

import app  # noqa: E402
import candidate_pool  # noqa: E402


class V12LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="proxyip-v12-guard-")
        self.data_dir = Path(self.tmp.name)
        self.previous_pool_dir = candidate_pool._DATA_DIR
        candidate_pool._DATA_DIR = self.data_dir

    def tearDown(self) -> None:
        candidate_pool._DATA_DIR = self.previous_pool_dir
        self.tmp.cleanup()

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
            self.assertEqual(result["final_available"], 1)
            pool = candidate_pool._load_region_pool("HK")
            self.assertTrue(pool["candidates"][0]["final_available"])
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
            candidate_pool._save_json(candidate_pool._region_pool_name("HK"), {
                "updated_at": candidate_pool._now(),
                "count": 2,
                "source_stats": [],
                "candidates": [
                    {"target": "1.1.1.1:443", "entry_asn": "100", "quality_score": 10, "final_available": True, "region_hints": ["HK"]},
                    {"target": "2.2.2.2:443", "entry_asn": "200", "quality_score": 9, "final_available": True, "region_hints": ["HK"]},
                ],
            })
            candidate_pool._record_region_meta("HK", candidate_pool._load_json(candidate_pool._region_pool_name("HK"), {}))
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


if __name__ == "__main__":
    unittest.main()
