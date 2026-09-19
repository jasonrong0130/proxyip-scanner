import asyncio
import tempfile
import unittest
from pathlib import Path

import candidate_pool
from quality_score import calculate_quality_score


class CandidatePoolIncrementalTests(unittest.TestCase):
    def test_incremental_lifecycle_and_refresh_preserve_state(self) -> None:
        async def scenario() -> None:
            original_data_dir = candidate_pool._DATA_DIR
            original_catalog = candidate_pool._region_catalog
            original_sources = candidate_pool._region_sources
            try:
                with tempfile.TemporaryDirectory(prefix="proxyip-candidate-tests-") as tmp:
                    candidate_pool._DATA_DIR = Path(tmp)
                    now = candidate_pool._now()
                    region_data = {
                        "updated_at": now,
                        "count": 2,
                        "source_stats": [],
                        "candidates": [
                            {
                                "target": "8.8.8.8:443",
                                "source": "seed",
                                "sources": ["seed"],
                                "region_hints": ["HK"],
                                "first_seen_at": now,
                                "last_seen_at": now,
                            },
                            {
                                "target": "1.1.1.1:443",
                                "source": "seed",
                                "sources": ["seed"],
                                "region_hints": ["HK"],
                                "first_seen_at": now,
                                "last_seen_at": now,
                            },
                        ],
                    }
                    candidate_pool._save_json(candidate_pool._region_pool_name("HK"), region_data)
                    candidate_pool._record_region_meta("HK", region_data)
                    candidate_pool._save_json("candidate_verified.json", {"regions": {}, "updated_at": None})

                    initial = await candidate_pool.get_scan_targets("HK")
                    self.assertEqual(set(initial), {"8.8.8.8:443", "1.1.1.1:443"})

                    await candidate_pool.record_scan_results(
                        "HK",
                        [
                            {
                                "candidate": "8.8.8.8:443",
                                "available": True,
                                "final_available": True,
                                "tcp_ms": 35,
                                "tls_ms": 70,
                            },
                            {
                                "candidate": "1.1.1.1:443",
                                "available": False,
                                "final_available": False,
                            },
                        ],
                    )
                    self.assertEqual(await candidate_pool.get_scan_targets("HK"), [])

                    pool = candidate_pool._load_region_pool("HK")
                    rows = {row["target"]: row for row in pool["candidates"]}
                    self.assertTrue(rows["8.8.8.8:443"]["final_available"])
                    self.assertEqual(rows["1.1.1.1:443"]["consecutive_failures"], 1)
                    self.assertGreater(
                        int(rows["8.8.8.8:443"]["quality_score"]),
                        int(rows["1.1.1.1:443"]["quality_score"]),
                    )

                    # A second failure should back off longer than a healthy endpoint.
                    await candidate_pool.record_scan_results(
                        "HK",
                        [{"candidate": "1.1.1.1:443", "available": False, "final_available": False}],
                    )
                    pool = candidate_pool._load_region_pool("HK")
                    for row in pool["candidates"]:
                        if row["target"] == "8.8.8.8:443":
                            row["last_checked_at"] = candidate_pool._now() - candidate_pool.AVAILABLE_RECHECK_INTERVAL - 10
                        else:
                            # Two consecutive failures use a 48h retry; 24h old is not due yet.
                            row["last_checked_at"] = candidate_pool._now() - candidate_pool.FAILED_RETRY_BASE - 10
                    candidate_pool._save_json(candidate_pool._region_pool_name("HK"), pool)
                    candidate_pool._record_region_meta("HK", pool)

                    due = await candidate_pool.get_scan_targets("HK")
                    self.assertEqual(due, ["8.8.8.8:443"])

                    verified = candidate_pool._verified_data()["regions"]["HK"]["results"]
                    self.assertEqual([row["candidate"] for row in verified], ["8.8.8.8:443"])

                    # Refresh adds one new address while preserving the checked state of the known one.
                    async def fake_catalog(force: bool = False) -> dict:
                        return {
                            "updated_at": candidate_pool._now(),
                            "regions": {"HK": {"count": 2, "candidates": ["8.8.8.8:443", "9.9.9.9:443"]}},
                        }

                    async def fake_sources(region: str) -> list[dict]:
                        return [
                            {
                                "name": "fake-source",
                                "region_hint": "HK",
                                "items": ["8.8.8.8:443", "9.9.9.9:443"],
                                "count": 2,
                                "status": "ok",
                                "ms": 1,
                            }
                        ]

                    candidate_pool._region_catalog = fake_catalog
                    candidate_pool._region_sources = fake_sources
                    await candidate_pool.refresh_region("HK")

                    refreshed = candidate_pool._load_region_pool("HK")["candidates"]
                    refreshed_rows = {row["target"]: row for row in refreshed}
                    self.assertIn("last_checked_at", refreshed_rows["8.8.8.8:443"])
                    self.assertNotIn("last_checked_at", refreshed_rows["9.9.9.9:443"])

                    pending = await candidate_pool.get_scan_targets("HK")
                    self.assertEqual(pending[0], "9.9.9.9:443")
            finally:
                candidate_pool._DATA_DIR = original_data_dir
                candidate_pool._region_catalog = original_catalog
                candidate_pool._region_sources = original_sources

        asyncio.run(scenario())

    def test_quality_score_rewards_verified_low_latency(self) -> None:
        good = calculate_quality_score(
            {
                "final_available": True,
                "tcp_ms": 40,
                "sources": ["a", "b"],
                "purity_score": 90,
                "risk_score": 10,
                "avg_mbps": 120,
            }
        )
        bad = calculate_quality_score(
            {
                "final_available": False,
                "last_checked_at": 1,
                "consecutive_failures": 3,
                "tcp_ms": 600,
                "sources": ["a"],
                "purity_score": 30,
                "risk_score": 80,
                "avg_mbps": 2,
            }
        )
        self.assertGreater(good, bad)


if __name__ == "__main__":
    unittest.main()
