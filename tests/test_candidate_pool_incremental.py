import asyncio
import tempfile
import unittest
from pathlib import Path

import candidate_pool
from purity import _normalize_ippure
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
                                "purity": {"provider": "IPPure", "purity_score": 18, "risk_score": 18},
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

    def test_region_pool_rejects_unscoped_global_sources_and_has_no_count_cap(self) -> None:
        async def scenario() -> None:
            original_data_dir = candidate_pool._DATA_DIR
            original_catalog = candidate_pool._region_catalog
            original_sources = candidate_pool._region_sources
            try:
                with tempfile.TemporaryDirectory(prefix="proxyip-region-scope-") as tmp:
                    candidate_pool._DATA_DIR = Path(tmp)
                    ar_targets = [f"10.0.{i // 250}.{i % 250 + 1}:443" for i in range(5005)]

                    async def fake_catalog(force: bool = False) -> dict:
                        return {
                            "updated_at": candidate_pool._now(),
                            "regions": {"AR": {"count": len(ar_targets), "candidates": ar_targets}},
                        }

                    async def fake_sources(region: str) -> list[dict]:
                        self.assertEqual(region, "AR")
                        return [
                            {
                                "name": "AR source",
                                "region_hint": "AR",
                                "items": ar_targets + ar_targets[:25],
                                "count": len(ar_targets),
                                "status": "ok",
                                "ms": 1,
                                "source_weight": 50,
                            },
                            {
                                "name": "global source",
                                "region_hint": None,
                                "items": [f"192.0.2.{i % 250 + 1}:443" for i in range(5000)],
                                "count": 5000,
                                "status": "ok",
                                "ms": 1,
                                "source_weight": 40,
                            },
                        ]

                    candidate_pool._region_catalog = fake_catalog
                    candidate_pool._region_sources = fake_sources
                    data = await candidate_pool.refresh_region("AR")

                    # _build_region_data accepts only region-tagged sources; duplicate rows
                    # from the same source are collapsed before source contribution stats.
                    scoped = [row for row in data["candidates"] if "AR" in (row.get("region_hints") or [])]
                    self.assertEqual(len(scoped), len(ar_targets))
                    self.assertEqual(data["count"], len(ar_targets))
                    self.assertGreater(data["count"], 5000)

                    scan_targets = await candidate_pool.get_scan_targets("AR", force=True)
                    self.assertEqual(len(scan_targets), len(ar_targets))
                    self.assertEqual(set(scan_targets), set(ar_targets))
            finally:
                candidate_pool._DATA_DIR = original_data_dir
                candidate_pool._region_catalog = original_catalog
                candidate_pool._region_sources = original_sources

        asyncio.run(scenario())

    def test_existing_polluted_region_pool_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="proxyip-region-clean-") as tmp:
            previous = candidate_pool._DATA_DIR
            try:
                candidate_pool._DATA_DIR = Path(tmp)
                data = {
                    "updated_at": candidate_pool._now(),
                    "count": 3,
                    "source_stats": [],
                    "candidates": [
                        {"target": "1.1.1.1:443", "region_hints": ["AR"]},
                        {"target": "2.2.2.2:443", "region_hints": ["AR"]},
                        {"target": "3.3.3.3:443", "region_hints": [], "source": "VPNGate", "sources": ["VPNGate"]},
                    ],
                }
                candidate_pool._save_json(candidate_pool._region_pool_name("AR"), data)
                candidate_pool._record_region_meta("AR", data)
                loaded = candidate_pool._load_region_pool("AR")
                self.assertEqual(loaded["count"], 2)
                self.assertEqual({row["target"] for row in loaded["candidates"]}, {"1.1.1.1:443", "2.2.2.2:443"})
            finally:
                candidate_pool._DATA_DIR = previous

    def test_ippure_coefficient_is_returned_without_inversion(self) -> None:
        self.assertEqual(_normalize_ippure({"fraudScore": 27})["purity_score"], 27)

    def test_quality_score_is_based_only_on_ippure_coefficient(self) -> None:
        row = {
            "final_available": False,
            "check_count": 50,
            "success_count": 1,
            "tcp_ms": 900,
            "avg_mbps": 1,
            "purity": {"provider": "IPPure", "purity_score": 27, "risk_score": 27},
        }
        self.assertEqual(calculate_quality_score(row), 73)

    def test_quality_score_ignores_non_purity_metrics_and_clamps(self) -> None:
        fast = {"final_available": True, "tcp_ms": 10, "avg_mbps": 1000, "purity_score": 120}
        slow = {"final_available": False, "tcp_ms": 900, "avg_mbps": 0, "purity_score": -10}
        unchecked = {"final_available": True, "tcp_ms": 10, "avg_mbps": 1000}
        self.assertEqual(calculate_quality_score(fast), 0)
        self.assertEqual(calculate_quality_score(slow), 100)
        self.assertEqual(calculate_quality_score(unchecked), 0)

    def test_candidate_keep_prefers_trusted_source(self) -> None:
        trusted = candidate_pool._candidate_keep_key({
            "final_available": True,
            "quality_score": 80,
            "source_weight": 80,
            "success_count": 20,
            "sources": ["verified"],
        })
        normal = candidate_pool._candidate_keep_key({
            "final_available": True,
            "quality_score": 80,
            "source_weight": 40,
            "success_count": 20,
            "sources": ["public"],
        })
        self.assertGreater(trusted, normal)


if __name__ == "__main__":
    unittest.main()
