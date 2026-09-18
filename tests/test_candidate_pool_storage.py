import tempfile
import unittest
from pathlib import Path

import candidate_pool


class CandidatePoolStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="proxyip-candidate-pool-")
        self.previous_data_dir = candidate_pool._DATA_DIR
        candidate_pool._DATA_DIR = Path(self.tmp.name)

    def tearDown(self) -> None:
        candidate_pool._DATA_DIR = self.previous_data_dir
        self.tmp.cleanup()

    def test_legacy_pool_migrates_to_region_files_once(self) -> None:
        legacy = {
            "updated_at": 1234.5,
            "regions": {
                "HK": {
                    "updated_at": 1200.0,
                    "count": 2,
                    "candidates": [
                        {"target": "1.1.1.1:443", "sources": ["a"], "region_hints": ["HK"]},
                        {"target": "1.0.0.1:443", "sources": ["b"], "region_hints": ["HK"]},
                    ],
                    "source_stats": [],
                },
                "US": {
                    "updated_at": 1210.0,
                    "count": 1,
                    "candidates": [
                        {"target": "8.8.8.8:443", "sources": ["c"], "region_hints": ["US"]},
                    ],
                    "source_stats": [],
                },
            },
        }
        candidate_pool._save_json("candidate_pool.json", legacy)
        candidate_pool._save_json("candidate_pool_meta.json", {"last_refresh_at": 999.0})

        candidate_pool._migrate_legacy_pool()

        hk = candidate_pool._load_json("candidate_pool_HK.json", None)
        us = candidate_pool._load_json("candidate_pool_US.json", None)
        meta = candidate_pool._load_json("candidate_pool_meta.json", {})

        self.assertEqual(hk["count"], 2)
        self.assertEqual(us["count"], 1)
        self.assertTrue(meta["split_pool_v1"])
        self.assertEqual(meta["last_refresh_at"], 999.0)
        self.assertEqual(meta["region_counts"]["HK"]["count"], 2)
        self.assertEqual(meta["region_counts"]["US"]["count"], 1)
        self.assertEqual(meta["pool_updated_at"], 1234.5)

        # Once migrated, normal region reads must not depend on the old large file.
        candidate_pool._save_json("candidate_pool.json", {"updated_at": 0, "regions": {}})
        loaded = candidate_pool._load_region_pool("HK")
        self.assertEqual(loaded["count"], 2)
        self.assertEqual(len(loaded["candidates"]), 2)

    def test_json_writer_uses_compact_stream_format(self) -> None:
        payload = {"rows": [{"target": f"10.0.0.{i}:443", "sources": ["x"]} for i in range(20)]}
        candidate_pool._save_json("compact.json", payload)

        raw = (Path(self.tmp.name) / "compact.json").read_text(encoding="utf-8")
        self.assertNotIn("\n  ", raw)
        self.assertEqual(candidate_pool._load_json("compact.json", {}), payload)


if __name__ == "__main__":
    unittest.main()
