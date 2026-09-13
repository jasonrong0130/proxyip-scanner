import asyncio
import os
import tempfile
import unittest
from pathlib import Path

TEST_DATA_DIR = tempfile.mkdtemp(prefix="proxyip-scanner-tests-")
os.environ["PROXY_SCANNER_DATA_DIR"] = TEST_DATA_DIR
os.environ.setdefault("ADMIN_PASSWORD_HASH", "x")
os.environ.setdefault("SESSION_SECRET", "x")

import app  # noqa: E402


def make_job(job_id: str, state: str = "completed", total: int = 2) -> dict:
    finished = app.now() if state not in app.JOB_ACTIVE_STATES else None
    return {
        "id": job_id,
        "created_at": app.now(),
        "started_at": app.now(),
        "finished_at": finished,
        "state": state,
        "cancel_requested": False,
        "interrupted_stage": None,
        "resume_available": False,
        "candidate_region": None,
        "targets": [f"8.8.8.{i + 1}:443" for i in range(total)],
        "total": total,
        "completed": total if state == "completed" else 0,
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
        "settings": {},
        "results": [
            {"candidate": f"8.8.8.{i + 1}:443", "state": "checked" if state == "completed" else "pending", "available": False}
            for i in range(total)
        ],
    }


class JobLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        app.JOBS.clear()
        app.POST_SPEED_TASKS.clear()
        app.PURITY_TASKS.clear()
        for path in Path(TEST_DATA_DIR).iterdir():
            if path.is_file():
                path.unlink()

    def test_release_job_memory_replaces_full_job_with_lazy_stub(self) -> None:
        job = make_job("111111111111")
        app.JOBS[job["id"]] = job
        app.persist_job(job)

        app.release_job_memory(job)

        stub = app.JOBS[job["id"]]
        self.assertTrue(stub["_lazy"])
        self.assertNotIn("targets", stub)
        self.assertNotIn("results", stub)
        self.assertNotIn("_task", stub)
        self.assertTrue(app.job_path(job["id"]).exists())

    def test_purge_job_removes_memory_and_all_job_files(self) -> None:
        job = make_job("222222222222")
        app.JOBS[job["id"]] = job
        app.persist_job(job)
        app.persist_job_meta(job)
        app.checkpoint_path(job["id"]).write_text('{"i":0,"row":{"state":"checked"}}\n', encoding="utf-8")

        result = app.purge_job(job["id"])

        self.assertTrue(result["deleted"])
        self.assertEqual(result["deleted_files"], 3)
        self.assertNotIn(job["id"], app.JOBS)
        self.assertFalse(app.job_path(job["id"]).exists())
        self.assertFalse(app.job_meta_path(job["id"]).exists())
        self.assertFalse(app.checkpoint_path(job["id"]).exists())

    def test_purge_history_removes_inactive_but_keeps_active_jobs(self) -> None:
        inactive = make_job("333333333333")
        active = make_job("444444444444", state="checking")
        app.JOBS[inactive["id"]] = inactive
        app.JOBS[active["id"]] = active
        app.persist_job(inactive)
        app.persist_job(active)

        result = app.purge_history_jobs()

        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["skipped_active"], 1)
        self.assertNotIn(inactive["id"], app.JOBS)
        self.assertIn(active["id"], app.JOBS)
        self.assertFalse(app.job_path(inactive["id"]).exists())
        self.assertTrue(app.job_path(active["id"]).exists())

    def test_cancelled_run_releases_full_job_reference(self) -> None:
        async def scenario() -> None:
            job = make_job("555555555555", state="queued")
            app.JOBS[job["id"]] = job
            app.persist_job(job)

            original = app._run_job_impl

            async def slow_impl(current: dict) -> None:
                current["state"] = "checking"
                await asyncio.sleep(3600)

            app._run_job_impl = slow_impl
            try:
                task = asyncio.create_task(app.run_job(job))
                job["_task"] = task
                await asyncio.sleep(0)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                app._run_job_impl = original

            stub = app.JOBS[job["id"]]
            self.assertEqual(stub["state"], "cancelled")
            self.assertTrue(stub["_lazy"])
            self.assertNotIn("targets", stub)
            self.assertNotIn("results", stub)
            self.assertNotIn("_task", stub)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
