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

        job_id = job["id"]
        result = app.purge_job(job_id)

        self.assertTrue(result["deleted"])
        self.assertEqual(result["deleted_files"], 3)
        self.assertNotIn(job_id, app.JOBS)
        self.assertFalse(app.job_path(job_id).exists())
        self.assertFalse(app.job_meta_path(job_id).exists())
        self.assertFalse(app.checkpoint_path(job_id).exists())
        self.assertEqual(job, {})

    def test_purge_history_removes_inactive_but_keeps_active_jobs(self) -> None:
        inactive = make_job("333333333333")
        active = make_job("444444444444", state="checking")
        app.JOBS[inactive["id"]] = inactive
        app.JOBS[active["id"]] = active
        app.persist_job(inactive)
        app.persist_job(active)

        inactive_id = inactive["id"]
        active_id = active["id"]
        result = app.purge_history_jobs()

        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["skipped_active"], 1)
        self.assertNotIn(inactive_id, app.JOBS)
        self.assertIn(active_id, app.JOBS)
        self.assertFalse(app.job_path(inactive_id).exists())
        self.assertTrue(app.job_path(active_id).exists())
        self.assertEqual(inactive, {})

    def test_completed_history_stub_skips_checkpoint_replay_and_meta_rewrite(self) -> None:
        job = make_job("666666666666")
        app.persist_job(job)
        app.checkpoint_path(job["id"]).write_text(
            '{"i":0,"row":{"state":"checked","available":false}}\n',
            encoding="utf-8",
        )

        original_checkpoint = app._checkpoint_summary
        original_persist_meta = app.persist_job_meta

        def unexpected_checkpoint(*args, **kwargs):
            raise AssertionError("stable completed history must not replay checkpoints at startup")

        def unexpected_meta_write(*args, **kwargs):
            raise AssertionError("stable completed history must not rewrite meta at startup")

        app._checkpoint_summary = unexpected_checkpoint
        app.persist_job_meta = unexpected_meta_write
        try:
            stub = app.read_job_stub(app.job_path(job["id"]))
        finally:
            app._checkpoint_summary = original_checkpoint
            app.persist_job_meta = original_persist_meta

        self.assertIsNotNone(stub)
        self.assertEqual(stub["state"], "completed")
        self.assertTrue(stub["_lazy"])
        self.assertEqual(stub["total"], job["total"])

    def test_inflight_history_stub_replays_checkpoint_for_crash_recovery(self) -> None:
        job = make_job("777777777777", state="checking")
        app.persist_job(job)
        called = []
        original_checkpoint = app._checkpoint_summary

        def checkpoint(job_id: str, total: int) -> dict:
            called.append((job_id, total))
            return {"completed": 1, "available": 1}

        app._checkpoint_summary = checkpoint
        try:
            stub = app.read_job_stub(app.job_path(job["id"]))
        finally:
            app._checkpoint_summary = original_checkpoint

        self.assertEqual(called, [(job["id"], job["total"])])
        self.assertEqual(stub["state"], "interrupted")
        self.assertEqual(stub["interrupted_stage"], "checking")
        self.assertEqual(stub["completed"], 1)
        self.assertEqual(stub["available"], 1)
        self.assertTrue(stub["resume_available"])

    def test_runtime_interruption_is_resumable_after_restart(self) -> None:
        job = make_job("787878787878", state="runtime_checking", total=8)
        job["completed"] = 8
        job["runtime_total"] = 3
        job["runtime_completed"] = 1
        for index, row in enumerate(job["results"]):
            row["state"] = "checked"
            row["available"] = index < 3
            if index == 0:
                row["edt_available"] = True
                row["final_available"] = True
        app.persist_job(job)

        stub = app.read_job_stub(app.job_path(job["id"]))

        self.assertIsNotNone(stub)
        self.assertEqual(stub["state"], "interrupted")
        self.assertEqual(stub["interrupted_stage"], "runtime_checking")
        self.assertTrue(stub["resume_available"])

    def test_existing_interrupted_runtime_job_recovers_resume_flag(self) -> None:
        job = make_job("797979797979", state="interrupted", total=8)
        job["interrupted_stage"] = "runtime_checking"
        job["resume_available"] = False
        job["completed"] = 5
        for index, row in enumerate(job["results"]):
            row["state"] = "checked" if index < 5 else "pending"
            row["available"] = index < 2
        app.persist_job(job)

        stub = app.read_job_stub(app.job_path(job["id"]))

        self.assertIsNotNone(stub)
        self.assertEqual(stub["state"], "interrupted")
        self.assertEqual(stub["interrupted_stage"], "runtime_checking")
        self.assertTrue(stub["resume_available"])

    def test_large_interrupted_job_disables_resume_without_hydrate(self) -> None:
        job = make_job("888888888888", state="checking", total=app.MAX_RESUME_ITEMS + 1)
        job["interrupted_stage"] = "checking"
        job["resume_available"] = True
        app.persist_job(job)

        stub = app.read_job_stub(app.job_path(job["id"]))

        self.assertIsNotNone(stub)
        self.assertFalse(stub["resume_available"])
        self.assertIsNone(app.hydrate_job(job["id"]))

    def test_large_interrupted_memory_cleanup_drops_payload(self) -> None:
        job = make_job("999999999999", state="interrupted", total=app.MAX_RESUME_ITEMS + 1)
        app.JOBS[job["id"]] = job
        app.release_job_memory(job)
        stub = app.JOBS[job["id"]]
        self.assertNotIn("targets", stub)
        self.assertNotIn("results", stub)

    def test_service_side_task_cancellation_becomes_resumable_interruption_and_releases_memory(self) -> None:
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
            self.assertEqual(stub["state"], "interrupted")
            self.assertEqual(stub["interrupted_stage"], "checking")
            self.assertTrue(stub["resume_available"])
            self.assertTrue(stub["_lazy"])
            self.assertNotIn("targets", stub)
            self.assertNotIn("results", stub)
            self.assertNotIn("_task", stub)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
