import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

import app


class FakeRequest:
    def __init__(self, payload=None):
        self.payload = payload or {}

    async def json(self):
        return self.payload


class DummyTask:
    def __init__(self, done=False):
        self._done = done
        self.cancelled = False

    def done(self):
        return self._done

    def cancel(self):
        self.cancelled = True
        self._done = True


def make_job(job_id: str, state: str = "completed", total: int = 3) -> dict:
    results = [
        {
            "candidate": f"8.8.8.{i + 1}:443",
            "state": "checked" if state == "completed" else "pending",
            "available": False if state == "completed" else None,
        }
        for i in range(total)
    ]
    return {
        "id": job_id,
        "created_at": app.now(),
        "started_at": app.now(),
        "finished_at": app.now() if state not in app.JOB_ACTIVE_STATES else None,
        "state": state,
        "cancel_requested": False,
        "interrupted_stage": None,
        "resume_available": False,
        "candidate_region": None,
        "targets": [row["candidate"] for row in results],
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
        "settings": {
            "probe_sni": "example.com",
            "probe_path": "/cdn-cgi/trace",
            "expect_cloudflare": True,
            "generic_sni": "",
            "timeout": 7.0,
            "check_concurrency": 20,
            "scan_ports": [443],
            "edt_runtime": {"enabled": False, "concurrency": 2},
            "speed": {"enabled": False},
        },
        "results": results,
    }


class JobStateMachineRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="proxyip-state-machine-")
        self.old_data_dir = app.DATA_DIR
        app.DATA_DIR = Path(self.tmp.name)
        app.JOBS.clear()
        app.POST_SPEED_TASKS.clear()
        app.PURITY_TASKS.clear()

    def tearDown(self):
        for job in list(app.JOBS.values()):
            task = job.get("_task") if isinstance(job, dict) else None
            if task is not None and hasattr(task, "done") and not task.done():
                task.cancel()
        app.JOBS.clear()
        app.POST_SPEED_TASKS.clear()
        app.PURITY_TASKS.clear()
        app.DATA_DIR = self.old_data_dir
        self.tmp.cleanup()

    def _without_auth(self):
        original_web = app.require_web_session
        original_csrf = app.require_csrf
        app.require_web_session = lambda request: {"sub": app.ADMIN_USER}
        app.require_csrf = lambda request, payload: None
        return original_web, original_csrf

    def test_listing_jobs_must_not_convert_live_task_to_interrupted_or_drop_task_reference(self):
        job = make_job("a11111111111", state="checking", total=3)
        job["results"][0] = {
            "candidate": "8.8.8.1:443",
            "state": "checked",
            "available": False,
        }
        job["completed"] = 1
        app.persist_job(job)
        live_task = DummyTask(done=False)
        job["_task"] = live_task
        app.JOBS[job["id"]] = job

        original_web, original_csrf = self._without_auth()
        try:
            asyncio.run(app.list_jobs(FakeRequest()))
        finally:
            app.require_web_session = original_web
            app.require_csrf = original_csrf

        self.assertIs(app.JOBS[job["id"]], job)
        self.assertEqual(app.JOBS[job["id"]]["state"], "checking")
        self.assertIs(app.JOBS[job["id"]]["_task"], live_task)
        self.assertFalse(live_task.done())

    def test_runtime_resume_processes_only_rows_without_edt_result_and_rebuilds_counters(self):
        job = make_job("b22222222222", state="interrupted", total=3)
        job["interrupted_stage"] = "runtime_checking"
        job["resume_available"] = True
        job["finished_at"] = app.now()
        job["settings"]["edt_runtime"] = {"enabled": True, "concurrency": 2}
        job["results"] = [
            {
                "candidate": "8.8.8.1:443",
                "host": "8.8.8.1",
                "port": 443,
                "state": "checked",
                "available": True,
                "edt_available": True,
                "final_available": True,
            },
            {
                "candidate": "8.8.8.2:443",
                "host": "8.8.8.2",
                "port": 443,
                "state": "checked",
                "available": True,
                "edt_available": False,
                "final_available": False,
            },
            {
                "candidate": "8.8.8.3:443",
                "host": "8.8.8.3",
                "port": 443,
                "state": "checked",
                "available": True,
                "edt_available": None,
                "final_available": None,
            },
        ]
        job["targets"] = [row["candidate"] for row in job["results"]]
        app.JOBS[job["id"]] = job
        calls = []

        original_check = app.check_edt_runtime_selected
        original_enrich = app.enrich_result

        async def fake_runtime(candidate, *args, **kwargs):
            calls.append(candidate)
            return {"ok": True, "ms": 1.0}

        async def fake_enrich(row, data_dir):
            return row

        app.check_edt_runtime_selected = fake_runtime
        app.enrich_result = fake_enrich
        try:
            asyncio.run(app._run_job_impl(job))
        finally:
            app.check_edt_runtime_selected = original_check
            app.enrich_result = original_enrich

        self.assertEqual(calls, ["8.8.8.3:443"])
        self.assertTrue(job["results"][0]["edt_available"])
        self.assertFalse(job["results"][1]["edt_available"])
        self.assertTrue(job["results"][2]["edt_available"])
        self.assertEqual(job["runtime_total"], 3)
        self.assertEqual(job["runtime_completed"], 3)
        self.assertEqual(job["runtime_available"], 2)
        self.assertEqual(job["final_available"], 2)
        self.assertLessEqual(job["runtime_completed"], job["runtime_total"])

    def test_resume_endpoint_finishes_partial_edt_without_recounting_completed_rows(self):
        async def scenario():
            job = make_job("bb22bb22bb22", state="interrupted", total=3)
            job["interrupted_stage"] = "runtime_checking"
            job["resume_available"] = True
            job["finished_at"] = app.now()
            job["settings"]["edt_runtime"] = {"enabled": True, "concurrency": 2}
            job["results"] = [
                {
                    "candidate": "8.8.8.1:443",
                    "host": "8.8.8.1",
                    "port": 443,
                    "state": "checked",
                    "available": True,
                    "edt_available": True,
                    "final_available": True,
                },
                {
                    "candidate": "8.8.8.2:443",
                    "host": "8.8.8.2",
                    "port": 443,
                    "state": "checked",
                    "available": True,
                    "edt_available": False,
                    "final_available": False,
                },
                {
                    "candidate": "8.8.8.3:443",
                    "host": "8.8.8.3",
                    "port": 443,
                    "state": "checked",
                    "available": True,
                    "edt_available": None,
                    "final_available": None,
                },
            ]
            job["targets"] = [row["candidate"] for row in job["results"]]
            app.rebuild_job_counters(job)
            job["runtime_total"] = 3
            app.persist_job(job)
            app.JOBS[job["id"]] = app.read_job_stub(app.job_path(job["id"]))

            calls = []
            original_check = app.check_edt_runtime_selected
            original_enrich = app.enrich_result
            original_web, original_csrf = self._without_auth()

            async def fake_runtime(candidate, *args, **kwargs):
                calls.append(candidate)
                return {"ok": True, "ms": 1.0}

            async def fake_enrich(row, data_dir):
                return row

            app.check_edt_runtime_selected = fake_runtime
            app.enrich_result = fake_enrich
            try:
                response = await app.resume_interrupted_scan(job["id"], FakeRequest({}))
                self.assertTrue(response["ok"])
                running = app.JOBS[job["id"]]
                task = running.get("_task")
                self.assertIsNotNone(task)
                await task
                final = app.hydrate_job(job["id"])
            finally:
                app.check_edt_runtime_selected = original_check
                app.enrich_result = original_enrich
                app.require_web_session = original_web
                app.require_csrf = original_csrf

            self.assertEqual(calls, ["8.8.8.3:443"])
            self.assertEqual(final["state"], "completed")
            self.assertEqual(final["runtime_total"], 3)
            self.assertEqual(final["runtime_completed"], 3)
            self.assertEqual(final["runtime_available"], 2)
            self.assertEqual(final["final_available"], 2)

        asyncio.run(scenario())

    def test_completed_job_with_full_edt_attempts_and_partial_passes_stays_completed(self):
        job = make_job("ee55ee55ee55", state="completed", total=7962)
        job["completed"] = 7962
        job["runtime_total"] = 2487
        job["runtime_completed"] = 2487
        job["runtime_available"] = 55
        job["final_available"] = 55
        job["finished_at"] = app.now()
        app.persist_job(job)

        stub = app.read_job_stub(app.job_path(job["id"]))

        self.assertEqual(stub["state"], "completed")
        self.assertFalse(bool(stub.get("resume_available")))
        self.assertEqual(stub["runtime_total"], 2487)
        self.assertEqual(stub["runtime_completed"], 2487)
        self.assertEqual(stub["runtime_available"], 55)
        self.assertEqual(stub["final_available"], 55)

    def test_ungraceful_restart_during_edt_preserves_progress_below_checkpoint_batch(self):
        job = make_job("ab12ab12ab12", state="runtime_checking", total=80)
        job["settings"]["edt_runtime"] = {"enabled": True, "concurrency": 1}
        for row in job["results"]:
            row.update({
                "host": row["candidate"].split(":")[0],
                "port": 443,
                "state": "checked",
                "available": True,
                "edt_available": None,
                "final_available": None,
            })
        app.rebuild_job_counters(job)
        job["runtime_total"] = 80

        # This is the durable snapshot at EDT start.
        app.persist_job(job)

        # Twelve EDT results finish in memory, but the default checkpoint batch is
        # larger than twelve. A real hard process loss must not make these rows run
        # again after restart.
        for idx in range(12):
            row = job["results"][idx]
            row["edt_available"] = (idx % 3 == 0)
            row["final_available"] = row["edt_available"]
            app.checkpoint_result(job, idx)
        app.rebuild_job_counters(job)
        job["runtime_total"] = 80
        self.assertEqual(job["runtime_completed"], 12)

        # Simulate abrupt process loss: all in-memory state/buffers disappear.
        app.JOBS.clear()
        app.load_job_index()
        recovered = app.hydrate_job(job["id"])

        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["state"], "interrupted")
        self.assertEqual(recovered["interrupted_stage"], "runtime_checking")
        self.assertTrue(recovered["resume_available"])
        self.assertEqual(recovered["runtime_total"], 80)
        self.assertEqual(recovered["runtime_completed"], 12)
        self.assertEqual(
            sum(1 for row in recovered["results"] if row.get("edt_available") is None),
            68,
        )

    def test_server_shutdown_cancellation_of_runtime_job_is_resumable_not_user_cancelled(self):
        async def scenario():
            job = make_job("ac13ac13ac13", state="runtime_checking", total=3)
            job["settings"]["edt_runtime"] = {"enabled": True, "concurrency": 1}
            for row in job["results"]:
                row.update({
                    "host": row["candidate"].split(":")[0],
                    "port": 443,
                    "state": "checked",
                    "available": True,
                    "edt_available": None,
                    "final_available": None,
                })
            app.rebuild_job_counters(job)
            job["runtime_total"] = 3
            job["state"] = "runtime_checking"
            app.persist_job(job)

            # A server shutdown cancels the background task without the user first
            # setting cancel_requested. That must remain distinguishable from the
            # explicit Stop button.
            task = asyncio.create_task(app.run_job(job))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            recovered = app.read_job_stub(app.job_path(job["id"]))
            self.assertIsNotNone(recovered)
            self.assertEqual(recovered["state"], "interrupted")
            self.assertEqual(recovered["interrupted_stage"], "runtime_checking")
            self.assertTrue(recovered["resume_available"])

        asyncio.run(scenario())

    def test_restart_during_speeding_becomes_resumable_speed_pause_not_dead_interruption(self):
        job = make_job("c33333333333", state="speeding", total=3)
        job["speed_total"] = 3
        job["speed_completed"] = 1
        job["speed_session"] = {
            "targets": [row["candidate"] for row in job["results"]],
            "mode": "quick",
            "completed": [job["results"][0]["candidate"]],
            "status": "running",
        }
        app.persist_job(job)

        stub = app.read_job_stub(app.job_path(job["id"]))

        self.assertEqual(stub["state"], "speed_paused")
        self.assertIsNone(stub["finished_at"])

    def test_restart_during_purity_becomes_resumable_purity_pause_not_dead_interruption(self):
        job = make_job("d44444444444", state="purity_checking", total=3)
        job["purity_total"] = 3
        job["purity_completed"] = 1
        job["purity_session"] = {
            "targets": [row["candidate"] for row in job["results"]],
            "concurrency": 2,
            "completed": [job["results"][0]["candidate"]],
            "status": "running",
        }
        app.persist_job(job)

        stub = app.read_job_stub(app.job_path(job["id"]))

        self.assertEqual(stub["state"], "purity_paused")
        self.assertIsNone(stub["finished_at"])

    def test_speed_restart_stub_can_hydrate_and_resume_existing_session(self):
        async def scenario():
            job = make_job("cc33cc33cc33", state="speeding", total=2)
            for row in job["results"]:
                row.update({"state": "checked", "available": True, "host": row["candidate"].split(":")[0], "port": 443})
            job["speed_total"] = 2
            job["speed_completed"] = 1
            job["speed_session"] = {
                "targets": [row["candidate"] for row in job["results"]],
                "mode": "quick",
                "completed": [job["results"][0]["candidate"]],
                "status": "running",
            }
            app.persist_job(job)
            app.JOBS[job["id"]] = app.read_job_stub(app.job_path(job["id"]))

            calls = []
            original_runner = app.run_post_speed
            original_web, original_csrf = self._without_auth()

            async def fake_runner(current, targets, mode):
                calls.append((set(targets), mode, list((current.get("speed_session") or {}).get("completed") or [])))

            app.run_post_speed = fake_runner
            try:
                response = await app.resume_speed(job["id"], FakeRequest({}))
                self.assertEqual(response["state"], "speeding")
                task = app.POST_SPEED_TASKS[job["id"]]
                await task
            finally:
                app.run_post_speed = original_runner
                app.require_web_session = original_web
                app.require_csrf = original_csrf

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], {row["candidate"] for row in job["results"]})
            self.assertEqual(calls[0][1], "quick")
            self.assertEqual(calls[0][2], [job["results"][0]["candidate"]])

        asyncio.run(scenario())

    def test_purity_restart_stub_can_hydrate_and_resume_existing_session(self):
        async def scenario():
            job = make_job("dd44dd44dd44", state="purity_checking", total=2)
            for row in job["results"]:
                row.update({"state": "checked", "available": True, "host": row["candidate"].split(":")[0], "port": 443})
            job["purity_total"] = 2
            job["purity_completed"] = 1
            job["purity_session"] = {
                "targets": [row["candidate"] for row in job["results"]],
                "concurrency": 2,
                "completed": [job["results"][0]["candidate"]],
                "status": "running",
            }
            app.persist_job(job)
            app.JOBS[job["id"]] = app.read_job_stub(app.job_path(job["id"]))

            calls = []
            original_runner = app.run_post_purity
            original_web, original_csrf = self._without_auth()

            async def fake_runner(current, targets, concurrency):
                calls.append((set(targets), concurrency, list((current.get("purity_session") or {}).get("completed") or [])))

            app.run_post_purity = fake_runner
            try:
                response = await app.resume_purity(job["id"], FakeRequest({}))
                self.assertEqual(response["state"], "purity_checking")
                task = app.PURITY_TASKS[job["id"]]
                await task
            finally:
                app.run_post_purity = original_runner
                app.require_web_session = original_web
                app.require_csrf = original_csrf

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], {row["candidate"] for row in job["results"]})
            self.assertEqual(calls[0][1], 2)
            self.assertEqual(calls[0][2], [job["results"][0]["candidate"]])

        asyncio.run(scenario())

    def test_second_primary_scan_is_rejected_while_one_is_active(self):
        existing = make_job("e55555555555", state="checking", total=1)
        existing["_task"] = DummyTask(done=False)
        app.JOBS[existing["id"]] = existing

        body = {
            "targets": "8.8.4.4:443",
            "probe_sni": "example.com",
            "probe_path": "/cdn-cgi/trace",
            "scan_ports": [443],
            "check_concurrency": 20,
            "timeout": 7,
            "expect_cloudflare": True,
            "edt_runtime": {"enabled": False},
            "speed": {"enabled": False},
        }

        original_web, original_csrf = self._without_auth()
        original_create_task = app.asyncio.create_task

        def fake_create_task(coro):
            coro.close()
            return DummyTask(done=False)

        app.asyncio.create_task = fake_create_task
        try:
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(app.create_job(FakeRequest(body)))
        finally:
            app.asyncio.create_task = original_create_task
            app.require_web_session = original_web
            app.require_csrf = original_csrf

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(len(app.JOBS), 1)

    def test_resume_rejects_if_old_primary_task_is_still_alive(self):
        job = make_job("f66666666666", state="interrupted", total=3)
        job["interrupted_stage"] = "checking"
        job["resume_available"] = True
        job["finished_at"] = app.now()
        job["_task"] = DummyTask(done=False)
        app.JOBS[job["id"]] = job

        original_web, original_csrf = self._without_auth()
        original_create_task = app.asyncio.create_task

        def fake_create_task(coro):
            coro.close()
            return DummyTask(done=False)

        app.asyncio.create_task = fake_create_task
        try:
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(app.resume_interrupted_scan(job["id"], FakeRequest({})))
        finally:
            app.asyncio.create_task = original_create_task
            app.require_web_session = original_web
            app.require_csrf = original_csrf

        self.assertEqual(ctx.exception.status_code, 409)

    def test_primary_cancel_waits_for_and_finishes_the_actual_task(self):
        async def scenario():
            job = make_job("0123456789ab", state="checking", total=2)
            gate = asyncio.Event()

            async def worker():
                try:
                    await gate.wait()
                except asyncio.CancelledError:
                    raise

            task = asyncio.create_task(worker())
            job["_task"] = task
            app.JOBS[job["id"]] = job

            original_web, original_csrf = self._without_auth()
            try:
                result = await app.cancel_job(job["id"], FakeRequest({}))
            finally:
                app.require_web_session = original_web
                app.require_csrf = original_csrf

            self.assertEqual(result["state"], "cancelled")
            self.assertTrue(task.done())
            self.assertTrue(task.cancelled())

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
