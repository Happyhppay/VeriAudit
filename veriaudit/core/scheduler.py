# VeriAudit - Scheduler
# Multi-project scheduling with configurable concurrency.
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List


class Scheduler:
    """
    Schedules multiple project audits with bounded concurrency.
    """

    def __init__(self, max_concurrent: int = 4):
        self._max_concurrent = max_concurrent
        self._jobs: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def audit_many(self, targets: List[str],
                    audit_fn: Callable[[str], Any],
                    mode: str = "standard",
                    on_start: Callable[[str], None] | None = None,
                    on_complete: Callable[[str, Any], None] | None = None,
                    on_error: Callable[[str, Exception], None] | None = None,
                    ) -> Dict[str, Any]:
        """
        Run audits on multiple targets concurrently (up to max_concurrent).

        Args:
            targets: List of repo URLs or local paths
            audit_fn: Function to call for each target. Signature: fn(target) -> result
            mode: Audit mode (passed with target to audit_fn)
            on_start: Callback when a target starts auditing
            on_complete: Callback when a target completes successfully
            on_error: Callback when a target fails

        Returns:
            Dict mapping target -> result (or None on error)
        """
        results: Dict[str, Any] = {}

        with ThreadPoolExecutor(max_workers=self._max_concurrent) as executor:
            future_map = {}
            for target in targets:
                job_id = f"job-{target.replace('://', '-').replace('/', '-')[:40]}"
                with self._lock:
                    self._jobs[job_id] = {"target": target, "status": "queued"}
                future = executor.submit(self._run_one, audit_fn, target, mode)
                future_map[future] = (job_id, target)

            for future in as_completed(future_map):
                job_id, target = future_map[future]
                with self._lock:
                    self._jobs[job_id]["status"] = "running"

                if on_start:
                    on_start(target)

                try:
                    result = future.result()
                    results[target] = result
                    with self._lock:
                        self._jobs[job_id]["status"] = "completed"
                    if on_complete:
                        on_complete(target, result)
                except Exception as e:
                    results[target] = None
                    with self._lock:
                        self._jobs[job_id]["status"] = "failed"
                    if on_error:
                        on_error(target, e)

        return results

    @staticmethod
    def _run_one(audit_fn, target, mode) -> Any:
        return audit_fn(target, mode)

    def get_status(self) -> Dict[str, dict]:
        with self._lock:
            return dict(self._jobs)

    def get_progress(self) -> Dict[str, int]:
        with self._lock:
            total = len(self._jobs)
            completed = sum(1 for j in self._jobs.values()
                            if j["status"] == "completed")
            failed = sum(1 for j in self._jobs.values()
                          if j["status"] == "failed")
            running = sum(1 for j in self._jobs.values()
                           if j["status"] == "running")
            queued = sum(1 for j in self._jobs.values()
                          if j["status"] == "queued")
        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "queued": queued,
        }
