"""Tests for TaskIndex — SQLite lightweight index."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from veriaudit.core.schema import (
    AuditReport,
    Finding,
    FindingStatus,
    ProjectProfile,
)
from veriaudit.db.index import TaskIndex, _now


# ── fixtures ─────────────────────────────────────────────────


@pytest.fixture
def index() -> TaskIndex:
    """Return a TaskIndex backed by a temporary SQLite file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    idx = TaskIndex(db_path=db_path)
    yield idx
    try:
        os.unlink(db_path)
    except FileNotFoundError:
        pass


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        finding_id="F-aaaaaaaaaaaa",
        task_id="task-1",
        status=FindingStatus.RAW,
        source_tool="semgrep",
        rule_id="python.lang.security.audit.sql-injection",
        file_path="src/app.py",
        line_start=42,
        message="Possible SQL injection",
        severity="high",
        cwe="CWE-89",
        confidence="high",
    )


@pytest.fixture
def sample_report(index: TaskIndex) -> AuditReport:
    """Create a task and return an AuditReport with findings."""
    index.create_task("task-1", "https://github.com/test/repo", "full")
    return AuditReport(
        task_id="task-1",
        project=ProjectProfile(
            task_id="task-1",
            repo_url="https://github.com/test/repo",
            language="python",
        ),
        completed_at=None,
        status="completed",
        findings=[
            Finding(
                finding_id="F-111111111111",
                task_id="task-1",
                status=FindingStatus.VERIFIED_STATIC,
                source_tool="semgrep",
                rule_id="python.lang.security.audit.sql-injection",
                file_path="src/app.py",
                line_start=42,
                message="Possible SQL injection",
                severity="high",
                cwe="CWE-89",
                confidence="high",
            ),
            Finding(
                finding_id="F-222222222222",
                task_id="task-1",
                status=FindingStatus.REJECTED_STATIC,
                source_tool="bandit",
                rule_id="B104",
                file_path="src/utils.py",
                line_start=88,
                message="Hardcoded bind IP",
                severity="low",
                cwe=None,
                confidence="medium",
            ),
        ],
        report_paths={
            "html": "/tmp/report.html",
            "json": "/tmp/report.json",
            "markdown": "/tmp/report.md",
        },
    )


# ── create_task ──────────────────────────────────────────────


class TestCreateTask:
    def test_creates_with_default_status(self, index: TaskIndex) -> None:
        """Given a new index, When create_task is called, Then the task is retrievable."""
        index.create_task("task-1", "https://github.com/a/b", "full")

        task = index.get_task("task-1")
        assert task is not None
        assert task["task_id"] == "task-1"
        assert task["repo_url"] == "https://github.com/a/b"
        assert task["mode"] == "full"
        assert task["status"] == "pending"
        assert task["created_at"] is not None
        assert task["completed_at"] is None
        assert task["report_paths"] == {}

    def test_creates_with_explicit_status(self, index: TaskIndex) -> None:
        """Given an explicit status, When create_task is called, Then it stores it."""
        index.create_task("task-2", "https://github.com/x/y", "sast", status="running")

        task = index.get_task("task-2")
        assert task is not None
        assert task["status"] == "running"

    def test_duplicate_task_id_raises(self, index: TaskIndex) -> None:
        """Given an existing task_id, When create_task reuses it, Then IntegrityError."""
        index.create_task("task-1", "https://github.com/a/b", "full")
        with pytest.raises(Exception):
            index.create_task("task-1", "https://github.com/other/repo", "sast")


# ── update_task_status ───────────────────────────────────────


class TestUpdateTaskStatus:
    def test_updates_to_terminal_sets_completed_at(self, index: TaskIndex) -> None:
        """Given a pending task, When status becomes completed, Then completed_at is set."""
        index.create_task("task-1", "https://github.com/a/b", "full")

        index.update_task_status("task-1", "completed")

        task = index.get_task("task-1")
        assert task is not None
        assert task["status"] == "completed"
        assert task["completed_at"] is not None

    def test_update_to_running_leaves_completed_at_none(self, index: TaskIndex) -> None:
        """Given a pending task, When status becomes running, Then completed_at stays None."""
        index.create_task("task-1", "https://github.com/a/b", "full")

        index.update_task_status("task-1", "running")

        task = index.get_task("task-1")
        assert task is not None
        assert task["status"] == "running"
        assert task["completed_at"] is None

    def test_update_nonexistent_task_is_noop(self, index: TaskIndex) -> None:
        """Given no matching task, When update_task_status is called, Then no error."""
        index.update_task_status("nonexistent", "completed")
        # no exception


# ── save_report ──────────────────────────────────────────────


class TestSaveReport:
    def test_saves_report_and_findings(
        self, index: TaskIndex, sample_report: AuditReport
    ) -> None:
        """Given a report with findings, When save_report is called, Then both tables updated."""
        index.save_report("task-1", sample_report)

        task = index.get_task("task-1")
        assert task is not None
        assert task["status"] == "completed"
        assert task["completed_at"] is not None
        assert task["report_paths"] == {
            "html": "/tmp/report.html",
            "json": "/tmp/report.json",
            "markdown": "/tmp/report.md",
        }

    def test_saves_correct_finding_count(
        self, index: TaskIndex, sample_report: AuditReport
    ) -> None:
        """Given a report with 2 findings, When saved, Then 2 finding summaries returned."""
        index.save_report("task-1", sample_report)

        summaries = index.get_finding_summaries("task-1")
        assert len(summaries) == 2

    def test_overwrites_previous_findings(
        self, index: TaskIndex, sample_report: AuditReport
    ) -> None:
        """Given an existing report, When a new report is saved, Then old findings replaced."""
        index.save_report("task-1", sample_report)

        updated_report = sample_report.model_copy(deep=True)
        updated_report.findings = [
            Finding(
                finding_id="F-333333333333",
                task_id="task-1",
                status=FindingStatus.CANDIDATE,
                source_tool="semgrep",
                rule_id="python.lang.security.audit.eval",
                file_path="src/eval.py",
                line_start=10,
                message="Use of eval()",
                severity="medium",
                cwe="CWE-95",
                confidence="high",
            ),
        ]
        index.save_report("task-1", updated_report)

        summaries = index.get_finding_summaries("task-1")
        assert len(summaries) == 1
        assert summaries[0]["finding_id"] == "F-333333333333"
        assert summaries[0]["severity"] == "medium"

    def test_finding_fields_are_correct(
        self, index: TaskIndex, sample_report: AuditReport
    ) -> None:
        """Given a saved report, When finding summaries queried, Then all fields match."""
        index.save_report("task-1", sample_report)

        summaries = index.get_finding_summaries("task-1")
        high = [s for s in summaries if s["finding_id"] == "F-111111111111"]
        assert len(high) == 1
        assert high[0]["status"] == "verified_static"
        assert high[0]["severity"] == "high"
        assert high[0]["cwe"] == "CWE-89"
        assert high[0]["file_path"] == "src/app.py"
        assert high[0]["message"] == "Possible SQL injection"


# ── get_task ─────────────────────────────────────────────────


class TestGetTask:
    def test_returns_none_for_unknown_id(self, index: TaskIndex) -> None:
        """Given no matching task, When get_task called, Then returns None."""
        result = index.get_task("nonexistent")
        assert result is None

    def test_handles_null_report_paths(self, index: TaskIndex) -> None:
        """Given a task with no report_paths, When retrieved, Then returns empty dict."""
        index.create_task("task-1", "https://github.com/a/b", "full")
        task = index.get_task("task-1")
        assert task["report_paths"] == {}


# ── list_tasks ───────────────────────────────────────────────


class TestListTasks:
    def test_returns_empty_list_when_no_tasks(self, index: TaskIndex) -> None:
        """Given empty index, When list_tasks called, Then returns []."""
        tasks = index.list_tasks()
        assert tasks == []

    def test_returns_tasks_ordered_by_created_at(self, index: TaskIndex) -> None:
        """Given multiple tasks, When list_tasks called, Then newest first."""
        index.create_task("task-1", "https://github.com/a/1", "full")
        index.create_task("task-2", "https://github.com/a/2", "sast")
        index.create_task("task-3", "https://github.com/a/3", "full")

        tasks = index.list_tasks()
        assert len(tasks) == 3
        assert tasks[0]["task_id"] == "task-3"
        assert tasks[1]["task_id"] == "task-2"
        assert tasks[2]["task_id"] == "task-1"

    def test_respects_limit_and_offset(self, index: TaskIndex) -> None:
        """Given 5 tasks, When limit=2 offset=1, Then returns 2 tasks starting at 2nd."""
        for i in range(5):
            index.create_task(f"task-{i}", f"https://github.com/a/{i}", "full")

        tasks = index.list_tasks(limit=2, offset=1)
        assert len(tasks) == 2


# ── get_finding_summaries ────────────────────────────────────


class TestGetFindingSummaries:
    def test_returns_empty_list_when_no_findings(self, index: TaskIndex) -> None:
        """Given a task with no findings, When queried, Then returns []."""
        index.create_task("task-1", "https://github.com/a/b", "full")
        summaries = index.get_finding_summaries("task-1")
        assert summaries == []

    def test_orders_by_severity_desc_then_file_path(
        self, index: TaskIndex, sample_report: AuditReport
    ) -> None:
        """Given findings with different severities, When queried, Then high first."""
        index.save_report("task-1", sample_report)

        summaries = index.get_finding_summaries("task-1")
        assert summaries[0]["severity"] == "high"
        assert summaries[0]["finding_id"] == "F-111111111111"
        assert summaries[1]["severity"] == "low"
        assert summaries[1]["finding_id"] == "F-222222222222"
