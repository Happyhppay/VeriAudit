"""Append-only JSONL Event Ledger with SHA-256 hash chaining (Person A)."""

import os
import secrets
import threading
from typing import Any, Dict, List, Optional

from veriaudit.core.exceptions import LedgerWriteError
from veriaudit.core.schema import AuditEvent, Finding, FindingStatus, LEDGERS_DIR

# ── Event type constants ────────────────────────────────────
EVENT_RAW_FINDING = "analysis.raw_finding_emitted"
EVENT_FINDING_PROMOTED = "analysis.finding_promoted"
EVENT_FINDING_REJECTED = "analysis.finding_rejected"
EVENT_ERROR = "system.error"

GENESIS_HASH = "0" * 64


def _new_event_id() -> str:
    return f"evt-{secrets.token_hex(6)}"


class EventLedger:
    """Append-only JSONL event ledger with SHA-256 hash chaining. Thread-safe."""

    def __init__(self, ledger_dir: str = LEDGERS_DIR) -> None:
        self.ledger_dir: str = ledger_dir
        os.makedirs(self.ledger_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._seq_path: str = os.path.join(self.ledger_dir, "_seq.txt")
        self._seq: int = self._load_seq()

    # ── State persistence ───────────────────────────────────

    def _load_seq(self) -> int:
        """Load the global sequence counter. Returns 0 on first run."""
        try:
            with open(self._seq_path, "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_seq(self) -> None:
        with open(self._seq_path, "w", encoding="utf-8") as f:
            f.write(str(self._seq))

    def _ledger_path(self, task_id: str) -> str:
        return os.path.join(self.ledger_dir, f"{task_id}.jsonl")

    def _last_event(self, task_id: str) -> Optional[AuditEvent]:
        path = self._ledger_path(task_id)
        if not os.path.isfile(path):
            return None
        line: Optional[str] = None
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                stripped = ln.strip()
                if stripped:
                    line = stripped
        return AuditEvent.model_validate_json(line) if line is not None else None

    # ── Core API ────────────────────────────────────────────

    def append(self, event: AuditEvent) -> AuditEvent:
        """Append one event. Auto-fills seq, prev_hash, hash. Thread-safe. Raises LedgerWriteError."""
        with self._lock:
            try:
                last = self._last_event(event.task_id)
                event.prev_hash = GENESIS_HASH if last is None else last.hash
                event.seq = self._seq
                if not event.event_id:
                    event.event_id = _new_event_id()
                event.hash = event.compute_hash()

                line = event.model_dump_json() + "\n"
                with open(self._ledger_path(event.task_id), "a", encoding="utf-8") as f:
                    f.write(line)
                self._seq += 1
                self._save_seq()
                return event
            except OSError as exc:
                raise LedgerWriteError(
                    f"Failed to write event to ledger for task {event.task_id!r}: {exc}"
                ) from exc

    def get_events(self, task_id: str) -> List[AuditEvent]:
        """All events for a task, sorted by seq. Empty list if no ledger."""
        path = self._ledger_path(task_id)
        if not os.path.isfile(path):
            return []
        events: List[AuditEvent] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    events.append(AuditEvent.model_validate_json(stripped))
        events.sort(key=lambda e: e.seq)
        return events

    def get_finding_events(self, finding_id: str) -> List[AuditEvent]:
        """All events for a finding across ALL ledger files."""
        events: List[AuditEvent] = []
        try:
            entries = sorted(os.listdir(self.ledger_dir))
        except FileNotFoundError:
            return events
        for entry in entries:
            if not entry.endswith(".jsonl"):
                continue
            filepath = os.path.join(self.ledger_dir, entry)
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    evt = AuditEvent.model_validate_json(stripped)
                    if evt.finding_id == finding_id:
                        events.append(evt)
        events.sort(key=lambda e: e.seq)
        return events

    def project_finding_status(self, finding_id: str) -> FindingStatus:
        """Deterministic projection: replay events → current status."""
        events = self.get_finding_events(finding_id)
        if not events:
            return FindingStatus.RAW
        status: FindingStatus = FindingStatus.RAW
        for evt in events:
            if evt.event_type == EVENT_FINDING_PROMOTED:
                to_status = evt.payload.get("to_status", "")
                try:
                    status = FindingStatus(to_status)
                except ValueError:
                    pass
            elif evt.event_type == EVENT_FINDING_REJECTED:
                status = FindingStatus.REJECTED_STATIC
        return status

    def project_all_findings(self, task_id: str) -> Dict[str, FindingStatus]:
        """Project statuses for all findings in a task → {finding_id: status}."""
        events = self.get_events(task_id)
        result: Dict[str, FindingStatus] = {}
        for evt in events:
            fid = evt.finding_id
            if fid is None:
                continue
            if evt.event_type == EVENT_RAW_FINDING:
                result.setdefault(fid, FindingStatus.RAW)
            elif evt.event_type == EVENT_FINDING_PROMOTED:
                to_status = evt.payload.get("to_status", "")
                try:
                    result[fid] = FindingStatus(to_status)
                except ValueError:
                    pass
            elif evt.event_type == EVENT_FINDING_REJECTED:
                result[fid] = FindingStatus.REJECTED_STATIC
        return result

    def project_finding_history(self, finding_id: str) -> List[Dict[str, Any]]:
        """Status-change history: [{seq, timestamp, from_status, to_status, reason}]."""
        events = self.get_finding_events(finding_id)
        history: List[Dict[str, Any]] = []
        for evt in events:
            if evt.event_type == EVENT_RAW_FINDING:
                from_s, to_s, reason = None, FindingStatus.RAW.value, "initial raw finding"
            elif evt.event_type == EVENT_FINDING_PROMOTED:
                p = evt.payload
                from_s, to_s, reason = p.get("from_status", ""), p.get("to_status", ""), p.get("reason", "")
            elif evt.event_type == EVENT_FINDING_REJECTED:
                p = evt.payload
                from_s, to_s, reason = p.get("from_status", ""), FindingStatus.REJECTED_STATIC.value, p.get("reason", "")
            else:
                continue
            history.append({
                "seq": evt.seq, "timestamp": evt.timestamp.isoformat(),
                "from_status": from_s, "to_status": to_s, "reason": reason,
            })
        return history

    def verify_integrity(self, task_id: str) -> Dict[str, Any]:
        """Verify hash chain: {"valid": bool, "total_events": N, "first_broken_seq": int/None}."""
        events = self.get_events(task_id)
        total = len(events)
        if total == 0:
            return {"valid": True, "total_events": 0, "first_broken_seq": None}
        for i, evt in enumerate(events):
            if evt.compute_hash() != evt.hash:
                return {"valid": False, "total_events": total, "first_broken_seq": evt.seq}
            if i == 0:
                if evt.prev_hash != GENESIS_HASH:
                    return {"valid": False, "total_events": total, "first_broken_seq": evt.seq}
            else:
                if evt.prev_hash != events[i - 1].hash:
                    return {"valid": False, "total_events": total, "first_broken_seq": evt.seq}
        return {"valid": True, "total_events": total, "first_broken_seq": None}


# ────────────────────────────────────────────────────────────
# Standalone emit helpers
# ────────────────────────────────────────────────────────────

def emit_raw_finding(ledger: EventLedger, finding: Finding) -> AuditEvent:
    """Emit analysis.raw_finding_emitted — full finding data in payload."""
    event = AuditEvent(
        event_id=_new_event_id(),
        task_id=finding.task_id,
        finding_id=finding.finding_id,
        seq=0,
        event_type=EVENT_RAW_FINDING,
        payload=finding.model_dump(mode="json"),
        prev_hash="",
        hash="",
    )
    return ledger.append(event)


def emit_finding_promoted(
    ledger: EventLedger,
    finding_id: str,
    from_status: str,
    to_status: str,
    reason: str,
    agent_id: str,
) -> AuditEvent:
    """Emit analysis.finding_promoted. Derives task_id from existing events."""
    existing = ledger.get_finding_events(finding_id)
    task_id: str = existing[0].task_id if existing else "unknown"
    event = AuditEvent(
        event_id=_new_event_id(),
        task_id=task_id,
        finding_id=finding_id,
        seq=0,
        event_type=EVENT_FINDING_PROMOTED,
        payload={
            "from_status": from_status,
            "to_status": to_status,
            "reason": reason,
            "agent_id": agent_id,
        },
        prev_hash="",
        hash="",
    )
    return ledger.append(event)


def emit_finding_rejected(
    ledger: EventLedger,
    finding_id: str,
    reason: str,
    agent_id: str,
) -> AuditEvent:
    """Emit analysis.finding_rejected. from_status = current projected status."""
    current_status = ledger.project_finding_status(finding_id)
    existing = ledger.get_finding_events(finding_id)
    task_id: str = existing[0].task_id if existing else "unknown"
    event = AuditEvent(
        event_id=_new_event_id(),
        task_id=task_id,
        finding_id=finding_id,
        seq=0,
        event_type=EVENT_FINDING_REJECTED,
        payload={
            "from_status": current_status.value,
            "to_status": FindingStatus.REJECTED_STATIC.value,
            "reason": reason,
            "agent_id": agent_id,
        },
        prev_hash="",
        hash="",
    )
    return ledger.append(event)


def emit_error(ledger: EventLedger, task_id: str, error_message: str) -> AuditEvent:
    """Emit system.error (not associated with any finding)."""
    event = AuditEvent(
        event_id=_new_event_id(),
        task_id=task_id,
        finding_id=None,
        seq=0,
        event_type=EVENT_ERROR,
        payload={"error_message": error_message},
        prev_hash="",
        hash="",
    )
    return ledger.append(event)
