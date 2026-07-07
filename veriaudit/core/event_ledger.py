# VeriAudit - Event Ledger
# Append-only JSONL event store with SHA-256 hash chain.
# This is the SINGLE SOURCE OF TRUTH for all system state.
# Finding status is a deterministic projection of events, not a database field.
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Dict, List, Tuple

from pydantic import ValidationError

from .exceptions import LedgerIntegrityError, LedgerWriteError
from .schema import AuditEvent, EventType, FindingStatus


class EventLedger:
    """
    Append-only JSONL event ledger.

    Storage path: <ledger_dir>/<correlation_id>.jsonl
    Thread-safe via internal file lock.

    Hash algorithm:
        hash = SHA256(prev_hash + canonical_json(payload) + timestamp_iso + event_type)
    """

    def __init__(self, ledger_dir: str = "./workspace/ledgers"):
        self._ledger_dir = Path(ledger_dir)
        self._ledger_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.Lock] = {}

    def _get_lock(self, correlation_id: str) -> threading.Lock:
        if correlation_id not in self._locks:
            self._locks[correlation_id] = threading.Lock()
        return self._locks[correlation_id]

    def _get_path(self, correlation_id: str) -> Path:
        return self._ledger_dir / f"{correlation_id}.jsonl"

    def _read_all_lines(self, correlation_id: str) -> List[str]:
        path = self._get_path(correlation_id)
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8").strip().split("\n")

    def _read_events_raw(self, correlation_id: str) -> List[dict]:
        lines = self._read_all_lines(correlation_id)
        events = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def _get_next_sequence(self, correlation_id: str) -> int:
        events = self._read_events_raw(correlation_id)
        if not events:
            return 1
        return max(e.get("sequence", 0) for e in events) + 1

    def _get_last_hash(self, correlation_id: str) -> str:
        events = self._read_events_raw(correlation_id)
        if not events:
            return "0000000000000000000000000000000000000000000000000000000000000000"
        return events[-1].get("hash", "")

    # ========== Write ==========

    def append(self, event: AuditEvent) -> AuditEvent:
        """
        Append an event. Auto-assigns sequence, prev_hash, and hash.
        Thread-safe.
        """
        correlation_id = event.correlation_id
        lock = self._get_lock(correlation_id)
        path = self._get_path(correlation_id)

        with lock:
            event.sequence = self._get_next_sequence(correlation_id)
            event.prev_hash = self._get_last_hash(correlation_id)
            event.hash = event.compute_hash()

            line = event.model_dump_json(exclude_defaults=False)
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                raise LedgerWriteError(f"Failed to write event {event.event_id}: {e}") from e

        return event

    def append_batch(self, events: List[AuditEvent]) -> List[AuditEvent]:
        """Append multiple events atomically (single lock). Returns populated events."""
        results = []
        correlation_id = events[0].correlation_id if events else ""
        lock = self._get_lock(correlation_id)
        path = self._get_path(correlation_id)

        with lock:
            for event in events:
                event.sequence = self._get_next_sequence(correlation_id)
                event.prev_hash = self._get_last_hash(correlation_id)
                event.hash = event.compute_hash()
                results.append(event)

                line = event.model_dump_json(exclude_defaults=False)
                try:
                    with open(path, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                except OSError as e:
                    raise LedgerWriteError(f"Failed to write event {event.event_id}: {e}") from e

        return results

    # ========== Read ==========

    def get_events(self, correlation_id: str) -> List[AuditEvent]:
        """Get all events for a session, sorted by sequence."""
        raw = self._read_events_raw(correlation_id)
        events = []
        for r in raw:
            try:
                events.append(AuditEvent(**r))
            except ValidationError:
                continue
        events.sort(key=lambda e: e.sequence)
        return events

    def get_events_by_type(self, correlation_id: str,
                            event_types: List[EventType]) -> List[AuditEvent]:
        """Get events filtered by type."""
        types_set = {e.value for e in event_types}
        return [e for e in self.get_events(correlation_id) if e.event_type.value in types_set]

    def get_finding_events(self, finding_id: str, correlation_id: str) -> List[AuditEvent]:
        """Get all events related to a specific finding."""
        return [
            e for e in self.get_events(correlation_id)
            if e.finding_id == finding_id or e.payload.get("finding_id") == finding_id
        ]

    def get_last_event(self, correlation_id: str) -> AuditEvent | None:
        events = self.get_events(correlation_id)
        return events[-1] if events else None

    # ========== Projection (Deterministic) ==========

    def project_finding_status(self, finding_id: str,
                                correlation_id: str) -> FindingStatus:
        """
        Deterministic projection: compute the current status of a finding
        from all its events.
        """
        events = self.get_finding_events(finding_id, correlation_id)
        status = FindingStatus.RAW

        for event in sorted(events, key=lambda e: e.sequence):
            p = event.payload
            if event.event_type == EventType.ANALYSIS_FINDING_PROMOTED:
                to_status = p.get("to_status") or p.get("to")
                if to_status:
                    try:
                        status = FindingStatus(to_status)
                    except ValueError:
                        pass
            elif event.event_type == EventType.ANALYSIS_FINDING_REJECTED:
                status = FindingStatus.REJECTED
            elif event.event_type == EventType.JUDGE_RULING_MADE:
                ruling = p.get("ruling")
                if ruling:
                    try:
                        status = FindingStatus(ruling)
                    except ValueError:
                        pass

        return status

    def project_all_findings(self, correlation_id: str) -> Dict[str, FindingStatus]:
        """Project current status for all findings in a session."""
        all_events = self.get_events(correlation_id)
        finding_ids = set()

        for e in all_events:
            fid = e.finding_id or e.payload.get("finding_id")
            if fid:
                finding_ids.add(fid)

        result = {}
        for fid in finding_ids:
            result[fid] = self.project_finding_status(fid, correlation_id)
        return result

    def project_finding_history(self, finding_id: str,
                                 correlation_id: str) -> List[Dict]:
        """Return the full status change history for a finding."""
        events = self.get_finding_events(finding_id, correlation_id)
        history = []

        for e in sorted(events, key=lambda e: e.sequence):
            if e.event_type in (EventType.ANALYSIS_FINDING_PROMOTED,
                                EventType.ANALYSIS_FINDING_REJECTED,
                                EventType.JUDGE_RULING_MADE):
                history.append({
                    "sequence": e.sequence,
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type.value,
                    "payload": e.payload,
                })
        return history

    # ========== Integrity Verification ==========

    def verify_integrity(self, correlation_id: str) -> Dict:
        """
        Verify the SHA-256 hash chain.
        Returns: {"valid": bool, "total_events": int, "first_broken_seq": int | None}
        """
        raw = self._read_events_raw(correlation_id)
        if not raw:
            return {"valid": True, "total_events": 0, "first_broken_seq": None}

        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        for i, r in enumerate(raw):
            seq = r.get("sequence", 0)
            stored_hash = r.get("hash", "")

            # Recompute
            payload_json = json.dumps(r.get("payload", {}), sort_keys=True, default=str)
            from datetime import datetime
            ts = r.get("timestamp", "")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass
            ts_iso = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            event_type = r.get("event_type", "")
            import hashlib
            raw_input = f"{prev_hash}{payload_json}{ts_iso}{event_type}"
            expected_hash = hashlib.sha256(raw_input.encode("utf-8")).hexdigest()

            if stored_hash != expected_hash:
                return {
                    "valid": False,
                    "total_events": len(raw),
                    "first_broken_seq": seq,
                }
            prev_hash = stored_hash

        return {"valid": True, "total_events": len(raw), "first_broken_seq": None}

    # ========== Lifecycle ==========

    def close(self, correlation_id: str) -> None:
        """Close and verify a ledger session."""
        self._locks.pop(correlation_id, None)
